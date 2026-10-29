package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// WSHandlers 处理面板 WS 推送的事件
type WSHandlers struct {
	// NodeID 携带在 request.devices / report.devices 消息体里
	NodeID int
	// OnConfig 收到 sync.config，raw 为 buildNodeConfig 的原始 JSON
	OnConfig func(raw json.RawMessage)
	// OnUsers 收到 sync.users（全量用户列表）
	OnUsers func(users []User)
	// OnUserDelta 收到 sync.user.delta（增量，remove 时 user 只保证 ID 有值）
	OnUserDelta func(add bool, users []User)
	// OnSyncDevices 收到 sync.devices（面板全局设备表，uid → ips）
	OnSyncDevices func(users map[int][]string)
	// DeviceSnapshot 返回本地在线设备表，非 nil 时定期上报 report.devices
	DeviceSnapshot func() map[int][]string
	// DeviceReportInterval 为 0 时默认 60s
	DeviceReportInterval time.Duration
	// StatusCollector 非 nil 时定期上报 node.status（负载/指标），间隔同 DeviceReportInterval
	StatusCollector func() map[string]any
	// OnlineConnSnapshot 返回 {uid: 活跃连接数}，随 node.status 一并上报 online
	OnlineConnSnapshot func() map[string]int
}

type wsHandshakeResponse struct {
	WebSocket struct {
		Enabled bool   `json:"enabled"`
		WSURL   string `json:"ws_url"`
	} `json:"websocket"`
}

// DiscoverWSURL 通过 /api/v2/server/handshake 查询面板是否启用 WS 推送
func DiscoverWSURL(apiHost, token string, nodeID int) (string, bool, error) {
	u := apiHost + "/api/v2/server/handshake?token=" + url.QueryEscape(token) + "&node_id=" + strconv.Itoa(nodeID)
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(u)
	if err != nil {
		return "", false, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", false, err
	}
	if resp.StatusCode != http.StatusOK {
		return "", false, fmt.Errorf("handshake status %d", resp.StatusCode)
	}
	var hs wsHandshakeResponse
	if err := json.Unmarshal(body, &hs); err != nil {
		return "", false, err
	}
	if !hs.WebSocket.Enabled || hs.WebSocket.WSURL == "" {
		return "", false, nil
	}
	return hs.WebSocket.WSURL, true, nil
}

type wsMessage struct {
	Event string          `json:"event"`
	Data  json.RawMessage `json:"data"`
}

type wsUserDelta struct {
	Action string `json:"action"`
	Users  []User `json:"users"`
}

type wsUsersPayload struct {
	Users []User `json:"users"`
}

type wsConfigPayload struct {
	Config json.RawMessage `json:"config"`
}

type wsDevicesPayload struct {
	Users map[string][]string `json:"users"`
}

// wsKeepaliveInterval 控制帧 ping 间隔；同时兼作应用层 pong（维持面板 node_ws_alive）
const wsKeepaliveInterval = 30 * time.Second

// wsReadTimeout 读超时，变量形式便于测试压缩。见 RunWSClient 内的半开连接说明。
var wsReadTimeout = 90 * time.Second

// RunWSClient 连接面板 WS 并处理推送，连接期间置 WSActive，断开时返回
func RunWSClient(wsURL, token string, nodeID int, h WSHandlers) error {
	u, err := url.Parse(wsURL)
	if err != nil {
		return err
	}
	q := u.Query()
	q.Set("token", token)
	q.Set("node_id", strconv.Itoa(nodeID))
	u.RawQuery = q.Encode()

	dialer := &websocket.Dialer{HandshakeTimeout: 15 * time.Second}
	conn, _, err := dialer.Dial(u.String(), nil)
	if err != nil {
		return err
	}
	defer conn.Close()

	WSActive.Store(true)
	defer WSActive.Store(false)
	log.Printf("v2board WS connected: %s", wsURL)

	// 半开连接检测：面板每 55s 发应用层 ping、Workerman 对控制帧 ping 自动回 pong，
	// 因此 90s 内无任何入站数据即可判定链路已死。没有这条读超时，NAT 超时或
	// 对端僵死时 ReadMessage 会无限阻塞，WSActive 一直是 true，REST 轮询被跳过，
	// 配置/用户更新要等到 TCP 重传超时（十几分钟）才恢复。
	extendReadDeadline := func() { _ = conn.SetReadDeadline(time.Now().Add(wsReadTimeout)) }
	extendReadDeadline()
	conn.SetPongHandler(func(string) error {
		extendReadDeadline()
		return nil
	})

	pingTicker := time.NewTicker(wsKeepaliveInterval)
	defer pingTicker.Stop()
	errChan := make(chan error, 4)
	// done 关闭后所有辅助 goroutine 退出，避免每次重连泄漏
	done := make(chan struct{})
	defer close(done)

	// gorilla/websocket 连接同一时刻只允许一个写 goroutine，
	// 心跳与读循环的 pong 都必须经过这把锁
	var writeMu sync.Mutex
	writeJSON := func(v any) error {
		writeMu.Lock()
		defer writeMu.Unlock()
		return conn.WriteJSON(v)
	}

	go func() {
		for {
			select {
			case <-done:
				return
			case <-pingTicker.C:
			}
			if err := conn.WriteControl(websocket.PingMessage, nil, time.Now().Add(5*time.Second)); err != nil {
				errChan <- err
				return
			}
			// 应用层 pong 维持面板 node_ws_alive cache
			if err := writeJSON(wsMessage{Event: "pong"}); err != nil {
				errChan <- err
				return
			}
		}
	}()

	// 定期上报本地在线设备与节点状态，驱动面板在线数/负载/指标展示
	if h.DeviceSnapshot != nil {
		interval := h.DeviceReportInterval
		if interval <= 0 {
			interval = time.Minute
		}
		reportTicker := time.NewTicker(interval)
		defer reportTicker.Stop()
		go func() {
			for {
				select {
				case <-done:
					return
				case <-reportTicker.C:
				}
				if snap := h.DeviceSnapshot(); len(snap) > 0 {
					if data, merr := json.Marshal(map[string]any{"node_id": h.NodeID, "devices": snap}); merr == nil {
						if err := writeJSON(wsMessage{Event: "report.devices", Data: data}); err != nil {
							errChan <- err
							return
						}
					}
				}
				if h.StatusCollector != nil {
					payload := map[string]any{"node_id": h.NodeID}
					for k, v := range h.StatusCollector() {
						payload[k] = v
					}
					if h.OnlineConnSnapshot != nil {
						payload["online"] = h.OnlineConnSnapshot()
					}
					if data, merr := json.Marshal(payload); merr == nil {
						if err := writeJSON(wsMessage{Event: "node.status", Data: data}); err != nil {
							errChan <- err
							return
						}
					}
				}
			}
		}()
	}

	go func() {
		for {
			_, msg, err := conn.ReadMessage()
			if err != nil {
				errChan <- err
				return
			}
			extendReadDeadline()
			var m wsMessage
			if err := json.Unmarshal(msg, &m); err != nil {
				continue
			}
			switch m.Event {
			case "auth.success":
				log.Printf("v2board WS auth success")
				// 拉一次面板全局设备表，供 device_limit 判定
				if h.OnSyncDevices != nil {
					if data, err := json.Marshal(map[string]int{"node_id": h.NodeID}); err == nil {
						_ = writeJSON(wsMessage{Event: "request.devices", Data: data})
					}
				}
			case "ping":
				_ = writeJSON(wsMessage{Event: "pong"})
			case "sync.config":
				if h.OnConfig != nil {
					var p wsConfigPayload
					if err := json.Unmarshal(m.Data, &p); err == nil && len(p.Config) > 0 {
						h.OnConfig(p.Config)
					}
				}
			case "sync.users":
				if h.OnUsers != nil {
					var p wsUsersPayload
					if err := json.Unmarshal(m.Data, &p); err == nil {
						h.OnUsers(p.Users)
					}
				}
			case "sync.user.delta":
				if h.OnUserDelta != nil {
					var p wsUserDelta
					if err := json.Unmarshal(m.Data, &p); err == nil {
						h.OnUserDelta(p.Action == "add", p.Users)
					}
				}
			case "sync.devices":
				if h.OnSyncDevices != nil {
					var p wsDevicesPayload
					if err := json.Unmarshal(m.Data, &p); err == nil {
						users := make(map[int][]string, len(p.Users))
						for k, v := range p.Users {
							if id, err := strconv.Atoi(k); err == nil {
								users[id] = v
							}
						}
						h.OnSyncDevices(users)
					}
				}
			}
		}
	}()

	return <-errChan
}

// ReconnectLoop 发现并维持 WS 连接；面板未启用或不可达时降频重试，
// 断开后指数退避重连，REST 轮询在 WS 断开期间自动接管
func ReconnectLoop(ctx context.Context, apiHost, token string, nodeID int, h WSHandlers) {
	wsURL := ""
	backoff := time.Second
	for {
		if wsURL == "" {
			u, enabled, err := DiscoverWSURL(apiHost, token, nodeID)
			if err != nil || !enabled {
				// 面板无 WS 或不可达：降频重试
				select {
				case <-ctx.Done():
					return
				case <-time.After(60 * time.Second):
				}
				continue
			}
			wsURL = u
			backoff = time.Second
		}

		start := time.Now()
		err := RunWSClient(wsURL, token, nodeID, h)
		log.Printf("v2board WS disconnected: %v", err)

		select {
		case <-ctx.Done():
			return
		default:
		}

		// 连接曾稳定保持则重置退避
		if time.Since(start) > 2*time.Minute {
			backoff = time.Second
		}
		wait := backoff + time.Duration(rand.Int63n(int64(backoff/5+1)))
		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
		if backoff < 60*time.Second {
			backoff *= 2
		} else {
			// 退避到顶仍连不上：面板可能换了 WS 地址（或关了推送），
			// 丢掉缓存 URL 重新走握手发现
			wsURL = ""
		}
	}
}
