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
	"time"

	"github.com/gorilla/websocket"
)

// WSHandlers 处理面板 WS 推送的事件
type WSHandlers struct {
	// OnConfig 收到 sync.config，raw 为 buildNodeConfig 的原始 JSON
	OnConfig func(raw json.RawMessage)
	// OnUsers 收到 sync.users（全量用户列表）
	OnUsers func(users []User)
	// OnUserDelta 收到 sync.user.delta（增量，remove 时 user 只保证 ID 有值）
	OnUserDelta func(add bool, users []User)
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

	pingTicker := time.NewTicker(30 * time.Second)
	defer pingTicker.Stop()
	errChan := make(chan error, 2)

	go func() {
		for range pingTicker.C {
			if err := conn.WriteControl(websocket.PingMessage, nil, time.Now().Add(5*time.Second)); err != nil {
				errChan <- err
				return
			}
			// 应用层 pong 维持面板 node_ws_alive cache
			if err := conn.WriteJSON(wsMessage{Event: "pong"}); err != nil {
				errChan <- err
				return
			}
		}
	}()

	go func() {
		for {
			_, msg, err := conn.ReadMessage()
			if err != nil {
				errChan <- err
				return
			}
			var m wsMessage
			if err := json.Unmarshal(msg, &m); err != nil {
				continue
			}
			switch m.Event {
			case "auth.success":
				log.Printf("v2board WS auth success")
			case "ping":
				_ = conn.WriteJSON(wsMessage{Event: "pong"})
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
				// 设备数限制本节点未实现，忽略
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
		}
	}
}
