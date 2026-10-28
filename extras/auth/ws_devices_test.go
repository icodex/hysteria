package auth

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/stretchr/testify/assert"
)

// 覆盖 auth.success 后的 request.devices 拉取、sync.devices 分发、
// DeviceSnapshot 的周期 report.devices 上报
func TestRunWSClientDevicesEvents(t *testing.T) {
	upgrader := websocket.Upgrader{}
	gotRequest := make(chan map[string]any, 4)
	gotReport := make(chan map[string]any, 4)
	gotDevices := make(chan map[int][]string, 1)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer c.Close()
		_ = c.WriteJSON(map[string]any{"event": "auth.success"})
		_ = c.WriteJSON(map[string]any{"event": "sync.devices", "data": map[string]any{
			"users": map[string]any{"5": []string{"1.1.1.1", "2.2.2.2"}},
		}})
		deadline := time.Now().Add(2 * time.Second)
		c.SetReadDeadline(deadline)
		for {
			_, msg, err := c.ReadMessage()
			if err != nil {
				return
			}
			var m struct {
				Event string         `json:"event"`
				Data  map[string]any `json:"data"`
			}
			if json.Unmarshal(msg, &m) != nil {
				continue
			}
			switch m.Event {
			case "request.devices":
				select {
				case gotRequest <- m.Data:
				default:
				}
			case "report.devices":
				select {
				case gotReport <- m.Data:
				default:
				}
			}
		}
	}))
	defer srv.Close()

	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http")
	done := make(chan error, 1)
	go func() {
		done <- RunWSClient(wsURL, "tok", 7, WSHandlers{
			NodeID: 7,
			OnSyncDevices: func(users map[int][]string) {
				gotDevices <- users
			},
			DeviceSnapshot:       func() map[int][]string { return map[int][]string{3: {"9.9.9.9"}} },
			DeviceReportInterval: 100 * time.Millisecond,
		})
	}()

	// auth.success 后必须立刻拉一次面板全局设备表
	select {
	case data := <-gotRequest:
		assert.Equal(t, float64(7), data["node_id"])
	case <-time.After(2 * time.Second):
		t.Fatal("no request.devices after auth.success")
	}

	// sync.devices 事件必须带 int 化的 uid 表分发到 OnSyncDevices
	select {
	case users := <-gotDevices:
		assert.Equal(t, map[int][]string{5: {"1.1.1.1", "2.2.2.2"}}, users)
	case <-time.After(2 * time.Second):
		t.Fatal("no sync.devices dispatch")
	}

	// DeviceSnapshot 周期上报 report.devices,携带 node_id 与设备表
	select {
	case data := <-gotReport:
		assert.Equal(t, float64(7), data["node_id"])
		devices, ok := data["devices"].(map[string]any)
		if assert.True(t, ok, "report.devices must carry devices map") {
			assert.Equal(t, []any{"9.9.9.9"}, devices["3"])
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no report.devices")
	}

	// 服务端读超时关连接,RunWSClient 返回错误并清掉 WSActive
	assert.Error(t, <-done)
	assert.False(t, WSActive.Load())
}
