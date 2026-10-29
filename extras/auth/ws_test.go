package auth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/stretchr/testify/assert"
)

func TestDiscoverWSURL(t *testing.T) {
	enabledFlag := true
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !enabledFlag {
			_, _ = w.Write([]byte(`{"websocket":{"enabled":false,"ws_url":""}}`))
			return
		}
		_, _ = w.Write([]byte(`{"websocket":{"enabled":true,"ws_url":"ws://127.0.0.1:19999/ws"}}`))
	}))
	defer srv.Close()

	u, enabled, err := DiscoverWSURL(srv.URL, "tok", 1)
	assert.NoError(t, err)
	assert.True(t, enabled)
	assert.Equal(t, "ws://127.0.0.1:19999/ws", u)

	enabledFlag = false
	_, enabled, err = DiscoverWSURL(srv.URL, "tok", 1)
	assert.NoError(t, err)
	assert.False(t, enabled)
}

func TestApplyUserDelta(t *testing.T) {
	ApplyUsers([]User{{ID: 1, UUID: "u1"}, {ID: 2, UUID: "u2"}}, nil)

	ApplyUserDelta(true, []User{{ID: 3, UUID: "u3"}}, nil)
	assert.Equal(t, map[string]User{"u1": {ID: 1, UUID: "u1"}, "u2": {ID: 2, UUID: "u2"}, "u3": {ID: 3, UUID: "u3"}}, usersMap)

	// remove 只带 id
	ApplyUserDelta(false, []User{{ID: 2}}, nil)
	assert.NotContains(t, usersMap, "u2")
	assert.Len(t, usersMap, 2)
}

func TestRunWSClientEvents(t *testing.T) {
	upgrader := websocket.Upgrader{}
	var mu sync.Mutex
	var gotPong bool

	var usersHook []User
	var configHook json.RawMessage
	var deltaAdd bool
	var deltaUsers []User

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "tok", r.URL.Query().Get("token"))
		assert.Equal(t, "7", r.URL.Query().Get("node_id"))
		c, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer c.Close()
		_ = c.WriteJSON(map[string]any{"event": "auth.success", "data": map[string]any{"node_id": 7}})
		_ = c.WriteJSON(map[string]any{"event": "sync.config", "data": map[string]any{"config": map[string]any{"server_port": 18443}}})
		_ = c.WriteJSON(map[string]any{"event": "sync.users", "data": map[string]any{"users": []map[string]any{{"id": 1, "uuid": "u1"}}}})
		_ = c.WriteJSON(map[string]any{"event": "sync.user.delta", "data": map[string]any{"action": "remove", "users": []map[string]any{{"id": 1}}}})
		_ = c.WriteJSON(map[string]any{"event": "ping"})
		// 等 pong 后关闭，客户端随之退出
		deadline := time.Now().Add(3 * time.Second)
		c.SetReadDeadline(deadline)
		for {
			_, msg, err := c.ReadMessage()
			if err != nil {
				return
			}
			if strings.Contains(string(msg), `"pong"`) {
				mu.Lock()
				gotPong = true
				mu.Unlock()
				return
			}
		}
	}))
	defer srv.Close()

	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http")
	err := RunWSClient(wsURL, "tok", 7, WSHandlers{
		OnConfig: func(raw json.RawMessage) { configHook = raw },
		OnUsers: func(users []User) {
			usersHook = users
			ApplyUsers(users, nil)
		},
		OnUserDelta: func(add bool, users []User) {
			deltaAdd, deltaUsers = add, users
			ApplyUserDelta(add, users, nil)
		},
	})
	assert.Error(t, err) // 服务端关闭导致断开
	assert.False(t, WSActive.Load())

	assert.Contains(t, string(configHook), "18443")
	assert.Equal(t, []User{{ID: 1, UUID: "u1"}}, usersHook)
	assert.False(t, deltaAdd)
	assert.Equal(t, []User{{ID: 1}}, deltaUsers)
	assert.Equal(t, map[string]User{}, usersMap) // delta remove 清空
	mu.Lock()
	assert.True(t, gotPong)
	mu.Unlock()
}

func TestRunWSClientReadTimeout(t *testing.T) {
	// 对端保持静默且不回 pong：客户端必须靠读超时自己放弃，
	// 否则半开连接会让 WSActive 永远为 true，REST 轮询一直被跳过。
	oldTimeout := wsReadTimeout
	wsReadTimeout = 200 * time.Millisecond
	defer func() { wsReadTimeout = oldTimeout }()

	upgrader := websocket.Upgrader{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer c.Close()
		_ = c.WriteJSON(map[string]any{"event": "auth.success"})
		// 之后不再写任何数据，也不回 pong
		for {
			if _, _, err := c.ReadMessage(); err != nil {
				return
			}
		}
	}))
	defer srv.Close()

	start := time.Now()
	err := RunWSClient("ws"+strings.TrimPrefix(srv.URL, "http"), "tok", 7, WSHandlers{})
	assert.Error(t, err)
	assert.Less(t, time.Since(start), 2*time.Second)
	assert.False(t, WSActive.Load())
}

func TestReconnectLoopDisabled(t *testing.T) {
	// 面板未启用 WS：ReconnectLoop 应静默等待而不是忙转
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"websocket":{"enabled":false}}`))
	}))
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	go ReconnectLoop(ctx, srv.URL, "tok", 1, WSHandlers{})
	time.Sleep(300 * time.Millisecond)
	assert.False(t, WSActive.Load())
	cancel()
}
