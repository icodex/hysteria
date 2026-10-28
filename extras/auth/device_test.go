package auth

import (
	"net"
	"sort"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func tcpAddr(ip string) *net.TCPAddr {
	return &net.TCPAddr{IP: net.ParseIP(ip), Port: 12345}
}

func resetDevices() {
	devices.mu.Lock()
	devices.local = make(map[int]map[string]int)
	devices.global = make(map[int]map[string]bool)
	devices.globalAt = time.Time{}
	devices.mu.Unlock()
}

func TestTrackConnectDisconnect(t *testing.T) {
	resetDevices()
	defer resetDevices()

	TrackConnect("5", tcpAddr("1.1.1.1"))
	TrackConnect("5", tcpAddr("1.1.1.1"))
	TrackConnect("5", tcpAddr("2.2.2.2"))

	snap := DeviceSnapshot()
	sort.Strings(snap[5])
	assert.Equal(t, []string{"1.1.1.1", "2.2.2.2"}, snap[5])

	TrackDisconnect("5", tcpAddr("1.1.1.1"))
	snap = DeviceSnapshot()
	sort.Strings(snap[5])
	assert.Equal(t, []string{"1.1.1.1", "2.2.2.2"}, snap[5], "refcount still holds one conn from 1.1.1.1")

	TrackDisconnect("5", tcpAddr("1.1.1.1"))
	TrackDisconnect("5", tcpAddr("2.2.2.2"))
	assert.Empty(t, DeviceSnapshot(), "all disconnected, snapshot should be empty")

	// 非 v2board 用户 id 与非法地址不应进表
	TrackConnect("nobody", tcpAddr("3.3.3.3"))
	TrackConnect("0", tcpAddr("3.3.3.3"))
	assert.Empty(t, DeviceSnapshot())
}

func TestDeviceLimitReject(t *testing.T) {
	resetDevices()
	defer resetDevices()

	// limit 0 永不拒绝
	assert.False(t, deviceLimitReject(7, 0, tcpAddr("9.9.9.9")))

	// 本地第 1、2 台放行，第 3 台拒绝；已知 IP 重连放行
	assert.False(t, deviceLimitReject(7, 2, tcpAddr("1.1.1.1")))
	TrackConnect("7", tcpAddr("1.1.1.1"))
	assert.False(t, deviceLimitReject(7, 2, tcpAddr("2.2.2.2")))
	TrackConnect("7", tcpAddr("2.2.2.2"))
	assert.True(t, deviceLimitReject(7, 2, tcpAddr("3.3.3.3")))
	assert.False(t, deviceLimitReject(7, 2, tcpAddr("1.1.1.1")), "known IP reconnects fine")
}

func TestDeviceLimitRejectMergedGlobal(t *testing.T) {
	resetDevices()
	defer resetDevices()

	// 面板全局设备表新鲜时参与合并判定：
	// 本地 2.2.2.2 + 全局 1.1.1.1 已满 2 台，新 IP 3.3.3.3 拒绝
	TrackConnect("8", tcpAddr("2.2.2.2"))
	SetGlobalDevices(map[int][]string{8: {"1.1.1.1"}})
	assert.True(t, deviceLimitReject(8, 2, tcpAddr("3.3.3.3")))
	assert.False(t, deviceLimitReject(8, 2, tcpAddr("1.1.1.1")), "IP known to panel is allowed")

	// 全局表过期（>60s）后退化为仅本地判定：只剩本地 1 台，放行
	devices.mu.Lock()
	devices.globalAt = time.Now().Add(-2 * time.Minute)
	devices.mu.Unlock()
	assert.False(t, deviceLimitReject(8, 2, tcpAddr("3.3.3.3")))
}

func TestAuthenticateDeviceGate(t *testing.T) {
	old := usersMap
	defer func() { usersMap = old; resetDevices() }()
	resetDevices()
	usersMap = map[string]User{
		"uuid-1": {ID: 5, UUID: "uuid-1", DeviceLimit: 1},
		"uuid-2": {ID: 6, UUID: "uuid-2"},
	}
	p := &V2boardApiProvider{URL: "http://panel.example/user"}

	// 第一台设备放行并进入本地设备表（serverLogger 在连接建立后上报）
	ok, id := p.Authenticate(tcpAddr("1.1.1.1"), "uuid-1", 0)
	assert.True(t, ok)
	assert.Equal(t, "5", id)
	TrackConnect("5", tcpAddr("1.1.1.1"))

	// 第二台设备超限拒绝
	ok, _ = p.Authenticate(tcpAddr("2.2.2.2"), "uuid-1", 0)
	assert.False(t, ok)

	// 已知 IP 重连放行
	ok, _ = p.Authenticate(tcpAddr("1.1.1.1"), "uuid-1", 0)
	assert.True(t, ok)

	// 无 device_limit 用户不受影响
	ok, id = p.Authenticate(tcpAddr("3.3.3.3"), "uuid-2", 0)
	assert.True(t, ok)
	assert.Equal(t, "6", id)

	// 未知用户拒绝
	ok, _ = p.Authenticate(tcpAddr("4.4.4.4"), "uuid-x", 0)
	assert.False(t, ok)
}

// 确认 strconv 在解析面板用户 id 时与 TrackConnect 行为一致
func TestParseIDIP(t *testing.T) {
	uid, ip := parseIDIP("12", tcpAddr("1.2.3.4"))
	assert.Equal(t, 12, uid)
	assert.Equal(t, "1.2.3.4", ip)

	uid, ip = parseIDIP("abc", tcpAddr("1.2.3.4"))
	assert.Zero(t, uid)
	assert.Empty(t, ip)

	uid, ip = parseIDIP(strconv.Itoa(0), tcpAddr("1.2.3.4"))
	assert.Zero(t, uid)
}

func TestDeviceLimitRejectCountsFallback(t *testing.T) {
	resetDevices()
	defer resetDevices()

	// 本地无视图时（节点刚重启）：计数无法归因，不参与判定 → 放行
	SetGlobalAliveCounts(map[int]int{9: 2})
	devices.mu.Lock()
	devices.globalAt = time.Now().Add(-2 * time.Minute) // IP 集过期
	devices.mu.Unlock()
	assert.False(t, deviceLimitReject(9, 2, tcpAddr("3.3.3.3")), "cold node must not reject on counts alone")

	// 有本地视图（本节点 1 台）：其余节点 = 2-1 = 1 ≥ limit 1 → 新 IP 拒
	TrackConnect("9", tcpAddr("1.1.1.1"))
	assert.True(t, deviceLimitReject(9, 1, tcpAddr("3.3.3.3")))
	// 已知本地 IP 仍放行
	assert.False(t, deviceLimitReject(9, 2, tcpAddr("1.1.1.1")))
	// 其余节点数 < limit → 放行（limit 5）
	assert.False(t, deviceLimitReject(9, 5, tcpAddr("4.4.4.4")))

	// 计数也过期：退回仅本地判定（本地 1 台 < limit 2）
	devices.mu.Lock()
	devices.globalCountsAt = time.Now().Add(-2 * time.Minute)
	devices.mu.Unlock()
	assert.False(t, deviceLimitReject(9, 2, tcpAddr("5.5.5.5")))
	// 同 IP 重连（本地已有 2 台、limit 2）——本地满员前已知 IP 恒放行
	assert.False(t, deviceLimitReject(9, 2, tcpAddr("2.2.2.2")))
	// 本地满员则拒
	TrackConnect("9", tcpAddr("2.2.2.2"))
	assert.True(t, deviceLimitReject(9, 2, tcpAddr("6.6.6.6")))
}
