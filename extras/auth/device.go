package auth

import (
	"bytes"
	"encoding/json"
	"log"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// deviceTracker 本地连接 IP 引用计数 + 面板 sync.devices 全局设备集
type deviceTracker struct {
	mu       sync.Mutex
	local    map[int]map[string]int // user id → ip → 连接引用数
	global   map[int]map[string]bool
	globalAt time.Time
}

var devices = &deviceTracker{
	local:  make(map[int]map[string]int),
	global: make(map[int]map[string]bool),
}

// TrackConnect/TrackDisconnect 由 app 层 serverLogger 的 Connect/Disconnect 调用
func TrackConnect(id string, addr net.Addr) {
	uid, ip := parseIDIP(id, addr)
	if uid == 0 || ip == "" {
		return
	}
	devices.mu.Lock()
	m := devices.local[uid]
	if m == nil {
		m = make(map[string]int)
		devices.local[uid] = m
	}
	m[ip]++
	devices.mu.Unlock()
}

func TrackDisconnect(id string, addr net.Addr) {
	uid, ip := parseIDIP(id, addr)
	if uid == 0 || ip == "" {
		return
	}
	devices.mu.Lock()
	defer devices.mu.Unlock()
	m := devices.local[uid]
	if m == nil {
		return
	}
	m[ip]--
	if m[ip] <= 0 {
		delete(m, ip)
	}
	if len(m) == 0 {
		delete(devices.local, uid)
	}
}

func parseIDIP(id string, addr net.Addr) (int, string) {
	uid, err := strconv.Atoi(id)
	if err != nil || uid <= 0 || addr == nil {
		return 0, ""
	}
	return uid, addrToIP(addr)
}

func addrToIP(addr net.Addr) string {
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		host = addr.String()
	}
	// 去掉 IPv6 zone（fe80::1%eth0）
	if i := strings.Index(host, "%"); i > 0 {
		host = host[:i]
	}
	return host
}

// SetGlobalDevices 处理面板 sync.devices 推送：{users: {uid: [ip...]}}
func SetGlobalDevices(users map[int][]string) {
	devices.mu.Lock()
	devices.global = make(map[int]map[string]bool, len(users))
	for uid, ips := range users {
		m := make(map[string]bool, len(ips))
		for _, ip := range ips {
			m[ip] = true
		}
		devices.global[uid] = m
	}
	devices.globalAt = time.Now()
	devices.mu.Unlock()
}

// deviceLimitReject 新连接设备数门控，true = 拒绝。
// 与 Xboard-node 一致：本地 + 全局（60s 内有效）合并后按字典序排序，
// 新 IP 必须排进前 limit 个才放行，保证多节点判定一致。
func deviceLimitReject(userID, limit int, addr net.Addr) bool {
	if limit <= 0 || addr == nil {
		return false
	}
	ip := addrToIP(addr)
	if ip == "" {
		return false
	}

	devices.mu.Lock()
	defer devices.mu.Unlock()

	local := devices.local[userID]
	if _, ok := local[ip]; ok {
		return false
	}

	merged := make(map[string]bool, len(local)+4)
	for k := range local {
		merged[k] = true
	}
	if time.Since(devices.globalAt) <= time.Minute {
		for k := range devices.global[userID] {
			merged[k] = true
		}
	}
	if len(merged) < limit {
		return false
	}

	ips := make([]string, 0, len(merged)+1)
	for k := range merged {
		ips = append(ips, k)
	}
	ips = append(ips, ip)
	sort.Strings(ips)
	for i := 0; i < limit && i < len(ips); i++ {
		if ips[i] == ip {
			return false
		}
	}
	return true
}

// DeviceSnapshot 返回本地在线设备表（uid → ips），用于向面板上报
func DeviceSnapshot() map[int][]string {
	devices.mu.Lock()
	defer devices.mu.Unlock()
	out := make(map[int][]string, len(devices.local))
	for uid, m := range devices.local {
		if len(m) == 0 {
			continue
		}
		ips := make([]string, 0, len(m))
		for ip := range m {
			ips = append(ips, ip)
		}
		out[uid] = ips
	}
	return out
}

// ReportDevices REST 兜底：WS 断开期间向面板 POST /alive 上报设备。
// 面板以 TTL 300s 过期设备记录，停报后在线状态自动消退。
func ReportDevices(aliveURL string, interval time.Duration, snapshot func() map[int][]string) {
	log.Println("设备在线情况上报已启动,提交周期为:", interval)

	post := func() {
		snap := snapshot()
		if len(snap) == 0 {
			return
		}
		body, err := json.Marshal(snap)
		if err != nil {
			return
		}
		resp, err := panelHTTP.Post(aliveURL, "application/json", bytes.NewReader(body))
		if err != nil {
			log.Println("设备在线上报失败:", err)
			return
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			log.Println("设备在线上报失败: status", resp.Status)
		}
	}
	post()

	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for range ticker.C {
		if WSActive.Load() {
			continue
		}
		post()
	}
}
