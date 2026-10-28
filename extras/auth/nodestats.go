package auth

import (
	"context"
	"log"
	"runtime"
	"strconv"
	"sync/atomic"
	"time"
)

// NodeStats 节点自采集指标。面板 WS node.status / REST /status 消费。
type NodeStats struct {
	Uptime        int64
	Goroutines    int
	ActiveConns   int64
	TotalConns    int64
	TotalUsers    int
	ActiveUsers   int
	InboundSpeed  int64
	OutboundSpeed int64
	KernelStatus  bool
}

var (
	statsActiveConns atomic.Int64
	statsTotalConns  atomic.Int64
	statsInBytes     atomic.Int64
	statsOutBytes    atomic.Int64
	statsStartTime   = time.Now()
)

// CountersConnect/CountersDisconnect 由 serverLogger Connect/Disconnect 调
func CountersConnect() { statsActiveConns.Add(1); statsTotalConns.Add(1) }

func CountersDisconnect() {
	if v := statsActiveConns.Add(-1); v < 0 {
		statsActiveConns.Store(0)
	}
}

// CountersTraffic 由 SpeedThrottle 回调路径顺带记账（tx=出 rx=入）
func CountersTraffic(tx, rx uint64) {
	if rx > 0 {
		statsInBytes.Add(int64(rx))
	}
	if tx > 0 {
		statsOutBytes.Add(int64(tx))
	}
}

// SnapshotUsers 由用户同步路径更新当前用户规模
var (
	statsTotalUsers  atomic.Int64
	statsActiveUsers atomic.Int64
)

func StatsUsers(total, active int) {
	statsTotalUsers.Store(int64(total))
	statsActiveUsers.Store(int64(active))
}

// CollectNodeStats 采样并重算速率
func CollectNodeStats(kernelUp bool) map[string]any {
	lastIn, lastOut := lastSpeedIn.Load(), lastSpeedOut.Load()
	lastNano := lastSpeedAt.Load()
	lastAt := time.Unix(0, lastNano)
	nowIn, nowOut := statsInBytes.Load(), statsOutBytes.Load()
	now := time.Now()
	var inRate, outRate int64
	if lastNano != 0 {
		dt := now.Sub(lastAt).Seconds()
		if dt > 0.5 {
			inRate = int64(float64(nowIn-lastIn) / dt)
			outRate = int64(float64(nowOut-lastOut) / dt)
			lastSpeedIn.Store(nowIn)
			lastSpeedOut.Store(nowOut)
			lastSpeedAt.Store(now.UnixNano())
		}
	} else {
		lastSpeedIn.Store(nowIn)
		lastSpeedOut.Store(nowOut)
		lastSpeedAt.Store(now.UnixNano())
	}

	return map[string]any{
		"uptime":             int64(time.Since(statsStartTime).Seconds()),
		"goroutines":         runtime.NumGoroutine(),
		"active_connections": statsActiveConns.Load(),
		"total_connections":  statsTotalConns.Load(),
		"total_users":        statsTotalUsers.Load(),
		"active_users":       statsActiveUsers.Load(),
		"inbound_speed":      inRate,
		"outbound_speed":     outRate,
		"kernel_status":      kernelUp,
	}
}

var (
	lastSpeedIn  atomic.Int64
	lastSpeedOut atomic.Int64
	lastSpeedAt  atomic.Int64 // unix nano
)

// ReportStatusLoop REST /status 兜底（WS 断开期间）。负载字段与
// UniProxyController::status 校验一致：cpu/mem/swap/disk 四元组。
func ReportStatusLoop(ctx context.Context, statusURL string, interval time.Duration, collect func() map[string]any) {
	log.Println("节点状态上报已启动,提交周期为:", interval)
	post := func() {
		body, err := jsonMarshal(collect())
		if err != nil {
			return
		}
		resp, err := panelHTTP.Post(statusURL, "application/json", stringsReader(body))
		if err != nil {
			log.Println("节点状态上报失败:", err)
			return
		}
		resp.Body.Close()
	}
	post()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		if WSActive.Load() {
			continue
		}
		post()
	}
}

// ReportOnlineLoop REST /online 兜底：{uid: 活跃连接数}
func ReportOnlineLoop(ctx context.Context, onlineURL string, interval time.Duration, snapshot func() map[string]int) {
	post := func() {
		snap := snapshot()
		if len(snap) == 0 {
			return
		}
		body, err := jsonMarshal(snap)
		if err != nil {
			return
		}
		resp, err := panelHTTP.Post(onlineURL, "application/json", stringsReader(body))
		if err != nil {
			log.Println("在线连接上报失败:", err)
			return
		}
		resp.Body.Close()
	}
	post()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		if WSActive.Load() {
			continue
		}
		post()
	}
}

// OnlineConnSnapshot 本地每用户活跃连接数（deviceTracker 复用其锁内计数）
func OnlineConnSnapshot() map[string]int {
	devices.mu.Lock()
	defer devices.mu.Unlock()
	out := make(map[string]int, len(devices.local))
	for uid, m := range devices.local {
		n := 0
		for _, refs := range m {
			n += refs
		}
		if n > 0 {
			out[strconv.Itoa(uid)] = n
		}
	}
	return out
}

// StatusPayload 组 UniProxy /status 要求的负载（cpu/mem/swap/disk）。
// hysteria 进程视角采集；cgroup 宿主值由部署环境决定，不在此模拟。
func StatusPayload(stats map[string]any) map[string]any {
	load1, load5, load15 := loadAverages()
	mem := memUsage()
	return map[string]any{
		"cpu":  cpuPercent(),
		"mem":  map[string]any{"total": mem.total, "used": mem.used},
		"swap": map[string]any{"total": mem.swapTotal, "used": mem.swapUsed},
		"disk": diskUsage(),
		"metrics": map[string]any{
			"uptime":             stats["uptime"],
			"goroutines":         stats["goroutines"],
			"active_connections": stats["active_connections"],
			"total_connections":  stats["total_connections"],
			"total_users":        stats["total_users"],
			"active_users":       stats["active_users"],
			"inbound_speed":      stats["inbound_speed"],
			"outbound_speed":     stats["outbound_speed"],
			"kernel_status":      stats["kernel_status"],
		},
		"load": []float64{load1, load5, load15},
	}
}
