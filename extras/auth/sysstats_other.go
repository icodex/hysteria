//go:build !(linux || darwin || freebsd)

package auth

import "time"

func loadAverages() (float64, float64, float64) { return 0, 0, 0 }
func memUsage() memInfo                         { return memInfo{} }
func diskUsage() map[string]any                 { return map[string]any{"total": 0, "used": 0} }
func cpuPercent() float64 {
	time.Sleep(0) // 保持签名一致；无实现
	return 0
}
