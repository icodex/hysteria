//go:build linux || darwin || freebsd

package auth

import (
	"os"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
)

func loadAverages() (float64, float64, float64) {
	if runtime.GOOS == "linux" {
		if b, err := os.ReadFile("/proc/loadavg"); err == nil {
			f := strings.Fields(string(b))
			if len(f) >= 3 {
				l1, _ := strconv.ParseFloat(f[0], 64)
				l5, _ := strconv.ParseFloat(f[1], 64)
				l15, _ := strconv.ParseFloat(f[2], 64)
				return l1, l5, l15
			}
		}
	}
	// 非 Linux 无可移植 loadavg，返回 0
	return 0, 0, 0
}

func memUsage() memInfo {
	if runtime.GOOS == "linux" {
		if b, err := os.ReadFile("/proc/meminfo"); err == nil {
			vals := map[string]uint64{}
			for _, line := range strings.Split(string(b), "\n") {
				kv := strings.SplitN(line, ":", 2)
				if len(kv) != 2 {
					continue
				}
				f := strings.Fields(kv[1])
				if len(f) == 0 {
					continue
				}
				v, _ := strconv.ParseUint(f[0], 10, 64)
				vals[kv[0]] = v
			}
			total := vals["MemTotal"]
			avail := vals["MemAvailable"]
			swapTotal := vals["SwapTotal"]
			swapFree := vals["SwapFree"]
			return memInfo{
				total:     total,
				used:      total - avail,
				swapTotal: swapTotal,
				swapUsed:  swapTotal - swapFree,
			}
		}
	}
	// 非 Linux：仅回报本进程 RSS（darwin 单位字节、linux KB，量级近似即可）
	var ru syscall.Rusage
	if err := syscall.Getrusage(syscall.RUSAGE_SELF, &ru); err == nil {
		rss := uint64(ru.Maxrss)
		if runtime.GOOS == "linux" {
			rss *= 1024
		}
		return memInfo{total: rss, used: rss}
	}
	return memInfo{}
}

func diskUsage() map[string]any {
	var st syscall.Statfs_t
	wd, _ := os.Getwd()
	if err := syscall.Statfs(wd, &st); err == nil {
		bsize := uint64(st.Bsize)
		total := st.Blocks * bsize
		free := st.Bfree * bsize
		return map[string]any{"total": total, "used": total - free}
	}
	return map[string]any{"total": 0, "used": 0}
}

var (
	cpuLastTicks float64
	cpuLastAt    time.Time
)

// cpuPercent 进程 CPU 占比（自身 CPU 时间差 / 墙钟差），窗口过短返回 0
func cpuPercent() float64 {
	var ru syscall.Rusage
	if err := syscall.Getrusage(syscall.RUSAGE_SELF, &ru); err == nil {
		user := float64(ru.Utime.Sec) + float64(ru.Utime.Usec)/1e6
		sysT := float64(ru.Stime.Sec) + float64(ru.Stime.Usec)/1e6
		ticks := user + sysT
		now := time.Now()
		if !cpuLastAt.IsZero() {
			dWall := now.Sub(cpuLastAt).Seconds()
			dTicks := ticks - cpuLastTicks
			if dWall > 0.1 {
				pct := dTicks / dWall * 100 / float64(runtime.NumCPU())
				if pct > 100 {
					pct = 100
				}
				cpuLastTicks, cpuLastAt = ticks, now
				return pct
			}
		}
		cpuLastTicks, cpuLastAt = ticks, now
	}
	return 0
}
