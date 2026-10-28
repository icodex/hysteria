package auth

import (
	"strconv"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// speedPair 每用户上行/下行各一个令牌桶。speed_limit 单位 Mbps，
// 换算 bytes/s = Mbps × 125000；0/nil 表示不限速。
type speedPair struct {
	up   *rate.Limiter
	down *rate.Limiter
}

var speedLimiters sync.Map // user id (int) → *speedPair

// speedLimiterBurst 令牌桶容量需 ≥ 核心 copy 循环的单次记账粒度（32KB）
const speedLimiterBurst = 64 * 1024

func newSpeedPair(limit *uint32) *speedPair {
	if limit == nil || *limit == 0 {
		return nil
	}
	bps := rate.Limit(*limit) * 125000
	return &speedPair{
		up:   rate.NewLimiter(bps, speedLimiterBurst),
		down: rate.NewLimiter(bps, speedLimiterBurst),
	}
}

// rebuildSpeedLimiters 全量重建限速表（ApplyUsers 时调用）
func rebuildSpeedLimiters(limits map[int]*uint32) {
	speedLimiters.Range(func(key, _ any) bool {
		speedLimiters.Delete(key)
		return true
	})
	for id, limit := range limits {
		if p := newSpeedPair(limit); p != nil {
			speedLimiters.Store(id, p)
		}
	}
}

// updateSpeedLimiter 单用户增量更新（sync.user.delta add）
func updateSpeedLimiter(id int, limit *uint32) {
	if p := newSpeedPair(limit); p != nil {
		speedLimiters.Store(id, p)
	} else {
		speedLimiters.Delete(id)
	}
}

// removeSpeedLimiter 单用户移除（sync.user.delta remove）
func removeSpeedLimiter(id int) {
	speedLimiters.Delete(id)
}

// Throttle 对流量记账前按用户限速；阻塞至令牌可用。
// 由 trafficlogger 在拿统计锁之前调用，绝不能持锁等待。
func Throttle(id string, tx, rx uint64) {
	idNum, err := strconv.Atoi(id)
	if err != nil {
		return
	}
	v, ok := speedLimiters.Load(idNum)
	if !ok {
		return
	}
	p := v.(*speedPair)
	if tx > 0 {
		waitLimiter(p.up, int(tx))
	}
	if rx > 0 {
		waitLimiter(p.down, int(rx))
	}
}

func waitLimiter(l *rate.Limiter, n int) {
	if l == nil {
		return
	}
	if n > l.Burst() {
		n = l.Burst()
	}
	if l.AllowN(time.Now(), n) {
		return
	}
	resv := l.ReserveN(time.Now(), n)
	if d := resv.Delay(); d > 0 {
		time.Sleep(d)
	}
}
