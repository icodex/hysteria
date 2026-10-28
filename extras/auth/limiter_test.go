package auth

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func speedLimitPtr(mbps uint32) *uint32 { return &mbps }

func TestThrottleUnlimitedUser(t *testing.T) {
	rebuildSpeedLimiters(nil)
	start := time.Now()
	Throttle("42", 64*1024, 64*1024)
	assert.Less(t, time.Since(start), 100*time.Millisecond)
}

func TestThrottleAppliesAndClears(t *testing.T) {
	// 1 Mbps = 125000 B/s，桶容量 64KB：
	// 第一块 64KB 吃掉整个桶，第二块必须等待约 0.5s
	rebuildSpeedLimiters(map[int]*uint32{7: speedLimitPtr(1)})

	start := time.Now()
	Throttle("7", 64*1024, 0)
	assert.Less(t, time.Since(start), 100*time.Millisecond)

	start = time.Now()
	Throttle("7", 64*1024, 0)
	assert.Greater(t, time.Since(start), 300*time.Millisecond, "second burst should be throttled at 1 Mbps")

	// 解除限速后立即放行
	removeSpeedLimiter(7)
	start = time.Now()
	Throttle("7", 64*1024, 0)
	assert.Less(t, time.Since(start), 100*time.Millisecond)
}

func TestApplyUsersRebuildsLimiters(t *testing.T) {
	old := usersMap
	defer func() { usersMap = old }()
	rebuildSpeedLimiters(nil)

	ApplyUsers([]User{
		{ID: 1, UUID: "u1", SpeedLimit: speedLimitPtr(1)},
		{ID: 2, UUID: "u2"},
	}, nil)

	start := time.Now()
	Throttle("1", 64*1024, 0)
	Throttle("1", 64*1024, 0)
	assert.Greater(t, time.Since(start), 300*time.Millisecond, "limited user should throttle")
	start = time.Now()
	Throttle("2", 64*1024, 0)
	Throttle("2", 64*1024, 0)
	assert.Less(t, time.Since(start), 100*time.Millisecond, "unlimited user should not throttle")

	// 全量替换为无限速列表后，旧限速必须消失
	ApplyUsers([]User{{ID: 1, UUID: "u1"}}, nil)
	start = time.Now()
	Throttle("1", 64*1024, 0)
	Throttle("1", 64*1024, 0)
	assert.Less(t, time.Since(start), 100*time.Millisecond)
}

func TestApplyUserDeltaUpdatesLimiters(t *testing.T) {
	old := usersMap
	defer func() { usersMap = old }()
	rebuildSpeedLimiters(nil)

	ApplyUserDelta(true, []User{{ID: 3, UUID: "u3", SpeedLimit: speedLimitPtr(1)}}, nil)
	start := time.Now()
	Throttle("3", 64*1024, 0)
	Throttle("3", 64*1024, 0)
	assert.Greater(t, time.Since(start), 300*time.Millisecond)

	ApplyUserDelta(false, []User{{ID: 3}}, nil)
	start = time.Now()
	Throttle("3", 64*1024, 0)
	assert.Less(t, time.Since(start), 100*time.Millisecond)
}
