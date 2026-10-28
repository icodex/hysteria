package trafficlogger

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestPushTrafficSwapKeepsDataOnFailure(t *testing.T) {
	var fail atomic.Bool
	fail.Store(true)
	var mu sync.Mutex
	var lastPush map[string][2]int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var got map[string][2]int64
		assert.NoError(t, json.NewDecoder(r.Body).Decode(&got))
		mu.Lock()
		lastPush = got
		mu.Unlock()
		if fail.Load() {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	s := NewTrafficStatsServer("").(*trafficStatsServerImpl)
	s.LogTraffic("1", 100, 200)

	// 第一次推送失败：流量必须合并回来，不能丢
	err := s.PushTrafficToV2board(srv.URL)
	assert.Error(t, err)
	assert.Equal(t, map[string]*trafficStatsEntry{
		"1": {Tx: 100, Rx: 200},
	}, s.StatsMap, "failed push merges the snapshot back")

	// 失败期间新流量照常记账
	s.LogTraffic("1", 10, 20)
	s.LogTraffic("2", 1, 2)

	fail.Store(false)
	assert.NoError(t, s.PushTrafficToV2board(srv.URL))
	mu.Lock()
	defer mu.Unlock()
	assert.Equal(t, map[string][2]int64{
		"1": {110, 220},
		"2": {1, 2},
	}, lastPush, "failed push must be merged back, not lost")
	assert.Len(t, s.StatsMap, 0, "successful push clears the map")
}

func TestPushEmptyMapSkipsRequest(t *testing.T) {
	var called atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called.Store(true)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	s := NewTrafficStatsServer("").(*trafficStatsServerImpl)
	assert.NoError(t, s.PushTrafficToV2board(srv.URL))
	assert.False(t, called.Load(), "empty stats should not hit the panel")
}

func TestKickExpiry(t *testing.T) {
	s := NewTrafficStatsServer("").(*trafficStatsServerImpl)
	s.NewKick("9")
	_, ok := s.KickMap["9"]
	assert.True(t, ok)

	// LogTraffic 消费踢出标记并断开
	assert.False(t, s.LogTraffic("9", 1, 1))
	_, ok = s.KickMap["9"]
	assert.False(t, ok)

	// 过期标记在推送时被清理，不会永久堆积
	s.NewKick("10")
	s.KickMap["10"] = time.Now().Add(-2 * time.Hour)
	s.NewKick("11")
	s.Mutex.Lock()
	s.pruneKicksLocked()
	s.Mutex.Unlock()
	assert.NotContains(t, s.KickMap, "10")
	assert.Contains(t, s.KickMap, "11")
}

func TestSpeedThrottleHookRunsBeforeKick(t *testing.T) {
	s := NewTrafficStatsServer("").(*trafficStatsServerImpl)
	var seen atomic.Int64
	s.SpeedThrottle = func(id string, tx, rx uint64) {
		seen.Add(int64(tx + rx))
	}
	s.LogTraffic("5", 10, 20)
	assert.Equal(t, int64(30), seen.Load(), "throttle hook must see every accounted chunk")
}
