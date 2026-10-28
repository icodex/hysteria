package auth

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPanelRouteRuleToACLLines(t *testing.T) {
	r := PanelRouteRule{ID: 1, Match: []string{"*.google.com", "8.8.8.0/24", " "}, Action: "direct"}
	assert.Equal(t, []string{"direct(google.com)", "direct(8.8.8.0/24)"}, r.ToACLLines())

	// proxy 带出站名 / 无出站名回退 default
	r = PanelRouteRule{Match: []string{"a.com"}, Action: "proxy", ActionValue: "myob"}
	assert.Equal(t, []string{"myob(a.com)"}, r.ToACLLines())
	r = PanelRouteRule{Match: []string{"a.com"}, Action: "proxy"}
	assert.Equal(t, []string{"default(a.com)"}, r.ToACLLines())

	// 未知 action → reject；空 match → 无输出
	r = PanelRouteRule{Match: []string{"b.com"}, Action: "whatever"}
	assert.Equal(t, []string{"reject(b.com)"}, r.ToACLLines())
	r = PanelRouteRule{Match: nil}
	assert.Empty(t, r.ToACLLines())
}

func TestPanelCustomRouteRuleToACLLines(t *testing.T) {
	var r PanelCustomRouteRule
	r.Match.Domains = []string{"exact.example.com"}
	r.Match.DomainSuffixes = []string{".suffix.example", "ok.example"}
	r.Match.IPCIDRs = []string{"10.0.0.0/8"}
	r.Action.Type = "proxy"
	r.Action.Target = "ob1"
	lines := r.ToACLLines()
	assert.Contains(t, lines, "ob1(exact.example.com)")
	assert.Contains(t, lines, "ob1(suffix:suffix.example)")
	assert.Contains(t, lines, "ob1(suffix:ok.example)")
	assert.Contains(t, lines, "ob1(10.0.0.0/8)")

	r.Disabled = true
	assert.Empty(t, r.ToACLLines())

	r.Disabled = false
	r.Action.Type = "block"
	assert.Equal(t, []string{"reject(exact.example.com)", "reject(suffix:suffix.example)", "reject(suffix:ok.example)", "reject(10.0.0.0/8)"}, r.ToACLLines())
}

func TestPanelOutboundToHyOutbound(t *testing.T) {
	o := PanelOutbound{Tag: "ob1", Protocol: "socks5", Settings: map[string]any{
		"addr": "1.2.3.4:1080", "username": "u", "password": "p",
	}}
	m, err := o.ToHyOutbound()
	assert.NoError(t, err)
	assert.Equal(t, "ob1", m["name"])
	assert.Equal(t, "socks5", m["type"])

	o = PanelOutbound{Tag: "", Protocol: "http", Settings: map[string]any{"url": "http://proxy.example:8080", "insecure": true}}
	m, err = o.ToHyOutbound()
	assert.NoError(t, err)
	assert.Equal(t, "http", m["name"])

	o = PanelOutbound{Protocol: "direct"}
	m, err = o.ToHyOutbound()
	assert.NoError(t, err)
	assert.Equal(t, "direct", m["type"])

	// 不支持的协议报错
	o = PanelOutbound{Tag: "vm", Protocol: "vmess"}
	_, err = o.ToHyOutbound()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported protocol")
}

func TestNodeStatsCounters(t *testing.T) {
	CountersConnect()
	CountersConnect()
	CountersDisconnect()
	StatsUsers(10, 3)
	CountersTraffic(100, 500)

	s := CollectNodeStats(true)
	assert.EqualValues(t, 1, s["active_connections"])
	assert.EqualValues(t, 2, s["total_connections"])
	assert.EqualValues(t, 10, s["total_users"])
	assert.EqualValues(t, 3, s["active_users"])
	assert.EqualValues(t, true, s["kernel_status"])
	// 首采样只记录基线，速率可为 0；字段存在即可
	assert.Contains(t, s, "inbound_speed")
}

func TestOnlineConnSnapshot(t *testing.T) {
	resetDevices()
	defer resetDevices()
	TrackConnect("9", tcpAddr("1.1.1.1"))
	TrackConnect("9", tcpAddr("1.1.1.1"))
	TrackConnect("9", tcpAddr("2.2.2.2"))
	snap := OnlineConnSnapshot()
	assert.Equal(t, map[string]int{"9": 3}, snap)
	TrackDisconnect("9", tcpAddr("1.1.1.1"))
	assert.Equal(t, map[string]int{"9": 2}, OnlineConnSnapshot())
}

func TestStatusPayloadShape(t *testing.T) {
	p := StatusPayload(CollectNodeStats(true))
	// UniProxy /status 校验必填四元组
	for _, k := range []string{"cpu", "mem", "swap", "disk"} {
		assert.Contains(t, p, k)
	}
	mem := p["mem"].(map[string]any)
	assert.Contains(t, mem, "total")
	assert.Contains(t, mem, "used")
	metrics := p["metrics"].(map[string]any)
	assert.Contains(t, metrics, "uptime")
	assert.Contains(t, metrics, "kernel_status")
}

func TestPanelOutboundEmptyArraySettings(t *testing.T) {
	// PHP 空关联数组序列化成 []，不能让整个 nodeInfo 解码失败
	var o PanelOutbound
	assert.NoError(t, json.Unmarshal([]byte(`{"tag":"ob","protocol":"direct","settings":[]}`), &o))
	assert.Equal(t, "ob", o.Tag)
	assert.Nil(t, o.Settings)

	// 对象 settings 正常解
	assert.NoError(t, json.Unmarshal([]byte(`{"tag":"s","protocol":"socks5","settings":{"addr":"1.2.3.4:1"}}`), &o))
	assert.Equal(t, map[string]any{"addr": "1.2.3.4:1"}, o.Settings)

	// 非对象非数组字面量（数字/字符串）同样按空 settings 容忍
	assert.NoError(t, json.Unmarshal([]byte(`{"tag":"n","protocol":"direct","settings":0}`), &o))
	assert.Nil(t, o.Settings)
}
