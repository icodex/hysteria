package cmd

import (
	"encoding/json"
	"os"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/stretchr/testify/assert"

	"github.com/apernet/hysteria/extras/v2/auth"
)

// TestApplyPanelNodeConfigSniff 面板 sniff：本地零值整体接
func TestApplyPanelNodeConfigSniff(t *testing.T) {
	var cfg serverConfig
	info := ResponseNodeInfo{Sniff: &panelSniffPayload{
		Enable: true, Timeout: 5, RewriteDomain: true, TCPPorts: "80,443", UDPPorts: "53",
	}}
	applyPanelNodeConfig(zap.NewNop(), &cfg, info)

	assert.True(t, cfg.Sniff.Enable)
	assert.Equal(t, 5*time.Second, cfg.Sniff.Timeout)
	assert.True(t, cfg.Sniff.RewriteDomain)
	assert.Equal(t, "80,443", cfg.Sniff.TCPPorts)
	assert.Equal(t, "53", cfg.Sniff.UDPPorts)
}

// TestApplyPanelNodeConfigMasquerade 面板 masquerade：type+子段、statusCode 原样、监听补空位
func TestApplyPanelNodeConfigMasquerade(t *testing.T) {
	// string 型：statusCode 原样透传
	var cfg serverConfig
	info := ResponseNodeInfo{Masquerade: &panelMasqueradePayload{
		Type: "string", ListenHTTP: ":80", ListenHTTPS: ":443", ForceHTTPS: true,
	}}
	info.Masquerade.String.Content = "<html>ok</html>"
	info.Masquerade.String.StatusCode = 403
	applyPanelNodeConfig(zap.NewNop(), &cfg, info)
	assert.Equal(t, "string", cfg.Masquerade.Type)
	assert.Equal(t, "<html>ok</html>", cfg.Masquerade.String.Content)
	assert.Equal(t, 403, cfg.Masquerade.String.StatusCode)
	assert.Equal(t, ":80", cfg.Masquerade.ListenHTTP)
	assert.Equal(t, ":443", cfg.Masquerade.ListenHTTPS)
	assert.True(t, cfg.Masquerade.ForceHTTPS)

	// proxy 型：子段全量映射
	cfg = serverConfig{}
	info = ResponseNodeInfo{Masquerade: &panelMasqueradePayload{Type: "proxy"}}
	info.Masquerade.Proxy.URL = "https://a.com"
	info.Masquerade.Proxy.RewriteHost = true
	info.Masquerade.Proxy.XForwarded = true
	info.Masquerade.Proxy.Insecure = true
	applyPanelNodeConfig(zap.NewNop(), &cfg, info)
	assert.Equal(t, serverConfigMasqueradeProxy{
		URL: "https://a.com", RewriteHost: true, XForwarded: true, Insecure: true,
	}, cfg.Masquerade.Proxy)

	// 非法 type：整体丢弃并告警
	cfg = serverConfig{}
	info = ResponseNodeInfo{Masquerade: &panelMasqueradePayload{Type: "redirect", ListenHTTP: ":80"}}
	applyPanelNodeConfig(zap.NewNop(), &cfg, info)
	assert.Empty(t, cfg.Masquerade.Type)
	assert.Empty(t, cfg.Masquerade.ListenHTTP)
}

// TestApplyPanelNodeConfigQuic 面板 quic：逐字段填空位、bool 用 || 合并
func TestApplyPanelNodeConfigQuic(t *testing.T) {
	var cfg serverConfig
	info := ResponseNodeInfo{Quic: &panelQUICPayload{
		InitStreamReceiveWindow: 1 << 20,
		MaxStreamReceiveWindow:  2 << 20,
		InitConnReceiveWindow:   3 << 20,
		MaxConnReceiveWindow:    4 << 20,
		MaxIdleTimeout:          30,
		MaxIncomingStreams:      100,
		DisablePathMTUDiscovery: true,
	}}
	applyPanelNodeConfig(zap.NewNop(), &cfg, info)
	assert.Equal(t, uint64(1<<20), cfg.QUIC.InitStreamReceiveWindow)
	assert.Equal(t, uint64(2<<20), cfg.QUIC.MaxStreamReceiveWindow)
	assert.Equal(t, uint64(3<<20), cfg.QUIC.InitConnectionReceiveWindow)
	assert.Equal(t, uint64(4<<20), cfg.QUIC.MaxConnectionReceiveWindow)
	assert.Equal(t, 30*time.Second, cfg.QUIC.MaxIdleTimeout)
	assert.Equal(t, int64(100), cfg.QUIC.MaxIncomingStreams)
	assert.True(t, cfg.QUIC.DisablePathMTUDiscovery)
	assert.False(t, cfg.QUIC.DisableStatelessReset)

	// 本地已置 true 的 bool 不会被面板 false 拉回
	cfg = serverConfig{QUIC: serverConfigQUIC{DisableStatelessReset: true}}
	info = ResponseNodeInfo{Quic: &panelQUICPayload{DisablePathMTUDiscovery: true}}
	applyPanelNodeConfig(zap.NewNop(), &cfg, info)
	assert.True(t, cfg.QUIC.DisableStatelessReset)
	assert.True(t, cfg.QUIC.DisablePathMTUDiscovery)
}

// TestApplyPanelNodeConfigCongestion 面板 congestion：type 非空才整体接
func TestApplyPanelNodeConfigCongestion(t *testing.T) {
	var cfg serverConfig
	info := ResponseNodeInfo{Congestion: &panelCongestionPayload{Type: "bbr", BBRProfile: "aggressive"}}
	applyPanelNodeConfig(zap.NewNop(), &cfg, info)
	assert.Equal(t, serverConfigCongestion{Type: "bbr", BBRProfile: "aggressive"}, cfg.Congestion)

	// 面板 type 为空则不接
	cfg = serverConfig{}
	info = ResponseNodeInfo{Congestion: &panelCongestionPayload{BBRProfile: "aggressive"}}
	applyPanelNodeConfig(zap.NewNop(), &cfg, info)
	assert.Empty(t, cfg.Congestion.Type)
}

// TestApplyPanelNodeConfigResolver 面板 resolver：各子 struct 对应映射
func TestApplyPanelNodeConfigResolver(t *testing.T) {
	var cfg serverConfig
	info := ResponseNodeInfo{Resolver: &panelResolverPayload{Type: "tls"}}
	info.Resolver.TLS.Addr = "8.8.8.8:853"
	info.Resolver.TLS.Timeout = 5
	info.Resolver.TLS.SNI = "dns.google"
	info.Resolver.TLS.Insecure = true
	applyPanelNodeConfig(zap.NewNop(), &cfg, info)
	assert.Equal(t, "tls", cfg.Resolver.Type)
	assert.Equal(t, serverConfigResolverTLS{
		Addr: "8.8.8.8:853", Timeout: 5 * time.Second, SNI: "dns.google", Insecure: true,
	}, cfg.Resolver.TLS)
	assert.Empty(t, cfg.Resolver.TCP.Addr)
	assert.Empty(t, cfg.Resolver.HTTPS.Addr)
}

// TestApplyPanelNodeConfigSwitches 开关类：false→true 单向、udp_idle_timeout 1-600
func TestApplyPanelNodeConfigSwitches(t *testing.T) {
	var cfg serverConfig
	info := ResponseNodeInfo{
		DisableUDP:              true,
		UDPIdleTimeout:          120,
		IgnoreClientBandwidth:   true,
		DisableLossCompensation: true,
	}
	applyPanelNodeConfig(zap.NewNop(), &cfg, info)
	assert.True(t, cfg.DisableUDP)
	assert.Equal(t, 120*time.Second, cfg.UDPIdleTimeout)
	assert.True(t, cfg.IgnoreClientBandwidth)
	assert.True(t, cfg.Bandwidth.DisableLossCompensation)

	// udp_idle_timeout 超出 1-600 不接
	cfg = serverConfig{}
	info = ResponseNodeInfo{UDPIdleTimeout: 700}
	applyPanelNodeConfig(zap.NewNop(), &cfg, info)
	assert.Zero(t, cfg.UDPIdleTimeout)
}

// TestApplyPanelNodeConfigNoOverride 本地已有值时不被面板覆盖
func TestApplyPanelNodeConfigNoOverride(t *testing.T) {
	cfg := serverConfig{
		Sniff:      serverConfigSniff{Enable: true, Timeout: 9 * time.Second, TCPPorts: "local"},
		QUIC:       serverConfigQUIC{InitStreamReceiveWindow: 999, MaxIdleTimeout: time.Minute, MaxIncomingStreams: 7},
		Congestion: serverConfigCongestion{Type: "reno"},
		Resolver:   serverConfigResolver{Type: "udp", UDP: serverConfigResolverUDP{Addr: "1.1.1.1:53"}},
		Bandwidth:  serverConfigBandwidth{Up: "100Mbps"},
	}
	cfg.Masquerade.Type = "proxy"
	cfg.Masquerade.Proxy.URL = "https://local"
	cfg.Masquerade.ListenHTTP = ":8080"
	cfg.DisableUDP = true
	cfg.UDPIdleTimeout = 5 * time.Second
	cfg.IgnoreClientBandwidth = true

	info := ResponseNodeInfo{
		Sniff:      &panelSniffPayload{Enable: true, Timeout: 5, TCPPorts: "panel"},
		Masquerade: &panelMasqueradePayload{Type: "string", ListenHTTP: ":80"},
		Quic: &panelQUICPayload{
			InitStreamReceiveWindow: 1 << 20, MaxIdleTimeout: 30, MaxIncomingStreams: 100,
		},
		Congestion: &panelCongestionPayload{Type: "bbr"},
		Resolver:   &panelResolverPayload{Type: "tls"},
	}
	info.Masquerade.String.Content = "panel"
	applyPanelNodeConfig(zap.NewNop(), &cfg, info)

	assert.Equal(t, serverConfigSniff{Enable: true, Timeout: 9 * time.Second, TCPPorts: "local"}, cfg.Sniff)
	assert.Equal(t, "proxy", cfg.Masquerade.Type)
	assert.Equal(t, "https://local", cfg.Masquerade.Proxy.URL)
	assert.Equal(t, ":8080", cfg.Masquerade.ListenHTTP)
	assert.Empty(t, cfg.Masquerade.String.Content)
	assert.Equal(t, uint64(999), cfg.QUIC.InitStreamReceiveWindow)
	assert.Equal(t, time.Minute, cfg.QUIC.MaxIdleTimeout)
	assert.Equal(t, int64(7), cfg.QUIC.MaxIncomingStreams)
	assert.Equal(t, "reno", cfg.Congestion.Type)
	assert.Equal(t, "udp", cfg.Resolver.Type)
	assert.Equal(t, "1.1.1.1:53", cfg.Resolver.UDP.Addr)
	assert.True(t, cfg.DisableUDP)
	assert.Equal(t, 5*time.Second, cfg.UDPIdleTimeout)
	assert.True(t, cfg.IgnoreClientBandwidth)
	assert.Empty(t, cfg.Bandwidth.DisableLossCompensation)
}

// TestPanelACLLines routes + custom_route_rules → ACL 行；raw custom_routes 不消费
func TestPanelACLLines(t *testing.T) {
	var rule auth.PanelCustomRouteRule
	rule.Match.Domains = []string{"a.com"}
	rule.Match.DomainSuffixes = []string{".b.com"}
	rule.Action.Type = "block"
	info := ResponseNodeInfo{
		Routes:           []auth.PanelRouteRule{{Match: []string{"c.com"}, Action: "direct"}},
		CustomRoutes:     json.RawMessage(`[{"raw":"kernel-private"}]`),
		CustomRouteRules: []auth.PanelCustomRouteRule{rule},
	}
	lines := panelACLLines(info)
	assert.Equal(t, []string{"direct(c.com)", "reject(a.com)", "reject(suffix:b.com)"}, lines)

	// 无 custom_route_rules 时仅 routes 生效
	info.CustomRouteRules = nil
	assert.Equal(t, []string{"direct(c.com)"}, panelACLLines(info))
}

// TestApplyPanelNodeConfigECH tls_settings.ech → config.ECH（仅 KeyPath）
func TestApplyPanelNodeConfigECH(t *testing.T) {
	// key_path 直用
	var cfg serverConfig
	info := ResponseNodeInfo{TLSSettings: map[string]any{
		"ech": map[string]any{"enabled": true, "key_path": "/etc/hy/ech.pem"},
	}}
	applyPanelNodeConfig(zap.NewNop(), &cfg, info)
	assert.NotNil(t, cfg.ECH)
	assert.Equal(t, "/etc/hy/ech.pem", cfg.ECH.KeyPath)

	// 仅给 key（PEM 内容）：落临时盘再指 KeyPath
	cfg = serverConfig{}
	keyPEM := "-----BEGIN ECH KEYS-----\nabc\n-----END ECH KEYS-----"
	info = ResponseNodeInfo{TLSSettings: map[string]any{
		"ech": map[string]any{"enabled": true, "key": keyPEM},
	}}
	applyPanelNodeConfig(zap.NewNop(), &cfg, info)
	assert.NotNil(t, cfg.ECH)
	got, err := os.ReadFile(cfg.ECH.KeyPath)
	assert.NoError(t, err)
	assert.Equal(t, keyPEM, string(got))
	assert.Contains(t, cfg.ECH.KeyPath, "hysteria-panel-ech.pem")

	// enabled=false / 缺 key 材料 不接
	cfg = serverConfig{}
	info = ResponseNodeInfo{TLSSettings: map[string]any{
		"ech": map[string]any{"enabled": false, "key_path": "/x.pem"},
	}}
	applyPanelNodeConfig(zap.NewNop(), &cfg, info)
	assert.Nil(t, cfg.ECH)

	info = ResponseNodeInfo{TLSSettings: map[string]any{
		"ech": map[string]any{"enabled": true},
	}}
	applyPanelNodeConfig(zap.NewNop(), &cfg, info)
	assert.Nil(t, cfg.ECH)

	// 本地已配 ECH 时面板让位
	cfg = serverConfig{ECH: &serverConfigECH{KeyPath: "/local/ech.pem"}}
	info = ResponseNodeInfo{TLSSettings: map[string]any{
		"ech": map[string]any{"enabled": true, "key_path": "/panel/ech.pem"},
	}}
	applyPanelNodeConfig(zap.NewNop(), &cfg, info)
	assert.Equal(t, "/local/ech.pem", cfg.ECH.KeyPath)
}

// TestV2boardNodeInfoChangedPolicy 策略字段变化触发重启
func TestV2boardNodeInfoChangedPolicy(t *testing.T) {
	var rule auth.PanelCustomRouteRule
	rule.Match.Domains = []string{"a.com"}
	rule.Action.Type = "block"

	same := func() ResponseNodeInfo {
		return ResponseNodeInfo{
			Sniff:            &panelSniffPayload{Enable: true, TCPPorts: "80"},
			DisableUDP:       true,
			UDPIdleTimeout:   30,
			CustomRouteRules: []auth.PanelCustomRouteRule{rule},
			TLSSettings:      map[string]any{"ech": map[string]any{"enabled": true, "key_path": "/x.pem"}},
		}
	}
	assert.False(t, v2boardNodeInfoChanged(same(), same()))

	// 一边 nil 一边非 nil 判变
	info := same()
	info.Sniff = nil
	assert.True(t, v2boardNodeInfoChanged(same(), info))

	// 同非 nil 但值不同
	info = same()
	info.Sniff.TCPPorts = "443"
	assert.True(t, v2boardNodeInfoChanged(same(), info))

	// 标量开关
	info = same()
	info.DisableUDP = false
	assert.True(t, v2boardNodeInfoChanged(same(), info))

	info = same()
	info.UDPIdleTimeout = 60
	assert.True(t, v2boardNodeInfoChanged(same(), info))

	// custom_route_rules 变化
	info = same()
	var rule2 auth.PanelCustomRouteRule
	rule2.Match.Domains = []string{"b.com"}
	rule2.Action.Type = "direct"
	info.CustomRouteRules = append(info.CustomRouteRules, rule2)
	assert.True(t, v2boardNodeInfoChanged(same(), info))

	// tls_settings 变化
	info = same()
	info.TLSSettings["ech"].(map[string]any)["key_path"] = "/y.pem"
	assert.True(t, v2boardNodeInfoChanged(same(), info))

	// 基础字段（端口）仍生效
	info = same()
	info.ServerPort = 12345
	assert.True(t, v2boardNodeInfoChanged(same(), info))
}
