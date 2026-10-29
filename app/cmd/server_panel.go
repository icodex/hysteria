package cmd

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"go.uber.org/zap"

	"github.com/apernet/hysteria/extras/v2/auth"
)

// —— 面板下发的 fork 策略载荷 ——
// 键名与 hysteria server.yaml 对应段一致（面板侧原样透传 protocol_settings），
// 仅 hysteria 后端消费；窗口/流数/秒数为面板字段的原始单位。

// panelSniffPayload 面板 sniff 段
type panelSniffPayload struct {
	Enable        bool   `json:"enable"`
	Timeout       int    `json:"timeout"` // 秒
	RewriteDomain bool   `json:"rewriteDomain"`
	TCPPorts      string `json:"tcpPorts"`
	UDPPorts      string `json:"udpPorts"`
}

// panelMasqueradePayload 面板 masquerade 段。
// JSON 键 "string" 为 Go 关键字，字段名用 String + tag 避开
type panelMasqueradePayload struct {
	Type        string `json:"type"` // 404/file/proxy/string
	ListenHTTP  string `json:"listenHTTP"`
	ListenHTTPS string `json:"listenHTTPS"`
	ForceHTTPS  bool   `json:"forceHTTPS"`
	File        struct {
		Dir string `json:"dir"`
	} `json:"file"`
	Proxy struct {
		URL         string `json:"url"`
		RewriteHost bool   `json:"rewriteHost"`
		XForwarded  bool   `json:"xForwarded"`
		Insecure    bool   `json:"insecure"`
	} `json:"proxy"`
	String struct {
		Content    string `json:"content"`
		StatusCode int    `json:"statusCode"`
	} `json:"string"`
}

// panelQUICPayload 面板 quic 段（maxIdleTimeout 秒）
type panelQUICPayload struct {
	InitStreamReceiveWindow uint64 `json:"initStreamReceiveWindow"`
	MaxStreamReceiveWindow  uint64 `json:"maxStreamReceiveWindow"`
	InitConnReceiveWindow   uint64 `json:"initConnReceiveWindow"`
	MaxConnReceiveWindow    uint64 `json:"maxConnReceiveWindow"`
	MaxIdleTimeout          int    `json:"maxIdleTimeout"` // 秒
	MaxIncomingStreams      int64  `json:"maxIncomingStreams"`
	DisablePathMTUDiscovery bool   `json:"disablePathMTUDiscovery"`
	DisableStatelessReset   bool   `json:"disableStatelessReset"`
}

// panelCongestionPayload 面板 congestion 段
type panelCongestionPayload struct {
	Type       string `json:"type"` // bbr/reno
	BBRProfile string `json:"bbrProfile"`
}

// panelResolverPayload 面板 resolver 段（timeout 秒）
type panelResolverPayload struct {
	Type string `json:"type"` // tcp/udp/tls/https
	TCP  struct {
		Addr    string `json:"addr"`
		Timeout int    `json:"timeout"`
	} `json:"tcp"`
	UDP struct {
		Addr    string `json:"addr"`
		Timeout int    `json:"timeout"`
	} `json:"udp"`
	TLS struct {
		Addr     string `json:"addr"`
		Timeout  int    `json:"timeout"`
		SNI      string `json:"sni"`
		Insecure bool   `json:"insecure"`
	} `json:"tls"`
	HTTPS struct {
		Addr     string `json:"addr"`
		Timeout  int    `json:"timeout"`
		SNI      string `json:"sni"`
		Insecure bool   `json:"insecure"`
	} `json:"https"`
}

// applyPanelNodeConfig 把面板 nodeInfo 的扩展能力落进本地 serverConfig：
// listen_ip、kernel_log_level、cert_config、routes/custom_route_rules、custom_outbounds、
// sniff/masquerade/quic/congestion/resolver 等策略字段与开关类、tls_settings.ech。
// 只填空位/追加，不覆盖用户显式配置的字段；本地已写 outbounds/acl 时面板的让位。
func applyPanelNodeConfig(logger *zap.Logger, config *serverConfig, info ResponseNodeInfo) {
	// listen_ip（面板恒下发 "0.0.0.0"，仅非空且非通配时改写监听主机）
	if info.ListenIP != "" && info.ListenIP != "0.0.0.0" && info.ListenIP != "::" {
		if _, port, err := splitHostPortOK(config.Listen); err == nil && port != "" {
			config.Listen = info.ListenIP + ":" + port
		}
	}

	// kernel_log_level → HYSTERIA_LOG_LEVEL；logger 在进程启动时定型，
	// 写 env 后由"配置变更退出→守护进程拉起"路径生效
	if info.KernelLogLevel != "" {
		if _, ok := logLevelMap[strings.ToLower(strings.TrimSpace(info.KernelLogLevel))]; ok {
			_ = os.Setenv(appLogLevelEnv, strings.ToLower(strings.TrimSpace(info.KernelLogLevel)))
			logger.Info("panel kernel_log_level applied (takes effect after restart)",
				zap.String("level", info.KernelLogLevel))
		} else {
			logger.Warn("panel kernel_log_level not recognized", zap.String("level", info.KernelLogLevel))
		}
	}

	// cert_config：仅当本地既无 tls.cert 也无 acme.domains 时接手
	hasLocalTLS := (config.TLS != nil && config.TLS.Cert != "") || (config.ACME != nil && len(config.ACME.Domains) > 0)
	if info.CertConfig != nil && !hasLocalTLS {
		applyPanelCertConfig(logger, config, info)
	}

	// 路由：面板 routes + custom_routes → acl.inline；用户已配 ACL 时不接
	panelACL := panelACLLines(info)
	if len(panelACL) > 0 && config.ACL.File == "" && len(config.ACL.Inline) == 0 {
		config.ACL.Inline = panelACL
		logger.Info("panel routes applied", zap.Int("rules", len(panelACL)))
	}

	// 自定义出站：面板 custom_outbounds → config.Outbounds；用户本地已配则不接
	if len(info.CustomOutbounds) > 0 && len(config.Outbounds) == 0 {
		obs, errs := panelOutboundEntries(info.CustomOutbounds)
		for _, e := range errs {
			logger.Warn("panel custom_outbound dropped", zap.String("err", e))
		}
		if len(obs) > 0 {
			config.Outbounds = obs
			logger.Info("panel custom_outbounds applied", zap.Int("count", len(obs)))
		}
	}

	// sniff：本地零值才整体接面板值
	if info.Sniff != nil && config.Sniff == (serverConfigSniff{}) {
		config.Sniff = serverConfigSniff{
			Enable:        info.Sniff.Enable,
			Timeout:       time.Duration(info.Sniff.Timeout) * time.Second,
			RewriteDomain: info.Sniff.RewriteDomain,
			TCPPorts:      info.Sniff.TCPPorts,
			UDPPorts:      info.Sniff.UDPPorts,
		}
		logger.Info("panel sniff applied",
			zap.Bool("enable", config.Sniff.Enable), zap.Duration("timeout", config.Sniff.Timeout))
	}

	// masquerade：本地未配 type 时接面板 type 及其对应子段；非法 type 整体丢弃
	if info.Masquerade != nil {
		applyPanelMasquerade(logger, config, info.Masquerade)
	}

	// quic：逐字段填空位，bool 用 || 合并
	if info.Quic != nil {
		quicBefore := config.QUIC
		q := info.Quic
		if config.QUIC.InitStreamReceiveWindow == 0 {
			config.QUIC.InitStreamReceiveWindow = q.InitStreamReceiveWindow
		}
		if config.QUIC.MaxStreamReceiveWindow == 0 {
			config.QUIC.MaxStreamReceiveWindow = q.MaxStreamReceiveWindow
		}
		if config.QUIC.InitConnectionReceiveWindow == 0 {
			config.QUIC.InitConnectionReceiveWindow = q.InitConnReceiveWindow
		}
		if config.QUIC.MaxConnectionReceiveWindow == 0 {
			config.QUIC.MaxConnectionReceiveWindow = q.MaxConnReceiveWindow
		}
		if config.QUIC.MaxIdleTimeout == 0 && q.MaxIdleTimeout > 0 {
			config.QUIC.MaxIdleTimeout = time.Duration(q.MaxIdleTimeout) * time.Second
		}
		if config.QUIC.MaxIncomingStreams == 0 {
			config.QUIC.MaxIncomingStreams = q.MaxIncomingStreams
		}
		config.QUIC.DisablePathMTUDiscovery = config.QUIC.DisablePathMTUDiscovery || q.DisablePathMTUDiscovery
		config.QUIC.DisableStatelessReset = config.QUIC.DisableStatelessReset || q.DisableStatelessReset
		if quicBefore != config.QUIC {
			logger.Info("panel quic applied")
		}
	}

	// congestion：本地未配 type 且面板 type 非空时整体接（Type + BBRProfile）
	if info.Congestion != nil && config.Congestion.Type == "" &&
		strings.TrimSpace(info.Congestion.Type) != "" {
		config.Congestion = serverConfigCongestion{
			Type:       info.Congestion.Type,
			BBRProfile: info.Congestion.BBRProfile,
		}
		logger.Info("panel congestion applied", zap.String("type", config.Congestion.Type))
	}

	// resolver：本地未配 type 且面板 type 非空时整体映射（各子 struct 对应）
	if info.Resolver != nil && config.Resolver.Type == "" &&
		strings.TrimSpace(info.Resolver.Type) != "" {
		r := info.Resolver
		config.Resolver = serverConfigResolver{
			Type: r.Type,
			TCP:  serverConfigResolverTCP{Addr: r.TCP.Addr, Timeout: panelSecs(r.TCP.Timeout)},
			UDP:  serverConfigResolverUDP{Addr: r.UDP.Addr, Timeout: panelSecs(r.UDP.Timeout)},
			TLS: serverConfigResolverTLS{
				Addr: r.TLS.Addr, Timeout: panelSecs(r.TLS.Timeout), SNI: r.TLS.SNI, Insecure: r.TLS.Insecure,
			},
			HTTPS: serverConfigResolverHTTPS{
				Addr: r.HTTPS.Addr, Timeout: panelSecs(r.HTTPS.Timeout), SNI: r.HTTPS.SNI, Insecure: r.HTTPS.Insecure,
			},
		}
		logger.Info("panel resolver applied", zap.String("type", config.Resolver.Type))
	}

	// 开关类：false→true 单向，本地显式关闭不受影响
	if info.DisableUDP && !config.DisableUDP {
		config.DisableUDP = true
		logger.Info("panel disable_udp applied")
	}
	if config.UDPIdleTimeout == 0 && info.UDPIdleTimeout >= 1 && info.UDPIdleTimeout <= 600 {
		config.UDPIdleTimeout = time.Duration(info.UDPIdleTimeout) * time.Second
		logger.Info("panel udp_idle_timeout applied", zap.Duration("timeout", config.UDPIdleTimeout))
	}
	if info.IgnoreClientBandwidth && !config.IgnoreClientBandwidth {
		config.IgnoreClientBandwidth = true
		logger.Info("panel ignore_client_bandwidth applied")
	}
	if info.DisableLossCompensation && !config.Bandwidth.DisableLossCompensation {
		config.Bandwidth.DisableLossCompensation = true
		logger.Info("panel disable_loss_compensation applied")
	}

	// ECH：面板 tls_settings.ech → config.ECH；本地已配或面板未开则不动
	if info.TLSSettings != nil && config.ECH == nil {
		applyPanelECH(logger, config, info.TLSSettings)
	}
}

// applyPanelMasquerade 面板 masquerade → config.Masquerade。
// type 404/file/proxy/string（与 fillMasqHandler 对齐），statusCode 原样透传
// （200-599 且非 233 的校验在面板侧）；listenHTTP/listenHTTPS/forceHTTPS 与
// type 独立，仅补本地零值。非法 type 整体丢弃并 Warn。
func applyPanelMasquerade(logger *zap.Logger, config *serverConfig, m *panelMasqueradePayload) {
	mt := strings.ToLower(strings.TrimSpace(m.Type))
	switch mt {
	case "", "404", "file", "proxy", "string":
	default:
		logger.Warn("panel masquerade dropped: bad type", zap.String("type", m.Type))
		return
	}
	if config.Masquerade.Type == "" && mt != "" {
		config.Masquerade.Type = m.Type
		switch mt {
		case "file":
			config.Masquerade.File.Dir = m.File.Dir
		case "proxy":
			config.Masquerade.Proxy = serverConfigMasqueradeProxy{
				URL:         m.Proxy.URL,
				RewriteHost: m.Proxy.RewriteHost,
				XForwarded:  m.Proxy.XForwarded,
				Insecure:    m.Proxy.Insecure,
			}
		case "string":
			config.Masquerade.String = serverConfigMasqueradeString{
				Content:    m.String.Content,
				StatusCode: m.String.StatusCode,
			}
		}
		logger.Info("panel masquerade applied", zap.String("type", config.Masquerade.Type))
	}
	if config.Masquerade.ListenHTTP == "" && m.ListenHTTP != "" {
		config.Masquerade.ListenHTTP = m.ListenHTTP
	}
	if config.Masquerade.ListenHTTPS == "" && m.ListenHTTPS != "" {
		config.Masquerade.ListenHTTPS = m.ListenHTTPS
	}
	if !config.Masquerade.ForceHTTPS && m.ForceHTTPS {
		config.Masquerade.ForceHTTPS = true
	}
}

// applyPanelECH 面板 tls_settings.ech → config.ECH（仅 KeyPath）。
// key_path 直用；仅给 key（PEM 内容）时落临时盘再指 KeyPath，参考 writeCertMaterial。
func applyPanelECH(logger *zap.Logger, config *serverConfig, tlsSettings map[string]any) {
	echRaw, ok := tlsSettings["ech"].(map[string]any)
	if !ok {
		return
	}
	if enabled, ok := echRaw["enabled"].(bool); !ok || !enabled {
		return
	}
	keyPath, _ := echRaw["key_path"].(string)
	key, _ := echRaw["key"].(string)
	if keyPath == "" && key != "" {
		p := filepath.Join(os.TempDir(), "hysteria-panel-ech.pem")
		if err := os.WriteFile(p, []byte(key), 0o600); err != nil {
			logger.Warn("panel ech key write failed", zap.Error(err))
			return
		}
		keyPath = p
	}
	if keyPath == "" {
		logger.Warn("panel ech enabled but no key material")
		return
	}
	config.ECH = &serverConfigECH{KeyPath: keyPath}
	logger.Info("panel ech applied", zap.String("key_path", keyPath))
}

// panelSecs 面板秒数 → time.Duration（0 表示用内核默认）
func panelSecs(v int) time.Duration {
	return time.Duration(v) * time.Second
}

// splitHostPortOK 轻量拆 host:port
func splitHostPortOK(addr string) (string, string, error) {
	i := strings.LastIndex(addr, ":")
	if i < 0 {
		return addr, "", fmt.Errorf("no port")
	}
	return addr[:i], addr[i+1:], nil
}

// applyPanelCertConfig 映射面板 cert_config 到本地 tls/acme 配置。
// 支持 self/file/content/http/dns；none 或不认识的 mode 保持原状
// （启动会因无证书失败，与未配置时行为一致，由用户自查）。
func applyPanelCertConfig(logger *zap.Logger, config *serverConfig, info ResponseNodeInfo) {
	cc := info.CertConfig
	domain := cc.Domain
	if domain == "" {
		domain = info.ServerName
	}
	switch strings.ToLower(strings.TrimSpace(cc.CertMode)) {
	case "self":
		// 自签：面板只给域名，节点现场生成短期证书
		certPath, keyPath, err := genSelfSignedCertPair(domain)
		if err != nil {
			logger.Warn("panel cert self mode failed", zap.Error(err))
			return
		}
		config.TLS = &serverConfigTLS{Cert: certPath, Key: keyPath}
		logger.Info("panel cert_config applied (self)", zap.String("domain", domain))
	case "file":
		if cc.CertFile == "" || cc.KeyFile == "" {
			logger.Warn("panel cert file mode missing paths")
			return
		}
		config.TLS = &serverConfigTLS{Cert: cc.CertFile, Key: cc.KeyFile}
		logger.Info("panel cert_config applied (file)", zap.String("cert", cc.CertFile))
	case "content":
		if cc.CertContent == "" || cc.KeyContent == "" {
			logger.Warn("panel cert content mode missing material")
			return
		}
		certPath, keyPath, err := writeCertMaterial(cc.CertContent, cc.KeyContent)
		if err != nil {
			logger.Warn("panel cert content mode failed", zap.Error(err))
			return
		}
		config.TLS = &serverConfigTLS{Cert: certPath, Key: keyPath}
		logger.Info("panel cert_config applied (content)")
	case "http":
		acme := &serverConfigACME{Domains: []string{domain}, Email: cc.Email, Type: "http"}
		if cc.HTTPPort > 0 {
			acme.HTTP.AltPort = cc.HTTPPort
		}
		config.ACME = acme
		config.TLS = nil
		logger.Info("panel cert_config applied (acme http)", zap.String("domain", domain))
	case "dns":
		if cc.DNSProvider == "" {
			logger.Warn("panel cert dns mode missing provider")
			return
		}
		acme := &serverConfigACME{
			Domains: []string{domain},
			Email:   cc.Email,
			Type:    "dns",
			DNS:     serverConfigACMEDNS{Name: strings.ToLower(cc.DNSProvider), Config: cc.DNSEnv},
		}
		config.ACME = acme
		config.TLS = nil
		logger.Info("panel cert_config applied (acme dns)", zap.String("domain", domain), zap.String("provider", cc.DNSProvider))
	default:
		logger.Warn("panel cert_config mode not supported by this node", zap.String("mode", cc.CertMode))
	}
}

// panelACLLines 面板 routes + custom_route_rules（结构化跨内核规则）→ hysteria ACL 行。
// raw custom_routes 为内核私有格式，此节点不消费（见 ResponseNodeInfo.CustomRoutes）。
func panelACLLines(info ResponseNodeInfo) []string {
	var lines []string
	for _, r := range info.Routes {
		lines = append(lines, r.ToACLLines()...)
	}
	for _, r := range info.CustomRouteRules {
		lines = append(lines, r.ToACLLines()...)
	}
	return lines
}

// panelOutboundEntries 面板出站 → serverConfigOutboundEntry。
// 仅映射 hysteria 内核具备的 socks5/http/direct；proxy_tag 链式出站
// 在 hysteria 里由 ACL 规则引用命名出站表达，这里不做额外展开。
func panelOutboundEntries(list []auth.PanelOutbound) ([]serverConfigOutboundEntry, []string) {
	var entries []serverConfigOutboundEntry
	var errs []string
	for _, o := range list {
		m, err := o.ToHyOutbound()
		if err != nil {
			errs = append(errs, err.Error())
			continue
		}
		e := serverConfigOutboundEntry{Name: m["name"].(string)}
		switch m["type"].(string) {
		case "socks5":
			s := m["socks5"].(map[string]any)
			e.Type = "socks5"
			e.SOCKS5 = serverConfigOutboundSOCKS5{
				Addr:     strOf(s["addr"]),
				Username: strOf(s["username"]),
				Password: strOf(s["password"]),
			}
		case "http":
			h := m["http"].(map[string]any)
			e.Type = "http"
			e.HTTP = serverConfigOutboundHTTP{URL: strOf(h["url"])}
		case "direct":
			e.Type = "direct"
			e.Direct = serverConfigOutboundDirect{Mode: "auto"}
		default:
			errs = append(errs, fmt.Sprintf("panel outbound %q: bad type", o.Tag))
			continue
		}
		entries = append(entries, e)
	}
	return entries, errs
}

func strOf(v any) string {
	s, _ := v.(string)
	return s
}

// genSelfSignedCertPair 现场生成自签证书（复用 cert.go 生成器，1 年有效期）
func genSelfSignedCertPair(domain string) (string, string, error) {
	dir := os.TempDir()
	certPath := filepath.Join(dir, fmt.Sprintf("hysteria-panel-self-%s.crt", sanitizeFilename(domain)))
	keyPath := filepath.Join(dir, fmt.Sprintf("hysteria-panel-self-%s.key", sanitizeFilename(domain)))
	if _, err := os.Stat(certPath); err == nil {
		if _, err := os.Stat(keyPath); err == nil {
			return certPath, keyPath, nil
		}
	}
	certPEM, keyPEM, _, err := generateSelfSignedCert(certHosts{DNSNames: []string{domain}}, 365*24*time.Hour)
	if err != nil {
		return "", "", err
	}
	if err := os.WriteFile(certPath, certPEM, 0o644); err != nil {
		return "", "", err
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		return "", "", err
	}
	return certPath, keyPath, nil
}

func sanitizeFilename(s string) string {
	return strings.Map(func(r rune) rune {
		switch r {
		case '*', '?', '/', '\\', ':', '<', '>', '"', '|':
			return '_'
		}
		return r
	}, s)
}

// writeCertMaterial content 模式：面板 PEM 落盘
func writeCertMaterial(certPEM, keyPEM string) (string, string, error) {
	dir := os.TempDir()
	certPath := filepath.Join(dir, "hysteria-panel-content.crt")
	keyPath := filepath.Join(dir, "hysteria-panel-content.key")
	if err := os.WriteFile(certPath, []byte(certPEM), 0o600); err != nil {
		return "", "", err
	}
	if err := os.WriteFile(keyPath, []byte(keyPEM), 0o600); err != nil {
		return "", "", err
	}
	return certPath, keyPath, nil
}

var (
	statsCtx    context.Context
	statsCancel context.CancelFunc
)

// statsLoopCtx 惰性创建 REST 兜底循环的生命周期 ctx
func statsLoopCtx() context.Context {
	if statsCtx == nil {
		statsCtx, statsCancel = context.WithCancel(context.Background())
	}
	return statsCtx
}

func stopStatsLoops() {
	if statsCancel != nil {
		statsCancel()
	}
}
