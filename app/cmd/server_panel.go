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

// applyPanelNodeConfig 把面板 nodeInfo 的扩展能力落进本地 serverConfig：
// listen_ip、kernel_log_level、cert_config、routes/custom_routes、custom_outbounds。
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

// panelACLLines 面板 routes + custom_routes → hysteria ACL 行
func panelACLLines(info ResponseNodeInfo) []string {
	var lines []string
	for _, r := range info.Routes {
		lines = append(lines, r.ToACLLines()...)
	}
	for _, r := range info.CustomRoutes {
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
