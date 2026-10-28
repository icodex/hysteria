package auth

import (
	"encoding/json"
	"fmt"
	"strings"
)

// PanelCertConfig 面板 cert_config（ServerService::buildNodeConfig）
type PanelCertConfig struct {
	CertMode    string            `json:"cert_mode"`    // none/self/http/dns/file/content
	Domain      string            `json:"domain"`       // ACME 域名
	Email       string            `json:"email"`        // ACME 邮箱
	DNSProvider string            `json:"dns_provider"` // dns 模式供应商
	DNSEnv      map[string]string `json:"dns_env"`      // 供应商凭据
	HTTPPort    int               `json:"http_port"`    // http 模式本地端口
	CertFile    string            `json:"cert_file"`    // file 模式证书路径
	KeyFile     string            `json:"key_file"`     // file 模式私钥路径
	CertContent string            `json:"cert_content"` // content 模式证书 PEM
	KeyContent  string            `json:"key_content"`  // content 模式私钥 PEM
}

// ACMEType 返回 hysteria tls/acme type（""=不适用）
func (c *PanelCertConfig) ACMEType() string {
	if c == nil {
		return ""
	}
	switch c.CertMode {
	case "http":
		return "http"
	case "dns":
		return "dns"
	default:
		return ""
	}
}

// PanelRouteRule 面板 routes（ServerRoute）
type PanelRouteRule struct {
	ID          int      `json:"id"`
	Match       []string `json:"match"`
	Action      string   `json:"action"`
	ActionValue string   `json:"action_value,omitempty"`
}

// PanelCustomRouteRule 面板 custom_routes（结构化规则）
type PanelCustomRouteRule struct {
	Name     string `json:"name,omitempty"`
	Disabled bool   `json:"disabled,omitempty"`
	Match    struct {
		Domains        []string `json:"domains,omitempty"`
		DomainSuffixes []string `json:"domain_suffixes,omitempty"`
		IPCIDRs        []string `json:"ip_cidrs,omitempty"`
	} `json:"match,omitempty"`
	Action struct {
		Type   string `json:"type"`
		Target string `json:"target,omitempty"`
	} `json:"action"`
}

// ToACLLines 把面板路由规则翻译成 hysteria ACL 文本行。
// 语义与 Xboard-node compilePanelRouteRule 一致：
// 域名走 suffix 精确匹配、CIDR 原样、action 映射 outbound 名。
func (r PanelRouteRule) ToACLLines() []string {
	if len(r.Match) == 0 {
		return nil
	}
	outbound := "reject"
	switch r.Action {
	case "direct":
		outbound = "direct"
	case "proxy":
		if r.ActionValue != "" {
			outbound = r.ActionValue
		} else {
			outbound = "default"
		}
	case "dns":
		// hysteria ACL 没有 dns 出站概念；面板用 dns 动作导流到指定出站
		if r.ActionValue != "" {
			outbound = r.ActionValue
		} else {
			outbound = "direct"
		}
	}

	var lines []string
	for _, m := range r.Match {
		m = strings.TrimSpace(m)
		if m == "" {
			continue
		}
		m = strings.TrimPrefix(m, "*.")
		lines = append(lines, fmt.Sprintf("%s(%s)", outbound, m))
	}
	return lines
}

// ToACLLines 结构化规则：域名/后缀/CIDR 三类匹配展开为 ACL 行
func (r PanelCustomRouteRule) ToACLLines() []string {
	if r.Disabled {
		return nil
	}
	outbound := "reject"
	switch r.Action.Type {
	case "direct":
		outbound = "direct"
	case "proxy":
		if r.Action.Target != "" {
			outbound = r.Action.Target
		} else {
			outbound = "default"
		}
	case "block":
		outbound = "reject"
	}

	var lines []string
	for _, d := range r.Match.Domains {
		if d = strings.TrimSpace(d); d != "" {
			lines = append(lines, fmt.Sprintf("%s(%s)", outbound, d))
		}
	}
	for _, d := range r.Match.DomainSuffixes {
		if d = strings.TrimSpace(d); d != "" {
			lines = append(lines, fmt.Sprintf("%s(suffix:%s)", outbound, strings.TrimPrefix(d, ".")))
		}
	}
	for _, c := range r.Match.IPCIDRs {
		if c = strings.TrimSpace(c); c != "" {
			lines = append(lines, fmt.Sprintf("%s(%s)", outbound, c))
		}
	}
	return lines
}

// PanelOutbound 面板 custom_outbounds。settings 为协议原生参数，
// 仅在启动时转换为 hysteria outbound 配置（见 app/cmd 消费端）。
type PanelOutbound struct {
	Tag      string         `json:"tag"`
	Protocol string         `json:"protocol"`
	Settings map[string]any `json:"settings,omitempty"`
	ProxyTag string         `json:"proxy_tag,omitempty"`
}

// UnmarshalJSON 容错：PHP 端空关联数组会序列化成 []，
// 直接声明 map[string]any 会整体解码失败（连节点启动都被阻断），这里吞掉。
func (o *PanelOutbound) UnmarshalJSON(data []byte) error {
	type plain PanelOutbound
	var p plain
	if err := json.Unmarshal(data, &p); err != nil {
		// 再试一次：settings 置空后能否解码
		var raw struct {
			Tag      string          `json:"tag"`
			Protocol string          `json:"protocol"`
			Settings json.RawMessage `json:"settings"`
			ProxyTag string          `json:"proxy_tag"`
		}
		if err2 := json.Unmarshal(data, &raw); err2 != nil {
			return err
		}
		trimmed := strings.TrimSpace(string(raw.Settings))
		if raw.Settings != nil && trimmed != "null" && trimmed != "" && trimmed[0] == '{' {
			return err // 真正的对象都解不动，才是错误
		}
		o.Tag, o.Protocol, o.ProxyTag, o.Settings = raw.Tag, raw.Protocol, raw.ProxyTag, nil
		return nil
	}
	*o = PanelOutbound(p)
	return nil
}

// HyOutboundYAML 是 hysteria server.yaml outbounds 条目的镜像。
// Protocol 仅支持本仓内核具备的三种；其余协议在消费端丢弃并告警。
type HyOutboundYAML struct {
	Name   string                    `yaml:"name" mapstructure:"name"`
	Type   string                    `yaml:"type" mapstructure:"type"`
	SOCKS5 map[string]any            `yaml:"socks5,omitempty" mapstructure:"socks5,omitempty"`
	HTTP   map[string]any            `yaml:"http,omitempty" mapstructure:"http,omitempty"`
	Direct map[string]any            `yaml:"direct,omitempty" mapstructure:"direct,omitempty"`
	Extra  map[string]map[string]any `yaml:"-" mapstructure:"-"`
}

// ToHyOutbound 翻译为 hysteria outbound 条目；不支持的协议返回错误。
// 识别的协议名与 Xboard-node 对齐：socks/http(s)/direct，别名归一。
func (o PanelOutbound) ToHyOutbound() (map[string]any, error) {
	proto := strings.ToLower(strings.TrimSpace(o.Protocol))
	tag := o.Tag
	if tag == "" {
		tag = proto
	}
	settings := o.Settings
	if settings == nil {
		settings = map[string]any{}
	}
	getStr := func(k string) string {
		if v, ok := settings[k]; ok {
			if s, ok := v.(string); ok {
				return s
			}
		}
		return ""
	}
	getBool := func(k string, def bool) bool {
		if v, ok := settings[k]; ok {
			if b, ok := v.(bool); ok {
				return b
			}
		}
		return def
	}

	entry := map[string]any{"name": tag}
	switch proto {
	case "socks", "socks5":
		socks := map[string]any{
			"addr":     getStr("addr"),
			"username": getStr("username"),
			"password": getStr("password"),
		}
		entry["type"] = "socks5"
		entry["socks5"] = socks
	case "http", "https":
		h := map[string]any{
			"url":      getStr("url"),
			"insecure": getBool("insecure", false),
		}
		entry["type"] = "http"
		entry["http"] = h
	case "direct":
		entry["type"] = "direct"
		entry["direct"] = map[string]any{"mode": "auto"}
	default:
		return nil, fmt.Errorf("panel outbound %q: unsupported protocol %q (supported: socks5/http/direct)", tag, o.Protocol)
	}
	_ = getBool
	return entry, nil
}
