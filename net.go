package vbox

import (
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"unicode"
)

// 网络目标条目与规则集（level + 原表序语义）。

// Entry 归一化目标条目（Host 小写/IP/loopback 归一，Port 数字串或 *）。
// 规则模式侧允许最左侧完整标签通配（*.example.com）。
type Entry struct {
	Host string
	Port string
}

// String 返回规范形态 host:port。
func (e Entry) String() string { return net.JoinHostPort(CanonicalNetHost(e.Host), e.Port) }

// ParseEntry 解析一个具体目标：禁止通配、level、空白与控制字符。
// bare host 的端口为 *；user@ 前缀用于 SSH 目标。多冒号形态必须是合法 IPv6。
func ParseEntry(s string) (Entry, error) {
	return parseEntry(s, false)
}

// ParseRuleEntry 解析权限表中的目标模式。只有最左侧完整标签可以是 *；
// 不接受 level 或效果前缀，那些由 ParseNetRule 处理。
func ParseRuleEntry(s string) (Entry, error) {
	return parseEntry(s, true)
}

func parseEntry(s string, rulePattern bool) (Entry, error) {
	if s == "" {
		return Entry{}, fmt.Errorf("empty target")
	}
	if strings.IndexFunc(s, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) }) >= 0 {
		return Entry{}, fmt.Errorf("invalid target %q: whitespace and control characters are not allowed", s)
	}
	if strings.Contains(s, "!") {
		return Entry{}, fmt.Errorf("invalid target %q: level prefix is only valid on a complete rule", s)
	}
	if i := strings.LastIndex(s, "@"); i >= 0 {
		s = s[i+1:]
	}
	if s == "" || strings.Contains(s, "/") {
		return Entry{}, fmt.Errorf("invalid target %q: want host[:port]", s)
	}

	host, port := "", ""
	switch {
	case strings.HasPrefix(s, "["):
		h, p, err := net.SplitHostPort(s)
		if err != nil {
			return Entry{}, fmt.Errorf("invalid target %q: %v", s, err)
		}
		host, port = h, p
	case strings.Count(s, ":") == 1:
		h, p, err := net.SplitHostPort(s)
		if err != nil {
			return Entry{}, fmt.Errorf("invalid target %q: %v", s, err)
		}
		host, port = h, p
	case strings.Count(s, ":") == 0:
		host, port = s, "*"
	default:
		if _, err := netip.ParseAddr(s); err != nil {
			return Entry{}, fmt.Errorf("invalid target %q: multi-colon host must be a valid IPv6 literal", s)
		}
		host, port = s, "*"
	}

	host = CanonicalNetHost(host)
	if err := validateRuleHost(host, rulePattern); err != nil {
		return Entry{}, fmt.Errorf("invalid target %q: %v", s, err)
	}
	if port != "*" {
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 {
			return Entry{}, fmt.Errorf("invalid port %q in %q: want 1-65535 or *", port, s)
		}
		port = strconv.Itoa(n)
	}
	return Entry{Host: host, Port: port}, nil
}

func validateRuleHost(host string, rulePattern bool) error {
	if host == "" {
		return fmt.Errorf("empty host")
	}
	if len(host) > 253 {
		return fmt.Errorf("host exceeds 253 bytes")
	}
	if _, err := netip.ParseAddr(host); err == nil {
		return nil
	}
	labels := strings.Split(host, ".")
	for i, label := range labels {
		if label == "" {
			return fmt.Errorf("empty host label")
		}
		if len(label) > 63 {
			return fmt.Errorf("host label exceeds 63 bytes")
		}
		if !strings.Contains(label, "*") {
			continue
		}
		if !rulePattern || i != 0 || label != "*" || len(labels) < 2 {
			return fmt.Errorf("wildcard is only supported as the leftmost complete host label")
		}
	}
	return nil
}

// NormalizeHost 归一化主机名：小写、去尾点、IP 经 netip 归一。
func NormalizeHost(host string) string {
	host = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
	if ip, err := netip.ParseAddr(host); err == nil {
		return ip.String()
	}
	return host
}

// CanonicalNetHost 归一化主机名，并把 localhost、.localhost 子名和回环 IP
// 归入同一个 loopback 类。规则模式 *.localhost 保留为该类的通配形式。
func CanonicalNetHost(host string) string {
	host = NormalizeHost(host)
	if host == "*.localhost" {
		return host
	}
	if host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return "localhost"
	}
	if ip, err := netip.ParseAddr(host); err == nil && ip.IsLoopback() {
		return "localhost"
	}
	return host
}

// ValidateEntries 批量校验具体目标（不接受通配或 level）。
func ValidateEntries(list []string) error {
	for _, s := range list {
		if _, err := ParseEntry(s); err != nil {
			return err
		}
	}
	return nil
}

// ParseNetRule 解析完整 net/ssh 规则：行首 ! 增加 level，随后是
// allow:/deny: 与目标模式。level 最多 255；旧配置不做兼容解析。
func ParseNetRule(raw string) (NetRule, error) {
	s := strings.TrimSpace(raw)
	var level uint8
	for strings.HasPrefix(s, "!") {
		if level == 255 {
			return NetRule{}, fmt.Errorf("invalid net rule %q: level exceeds 255", raw)
		}
		level++
		s = s[1:]
	}
	allow, e, err := parseTargetRule(s, true)
	if err != nil {
		return NetRule{}, err
	}
	return NetRule{HostPort: e.String(), Allow: allow, Level: level}, nil
}

// ParseTargetRule 解析具体目标规则，不接受 level 或通配。
func ParseTargetRule(raw string) (allow bool, e Entry, err error) {
	return parseTargetRule(raw, false)
}

func parseTargetRule(raw string, rulePattern bool) (allow bool, e Entry, err error) {
	s := strings.TrimSpace(raw)
	switch {
	case strings.HasPrefix(s, "allow:"):
		allow, s = true, strings.TrimSpace(strings.TrimPrefix(s, "allow:"))
	case strings.HasPrefix(s, "deny:"):
		s = strings.TrimSpace(strings.TrimPrefix(s, "deny:"))
	default:
		return false, Entry{}, fmt.Errorf("invalid target rule %q: missing effect prefix (allow: / deny:)", raw)
	}
	parse := ParseEntry
	if rulePattern {
		parse = ParseRuleEntry
	}
	e, err = parse(s)
	if err != nil {
		return false, Entry{}, err
	}
	return allow, e, nil
}

// ValidateTargetRules 批量校验完整规则行（加载/入表即报错）。
func ValidateTargetRules(list []string) error {
	for _, raw := range list {
		if _, err := ParseNetRule(raw); err != nil {
			return err
		}
	}
	return nil
}

// NetRule 网络规则行。HostPort 形如 "example.com:443"，端口可 *。
type NetRule struct {
	HostPort string
	Allow    bool
	Level    uint8
}

// String 返回包含 level 的规范形态，供日志/回执展示。
func (r NetRule) String() string {
	effect := "deny:"
	if r.Allow {
		effect = "allow:"
	}
	return strings.Repeat("!", int(r.Level)) + effect + r.HostPort
}

// NetRuleSet 网络规则集：高 level 优先，同 level 按原表序首命中。
type NetRuleSet struct {
	Rules   []NetRule
	Default bool // 未命中兜底 = net_policy open/deny
	// UpstreamProxy is the optional explicit upstream HTTP/SOCKS5 proxy URL.
	// It is part of the policy snapshot; ambient process proxy variables are ignored.
	UpstreamProxy string
}

// Match 判定目标是否放行。非法目标或规则行均 fail-closed。
// 端口匹配取保守交集语义：规则为 * 或相等即命中；查询为 * 时重叠即命中。
func (s NetRuleSet) Match(hostport string) bool { allow, _ := s.Resolve(hostport); return allow }

// Resolve reports the highest-priority matching row, or -1 for the default/invalid target.
func (s NetRuleSet) Resolve(hostport string) (allow bool, matched int) {
	q, err := ParseEntry(hostport)
	if err != nil {
		return false, -1
	}
	best := -1
	var bestLevel uint8
	for i, row := range s.Rules {
		target, err := ParseRuleEntry(row.HostPort)
		if err != nil {
			return false, i
		}
		if best >= 0 && row.Level <= bestLevel {
			continue
		}
		if EntryMatch(target, q) {
			best, bestLevel, allow = i, row.Level, row.Allow
		}
	}
	if best >= 0 {
		return allow, best
	}
	return s.Default, -1
}

// EntryMatch 判定规则模式 r 是否覆盖具体目标 q，并应用端口保守交集语义。
func EntryMatch(r, q Entry) bool {
	r.Host, q.Host = CanonicalNetHost(r.Host), CanonicalNetHost(q.Host)
	hostMatched := r.Host == q.Host
	if strings.HasPrefix(r.Host, "*.") {
		if r.Host == "*.localhost" {
			hostMatched = q.Host == "localhost"
		} else {
			base := strings.TrimPrefix(r.Host, "*.")
			hostMatched = q.Host != base && strings.HasSuffix(q.Host, "."+base)
		}
	}
	return hostMatched && (r.Port == "*" || r.Port == q.Port || q.Port == "*")
}

// NetRowLanding 描述一条原始规则在启动计划中的落地方式。
type NetRowLanding struct {
	Rule     NetRule
	Kernel   bool // 由内核逐条规则落实
	Proxy    bool // 由出站代理按完整快照落实
	Absorbed bool // 死行、冗余行，或省略后只会收窄的规则
	Reserved bool // 内部 transport 保留项，不对应调用方规则
	Reason   string
}

// CheckNetPolicy 用平台的真实 NetCaps 预检完整快照，返回与原始行序一致的
// Kernel / Proxy / Absorbed / Reserved 诊断。语法错误与 UnsupportedError 分开；
// 一个仍然有效的 deny 无法落实时拒绝启动，allow 省略后只会收窄时可以吸收。
//
// darwin 的 loopback 投影按 level + 原表序求每个具体端口及其他端口代表集的
// 真实胜者；所有胜者进入内核计划，非胜者吸收。静态预检和 Seatbelt 输出共用
// compileNetPlan，不再把混合拼写或冲突本身当作错误。
func CheckNetPolicy(platform string, s NetRuleSet) ([]NetRowLanding, error) {
	plan, err := compileNetPlan(platform, s, netCapsForPlatform(platform))
	return plan.landings, err
}
