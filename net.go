package vbox

import (
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"unicode"
)

// 网络目标条目与规则集（first-wins 语义）。

// Entry 归一化目标条目（Host 小写/IP 归一，Port 数字串或 *）。
type Entry struct {
	Host string
	Port string
}

// String 返回规范形态 host:port。
func (e Entry) String() string { return net.JoinHostPort(e.Host, e.Port) }

// ParseEntry 解析并归一化目标条目：bare host → host:*；剥 user@ 前缀；
// host 小写/去尾点、IP 经 netip 归一；port 须为 1-65535 或 *。
// IPv6 须带括号（[::1]:22）；不带括号的多冒号形态按 bare host 处理（port=*）。
// 通配 host（含 "*"）整条拒绝——归一后字符串相等匹配下 * 条目恒惰性（永不匹配），
// 静默接受会让用户以为生效。
func ParseEntry(s string) (Entry, error) {
	s = strings.TrimSpace(s)
	if i := strings.LastIndex(s, "@"); i >= 0 {
		s = s[i+1:] // 剥 user@（ssh 目标形态 user@host:port）
	}
	if s == "" {
		return Entry{}, fmt.Errorf("empty target")
	}
	if strings.IndexFunc(s, func(r rune) bool { return r == '/' || unicode.IsSpace(r) }) >= 0 {
		return Entry{}, fmt.Errorf("invalid target %q: want host[:port]", s)
	}
	host, port := "", ""
	if strings.HasPrefix(s, "[") {
		h, p, err := net.SplitHostPort(s)
		if err != nil {
			return Entry{}, fmt.Errorf("invalid target %q: %v", s, err)
		}
		host, port = h, p
	} else if strings.Count(s, ":") == 1 {
		h, p, err := net.SplitHostPort(s)
		if err != nil {
			return Entry{}, fmt.Errorf("invalid target %q: %v", s, err)
		}
		host, port = h, p
	} else if strings.Count(s, ":") == 0 {
		host, port = s, "*"
	} else {
		host, port = s, "*" // 不带括号的 bare IPv6
	}
	host = NormalizeHost(host)
	if host == "" {
		return Entry{}, fmt.Errorf("invalid target %q: empty host", s)
	}
	if strings.Contains(host, "*") {
		return Entry{}, fmt.Errorf("invalid target %q: wildcard host is not supported (entries match exact hosts only)", s)
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

// NormalizeHost 归一化主机名：小写、去尾点、IP 经 netip 归一（与 ParseEntry 同口径）。
func NormalizeHost(host string) string {
	host = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
	if ip, err := netip.ParseAddr(host); err == nil {
		return ip.String()
	}
	return host
}

// ValidateEntries 批量校验条目合法性（set_config 显式校验用；首个非法条目即报错）。
func ValidateEntries(list []string) error {
	for _, s := range list {
		if _, err := ParseEntry(s); err != nil {
			return err
		}
	}
	return nil
}

// ParseTargetRule 解析 net/ssh 规则行：剥 allow:/deny: 前缀后按 Entry 归一。
// Entry 解析本身拒绝通配 host，allow:* / deny:* 等全域行在此自然报错（指向 *_policy）。
func ParseTargetRule(raw string) (allow bool, e Entry, err error) {
	s := strings.TrimSpace(raw)
	switch {
	case strings.HasPrefix(s, "allow:"):
		allow, s = true, strings.TrimSpace(strings.TrimPrefix(s, "allow:"))
	case strings.HasPrefix(s, "deny:"):
		s = strings.TrimSpace(strings.TrimPrefix(s, "deny:"))
	default:
		return false, Entry{}, fmt.Errorf("invalid target rule %q: missing effect prefix (allow: / deny:)", raw)
	}
	e, err = ParseEntry(s)
	if err != nil {
		return false, Entry{}, err
	}
	return allow, e, nil
}

// ValidateTargetRules 批量校验 net/ssh 规则行（加载/入表即报错；首个非法条目即报错）。
func ValidateTargetRules(list []string) error {
	for _, raw := range list {
		if _, _, err := ParseTargetRule(raw); err != nil {
			return err
		}
	}
	return nil
}

// NetRule 网络规则行。HostPort 形如 "example.com:443"，端口可 *。
type NetRule struct {
	HostPort string
	Allow    bool
}

// NetRuleSet 网络规则集：有序表，从头扫、首命中生效；新规则插表头。
type NetRuleSet struct {
	Rules   []NetRule // 有序：从头扫、首命中生效；新规则插表头
	Default bool      // 未命中兜底 = net_policy open/deny
}

// Match 判定目标是否放行（first-wins）。目标非法（解析失败）→ false（fail-closed）；
// 规则行解析失败跳过（编译期/入表校验应已拦截，运行时宁缺毋滥）。
// 端口匹配取保守交集语义：规则为 * 或相等即命中；查询为 * 时重叠即命中。
func (s NetRuleSet) Match(hostport string) bool { allow, _ := s.Resolve(hostport); return allow }

// Resolve reports the first matching row, or -1 for the default/invalid target.
func (s NetRuleSet) Resolve(hostport string) (allow bool, matched int) {
	q, err := ParseEntry(hostport)
	if err != nil {
		return false, -1
	}
	for i, row := range s.Rules {
		target, err := ParseEntry(row.HostPort)
		if err != nil {
			return false, i
		}
		if EntryMatch(target, q) {
			return row.Allow, i
		}
	}
	return s.Default, -1
}

// EntryMatch 判定规则条目 r 是否覆盖查询条目 q：host 字符串相等（双方已归一）
// 且端口匹配（r 为 * 或相等；q 为 * 时取保守交集——重叠即命中）。
func EntryMatch(r, q Entry) bool {
	if r.Host != q.Host {
		return false
	}
	return r.Port == "*" || r.Port == q.Port || q.Port == "*"
}
