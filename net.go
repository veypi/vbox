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

// ParseNetRule 解析 net/ssh 规则行：可选 tool: 前缀 + allow:/deny: + 目标。
// tool: 声明该行仅工具层生效（见 NetRule.ToolOnly）。
func ParseNetRule(raw string) (NetRule, error) {
	s := strings.TrimSpace(raw)
	toolOnly := false
	if strings.HasPrefix(s, "tool:") {
		toolOnly = true
		s = strings.TrimSpace(strings.TrimPrefix(s, "tool:"))
	}
	allow, e, err := ParseTargetRule(s)
	if err != nil {
		return NetRule{}, err
	}
	return NetRule{HostPort: e.String(), Allow: allow, ToolOnly: toolOnly}, nil
}

// ParseTargetRule 解析 net/ssh 规则行：剥 allow:/deny: 前缀后按 Entry 归一。
// Entry 解析本身拒绝通配 host，allow:* / deny:* 等全域行在此自然报错（指向 *_policy）。
// tool: 前缀请用 ParseNetRule。
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
// 接受 tool: 前缀（ParseNetRule 口径）。
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
	// ToolOnly 声明本行仅由调用方的工具层执行（进程内 HTTP/MCP 客户端等）：
	// 内核沙箱落地（CheckNetPolicy / validateProcessPolicy / Seatbelt 输出）
	// 一律跳过，不参与「能否落实」的判定。用于本平台无法内核落实、但工具层
	// 可执行的规则（典型：linux/windows 上的选择性 deny）。判定入口
	//（Match/Resolve）不看 ToolOnly——工具层照常命中。
	ToolOnly bool
}

// String 返回规范形态（含 tool: 前缀），供日志/回执展示。
func (r NetRule) String() string {
	effect := "deny:"
	if r.Allow {
		effect = "allow:"
	}
	if r.ToolOnly {
		return "tool:" + effect + r.HostPort
	}
	return effect + r.HostPort
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

// NetRowLanding 单条 net 规则在指定平台上的内核落地分类（CheckNetPolicy 的输出）。
type NetRowLanding struct {
	Rule NetRule
	// Landed true = 由内核沙箱落实（姿态或逐条）。
	Landed bool
	// Noop true = 本行被落地姿态吸收且语义不变（open 姿态下的 allow、deny 姿态
	// 下的 deny、与可落地 deny 行不相交的 allow）——既未放宽也未收紧。
	// Landed=false 且 Noop=false 时本行语义被收窄（目标在沙箱内本不可达），
	// Reason 必读。
	Noop   bool
	Reason string
}

// CheckNetPolicy 按平台能力对整表 net 规则做启动前分类：逐条给出 landed /
// absorbed 结论；遇到第一条「落实不了、跳过又会比策略更宽」的规则即整体失败
// （error 与 validateProcessPolicy 同口径）。ToolOnly 行不参与内核落地，直接
// 跳过（不出现在返回值里，也不触发失败）。
//
// 落地能力矩阵（逐条规则）：darwin 落实 loopback 逐条（Seatbelt remote tcp）；
// linux 只落实姿态（deny = --unshare-net 全断，沙箱 netns 的 loopback 未配置，
// 回环亦不可达）；windows 无网络能力（deny 姿态整体报错）。未被姿态覆盖又不
// 可逐条落实的行：deny 行一律报错（跳过即变宽）；allow 行在 deny 姿态下被吸收
// （目标本不可达，收窄方向与 fail-closed 同向），在 open 姿态下报错（有 deny 行
// 时它承担成洞语义）。
//
// darwin 的 loopback 逐条落地不是真正的「逐行」：Seatbelt 输出把所有 loopback
// 拼写（localhost/127.0.0.1/::1…）统一坍缩为 localhost:port，按端口首行生效，
// 且首个端口 * 行之后整表截断（seatbeltNetForms 同口径）。本函数按该内核表
// 模拟分类：同端口后续行效果相同为 no-op 重复；效果相反时 deny 行报错（内核
// 落不下 = 比策略更宽），allow 行被吸收（收窄）。已知残余：跨拼写的
// 「allow 具体端口 + deny 通配端口」组合（逐行口径覆盖不到），配置请统一用
// localhost 拼写。
//
// platform 取 runtime.GOOS 风格值（darwin/linux/windows/…）；未列名平台按
// 「无逐条能力」处理，后端可用性由 planConfined 兜底。
func CheckNetPolicy(platform string, s NetRuleSet) ([]NetRowLanding, error) {
	if platform == "windows" && !s.Default {
		return nil, fmt.Errorf("this Windows backend does not implement network rules")
	}
	// 内核视角的 deny 行存在性：tool-only 行不参与内核落地，不影响 allow 行
	// 是否承担成洞语义。
	hasDeny := false
	for _, r := range s.Rules {
		if !r.Allow && !r.ToolOnly {
			hasDeny = true
			break
		}
	}
	// darwin loopback 内核表模拟状态（见函数注释）：端口 → 首行效果；
	// loClosed = 已见 loopback 端口 * 行（内核表在此截断）。
	loPortEffect := map[string]bool{}
	loClosed := false
	var out []NetRowLanding
	for _, r := range s.Rules {
		if r.ToolOnly {
			continue
		}
		e, err := ParseEntry(r.HostPort)
		if err != nil {
			return out, err
		}
		l := NetRowLanding{Rule: r}
		if platform == "darwin" && isLoopbackHost(e.Host) {
			eff, seen := loPortEffect[e.Port]
			switch {
			case loClosed:
				if !r.Allow {
					return out, fmt.Errorf("loopback deny rule %s cannot land: the kernel loopback table is closed by an earlier wildcard-port row (seatbelt collapses every loopback spelling into one per-port entry); unify the loopback spelling or use the tool: prefix", r.HostPort)
				}
				l.Reason = "内核 loopback 表在首个端口 * 行处截断，本行被吸收（收窄）"
			case seen && eff == r.Allow:
				l.Noop = true
				l.Reason = "与同端口 loopback 前行重复（内核按端口落地、不区分拼写）"
			case seen:
				if !r.Allow {
					return out, fmt.Errorf("loopback rules on port %s conflict: the kernel collapses every loopback spelling into one per-port entry and cannot land this deny row without widening the sandbox; unify the loopback spelling or use the tool: prefix", e.Port)
				}
				l.Reason = "同端口 loopback 前行已按 deny 落地（内核不区分拼写），本行被吸收（收窄）"
			default:
				loPortEffect[e.Port] = r.Allow
				if e.Port == "*" {
					loClosed = true
				}
				switch {
				case !s.Default: // deny 姿态：内核全断，loopback 洞逐条
					if !r.Allow {
						l.Noop = true
						l.Reason = "deny 姿态已覆盖本行"
					} else {
						l.Landed = true // Seatbelt loopback 洞
						l.Reason = "kernel-enforced (seatbelt loopback rule)"
					}
				default: // open 姿态
					if r.Allow && !hasDeny {
						l.Noop = true
						l.Reason = "open 姿态下 allow 行不收紧"
					} else {
						l.Landed = true // deny 行本体，或对 loopback deny 行的成洞
						l.Reason = "kernel-enforced (seatbelt loopback rule)"
					}
				}
			}
			out = append(out, l)
			continue
		}
		switch {
		case !s.Default: // deny 姿态：内核全断
			if !r.Allow {
				l.Noop = true
				l.Reason = "deny 姿态已覆盖本行"
			} else {
				l.Reason = "deny 姿态下目标在本平台沙箱内本不可达"
			}
		default: // open 姿态
			if r.Allow {
				switch {
				case !hasDeny:
					l.Noop = true
					l.Reason = "open 姿态下 allow 行不收紧"
				case platform == "darwin":
					// darwin 可落实的 deny 只有 loopback，与非 loopback allow 恒不相交
					l.Noop = true
					l.Reason = "与可落实的 loopback deny 行不相交"
				default:
					return out, fmt.Errorf("selective network rule is unsupported by this backend")
				}
			} else {
				return out, fmt.Errorf("selective network rule is unsupported by this backend")
			}
		}
		out = append(out, l)
	}
	return out, nil
}
