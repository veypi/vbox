package vbox

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// fs 规则行解析与编译：
// 行首效果前缀 + 全域禁写护栏 + 变量展开 + canonical——产出可直接入表的 Rule。
//
// 注意：vbox 的 Rule 是纯数据；「裸路径覆盖子树」由 matcher 承担（不再需要
// /** 子树展开行）；字面前缀的 canonical 在编译期完成（macOS /var symlink 类）。

// fsEffectPrefixes 行首白名单前缀（保护盘符形——"C:" 不在白名单，
// 整行按缺前缀报错）。
var fsEffectPrefixes = []struct {
	prefix string
	eff    Effect
}{
	{"deny:", EffDeny}, {"ro:", EffRO}, {"rw:", EffRW},
}

// ParseFSRule 解析一条 fs 规则行：剥取行首效果前缀（deny:/ro:/rw:）+
// 全域模式禁写护栏（放行类禁字面全域、家目录根与整盘根；deny 禁字面全域——
// 全域姿态只用 fs_policy 表达）。
func ParseFSRule(raw string) (Effect, string, error) {
	s := strings.TrimSpace(raw)
	var eff Effect
	var pattern string
	found := false
	for _, p := range fsEffectPrefixes {
		if strings.HasPrefix(s, p.prefix) {
			eff, pattern = p.eff, strings.TrimSpace(strings.TrimPrefix(s, p.prefix))
			found = true
			break
		}
	}
	if !found {
		return EffDeny, "", fmt.Errorf("invalid fs rule %q: missing effect prefix (deny: / ro: / rw:)", raw)
	}
	if pattern == "" || strings.ContainsRune(pattern, 0) {
		return EffDeny, "", fmt.Errorf("invalid fs rule %q: empty or invalid pattern", raw)
	}
	if err := checkGlobalFS(eff, pattern); err != nil {
		return EffDeny, "", fmt.Errorf("invalid fs rule %q: %v", raw, err)
	}
	return eff, pattern, nil
}

// checkGlobalFS 全域模式禁写：字面全域三形态全效果禁写（一条放行全域拆光
// 整张表含 builtin 凭证 deny；deny 全域与 fs_policy 同义，保持单一表达）；
// 放行类另禁家目录根与整盘根。报错信息指向 fs_policy 或更细条目。
func checkGlobalFS(effect Effect, pattern string) error {
	p := strings.TrimSpace(pattern)
	if isLiteralGlobal(p) {
		return fmt.Errorf("global pattern is not expressible as a rule (use fs_policy for the whole-stance, or a narrower entry)")
	}
	if effect == EffDeny {
		return nil
	}
	if p == "~" || p == "~/" || p == "~/**" {
		return fmt.Errorf("home directory root is not expressible as an allow rule (use fs_policy: open or narrower entries)")
	}
	if home, err := os.UserHomeDir(); err == nil {
		if h, q := normalizeHostPath(filepath.ToSlash(home)), normalizeHostPath(p); q == h || q == h+"/" || q == h+"/**" {
			return fmt.Errorf("home directory root is not expressible as an allow rule (use fs_policy: open or narrower entries)")
		}
	}
	if driveRootRe.MatchString(strings.ReplaceAll(p, "\\", "/")) {
		return fmt.Errorf("drive root is not expressible as an allow rule (use narrower entries)")
	}
	return nil
}

func isLiteralGlobal(p string) bool {
	return p == "/" || p == "**" || p == "/**"
}

// driveRootRe 匹配整盘根：旧输入形 C: / C:/ / C:/** 与 /c/ 规范形
// /c / /c/ / /c/**（大小写不限；配置跨平台共享，统一禁写）。
var driveRootRe = regexp.MustCompile(`(?i)^([a-z]:|/[a-z])(/\*\*)?/?$`)

// ValidateFSGrantTarget 校验 grant fs 目标（具体绝对路径，非模式）——
// 与规则行同护栏：全域/家根/盘根不可授。
func ValidateFSGrantTarget(abs string) error {
	p := normalizeHostPath(filepath.ToSlash(strings.TrimSpace(abs)))
	if p == "" || strings.ContainsRune(p, 0) {
		return fmt.Errorf("invalid grant target %q", abs)
	}
	if p == "/" {
		return fmt.Errorf("filesystem root cannot be granted (use fs_policy: open or narrower paths)")
	}
	if home, err := os.UserHomeDir(); err == nil {
		if p == normalizeHostPath(filepath.ToSlash(home)) {
			return fmt.Errorf("home directory root cannot be granted (use fs_policy: open or narrower paths)")
		}
	}
	if driveRootRe.MatchString(strings.ReplaceAll(p, "\\", "/")) {
		return fmt.Errorf("drive root cannot be granted (use narrower paths)")
	}
	return nil
}

// ValidateFSRules validates the complete compilation, including variable expansion.
func ValidateFSRules(list []string) error {
	_, err := CompileFSRules(list, ClassCfg)
	return err
}

// CompileFSRules compiles an ordered table. Both resolved and literal path
// spellings belong to the same row and retain its priority. Invalid rows reject
// the entire table; dropping a deny row would widen permissions.
func CompileFSRules(raws []string, class Class) ([]Rule, error) {
	var out []Rule
	for i, raw := range raws {
		eff, pat, err := ParseFSRule(raw)
		if err != nil {
			return nil, fmt.Errorf("rule %d: %w", i+1, err)
		}
		expanded, ok := ExpandVars(pat)
		if !ok || expanded == "" {
			return nil, fmt.Errorf("rule %d: cannot expand %q", i+1, pat)
		}
		if err := checkGlobalFS(eff, expanded); err != nil {
			return nil, fmt.Errorf("rule %d: %w", i+1, err)
		}
		literal := hostPathFromOS(expanded)
		for _, pattern := range DedupClean([]string{CanonicalPattern(expanded), literal}) {
			out = append(out, Rule{Pattern: pattern, Effect: eff, Class: class})
		}
	}
	return out, nil
}

// IneffectiveRows 返回【永不生效】的行下标：first-wins 下，一旦某条更靠前的
// rw 行（外层）覆盖了后续 deny/ro 行（内层）的全部匹配路径，内层行永远轮不到
// 求值。最常见的踩法是把 deny 写在 rw 之后——执行端按 first-wins 放行（Windows
// 只留一句 "deny ACE skip rw-hole" 日志），使用者很难察觉自己的 deny 形同虚设。
//
// 判定保守（宁可漏报不误报），只在能静态确定包含关系时报告：
//   - 两行模式相同；
//   - 外层以 /** 结尾：内层等于其前缀或落在其下（** 含零段，故含根目录）；
//   - 外层无通配元字符 `* ?`（裸路径覆盖子树）：内层落在其子树下。
//
// 外层模式自身含通配元字符且非 /** 尾形态时不判定（包含关系不可静态确定）。
// 编译不因这些行失败——整表仍合法，只是内层永不命中；调用方可在装配配置时
// 用它提示或拒绝（见 README「规则表」）。
func IneffectiveRows(rules []Rule) []int {
	var out []int
	for i, r := range rules {
		if r.Effect == EffRW {
			continue
		}
		for j := 0; j < i; j++ {
			if rules[j].Effect != EffRW {
				continue
			}
			if patternCovers(rules[j].Pattern, r.Pattern) {
				out = append(out, i)
				break
			}
		}
	}
	return out
}

// patternCovers 报告 outer（rw 行模式）是否覆盖 inner（后续行模式）的全部匹配
// 路径。两侧先按 CanonicalPattern 归一（与 Match 入口的路径侧同口径），再按
// MatchPattern 的语义比对：裸路径覆盖子树、/** 含零段、/ 为段边界。
func patternCovers(outer, inner string) bool {
	outer = CanonicalPattern(strings.TrimSpace(outer))
	inner = CanonicalPattern(strings.TrimSpace(inner))
	if outer == "" || inner == "" {
		return false
	}
	if outer == inner {
		return true
	}
	if base := strings.TrimSuffix(outer, "/**"); base != outer {
		return inner == base || strings.HasPrefix(inner, base+"/")
	}
	if strings.ContainsAny(outer, "*?") {
		return false // 通配外层：包含关系不能静态断定
	}
	return strings.HasPrefix(inner, outer+"/")
}
