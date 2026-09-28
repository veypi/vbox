package vbox

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// fs 规则行解析与编译（自 aic-pod libs/policy + fsauth compileFSRule 合并移植）：
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
		if h := filepath.ToSlash(home); p == h || p == h+"/" || p == h+"/**" {
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
	p := filepath.ToSlash(strings.TrimSpace(abs))
	if p == "" || strings.ContainsRune(p, 0) {
		return fmt.Errorf("invalid grant target %q", abs)
	}
	if p == "/" {
		return fmt.Errorf("filesystem root cannot be granted (use fs_policy: open or narrower paths)")
	}
	if home, err := os.UserHomeDir(); err == nil {
		if p == filepath.ToSlash(home) {
			return fmt.Errorf("home directory root cannot be granted (use fs_policy: open or narrower paths)")
		}
	}
	if driveRootRe.MatchString(strings.ReplaceAll(p, "\\", "/")) {
		return fmt.Errorf("drive root cannot be granted (use narrower paths)")
	}
	return nil
}

// ValidateFSRules 批量校验 fs 规则行（加载/入表即报错；首个非法行即返回）。
func ValidateFSRules(list []string) error {
	for _, raw := range list {
		if _, _, err := ParseFSRule(raw); err != nil {
			return err
		}
	}
	return nil
}

// CompileFSRule 编译一条规则行：ParseFSRule + ExpandVars + CanonicalPattern。
// 展开失败（未定义变量/无家目录）或非法行返回 ok=false（宁缺毋滥——cfg 校验
// 已在加载/保存路径点名报错）。
func CompileFSRule(raw string, class Class) (Rule, bool) {
	eff, pat, err := ParseFSRule(raw)
	if err != nil {
		return Rule{}, false
	}
	e, ok := ExpandVars(pat)
	if !ok || e == "" {
		return Rule{}, false
	}
	return Rule{Pattern: CanonicalPattern(e), Effect: eff, Class: class}, true
}

// CompileFSRules 批量编译（坏行跳过，保序）。
func CompileFSRules(raws []string, class Class) []Rule {
	out := make([]Rule, 0, len(raws))
	for _, raw := range raws {
		if r, ok := CompileFSRule(raw, class); ok {
			out = append(out, r)
		}
	}
	return out
}
