package vbox

import (
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
)

// 路径 canonical 化与双形态（自 fsauth 移植，语义不变）。规则匹配前查询路径
// 与规则模式都经 canonical——进程内门（FSRuleSet.Match）两侧同口径；
// dualForms 供 OS 沙箱名单派生用（seatbelt 按系统调用原始路径串匹配，
// 无 canonical 化，故名单须同时含字面形与解析形）。

// bareDriveRe 匹配裸盘符形态（"C:"）。
var bareDriveRe = regexp.MustCompile(`^[A-Za-z]:$`)

// isBareDrive 报告 p 是否为 windows 裸盘符（非 windows 恒 false——posix 上
// "C:" 是普通相对路径名，不做特殊处理）。
func isBareDrive(p string) bool {
	return runtime.GOOS == "windows" && bareDriveRe.MatchString(p)
}

// Canonical 展开符号链接到真实文件系统身份：EvalSymlinks 逐级向父目录回退
// （目标不存在时展开最近存在祖先，剩余路径原样拼接——写新文件场景）。
// 反斜杠归一为 /（匹配器统一斜杠语义）。
// 递归到文件系统根基（/ 或 C:\）时直接返回原路径：根基无可展开项，且
// TrimSuffix 根基分隔符得空串/盘符，继续递归会退化成相对路径。
// windows 裸盘符（"C:"）先补为盘根（"C:\"）再展开：EvalSymlinks 对裸盘符
// 是盘符当前目录语义，权限判定必须按盘根口径。
func Canonical(p string) string {
	if isBareDrive(p) {
		p += `\`
	}
	p = filepath.Clean(p)
	if r, err := filepath.EvalSymlinks(p); err == nil {
		return filepath.ToSlash(r)
	}
	dir, base := filepath.Split(p)
	if dir == "" {
		return filepath.ToSlash(p)
	}
	parent := strings.TrimSuffix(dir, string(filepath.Separator))
	if parent == filepath.VolumeName(dir) {
		return filepath.ToSlash(p)
	}
	return Canonical(parent) + "/" + base
}

// CanonicalNoFollow 展开父目录符号链接、保留末段字面形（unlink/rename 语义：
// 系统调用作用于链接本身，判定必须同口径）。父链复用 Canonical（含最近存在
// 祖先回退）；末段为根/退化形态时退回跟随版。
func CanonicalNoFollow(p string) string {
	if isBareDrive(p) {
		p += `\`
	}
	p = filepath.Clean(p)
	parent := filepath.Dir(p)
	base := filepath.Base(p)
	if base == "." || base == string(filepath.Separator) || parent == p {
		return Canonical(p)
	}
	return filepath.ToSlash(filepath.Join(Canonical(parent), base))
}

// DualForms 返回路径的 canonical 形与原始字面形（去尾斜杠；相同则只给一个）。
// 沙箱（seatbelt）按系统调用实际传入的路径串匹配规则：macOS 的 /tmp、/etc、
// $TMPDIR(/var/folders/…) 都是 symlink 前缀，只留 canonical 形会让字面拼写的
// 访问（含路径解析的 metadata 读）被拒（2026-09-22）。
func DualForms(p string) []string {
	p = strings.TrimSpace(p)
	if p == "" {
		return nil
	}
	for len(p) > 1 && strings.HasSuffix(p, "/") {
		p = strings.TrimSuffix(p, "/")
	}
	c := Canonical(p)
	if c == "" {
		c = filepath.Clean(p)
	}
	if c == p {
		return []string{c}
	}
	return []string{c, p}
}

// DualList 对一组路径逐个展开 DualForms（去重交给 DedupClean）。
func DualList(paths []string) []string {
	out := make([]string, 0, len(paths)*2)
	for _, p := range paths {
		out = append(out, DualForms(p)...)
	}
	return out
}

// CanonicalPattern 对 glob 模式的字面前缀段（首个含通配符段之前）做
// canonical 展开：/var/tmp/x/** → /private/var/tmp/x/**（macOS /var symlink）。
// 纯字面模式（无通配符）：整串展开；** 开头的模式无前缀可展开（原样返回）。
func CanonicalPattern(pat string) string {
	pat = filepath.ToSlash(pat)
	segs := strings.Split(pat, "/")
	lit := 0
	for _, s := range segs {
		// 与 matchOne 实现口径一致：只认 * ?（[ 按字面匹配，检测集不得超实现集，
		// 否则含 [ 的模式会在此误断字面前缀、预展开错位）
		if strings.ContainsAny(s, "*?") {
			break
		}
		lit++
	}
	if lit == 0 {
		return pat
	}
	prefix := Canonical(strings.Join(segs[:lit], "/"))
	if lit == len(segs) {
		return prefix
	}
	return prefix + "/" + strings.Join(segs[lit:], "/")
}

// ExpandVars 展开模式中的 ~（~ 与 ~/ 前缀）与环境变量：$VAR/${VAR}（unix）、
// %VAR%（windows 形态，跨平台都展开——用户 cfg 条目可能引用任一形态）、特殊记号
// $UserConfigDir（Go 的 os.UserConfigDir，无对应环境变量）。
// 任一变量的展开失败（未定义变量、无家目录）使整条模式失配（ok=false）——
// 初始名单已按平台分表，此规则只防御用户 cfg 条目（写了本平台不存在的变量时宁缺毋滥）。
func ExpandVars(s string) (string, bool) {
	home, herr := os.UserHomeDir()
	if s == "~" {
		if herr != nil {
			return "", false
		}
		s = home
	} else if strings.HasPrefix(s, "~/") {
		if herr != nil {
			return "", false
		}
		s = home + s[1:]
	}
	ok := true
	expand := func(name string) string {
		if name == "UserConfigDir" {
			d, err := os.UserConfigDir()
			if err != nil {
				ok = false
				return ""
			}
			return d
		}
		v, found := os.LookupEnv(name)
		if !found {
			ok = false
			return ""
		}
		return v
	}
	s = os.Expand(s, expand)
	for {
		i := strings.IndexByte(s, '%')
		if i < 0 {
			break
		}
		j := strings.IndexByte(s[i+1:], '%')
		if j < 0 {
			break
		}
		name := s[i+1 : i+1+j]
		s = s[:i] + expand(name) + s[i+j+2:]
	}
	return filepath.ToSlash(s), ok
}

// JoinPattern 拼接「根 + 子模式」（根为 "/" 时不产生 "//"——matchPattern 按 / 分段，
// 双斜杠会引入空段使模式整体失配）。空 root 返回空串（调用方丢弃）——
// 2026-09-22：GOCACHE/XDG_CACHE_HOME 未设置 → 空缓存根曾把名单退化成全匹配。
func JoinPattern(root, sub string) string {
	if root == "" {
		return ""
	}
	if root == "/" {
		return "/" + sub
	}
	return strings.TrimSuffix(root, "/") + "/" + sub
}

// DedupClean 去空去重，保序。
func DedupClean(roots []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(roots))
	for _, r := range roots {
		if r == "" || seen[r] {
			continue
		}
		seen[r] = true
		out = append(out, r)
	}
	return out
}
