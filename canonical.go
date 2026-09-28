package vbox

import (
	"os"
	"path"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
)

// 路径 canonical 化与双形态（自 fsauth 移植，语义不变）。规则匹配前查询路径
// 与规则模式都经 canonical——进程内门（FSRuleSet.Match）两侧同口径；
// dualForms 供 OS 沙箱名单派生用（seatbelt 按系统调用原始路径串匹配，
// 无 canonical 化，故名单须同时含字面形与解析形）。
//
// 2026-09-24：windows 规范形全局统一为 /c/ 类 Linux 形（废除 C:/ 盘符形）——
// canonical 出口一律 /c/…；入口接受任意盘符形态容错归一。以下三个helper
// 与 aic-pod/libs/proto 同源（vbox 自持不引 aic-pod，避免模块环）。

// normalizeHostPath 把 windows 盘符输入归一为 /c/… 规范形（纯语法、与 GOOS
// 无关——匹配层与执行层结果必须一致，归一不按 GOOS 分叉）；非盘符形态
// 原样返回。
func normalizeHostPath(p string) string {
	if driveInputRe.MatchString(p) {
		rest := strings.ReplaceAll(p[2:], `\`, "/")
		return path.Clean("/" + strings.ToLower(p[:1]) + "/" + rest)
	}
	if strings.HasPrefix(p, "/") {
		p = path.Clean(p)
		if len(p) > 1 && driveInputRe.MatchString(p[1:]) {
			rest := strings.ReplaceAll(p[3:], `\`, "/")
			return path.Clean("/" + strings.ToLower(p[1:2]) + "/" + rest)
		}
	}
	return p
}

// driveInputRe 匹配盘符输入形态：C:（裸盘符）、C:/…、C:\…（C:foo 不匹配）。
var driveInputRe = regexp.MustCompile(`^[A-Za-z]:([\\/]|$)`)

// splitDriveRoot 拆规范形首段盘符（/c → 'c'；/c/x → 'c',"x"）。
func splitDriveRoot(p string) (drive byte, rest string, ok bool) {
	if len(p) >= 2 && p[0] == '/' && isLetterByte(p[1]) {
		if len(p) == 2 {
			return p[1], "", true
		}
		if p[2] == '/' {
			return p[1], p[3:], true
		}
	}
	return 0, "", false
}

func isLetterByte(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z')
}

// hostPathToOS 把 /c/ 规范形（及旧输入形）转回 OS 原生路径（windows；posix
// 恒等——"C:" 是合法相对文件名，不做盘符归一）。windows 上 /tmp 是虚拟别名：
// cygwin 式映射 os.TempDir()（与 aic-pod/libs/proto.HostPathToOS 同口径——
// /tmp 查询 canonical 后落进临时目录便利根，无需字面 /tmp 规则行）。
func hostPathToOS(p string) string {
	if runtime.GOOS != "windows" {
		return p
	}
	p = normalizeHostPath(p)
	if q, ok := tmpToOS(p, os.TempDir()); ok {
		return q
	}
	if d, rest, ok := splitDriveRoot(p); ok {
		return strings.ToUpper(string(d)) + `:\` + strings.ReplaceAll(rest, "/", `\`)
	}
	return p
}

// tmpToOS 把 /tmp（及子路径）映射为 windows 临时目录原生路径（与
// aic-pod/libs/proto.WinTmpToOS 同源——vbox 自持不引 aic-pod，避免模块环）。
// 纯函数（tmpDir 注入，跨平台可测）。
func tmpToOS(p, tmpDir string) (string, bool) {
	if p != "/tmp" && !strings.HasPrefix(p, "/tmp/") {
		return "", false
	}
	rest := strings.TrimPrefix(p[len("/tmp"):], "/")
	tmpDir = strings.TrimSuffix(tmpDir, `\`)
	if rest == "" {
		return tmpDir, true
	}
	return tmpDir + `\` + strings.ReplaceAll(rest, "/", `\`), true
}

// hostPathFromOS canonical 系列出口归一：windows 原生态 → /c/ 规范形；
// posix 仅斜杠归一。
func hostPathFromOS(p string) string {
	if runtime.GOOS != "windows" {
		return filepath.ToSlash(p)
	}
	return normalizeHostPath(filepath.ToSlash(p))
}

// Canonical 展开符号链接到真实文件系统身份：EvalSymlinks 逐级向父目录回退
// （目标不存在时展开最近存在祖先，剩余路径原样拼接——写新文件场景）。
// 输出为 /c/ 规范形（posix 为 posix 形）。
// 递归到文件系统根基（/ 或 C:\）时直接返回原路径：根基无可展开项，且
// TrimSuffix 根基分隔符得空串/盘符，继续递归会退化成相对路径。
func Canonical(p string) string {
	p = hostPathToOS(p)
	p = filepath.Clean(p)
	if r, err := filepath.EvalSymlinks(p); err == nil {
		return hostPathFromOS(r)
	}
	dir, base := filepath.Split(p)
	if dir == "" {
		return hostPathFromOS(p)
	}
	parent := strings.TrimSuffix(dir, string(filepath.Separator))
	if parent == filepath.VolumeName(dir) {
		return hostPathFromOS(p)
	}
	return Canonical(parent) + "/" + base
}

// CanonicalNoFollow 展开父目录符号链接、保留末段字面形（unlink/rename 语义：
// 系统调用作用于链接本身，判定必须同口径）。父链复用 Canonical（含最近存在
// 祖先回退）；末段为根/退化形态时退回跟随版。输出同为 /c/ 规范形。
func CanonicalNoFollow(p string) string {
	p = hostPathToOS(p)
	p = filepath.Clean(p)
	parent := filepath.Dir(p)
	base := filepath.Base(p)
	if base == "." || base == string(filepath.Separator) || parent == p {
		return Canonical(p)
	}
	return hostPathFromOS(filepath.Join(Canonical(parent), base))
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
		c = hostPathFromOS(filepath.Clean(p))
	}
	lit := hostPathFromOS(p)
	if c == lit {
		return []string{c}
	}
	return []string{c, lit}
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
