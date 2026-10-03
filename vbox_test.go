package vbox

import (
	"os"
	"path/filepath"
	"testing"
)

// ---- first-wins 行序（语义反转的核心） ----

func TestFSRuleSetFirstMatchWins(t *testing.T) {
	t.Parallel()
	set := NewFSRuleSet(
		[]Rule{
			{Pattern: "/proj", Effect: EffRW, Class: ClassTemp},         // 表头
			{Pattern: "/proj/secret", Effect: EffDeny, Class: ClassCfg}, // 永远到不了
			{Pattern: "/proj", Effect: EffDeny, Class: ClassBuiltin},    // 永远到不了
		},
		EffDeny)
	// 首命中生效：temp rw 压住行序靠后的 cfg/builtin deny（"用户点就点了"）。
	if d := set.Match("/proj/secret/x.txt", OpWrite); !d.Allow || d.Matched != 0 {
		t.Fatalf("Match(/proj/secret/x.txt, write) = %+v, want allow matched=0", d)
	}
}

func TestFSRuleSetDenyRowBlocksBoth(t *testing.T) {
	t.Parallel()
	set := NewFSRuleSet(
		[]Rule{
			{Pattern: "/home/u/.ssh", Effect: EffDeny, Class: ClassBuiltin},
			{Pattern: "/home/u", Effect: EffRO, Class: ClassCfg},
		},
		EffDeny)
	if d := set.Match("/home/u/.ssh/id_rsa", OpRead); d.Allow {
		t.Fatalf("deny row read = %+v, want deny", d)
	}
	if d := set.Match("/home/u/.ssh/id_rsa", OpWrite); d.Allow {
		t.Fatalf("deny row write = %+v, want deny", d)
	}
	// ro 行：读放写拒；读默认开放但命中 ro 行后写仍拒。
	if d := set.Match("/home/u/notes.txt", OpRead); !d.Allow || d.Matched != 1 {
		t.Fatalf("ro row read = %+v, want allow matched=1", d)
	}
	if d := set.Match("/home/u/notes.txt", OpWrite); d.Allow {
		t.Fatalf("ro row write = %+v, want deny", d)
	}
}

// cloud 行序回归（design 验收 3）：ro 行存在时会话目录可写（首命中生效）。
func TestFSRuleSetCloudRowOrderSessionWritable(t *testing.T) {
	t.Parallel()
	set := NewFSRuleSet(
		[]Rule{
			// temp（grant 来，表头）——本用例为空
			{Pattern: "/u/u1/.sessions/s1", Effect: EffRW, Class: ClassConvenience}, // 便利根
			{Pattern: "/u/u1", Effect: EffRO, Class: ClassCfg},
			{Pattern: "/u/u1/skills", Effect: EffRO, Class: ClassCfg},
		},
		EffDeny)
	if d := set.Match("/u/u1/.sessions/s1/out.txt", OpWrite); !d.Allow {
		t.Fatalf("session dir write = %+v, want allow（ro 行存在时会话目录必须可写）", d)
	}
	if d := set.Match("/u/u1/docs/a.md", OpWrite); d.Allow {
		t.Fatalf("user root write = %+v, want deny（ro）", d)
	}
	if d := set.Match("/u/u1/docs/a.md", OpRead); !d.Allow {
		t.Fatalf("user root read = %+v, want allow（ro）", d)
	}
	// 未命中：读默认开放，写 DefaultWrite=deny。
	if d := set.Match("/etc/hosts", OpRead); !d.Allow || d.Matched != -1 {
		t.Fatalf("unmatched read = %+v, want allow unmatched", d)
	}
	if d := set.Match("/etc/hosts", OpWrite); d.Allow {
		t.Fatalf("unmatched write = %+v, want deny（DefaultWrite）", d)
	}
}

func TestFSRuleSetOpenStance(t *testing.T) {
	t.Parallel()
	set := NewFSRuleSet(
		[]Rule{{Pattern: "/home/u/.gnupg", Effect: EffDeny}},
		EffRW) // fs_policy: open
	if d := set.Match("/anywhere/file", OpWrite); !d.Allow || d.Matched != -1 {
		t.Fatalf("open stance write = %+v, want allow", d)
	}
	if d := set.Match("/home/u/.gnupg/key", OpWrite); d.Allow {
		t.Fatalf("deny row under open stance = %+v, want deny", d)
	}
}

// ---- 裸路径子树与 glob ----

func TestMatchPatternBareCoversSubtree(t *testing.T) {
	t.Parallel()
	cases := []struct {
		pat, path string
		want      bool
	}{
		{"/a", "/a", true},
		{"/a", "/a/b/c", true},
		{"/a", "/ab", false},
		{"/a/", "/a/b", true},
		{"/a/*", "/a/b", true},
		{"/a/*", "/a/b/c", false},
		{"/a/**", "/a/b/c/d", true},
		{"/a/**/x", "/a/b/c/x", true},
		{"/a/?", "/a/b", true},
		{"/a/?", "/a/bc", false},
		{"**/x", "/a/b/x", true},
		{"/a/[", "/a/[", true}, // [ 按字面
	}
	for _, c := range cases {
		if got := MatchPattern(c.pat, c.path); got != c.want {
			t.Fatalf("MatchPattern(%q, %q) = %v, want %v", c.pat, c.path, got, c.want)
		}
	}
}

// ---- MatchNoFollow（unlink/rename 语义） ----

func TestMatchNoFollowSymlink(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	writable := filepath.Join(root, "proj")
	outside := filepath.Join(root, "outside")
	if err := os.MkdirAll(writable, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(outside, 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(writable, "venv-python")
	if err := os.Symlink(outside, link); err != nil {
		t.Fatal(err)
	}

	set := NewFSRuleSet(
		[]Rule{
			{Pattern: writable, Effect: EffRW, Class: ClassConvenience},
			{Pattern: outside, Effect: EffDeny, Class: ClassBuiltin},
		},
		EffDeny)
	// unlink 语义：删的是链接本身（在写域内）→ 放行；若跟随末段链接会被 outside deny 误伤
	//（2026-09-22 .venv 删除被阻的修复）。
	if d := set.MatchNoFollow(link, OpWrite); !d.Allow {
		t.Fatalf("MatchNoFollow(%s, write) = %+v, want allow", link, d)
	}
	// 跟随版：同一路径按目标判定 → deny（open 语义仍保护目标）。
	if d := set.Match(link, OpWrite); d.Allow {
		t.Fatalf("Match(%s, write) = %+v, want deny（跟随到 outside）", link, d)
	}
	// 链接内下钻：NoFollow 只豁免末段——父链穿越照判。
	inner := filepath.Join(link, "bin", "x")
	if d := set.Match(inner, OpWrite); d.Allow {
		t.Fatalf("Match(%s, write) = %+v, want deny（父链穿越）", inner, d)
	}
}

// ---- 规则编译与护栏 ----

func TestParseFSRuleGuards(t *testing.T) {
	t.Parallel()
	bad := []string{
		"", "x", "/no/prefix",
		"rw:/", "ro:/", "deny:/", "rw:/**", "deny:**",
		"rw:~", "rw:~/", "rw:~/**",
		"rw:C:/", "rw:C:", "rw:c:/**",
	}
	for _, raw := range bad {
		if _, _, err := ParseFSRule(raw); err == nil {
			t.Fatalf("ParseFSRule(%q) 应报错", raw)
		}
	}
	good := []string{"deny:~/.ssh", "ro:/usr", "rw:/proj/x", "rw:~/work/**", "deny:C:/Windows/**"}
	for _, raw := range good {
		if _, _, err := ParseFSRule(raw); err != nil {
			t.Fatalf("ParseFSRule(%q) err = %v", raw, err)
		}
	}
}

func TestCompileFSRuleCanonical(t *testing.T) {
	t.Parallel()
	rows, err := CompileFSRules([]string{"rw:/var/tmp/x/**"}, ClassCfg)
	if err != nil {
		t.Fatalf("CompileFSRule 失败")
	}
	// macOS /var → /private/var 字面前缀展开（linux 上相同则相等，断言语义不限平台）。
	r := rows[0]
	want := CanonicalPattern("/var/tmp/x/**")
	if r.Pattern != want {
		t.Fatalf("Pattern = %q, want %q", r.Pattern, want)
	}
	if r.Effect != EffRW || r.Class != ClassCfg {
		t.Fatalf("Rule = %+v", r)
	}
}

// ---- 便捷构造函数的行序（调用方拼接约定） ----

func TestClassStringRoundTrip(t *testing.T) {
	t.Parallel()
	for c, want := range map[Class]string{
		ClassTemp: "temp", ClassCfg: "cfg", ClassBuiltin: "builtin", ClassConvenience: "convenience",
	} {
		if c.String() != want {
			t.Fatalf("Class(%d).String() = %q, want %q", c, c.String(), want)
		}
	}
}

// tmpToOS 固定向量（纯函数，跨平台可测）：/tmp 虚拟别名 → windows 临时目录
// 原生路径；非 /tmp 前缀一律 ok=false（与 proto.WinTmpToOS 同源同向量）。
func TestTmpToOS(t *testing.T) {
	t.Parallel()
	tmp := `C:\Users\x\AppData\Local\Temp`
	cases := []struct {
		in, want string
		ok       bool
	}{
		{"/tmp", tmp, true},
		{"/tmp/", tmp, true},
		{"/tmp/a", tmp + `\a`, true},
		{"/tmp/a b/c.txt", tmp + `\a b\c.txt`, true},
		{"/tmpfoo", "", false},
		{"/c/tmp", "", false},
		{"/", "", false},
	}
	for _, c := range cases {
		got, ok := tmpToOS(c.in, tmp)
		if ok != c.ok || (ok && got != c.want) {
			t.Errorf("tmpToOS(%q) = %q, %v; want %q, %v", c.in, got, ok, c.want, c.ok)
		}
	}
}
