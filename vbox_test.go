package vbox

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ---- 动态行（Resolve：按路径现算） ----

// 动态行：行序照旧（前面行先命中），命中本行时由回调按「路径 + 操作」定效果；
// 回调不表态（ok=false）落回静态 Effect。
func TestFSRuleSetDynamicRowResolve(t *testing.T) {
	t.Parallel()
	var calls []string
	set := NewFSRuleSet([]Rule{
		{Pattern: "/granted", Effect: EffRW, Class: ClassTemp},
		{Pattern: "/skills", Effect: EffDeny, Class: ClassCfg, Resolve: func(path string, op FileOp) Resolution {
			calls = append(calls, path)
			if strings.HasPrefix(path, "/skills/mine") {
				if op == OpRead {
					return Resolution{Handled: true, Effect: EffRO}
				}
				return Resolution{Handled: true, Effect: EffDeny, Reason: "本人私有包：写需 grant"}
			}
			if strings.HasPrefix(path, "/skills/unsure") {
				return Resolution{}
			}
			return Resolution{Handled: true, Effect: EffDeny, Reason: "不可见"}
		}},
	}, EffDeny)

	// 前序行先命中：动态行的回调根本不被调用。
	if d := set.Match("/granted/sk/x", OpWrite); !d.Allow || d.Matched != 0 {
		t.Fatalf("prior row must win: %+v", d)
	}
	if len(calls) != 0 {
		t.Fatalf("resolver must not run when an earlier row matches: %v", calls)
	}
	// 命中动态行：回调定效果（读 ro 放行、写 deny）。
	if d := set.Match("/skills/mine/SKILL.md", OpRead); !d.Allow || d.Effect != EffRO || d.Matched != 1 {
		t.Fatalf("dynamic ro read = %+v", d)
	}
	// 回调的 Reason 随判定返回（调用方拿它做报错文案；静态行/兜底为空）。
	if d := set.Match("/skills/mine/SKILL.md", OpWrite); d.Allow || d.Reason != "本人私有包：写需 grant" {
		t.Fatalf("dynamic write must deny with reason: %+v", d)
	}
	if d := set.Match("/skills/other/x", OpRead); d.Allow || d.Reason != "不可见" {
		t.Fatalf("dynamic deny reason = %+v", d)
	}
	// 回调不表态（Handled=false）→ 落回静态 Effect（deny），Reason 为空。
	if d := set.Match("/skills/unsure/x", OpRead); d.Allow || d.Effect != EffDeny || d.Reason != "" {
		t.Fatalf("fallback to static effect = %+v", d)
	}
	// 静态行/兜底不产生 Reason。
	if d := set.Match("/granted/sk/x", OpRead); d.Reason != "" {
		t.Fatalf("static row must not carry reason: %+v", d)
	}
	// 子路径仍覆盖（裸路径覆盖子树），只查当前这一个路径。
	if len(calls) == 0 || calls[len(calls)-1] != "/skills/unsure/x" {
		t.Fatalf("resolver got %v, want last = /skills/unsure/x", calls)
	}
}

// 动态行只属进程内匹配：OS 级沙箱计划必须拒启（拿静态 Effect 当终局会
// 与真实判定不一致，可能更宽松）。
func TestValidateProcessPolicyRejectsDynamicRows(t *testing.T) {
	t.Parallel()
	spec := confineSpec{fsRules: NewFSRuleSet([]Rule{
		{Pattern: "/skills", Effect: EffDeny, Class: ClassCfg, Resolve: func(string, FileOp) Resolution {
			return Resolution{Handled: true, Effect: EffRO}
		}},
	}, EffDeny)}
	err := validateProcessPolicy(spec, "darwin")
	if err == nil {
		t.Fatal("dynamic row must be rejected by OS backends")
	}
	var denied *DeniedError
	if !errors.As(err, &denied) {
		t.Fatalf("err = %v, want DeniedError（fail-closed）", err)
	}
	// 同一张表去掉回调即合法。
	spec.fsRules = NewFSRuleSet([]Rule{{Pattern: "/skills", Effect: EffDeny, Class: ClassCfg}}, EffDeny)
	if err := validateProcessPolicy(spec, "darwin"); err != nil {
		t.Fatalf("static table must pass: %v", err)
	}
}

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
	requireSymlink(t, outside, link)

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
