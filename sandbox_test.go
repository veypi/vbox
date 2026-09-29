package vbox

import (
	"bytes"
	"context"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// Confine 无豁免分支：沙箱 profile 由 rules 派生（数字等级已删除），
// 免沙箱不经 Confine 表达（StartOptions.NoSandbox 才是唯一通道）。
func TestConfineApprovedStillConfined(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("windows uses token injection, covered by TestWindowsSandbox*")
	}
	argv := []string{"bash", "-c", "echo hi"}
	got, err := Confine("/ws", argv)
	if err != nil {
		t.Logf("Confine unavailable on this host (fail-closed): %v", err)
		return
	}
	if len(got) == 0 || got[0] == argv[0] {
		t.Fatalf("Confine = %v, want wrapped argv", got)
	}
}

func TestUnsupportedProcessPolicyRejected(t *testing.T) {
	for _, tc := range []struct {
		platform string
		spec     confineSpec
	}{
		{"linux", confineSpec{netOpen: true, writeAllow: []string{"/work/*/public/**"}}},
		{"windows", confineSpec{netOpen: false}},
		{"windows", confineSpec{netOpen: true, fsOpen: true}},
		{"windows", confineSpec{netOpen: true, netDeny: []Entry{{Host: "example.com"}}}},
		{"darwin", confineSpec{fsOpen: true, netOpen: true, netDeny: []Entry{{Host: "example.com"}}}},
	} {
		if err := validateProcessPolicy(tc.spec, tc.platform); err == nil {
			t.Fatalf("%s accepted unenforceable policy after approval: %+v", tc.platform, tc.spec)
		}
	}
}

// Confine 的 confined 分支：本机有后端（darwin=seatbelt / linux=bwrap）时
// 返回包装 argv 而非原样；无后端平台（windows/其他）返回 fail-closed 错误。
// windows 是 argv 原样 + token 注入语义，由 sandbox_windows_test.go 覆盖。
func TestConfineConfined(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("windows uses token injection, covered by TestWindowsSandbox*")
	}
	argv := []string{"bash", "-c", "echo hi"}
	got, err := Confine("/ws", argv)
	if err != nil {
		t.Logf("Confine unavailable on this host (fail-closed): %v", err)
		return
	}
	if len(got) == 0 || got[0] == argv[0] {
		t.Fatalf("Confine = %v, want wrapped argv", got)
	}
}

// Manager.NoSandbox 全局免沙箱：置 true 后 RunProcess 跳过沙箱包装（与
// StartOptions.NoSandbox 同效）——无沙箱后端的环境亦正常执行。
func TestManagerNoSandboxGlobal(t *testing.T) {
	m := NewManager(time.Minute)
	m.SetNoSandbox(true)
	var out bytes.Buffer
	code, err := m.RunProcess(context.Background(), StartOptions{
		Exec: []string{"sh", "-c", "echo hi"},
	}, nil, &out, &out)
	if err != nil {
		t.Fatalf("run with global NoSandbox: %v", err)
	}
	if code != 0 || !strings.Contains(out.String(), "hi") {
		t.Fatalf("code = %d, out = %q, want exit 0 with hi", code, out.String())
	}
}

// 免沙箱不叠加 fs/net 策略校验：受限策略（fs 非 open + deny 非空 + net 非
// open）下，NoSandbox 仍直接执行。
func TestUnconfinedIgnoresPolicy(t *testing.T) {
	m := NewManager(time.Minute)
	var out bytes.Buffer
	code, err := m.RunProcess(context.Background(), StartOptions{
		FsOpen:    false,
		NetOpen:   false,
		DenyPaths: []string{"/private/**"},
		NoSandbox: true,
		Exec:      []string{"sh", "-c", "echo hi"},
	}, nil, &out, &out)
	if err != nil {
		t.Fatalf("run with nosandbox under restricted policy: %v", err)
	}
	if code != 0 || !strings.Contains(out.String(), "hi") {
		t.Fatalf("code = %d, out = %q, want exit 0 with hi", code, out.String())
	}
}

// bwrap 包装：读视图为整机 ro-bind（读默认开放）；fsOpen 改 rw bind；
// 临时区 tmpfs + 缓存目录 bind 恒定携带（profile 由 rules 派生）；命令在
// -- 之后原样。资源限制段（rlimitArgs，与文件隔离正交）恒定携带。
func TestBwrapArgs(t *testing.T) {
	argv := []string{"bash", "-c", "echo hi"}
	spec := confineSpec{workdir: "/ungranted", argv: argv, netOpen: true}
	got := bwrapArgs(spec, []string{"/workspace"}, nil, nil)
	if !contains(got, "--ro-bind", "/", "/") || contains(got, "--tmpfs", "/") {
		t.Fatalf("read-open root required (ro-bind /): %v", got)
	}
	if contains(got, "--bind", "/ungranted", "/ungranted") {
		t.Fatal("cwd granted access")
	}
	if !contains(got, "--bind", "/workspace", "/workspace") {
		t.Fatalf("cache dir must be writable-bound: %v", got)
	}
}

// seatbelt 包装：工作区 + 平台临时区 + 缓存目录（全部 canonicalize）+
// .git deny 覆盖；git 自身豁免 .git 覆盖。
func TestSeatbeltArgs(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix path semantics")
	}
	argv := []string{"bash", "-c", "echo hi"}

	ww := seatbeltArgs(confineSpec{workdir: "/ws", argv: argv, netOpen: true, extra: []string{"/ws", "/private/tmp"}})
	if ww[0] != macosSeatbeltExecutable || ww[1] != "-p" || ww[3] != "--" {
		t.Fatalf("unexpected seatbelt argv head: %v", ww[:4])
	}
	profile := ww[2]
	for _, want := range []string{"/private/tmp", "/ws"} {
		if !strings.Contains(profile, `(subpath "`+want+`")`) {
			t.Fatalf("workspace-write profile missing %q: %s", want, profile)
		}
	}
	// .git 敏感子路径 deny 覆盖（SBPL deny 优先于 allow）
	if !strings.Contains(profile, `(deny file-write* (subpath "`+canonicalRoot("/ws/.git")+`"))`) {
		t.Fatalf("workspace-write profile missing .git deny: %s", profile)
	}
	// git 自身豁免 .git 覆盖（保护对象是 bash/rm 等通用命令）
	gw := seatbeltArgs(confineSpec{workdir: "/ws", argv: []string{"git", "commit", "-m", "x"}, netOpen: true})
	if strings.Contains(gw[2], "deny file-write* (subpath") {
		t.Fatalf("git invocation should be exempt from .git deny: %s", gw[2])
	}
}

// seatbelt deny 三拒：每条模式转 file-read*、file-write* 与 network-outbound
// (remote unix) 三条 (regex ...) 规则（SBPL 无 glob filter；读写对称双拒——
// 修复前仅拒读，纯写打开仍可改写可写根内 deny 文件，实测 2026-09-05；
// AF_UNIX connect 不走 file-* 判定，docker.sock 文件操作全拒而 curl --unix-socket
// 直通，须 network-outbound 补拒，实测 2026-09-05）。字面/glob 混合形态；
// SBPL 后规则胜（last-match-wins；2026-09-23 探针复核），此处仅断言 deny 行产物形态。
func TestSeatbeltDenyReads(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix path semantics")
	}
	argv := []string{"bash", "-c", "echo hi"}
	dn := seatbeltArgs(confineSpec{workdir: "/ws", argv: argv, netOpen: true, deny: []string{
		"/Users/veypi/.ssh/**", "**/id_ed25519*", "/etc/master.passwd",
	}})
	profile := dn[2]
	for _, want := range []string{
		`(deny file-read* (regex "^/Users/veypi/\\.ssh(/.*)?$"))`,
		`(deny file-write* (regex "^/Users/veypi/\\.ssh(/.*)?$"))`,
		`(deny network-outbound (remote unix (regex "^/Users/veypi/\\.ssh(/.*)?$")))`,
		`(deny file-read* (regex "^(.*)?/id_ed25519[^/]*$"))`,
		`(deny file-write* (regex "^(.*)?/id_ed25519[^/]*$"))`,
		`(deny network-outbound (remote unix (regex "^(.*)?/id_ed25519[^/]*$")))`,
		`(deny file-read* (regex "^/etc/master\\.passwd$"))`,
		`(deny file-write* (regex "^/etc/master\\.passwd$"))`,
		`(deny network-outbound (remote unix (regex "^/etc/master\\.passwd$")))`,
	} {
		if !strings.Contains(profile, want) {
			t.Fatalf("profile missing deny rule %s: %s", want, profile)
		}
	}
	// 拒绝规则恒定携带（只随规则表，不再有等级维度）
	ww := seatbeltArgs(confineSpec{workdir: "/ws", argv: argv, netOpen: true, deny: []string{"/etc/shadow"}})
	if !strings.Contains(ww[2], `(deny file-read* (regex "^/etc/shadow$"))`) ||
		!strings.Contains(ww[2], `(deny file-write* (regex "^/etc/shadow$"))`) ||
		!strings.Contains(ww[2], `(deny network-outbound (remote unix (regex "^/etc/shadow$")))`) {
		t.Fatalf("workspace-write profile missing deny rules: %s", ww[2])
	}
}

// TestSeatbeltDenyAfterWriteAllow：SBPL 后匹配覆盖先匹配——deny 表必须在写白名单
// 之后输出，否则可写根内 deny 条目（工作区的 **/.env / *.key 等）写保护被
// allow subpath 覆盖（.git 覆盖幸存仅因其在白名单后输出；实测修复 2026-09-05）。
func TestSeatbeltDenyAfterWriteAllow(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix path semantics")
	}
	argv := []string{"bash", "-c", "echo hi"}
	ww := seatbeltArgs(confineSpec{workdir: "/ws", argv: argv, netOpen: true, extra: []string{"/ws"}, deny: []string{"**/.env"}})
	profile := ww[2]
	allowIdx := strings.LastIndex(profile, `(allow file-write* (subpath "/ws"))`)
	denyIdx := strings.Index(profile, `(deny file-write* (regex "^(.*)?/\\.env$"))`)
	if allowIdx < 0 || denyIdx < 0 || denyIdx < allowIdx {
		t.Fatalf("deny rules must come after write allow (SBPL last-match-wins): %s", profile)
	}
}

// 旧 deny 全量路径（rules 空）保持零 file-read* allow；rules 行序模式下
// ro/rw 行的读放行是显式语义（读洞，见 TestSeatbeltRuleOrderEmission）。
func TestSeatbeltReadAllowRemoved(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("seatbelt only")
	}
	argv := []string{"curl", "https://example.com"}
	ww := seatbeltArgs(confineSpec{workdir: "/ws", argv: argv, netOpen: true,
		deny: []string{"**/*.pem"}, writeAllow: []string{"/ws/**/*.pem"}})
	if strings.Contains(ww[2], "(allow file-read*") {
		t.Fatalf("profile must not emit file-read* allow rules: %s", ww[2])
	}
}

func TestSeatbeltDenyWinsOverWriteAllow(t *testing.T) {
	pat := "/ws/**/.env"
	spec := confineSpec{workdir: "/outside", argv: []string{"true"}, netOpen: true, deny: []string{"**/.env"}, writeAllow: []string{pat}}
	p := seatbeltArgs(spec)[2]
	denyRead := strings.Index(p, "(deny file-read* (regex "+sbplString(globToSBPLRegex("**/.env"))+")")
	denyWrite := strings.Index(p, "(deny file-write* (regex "+sbplString(globToSBPLRegex("**/.env"))+")")
	if denyRead < 0 || denyWrite < 0 {
		t.Fatalf("read/write deny rules missing: %s", p)
	}
	// 读方向不再有白名单 allow（读默认开放）
	if strings.Contains(p, "(allow file-read* (regex "+sbplString(globToSBPLRegex(pat))+")") {
		t.Fatalf("read allow must not be emitted: %s", p)
	}
	allowIdx := strings.Index(p, "(allow file-write* (regex "+sbplString(globToSBPLRegex(pat))+")")
	if allowIdx < 0 {
		t.Fatalf("write glob must be emitted: %s", p)
	}
	// SBPL 后匹配覆盖先匹配：deny 必须在写 allow 之后输出
	if denyWrite < allowIdx {
		t.Fatalf("deny must come after write allow: %s", p)
	}
	if strings.Contains(p, `(allow file-write* (subpath "/outside"))`) {
		t.Fatal("cwd granted access")
	}
}

// TestSeatbeltRuleOrderEmission：fsRules（vbox first-wins 快照）非空 = 逆序
// 输出映射 SBPL 后规则胜（2026-09-29 W2b）：首命中行最后输出——deny 三形态
// 照旧；ro/rw 洞（表中在 deny 前）输出在其后，内核可读/可写真实生效。
// 裸模式输出 subpath 形态，glob 输出 regex。
func TestSeatbeltRuleOrderEmission(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("seatbelt only")
	}
	argv := []string{"bash", "-c", "echo hi"}
	snap := FSRuleSet{Rules: []Rule{
		{Pattern: "/probe/hole", Effect: EffRW},
		{Pattern: "/probe/readonly", Effect: EffRO},
		{Pattern: "/probe/**", Effect: EffDeny},
	}}
	ww := seatbeltArgs(confineSpec{workdir: "/ws", argv: argv, netOpen: true, fsRules: &snap})
	profile := ww[2]
	denyIdx := strings.Index(profile, `(deny file-write* (regex "^/probe(/.*)?$"))`)
	roIdx := strings.Index(profile, `(allow file-read* (subpath "/probe/readonly"))`)
	rwIdx := strings.Index(profile, `(allow file-write* (subpath "/probe/hole"))`)
	if denyIdx < 0 || roIdx < 0 || rwIdx < 0 {
		t.Fatalf("missing rule forms: %s", profile)
	}
	if !(denyIdx < roIdx && roIdx < rwIdx) {
		t.Fatalf("rules must be emitted reversed (first-wins → SBPL last-wins): %s", profile)
	}
	for _, want := range []string{
		`(allow network-outbound (remote unix (subpath "/probe/readonly")))`,
		`(allow network-outbound (remote unix (subpath "/probe/hole")))`,
	} {
		if !strings.Contains(profile, want) {
			t.Fatalf("rule allow forms must carry unix socket coverage (%s): %s", want, profile)
		}
	}
	if strings.Contains(profile, `(allow file-write* (subpath "/probe/readonly"))`) {
		t.Fatalf("ro row must not allow write: %s", profile)
	}
}

// globToSBPLRegex 段语义转换（fsauth matchPattern 对齐）：** 跨段（(.*)?）、
// * 段内（[^/]*）、? 单字符（[^/]）、字面转义；整串锚定 ^...$。
func TestGlobToSBPLRegex(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"**/.ssh/**", "^(.*)?/\\.ssh(/.*)?$"},
		{"**/id_ed25519*", "^(.*)?/id_ed25519[^/]*$"},
		{"/etc/master.passwd", "^/etc/master\\.passwd$"},
		{"**/*.key", "^(.*)?/[^/]*\\.key$"},
		{"/Users/veypi/.aws/**", "^/Users/veypi/\\.aws(/.*)?$"},
		{"**", "^(.*)?$"},
		{"/a/**/b", "^/a/(.*/)?b$"},
	}
	for _, c := range cases {
		if got := globToSBPLRegex(c.in); got != c.want {
			t.Fatalf("globToSBPLRegex(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// bwrap deny 隔离实例化（真实文件系统判定，t.TempDir 场景）：
// 字面文件 → /dev/null 覆盖；字面目录 / 尾 /** → tmpfs；** 开头 →
// $HOME 起步递归（t.Setenv 指向临时目录）；不存在 → 跳过。
// 注意：fixture 命名必须避开宿主默认 deny 表形态（*.pem/.ssh/id_ed25519* 等）——
// 本测试跑在平台自身沙箱内（exec 通道）时，对命中默认表名的路径 os.Stat
// 得 EPERM，覆盖项丢失造成假失败（实测 2026-09-05）。
// 每个形态单独实例化：父目录目标会剪掉子孙（覆盖等价），混在一组会互相吞并。
func TestBwrapDenyArgs(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "secret.dat")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	sub := filepath.Join(dir, "sub")
	if err := os.MkdirAll(sub, 0o700); err != nil {
		t.Fatal(err)
	}
	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, ".testdeny"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, "testkey_x"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)

	// unix socket → /dev/null 覆盖（connect 隔离，对齐 seatbelt network-outbound）
	var sockPath string
	if runtime.GOOS != "windows" {
		sockPath = filepath.Join(dir, "denyprobe.sock")
		ln, err := net.Listen("unix", sockPath)
		if err != nil {
			t.Fatalf("listen unix: %v", err)
		}
		t.Cleanup(func() { ln.Close() })
	}

	overlayFor := func(pat string) []string {
		t.Helper()
		return bwrapDenyArgs(mustDenyTargets(t, []string{pat}))
	}
	if got := overlayFor(file); !contains(got, "--ro-bind", "/dev/null", file) {
		t.Fatalf("literal file cover missing: %v", got)
	}
	if got := overlayFor(sub + "/**"); !contains(got, "--tmpfs", sub) {
		t.Fatalf("subtree dir cover missing: %v", got)
	}
	if got := overlayFor("**/.testdeny/**"); !contains(got, "--tmpfs", filepath.Join(home, ".testdeny")) {
		t.Fatalf("home-anchored dir cover missing: %v", got)
	}
	if got := overlayFor("**/testkey_*"); !contains(got, "--ro-bind", "/dev/null", filepath.Join(home, "testkey_x")) {
		t.Fatalf("home-anchored glob cover missing: %v", got)
	}
	if sockPath != "" {
		if got := overlayFor(sockPath); !contains(got, "--ro-bind", "/dev/null", sockPath) {
			t.Fatalf("socket cover missing: %v", got)
		}
	}
	// 不存在的路径不产出覆盖（不可读无害）
	if got := overlayFor("/nonexistent-zzz"); len(got) != 0 {
		t.Fatalf("nonexistent deny target should be skipped: %v", got)
	}
	// 父目录剪枝：字面目录目标覆盖其子孙，子目标不再单独覆盖。
	targets := mustDenyTargets(t, []string{dir, file, sub + "/**"})
	if len(targets) != 1 || targets[0] != dir {
		t.Fatalf("nested targets must collapse to parent dir: %v", targets)
	}
}

// validateProcessPolicy（windows）：写白名单 + deny（per-call ACE）可落地；
// 写全放（fs_policy=open）与网络管控仍拒绝（fsOpen 恒为写全放语义——等级
// 维度已删除）。
func TestWindowsPolicyValidation(t *testing.T) {
	for _, ok := range []confineSpec{
		{netOpen: true, deny: []string{"C:/Users/x/.ssh/**"}},
		{netOpen: true, writeAllow: []string{"C:/work/**"}},
	} {
		if err := validateProcessPolicy(ok, "windows"); err != nil {
			t.Fatalf("windows policy must be accepted (%+v): %v", ok, err)
		}
	}
	for _, bad := range []confineSpec{
		{netOpen: true, fsOpen: true},
		{fsOpen: true},
		{},
	} {
		if err := validateProcessPolicy(bad, "windows"); err == nil {
			t.Fatalf("windows unenforceable policy accepted: %+v", bad)
		}
	}
}

// denyCoverAll 形态判定：支持形态（字面、尾 /**、单 glob、** 递归）；
// 不可实例化形态（无字面前缀的全 glob）返回错误；子孙目标被父目录剪枝。
func TestDenyCoverAll(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "secret.dat")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	sub := filepath.Join(dir, "sub")
	deep := filepath.Join(sub, "deep")
	if err := os.MkdirAll(deep, 0o700); err != nil {
		t.Fatal(err)
	}
	deepFile := filepath.Join(deep, "probe_key.dat")
	if err := os.WriteFile(deepFile, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}

	targets, err := denyCoverAll([]string{file, sub + "/**", deepFile})
	if err != nil {
		t.Fatal(err)
	}
	if !contains(targets, file) || !contains(targets, sub) {
		t.Fatalf("targets = %v", targets)
	}
	if contains(targets, deepFile) {
		t.Fatalf("nested target must be pruned by parent dir: %v", targets)
	}

	targets, err = denyCoverAll([]string{dir + "/**/probe_key.dat"})
	if err != nil || !contains(targets, deepFile) {
		t.Fatalf("recursive ** targets = %v (%v)", targets, err)
	}

	for _, bad := range []string{"**", "*/x", "*"} {
		if _, err := denyCoverAll([]string{bad}); err == nil {
			t.Fatalf("denyCoverAll(%q) accepted unsupported form", bad)
		}
	}
}

// 多个 ** 模式共享一趟遍历：同一快照下目标集合与逐模式遍历一致——文件命中
// 逐条产出，目录命中（.probe_ssh）剪枝后其内更深命中由父目标收敛。修复前
// ~11 条内置 ** 模式各走一趟 $HOME（win 实测每次 exec 多付 ~17s），现同根只走一趟。
// 文件名用中性词（不对撞环境自身的内置 deny 表，如 **/id_rsa*、**/.ssh/**）。
func TestDenyWalkAllSharedTraversal(t *testing.T) {
	dir := filepath.ToSlash(t.TempDir())
	mk := func(rel string) string {
		p := filepath.Join(dir, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		return filepath.ToSlash(p)
	}
	secret := mk("app/a.secret")
	probe := mk("keys/id_probe")
	inner := mk(".probe_ssh/id_probe")
	probeDir := dir + "/.probe_ssh"

	targets := mustDenyTargets(t, []string{dir + "/**/*.secret", dir + "/**/id_probe*", dir + "/**/.probe_ssh/**"})
	if !contains(targets, secret) || !contains(targets, probe) {
		t.Fatalf("file targets missing: %v", targets)
	}
	if !contains(targets, probeDir) {
		t.Fatalf("matched dir target missing: %v", targets)
	}
	if contains(targets, inner) {
		t.Fatalf("nested target under matched dir must be pruned: %v", targets)
	}
	if len(targets) != 3 {
		t.Fatalf("targets = %v, want 3 entries", targets)
	}
}

// mustDenyTargets 实例化 deny 模式（测试 helper）。
func mustDenyTargets(t *testing.T, pats []string) []string {
	t.Helper()
	targets, err := denyCoverAll(pats)
	if err != nil {
		t.Fatal(err)
	}
	return targets
}

// deny 实例化缓存（B 方案）：TTL 内同一模式集复用快照（跳过 $HOME 递归）；
// 过期重算反映当前文件系统；模式集不同即不命中。语义取舍：TTL 窗口内新建的
// 匹配对象在下次重算前不会被实例化（2026-09-23 用户批准）。生产路径走
// denyCoverAllCached，测试直接调 denyCoverAll 不受缓存影响。
func TestDenyCoverAllCached(t *testing.T) {
	oldTTL := denyCoverCacheTTL
	denyCoverCacheTTL = time.Minute
	defer func() { denyCoverCacheTTL = oldTTL }()
	denyCoverCacheMu.Lock()
	denyCoverCache = nil // 清空，免与同进程其他用例互相污染
	denyCoverCacheMu.Unlock()

	dir := filepath.ToSlash(t.TempDir())
	first := filepath.Join(dir, "a.probecache")
	if err := os.WriteFile(first, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	pats := []string{dir + "/**/*.probecache"}

	targets, cached, err := denyCoverAllCached(pats, nil)
	if err != nil {
		t.Fatal(err)
	}
	if cached {
		t.Fatalf("first instantiation must not be cached")
	}
	if !contains(targets, filepath.ToSlash(first)) {
		t.Fatalf("first instantiation must contain %s: %v", first, targets)
	}

	// 文件系统变化（删旧建新）：TTL 内命中缓存 → 返回旧快照
	second := filepath.Join(dir, "b.probecache")
	if err := os.WriteFile(second, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(first); err != nil {
		t.Fatal(err)
	}
	targets, cached, err = denyCoverAllCached(pats, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !cached {
		t.Fatalf("second call within TTL must be served from cache")
	}
	if !contains(targets, filepath.ToSlash(first)) || contains(targets, filepath.ToSlash(second)) {
		t.Fatalf("TTL 内必须复用旧快照（含已删的 %s、不含新建的 %s）: %v", first, second, targets)
	}

	// TTL 过期：重算反映当前文件系统
	denyCoverCacheTTL = 0
	targets, cached, err = denyCoverAllCached(pats, nil)
	if err != nil {
		t.Fatal(err)
	}
	if cached {
		t.Fatalf("expired entry must be recomputed")
	}
	if contains(targets, filepath.ToSlash(first)) || !contains(targets, filepath.ToSlash(second)) {
		t.Fatalf("TTL 过期必须重算（不含 %s、含 %s）: %v", first, second, targets)
	}

	// 模式集不同：不命中（同一缓存槽直接替换）
	other := []string{dir + "/**/*.probemiss"}
	targets, cached, err = denyCoverAllCached(other, nil)
	if err != nil {
		t.Fatal(err)
	}
	if cached {
		t.Fatalf("different pattern set must recompute")
	}
	if len(targets) != 0 {
		t.Fatalf("不同模式集必须重算（当前无目标）: %v", targets)
	}
}

// rlimitArgs 三端同一组上限：AS 4GiB / NOFILE 1024 / CPU 600 /
// FSIZE 1GiB / CORE 0（与 resourceLimit* 常量一致，防硬编码漂移）。
// 不含 NPROC：RLIMIT_NPROC 按 real-UID 全系统计数，桌面常驻进程即超限（见
// sandbox.go 常量块注释）。
func TestRlimitArgs(t *testing.T) {
	got := rlimitArgs()
	want := []string{
		"--rlimit", "AS", "4294967296",
		"--rlimit", "NOFILE", "1024",
		"--rlimit", "CPU", "600",
		"--rlimit", "FSIZE", "1073741824",
		"--rlimit", "CORE", "0",
	}
	assertEqual(t, "rlimits", got, want)
}

// confineRlimits（darwin）：sh ulimit 包装——脚本含资源上限 + exec "$@"
// 透传；argv 尾部原样保留（/bin/sh -c <script> sh <argv...>）。
func TestConfineRlimits(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("windows uses job object, covered by TestWindowsJobLimits")
	}
	got := confineRlimits([]string{"bash", "-c", "echo hi"})
	if len(got) != 7 || got[0] != "/bin/sh" || got[1] != "-c" || got[3] != "sh" {
		t.Fatalf("confineRlimits head: %v", got)
	}
	script := got[2]
	for _, want := range []string{"ulimit -n 1024", "-t 600", "-f 2097152", "-c 0", `exec "$@"`} {
		if !strings.Contains(script, want) {
			t.Fatalf("script missing %q: %s", want, script)
		}
	}
	// macOS 内核不支持 RLIMIT_AS：-v 不得出现在脚本中（RSS 监控兜底）
	if strings.Contains(script, "-v") {
		t.Fatalf("script must not set -v (RLIMIT_AS unsupported on darwin): %s", script)
	}
	for i, a := range []string{"bash", "-c", "echo hi"} {
		if got[4+i] != a {
			t.Fatalf("argv tail %d: %v", i, got[4:])
		}
	}
}

// isGitArgv 只认 argv[0] basename 为 git；shell 包装不豁免。
func TestIsGitArgv(t *testing.T) {
	for _, argv := range [][]string{
		{"git", "status"}, {"git", "checkout", "main"}, {"/usr/bin/git", "log"},
	} {
		if !isGitArgv(argv) {
			t.Fatalf("isGitArgv(%v) = false, want true", argv)
		}
	}
	for _, argv := range [][]string{
		{"bash", "-c", "git commit"}, {"sh", "-c", "rm -rf .git"}, {"git-lfs", "pull"}, nil,
	} {
		if isGitArgv(argv) {
			t.Fatalf("isGitArgv(%v) = true, want false", argv)
		}
	}
}

// seatbelt 网络管控段（net_policy=deny 锁定模式）：deny inbound/outbound 打底 +
// loopback localhost 两形态（remote 连通 + local inbound bind/listen）+
// 非 loopback 条目退化 *:port（2026-09-07 实测：host 必须为 */localhost；
// outbound local tcp 是毒形态严禁输出；DNS 沙箱内不可修复不放行）+
// port=* 跳过。open 模式零网络规则。
func TestSeatbeltNetForms(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix path semantics")
	}
	argv := []string{"bash", "-c", "echo hi"}
	mustEntry := func(s string) Entry {
		e, err := ParseEntry(s)
		if err != nil {
			t.Fatalf("ParseEntry(%q): %v", s, err)
		}
		return e
	}

	spec := confineSpec{workdir: "/ws", argv: argv,
		netAllow: []Entry{mustEntry("localhost:*"), mustEntry("123.56.83.149:1022"), mustEntry("anyhost.example:*")},
		netDeny:  []Entry{mustEntry("203.0.113.9:443"), mustEntry("localhost:6379")},
	}
	profile := seatbeltArgs(spec)[2]
	for _, want := range []string{
		"(deny network-inbound)",
		"(deny network-outbound)",
		`(allow network-outbound (remote tcp "localhost:*"))`,
		`(allow network-inbound (local tcp "localhost:*"))`,     // loopback bind/listen
		`(allow network-outbound (remote tcp "*:1022"))`,        // 非 loopback 退化为按端口
		`(deny network-outbound (remote tcp "localhost:6379"))`, // loopback deny 落地（对抗内建 allow）
	} {
		if !strings.Contains(profile, want) {
			t.Fatalf("deny-mode profile missing %s: %s", want, profile)
		}
	}
	// 毒形态严禁出现（outbound local tcp = 放掉一切出站，2026-09-07 实测）
	if strings.Contains(profile, "network-outbound (local tcp") {
		t.Fatalf("poison form (allow network-outbound (local tcp ...)) must never be emitted: %s", profile)
	}
	// port=* 的非 loopback 条目内核不可表达：不输出
	if strings.Contains(profile, "anyhost.example") {
		t.Fatalf("port=* non-loopback entry should be skipped: %s", profile)
	}
	// 非 loopback deny 不输出内核规则（基线全拒已覆盖；*:port 会株连同端口
	// allow 目标——2026-09-07 评审修复）
	if strings.Contains(profile, `(deny network-outbound (remote tcp "*:443"))`) {
		t.Fatalf("non-loopback deny must not emit kernel rule (would kill same-port allows): %s", profile)
	}

	// open 模式：零网络规则
	open := seatbeltArgs(confineSpec{workdir: "/ws", argv: argv, netOpen: true})
	if strings.Contains(open[2], "network") {
		t.Fatalf("open-mode profile should carry no network rules: %s", open[2])
	}
}

// bwrap 网络与 fs_open：net_policy=deny → --unshare-net（全断，粒度不生效）；
// fs_policy=open → 整机 ro-bind 改 rw bind。
func TestBwrapNetAndFsOpen(t *testing.T) {
	argv := []string{"bash", "-c", "echo hi"}

	deny := bwrapArgs(confineSpec{workdir: "/ws", argv: argv}, nil, nil, nil)
	if !contains(deny, "--unshare-net") {
		t.Fatalf("deny mode missing --unshare-net: %v", deny)
	}
	open := bwrapArgs(confineSpec{workdir: "/ws", argv: argv, netOpen: true}, nil, nil, nil)
	if contains(open, "--unshare-net") {
		t.Fatalf("open mode should not unshare net: %v", open)
	}
	// fsOpen：--bind / /（读开放 + 写全放）
	fsOpen := bwrapArgs(confineSpec{workdir: "/ws", argv: argv, netOpen: true, fsOpen: true}, nil, nil, nil)
	if !contains(fsOpen, "--bind", "/", "/") {
		t.Fatalf("fs_open should rw-bind root: %v", fsOpen)
	}
}

// sbplString 转义反斜杠与引号。
func TestSbplString(t *testing.T) {
	got := sbplString(`C:\a"b`)
	if got != `"C:\\a\"b"` {
		t.Fatalf("sbplString = %s", got)
	}
}

func assertEqual(t *testing.T, name string, got, want []string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("%s: got %v, want %v", name, got, want)
	}
	for i := range got {
		if got[i] != want[i] {
			t.Fatalf("%s: got %v, want %v", name, got, want)
		}
	}
}

func contains(s []string, sub ...string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		ok := true
		for j := range sub {
			if s[i+j] != sub[j] {
				ok = false
				break
			}
		}
		if ok {
			return true
		}
	}
	return false
}
