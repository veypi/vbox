// Native processes enforce an ordered file/network policy snapshot.
// Cwd grants no access. Unsupported restrictions fail before execution.
package vbox

import (
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// probeTimeout 是每个后端功能性 probe 的超时（真跑一次最小命令验证；
// 0 会被视为无超时，故必须为正数）。
const probeTimeout = 5 * time.Second

// 沙箱资源上限（三端统一语义，与文件隔离正交；read-only 与 workspace-write 同限）：
//   - AS 4GiB：防大 malloc 吃满物理内存 + swap 导致系统假死（死机事故根因）
//   - job 内存 8GiB：windows Job Object 整个 job（含全部子孙）合计上限
//   - NOFILE 1024：防 fd 耗尽
//   - CPU 600s：与 30m wall-clock 超时双保险
//   - FSIZE 1GiB：防单文件写爆磁盘（write 级沙箱）
//   - CORE 0：禁 core dump 落盘
//
// 不设 RLIMIT_NPROC（2026-08-31 事故修正）：unix 内核按 real-UID 全系统计数，
// 计数 >= 上限即 fork EAGAIN——桌面开发机单 UID 常驻进程数百个（本机实测约
// 600），设 256 等于禁掉沙箱内一切 fork，全部命令瘫痪。防 fork 炸弹由既有机制
// 兜底：30m wall 超时 + 进程组 killEntry 全灭 + CPU 600s。windows Job Object
// 的活动进程上限（resourceLimitJobProcesses）是 job 级计数（语义正确）不受影响，
// 仍在 sandbox_windows.go。
const (
	resourceLimitAS           = 4 << 30
	resourceLimitJobMemory    = 8 << 30
	resourceLimitJobProcesses = 256
	resourceLimitNoFile       = 1024
	resourceLimitCPU          = 600
	resourceLimitFSize        = 1 << 30
)

// 工作区元数据保护（.git/.aws 只读）曾以 protectedMetadataNames 专路实现；
// 2026-10-01 收敛为 pod 侧内置 ro 行（aic-pod fsauth.SnapshotForNative）：
// 三平台统一经规则表求值/落地，git 命令豁免（argv[0] basename 判据）同交 pod。
// ro-bind 覆盖的 linux 有效性实测见 aic-pod 记录（2026-08-14，Debian 13）。

// sandboxBackend 是选中的平台后端。
type sandboxBackend int

const (
	backendUnavailable sandboxBackend = iota
	backendBwrap
	backendSeatbelt
	backendWindowsAcl
)

// launchPlan 是一次 confined 启动的平台方案：
//   - argv：替换启动参数（bwrap/seatbelt 包装；windows 原样）
//   - token：windows 受限令牌句柄（其他平台恒 0；spawn 成功后由
//     Manager 关闭——子进程持有令牌副本）
//   - job：windows Job Object 句柄（资源限制：内存/进程数；其他平台恒 0；
//     spawn 成功后由 Manager assign 子进程，进程结束后随 cleanup 关闭）
//   - env：附加环境变量（windows：TMP/TEMP 指向私有临时目录）
//   - cleanup：进程结束后调用（windows：撤销 per-call deny ACE + 删除私有
//     临时目录 + 关闭 Job Object；其他平台 nil）
type launchPlan struct {
	argv    []string
	token   uintptr
	job     uintptr
	env     []string
	cleanup func()
}

var (
	sandboxMu      sync.Mutex
	sandboxVerdict sandboxBackend = -1 // -1 = 未探测
)

// confineSpec 是一次沙箱包装的完整输入（三域授权模型快照 + 等级/工作区/argv）。
// 快照语义：每次 Start 读当次值（set_config/grant 动态生效），已启动进程不回溯。
type confineSpec struct {
	workdir  string
	argv     []string
	fsRules  FSRuleSet
	netRules NetRuleSet
	logf     func(string, ...any)
}

func processSpec(opts StartOptions, logf func(string, ...any)) confineSpec {
	return confineSpec{workdir: opts.Workdir, argv: opts.Exec, fsRules: opts.Policy.FS, netRules: opts.Policy.Net, logf: logf}
}

func (s confineSpec) denyPatterns() []string {
	var out []string
	for _, r := range s.fsRules.Rules {
		if r.Effect == EffDeny {
			out = append(out, r.Pattern)
		}
	}
	return out
}

func (s confineSpec) writeRoots() []string {
	var out []string
	for _, r := range s.fsRules.Rules {
		if r.Effect != EffRW {
			continue
		}
		p := strings.TrimSuffix(r.Pattern, "/**")
		if !strings.ContainsAny(p, "*?") {
			out = append(out, p)
		}
	}
	return out
}

// Confine 将 argv 包装为沙箱执行形态（返回替换 argv；windows 的实际
// confined 路径走 planConfined 的令牌注入，本函数仅供非 windows 调用与
// 统一测试）。沙箱 profile 由 rules 派生（hosts-vsh-redesign：数字等级
// 已删除）；免沙箱不经本函数表达（StartOptions.NoSandbox）。
// 无可用后端返回错误（fail-closed），绝不返回未包装 argv。
// deny/net 快照恒零值：现调用方仅测试；生产路径必须走 Start（StartOptions
// 授权快照字段），否则 deny 隔离与网络管控静默缺失。
func Confine(workdir string, argv []string) ([]string, error) {
	plan, err := planConfined(confineSpec{workdir: workdir, argv: argv, netRules: NetRuleSet{Default: true}})
	if err != nil {
		return nil, err
	}
	return plan.argv, nil
}

// selectBackend 返回本平台后端（功能性探测一次并缓存整个进程生命周期）。
func selectBackend() sandboxBackend {
	sandboxMu.Lock()
	defer sandboxMu.Unlock()
	if sandboxVerdict < 0 {
		sandboxVerdict = probeBackend()
	}
	return sandboxVerdict
}

// sandboxUnavailable 构造 fail-closed 错误（命令未执行）。
// 云端批准不会豁免执行端必须落实的本地策略。
func sandboxUnavailable() error {
	return fmt.Errorf(
		"sandbox: confinement required but no sandbox backend is usable on this host " +
			"(install bubblewrap on Linux); the command was not run")
}

// ---- linux: bubblewrap（跨平台编译的纯 argv 构建，测试直接引用）----

// bwrapArgs 构建 bwrap 包装 argv：
//   - 基础：整机只读挂载（--ro-bind / /，读默认开放；fs_policy=open 且写级
//     时改整机 rw bind）+ /dev + /proc + --die-with-parent（host 退出沙箱
//     进程组随之终止，与 killEntry 进程组语义一致）
//   - workspace-write（level 2/3/4）：/tmp 换 tmpfs（全新空目录，临时文件
//     不落盘）+ 工作区可写 bind + 缓存目录（cacheDirs，cacheRoots 采集）
//     逐个可写 bind
//   - deny 隔离覆盖（§5.10）与 ro/rw 洞回补：evaluateFSPolicy 求值后按深度
//     排序输出（后绑定覆盖先绑定）
//   - read-only（level 1）：无任何可写挂载（/dev/null 由 --dev 提供）
//
// rlimitArgs 构建 bwrap 资源限制参数段（--rlimit TYPE VALUE ...）。
// bwrap 在 exec 前对子进程 setrlimit（soft=hard），与文件隔离正交、
// read-only 与 workspace-write 同限（resourceLimit* 常量统一语义）。
func rlimitArgs() []string {
	return []string{
		"--rlimit", "AS", strconv.FormatUint(uint64(resourceLimitAS), 10),
		"--rlimit", "NOFILE", strconv.Itoa(resourceLimitNoFile),
		"--rlimit", "CPU", strconv.Itoa(resourceLimitCPU),
		"--rlimit", "FSIZE", strconv.FormatUint(uint64(resourceLimitFSize), 10),
		"--rlimit", "CORE", "0",
	}
}

// confineRlimits 构造 sh ulimit 包装 argv（darwin planConfined 使用，
// 测试跨平台直接引用）。Seatbelt 不支持资源限制，包一层 /bin/sh：
// ulimit 设置的 RLIMIT 跨 exec 继承（sandbox-exec 与其最终命令同受约束），
// 且子进程只能降低不能提高；ulimit 失败即退出（fail-closed，命令不执行）。
// 注意：macOS 内核不支持 RLIMIT_AS（-v）/RLIMIT_DATA（-d），setrlimit 恒
// EINVAL（实测 2026-08-28）——大内存分配由 vbox 进程组 RSS 监控
// 兜底（rss_darwin.go）。不设 -u（RLIMIT_NPROC 按 UID 全系统计数，桌面
// 常驻进程即超限，见常量块注释）。单位：-n fd、-t CPU 秒、-f 512B 块、-c core。
func confineRlimits(argv []string) []string {
	script := fmt.Sprintf(
		"ulimit -n %d -t %d -f %d -c 0 2>/dev/null || exit 1; exec \"$@\"",
		resourceLimitNoFile, resourceLimitCPU, resourceLimitFSize>>9)
	return append([]string{"/bin/sh", "-c", script, "sh"}, argv...)
}

func bwrapArgs(spec confineSpec, cacheDirs []string, deny denyMountPlan) []string {
	// 读默认开放：整机 ro-bind 读视图；fs_policy=open（写级）整机 rw bind。
	// deny 覆盖挂载在末尾追加，恒优先。
	args := []string{"bwrap"}
	flag := "--ro-bind"
	if spec.fsRules.DefaultWrite == EffRW {
		flag = "--bind"
	}
	args = append(args, flag, "/", "/")
	args = append(args, "--dev", "/dev", "--proc", "/proc", "--die-with-parent")
	if !spec.netRules.Default {
		// net_policy=deny：--unshare-net 全断（新 net ns 仅 loopback 且未配置——
		// loopback 也不可用）。bwrap 无 per-destination 规则引擎，白名单粒度
		// linux 不生效（近似层，net_allow 仅 darwin 落地；见 host_sandbox.md）。
		args = append(args, "--unshare-net")
	}
	args = append(args, rlimitArgs()...)
	// 沙箱 profile 由 rules 派生（数字等级已删除）：临时区/缓存/可写根一律放行。
	args = append(args, "--tmpfs", "/tmp")
	for _, d := range cacheDirs {
		if d != "" {
			args = append(args, bindIfExists(d, false)...)
		}
	}
	// deny 隔离覆盖（§5.10）：后挂载优先（bwrap 后绑定覆盖前绑定），
	// 追加在全部 bind 之后；read-only 与 workspace-write 同隔离。
	args = append(args, deny.args()...)
	return append(append(args, "--"), spec.argv...)
}

// denyMountPlan 授权快照经 first-wins 求值后的内核处置计划（W3）。
type denyMountPlan struct {
	cover []string // 终局 deny：覆盖挂载（目录 tmpfs / 文件·socket 以 /dev/null ro-bind）
	ro    []string // 终局 ro：--ro-bind（可读不可写）
	rw    []string // 终局 rw：--bind（覆盖失效，与快照终局一致）
}

// args 输出挂载参数：按路径深度浅→深排序（bwrap 后绑定覆盖先绑定——嵌套
// 路径深层必须后挂，否则浅层后挂会把深层挂载一并遮蔽）；同深度按
// cover → ro → rw 定序。同一路径经求值只出一个动作（evaluateFSPolicy
// 按 canonical 路径去重）。
func (p denyMountPlan) args() []string {
	type mount struct {
		path string
		kind int // 0=cover 1=ro 2=rw
	}
	mounts := make([]mount, 0, len(p.cover)+len(p.ro)+len(p.rw))
	for _, t := range p.cover {
		mounts = append(mounts, mount{t, 0})
	}
	for _, t := range p.ro {
		mounts = append(mounts, mount{t, 1})
	}
	for _, t := range p.rw {
		mounts = append(mounts, mount{t, 2})
	}
	sort.SliceStable(mounts, func(i, j int) bool {
		di, dj := pathDepth(mounts[i].path), pathDepth(mounts[j].path)
		if di != dj {
			return di < dj
		}
		return mounts[i].kind < mounts[j].kind
	})
	var args []string
	for _, m := range mounts {
		switch m.kind {
		case 0:
			args = append(args, overlayArgs(m.path)...)
		case 1:
			args = append(args, bindIfExists(m.path, true)...)
		default:
			args = append(args, bindIfExists(m.path, false)...)
		}
	}
	return args
}

// pathDepth 路径段数（挂载排序用深度）。
func pathDepth(p string) int {
	return strings.Count(filepath.ToSlash(strings.TrimSuffix(p, "/")), "/")
}

// evaluateFSPolicy 是「先求值后落措施」（W3，permission_rules §5）的单一
// 入口：候选路径 = deny 实例化目标 ∪ 规则表 ro/rw 字面行中落在覆盖目标/
// 可写根之下（fsOpen 时任意位置）者；每个候选经 first-wins Match 求终局——
// 终局 deny → 覆盖；ro（写拒读放）→ ro-bind；rw → rw-bind。每路径只出一
// 个动作，天然消除「同路径先 ro 后 rw」的行序失真与独立 ro 规则遗漏。
// rules 为空 = deny 目标全覆盖（旧行为，fail-closed）。
//
// ro/rw 通配行无法以挂载精确表达（字面前缀不是该行的真实作用域）：ro 通配
// 行落在可写根之下或 fsOpen 时返回错误、启动前拒绝执行（该方向沙箱比
// matcher 宽松，必须 fail-closed，与 deny 不可实例化同口径）；rw 通配行与
// 覆盖目标内的 ro 通配行属「沙箱更严」的安全方向，跳过（仅工具层生效）。
func evaluateFSPolicy(targets []string, rules *FSRuleSet, writable []string, fsOpen bool) (denyMountPlan, error) {
	var plan denyMountPlan
	if rules == nil {
		plan.cover = append(plan.cover, targets...)
		return plan, nil
	}
	seen := map[string]bool{}
	// 覆盖目标逐个求终局；两侧同口径 canonical（生产快照行已 canonical；
	// 目标来自实例化名单可能含字面形——macOS firmlink 下两侧错位会漏判）。
	canonCover := make([]string, 0, len(targets))
	for _, t := range targets {
		seen[Canonical(t)] = true
		switch {
		case rules.Match(t, OpWrite).Allow:
			plan.rw = append(plan.rw, t)
		case rules.Match(t, OpRead).Allow:
			plan.ro = append(plan.ro, t)
		default:
			plan.cover = append(plan.cover, t)
			canonCover = append(canonCover, Canonical(t))
		}
	}
	canonWritable := make([]string, 0, len(writable))
	for _, w := range writable {
		if w = Canonical(w); w != "" {
			canonWritable = append(canonWritable, w)
		}
	}
	// 需显式挂载 = 基底可写性与终局判定可能不一致：落在可写根/fsOpen 之下
	// （基底可写）或覆盖目标之下（整树被遮、洞需回补）。
	needsMount := func(cpath string) bool {
		return fsOpen || underAnyPath(cpath, canonCover) || underAnyPath(cpath, canonWritable)
	}
	var globs []string
	for _, r := range rules.Rules {
		if r.Effect == EffDeny {
			continue
		}
		if strings.ContainsAny(r.Pattern, "*?") {
			// ro 通配行收紧可写基底而挂载层无法表达 → 拒启；其余方向安全。
			if r.Effect == EffRO {
				if lit := literalPrefix(r.Pattern); lit == "" || fsOpen || underAnyPath(Canonical(lit), canonWritable) {
					globs = append(globs, r.Pattern)
				}
			}
			continue
		}
		cpath := Canonical(r.Pattern)
		if seen[cpath] || !needsMount(cpath) {
			continue
		}
		seen[cpath] = true
		switch {
		case rules.Match(cpath, OpWrite).Allow:
			// rw：仅在覆盖目标之内才是洞（可写根内本就 rw，无需重复挂载）。
			if underAnyPath(cpath, canonCover) {
				plan.rw = append(plan.rw, cpath)
			}
		case rules.Match(cpath, OpRead).Allow:
			// ro：可写基底或覆盖目标内都需显式 ro-bind 收紧。
			plan.ro = append(plan.ro, cpath)
		default:
			// 终局 deny 的 ro/rw 行（被后续 deny 行压中）：无需动作——
			// deny 目标由 DenyPatterns 全量实例化，不在目标内即不受遮。
		}
	}
	if len(globs) > 0 {
		return plan, &DeniedError{Reason: "sandbox cannot enforce host policy: inexpressible ro glob rule(s): " + strings.Join(globs, " ")}
	}
	return plan, nil
}

// writableMountRoots 返回 linux 挂载层的可写根（bwrapArgs 实际 rw 绑定的
// 路径 + /tmp tmpfs）——evaluateFSPolicy 据此判定哪些 ro 行需显式挂载收紧。
func writableMountRoots(spec confineSpec) []string {
	roots := spec.writeRoots()
	return append(roots, "/tmp")
}

// literalPrefix 取 glob 模式的字面前缀（首个通配段之前；无通配 = 整串；
// 首段即通配返回空）。
func literalPrefix(pat string) string {
	segs := strings.Split(filepath.ToSlash(pat), "/")
	out := make([]string, 0, len(segs))
	for _, s := range segs {
		if strings.ContainsAny(s, "*?") {
			break
		}
		out = append(out, s)
	}
	if len(out) == 0 {
		return ""
	}
	return strings.Join(out, "/")
}

// underAnyPath 报告 p 是否等于或落在 roots 任一根之下。
func underAnyPath(p string, roots []string) bool {
	for _, r := range roots {
		if p == r || strings.HasPrefix(p, r+"/") {
			return true
		}
	}
	return false
}

// bindIfExists 洞回补挂载（源不存在跳过并声明仅工具层生效——不静默创目录）。
func bindIfExists(p string, ro bool) []string {
	if p == "" {
		return nil
	}
	if _, err := os.Stat(p); err != nil {
		return nil
	}
	if ro {
		return []string{"--ro-bind", p, p}
	}
	return []string{"--bind", p, p}
}

// overlayArgs 返回单目标路径的覆盖挂载参数（目录 tmpfs / 普通文件与 unix
// socket 以 /dev/null ro-bind 覆盖；其余（设备/不存在）跳过）。socket 覆盖 =
// linux 侧 AF_UNIX connect 隔离：覆盖后 connect 只见到 /dev/null 直接失败
// （对齐 darwin seatbelt 的 network-outbound 规则；修复前 socket 被跳过，
// docker.sock 可直通，实测 2026-09-05）。
func overlayArgs(p string) []string {
	if p == "" {
		return nil
	}
	st, err := os.Stat(p)
	if err != nil {
		return nil
	}
	if st.IsDir() {
		return []string{"--tmpfs", p}
	}
	if st.Mode().IsRegular() || st.Mode()&os.ModeSocket != 0 {
		return []string{"--ro-bind", "/dev/null", p}
	}
	return nil
}

// denyCoverAll 把一组 deny 模式实例化为覆盖挂载目标：任何形态不可实例化
// （无字面前缀的全 glob、递归枚举超预算）即返回错误——启动前拒绝执行，
// 不静默放行。目标去重并丢弃被其他目标覆盖的子孙（先挂父目录、后挂子孙
// 会失败；父目录覆盖整棵子树已足够）。
//
// ** 形态共同走一趟遍历（denyWalkAll）：同一份快照下的目标集合与逐模式
// 遍历一致，但每调用只付一趟目录枚举代价（此前 ~11 条内置 ** 模式各走
// 一趟 $HOME 递归，win 实测每次 exec 因此多付 ~17s）。
func denyCoverAll(pats []string) ([]string, error) {
	var out []string
	var walks []string
	for _, pat := range pats {
		if pat == "" {
			continue
		}
		pat = filepath.ToSlash(pat)
		if !strings.ContainsAny(pat, "*?") {
			out = append(out, pat)
			continue
		}
		if !strings.Contains(pat, "**") {
			targets, ok := denyGlobTargets(pat)
			if !ok {
				return nil, &DeniedError{Reason: "sandbox cannot enforce host policy: unsupported deny pattern " + pat}
			}
			out = append(out, targets...)
			continue
		}
		if dir, ok := denySubtreeDir(pat); ok {
			out = append(out, dir)
			continue
		}
		walks = append(walks, pat)
	}
	if len(walks) > 0 {
		targets, ok := denyWalkAll(walks)
		if !ok {
			return nil, &DeniedError{Reason: "sandbox cannot enforce host policy: unsupported deny pattern(s): " + strings.Join(walks, " ")}
		}
		out = append(out, targets...)
	}
	return pruneCoverTargets(out), nil
}

// pruneCoverTargets 去重并用路径前缀丢弃被覆盖的子孙目标（排序保证父目录
// 先入结果集）。
func pruneCoverTargets(targets []string) []string {
	seen := map[string]bool{}
	kept := make([]string, 0, len(targets))
	for _, t := range targets {
		t = filepath.ToSlash(t)
		if t == "" || seen[t] {
			continue
		}
		seen[t] = true
		kept = append(kept, t)
	}
	sort.Strings(kept)
	out := kept[:0]
	for _, t := range kept {
		covered := false
		for _, k := range out {
			if strings.HasPrefix(t, k+"/") {
				covered = true
				break
			}
		}
		if !covered {
			out = append(out, t)
		}
	}
	return out
}

// denySubtreeDir 返回「<字面目录>/**」形态的目录。
func denySubtreeDir(pat string) (string, bool) {
	const tail = "/**"
	if !strings.HasSuffix(pat, tail) {
		return "", false
	}
	dir := strings.TrimSuffix(pat, tail)
	if dir == "" || strings.ContainsAny(dir, "*?") {
		return "", false
	}
	return dir, true
}

// denyGlobTargets 处理无 ** 的单 glob 段形态：字面前缀 readdir + 段内匹配。
// 多 glob 段或无字面前缀的形态不可实例化。
func denyGlobTargets(pat string) ([]string, bool) {
	segs := strings.Split(pat, "/")
	lit := 0
	for _, s := range segs {
		if strings.ContainsAny(s, "*?") {
			break
		}
		lit++
	}
	if lit == 0 || lit >= len(segs) {
		return nil, false
	}
	for _, rest := range segs[lit+1:] {
		if strings.ContainsAny(rest, "*?") {
			return nil, false
		}
	}
	prefix := strings.Join(segs[:lit], "/")
	if prefix == "" {
		return nil, false // 形如 /*/x 的无根形态无法静态枚举
	}
	st, err := os.Stat(prefix)
	if err != nil || !st.IsDir() {
		return nil, true // 前缀不存在/非目录：当前无目标
	}
	want := segs[lit]
	entries, err := os.ReadDir(prefix)
	if err != nil {
		return nil, true
	}
	var out []string
	for _, e := range entries {
		if ok, _ := filepath.Match(want, e.Name()); ok {
			out = append(out, filepath.Join(prefix, e.Name()))
		}
	}
	return out, true
}

// denyWalkMaxDirs 限制 ** 模式递归枚举访问的目录数：超限 = 不可实例化
// （启动前拒绝执行），不静默放行。
const denyWalkMaxDirs = 50000

// denyWalkAll 为全部含 ** 的模式共享一趟递归遍历：按 walk 根（denyWalkRoot）
// 分组，同组只枚举一次目录树，同一目录项同时匹配该组全部模式。命中即记录
// 且不再下探（整棵子树已被目标覆盖；其内更深命中即便存在也会被
// pruneCoverTargets 按父目标收敛），因此调用方拿到的目标集合与逐模式遍历
// 一致。
//
// 目录访问预算（denyWalkMaxDirs）按共享遍历计：同组模式此前各自独立走同一
// 棵树，超限时同样整体不可实例化（fail-closed），分组后语义不变且剪枝使
// 访问量更低。
func denyWalkAll(pats []string) ([]string, bool) {
	type walkGroup struct {
		root string
		pats []string
	}
	var groups []*walkGroup
	index := map[string]*walkGroup{}
	for _, pat := range pats {
		root, ok := denyWalkRoot(pat)
		if !ok {
			return nil, false
		}
		g := index[root]
		if g == nil {
			g = &walkGroup{root: root}
			index[root] = g
			groups = append(groups, g)
		}
		g.pats = append(g.pats, pat)
	}
	var out []string
	for _, g := range groups {
		visited := 0
		var walk func(dir string) bool
		walk = func(dir string) bool {
			visited++
			if visited > denyWalkMaxDirs {
				return false
			}
			entries, err := os.ReadDir(dir)
			if err != nil {
				return true
			}
			for _, e := range entries {
				p := dir + "/" + e.Name()
				matched := false
				for _, pat := range g.pats {
					if MatchPattern(pat, p) {
						matched = true
						break
					}
				}
				if matched {
					out = append(out, p)
					continue // 命中即覆盖：不再下探（目录整棵子树已覆盖）
				}
				if e.IsDir() && e.Type()&os.ModeSymlink == 0 {
					if !walk(p) {
						return false
					}
				}
			}
			return true
		}
		// 根不存在/非目录：ReadDir 失败即视为该根下当前无目标（与单模式语义一致）。
		if !walk(g.root) {
			return nil, false
		}
	}
	return out, true
}

// denyWalkRoot 取 ** 模式的递归起点：** 开头（无字面前缀）→ $HOME；
// 否则为首个通配段之前的字面前缀（无前缀 → 不可实例化）。
func denyWalkRoot(pat string) (string, bool) {
	if strings.HasPrefix(pat, "**/") {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", false
		}
		return filepath.ToSlash(home), true
	}
	segs := strings.Split(pat, "/")
	lit := 0
	for _, s := range segs {
		if strings.ContainsAny(s, "*?") {
			break
		}
		lit++
	}
	if lit == 0 {
		return "", false
	}
	root := strings.Join(segs[:lit], "/")
	if root == "" {
		return "", false // 形如 /*/**/x 的无根形态无法静态枚举
	}
	return root, true
}

// ---- deny 实例化缓存（per-call 沙箱提速：B 方案）----

// denyCoverCacheTTL 是 deny 实例化结果的保鲜期：TTL 内同一 deny 模式集的
// ** 递归枚举结果直接复用（win 实测一趟 $HOME 枚举 1.9-2.6s，共享遍历后
// 仍是每条沙箱命令的最大单项开销）。语义取舍（2026-09-23 用户批准）：
// 窗口内新建的匹配对象在下次重算前不会被打 deny ACE / 覆盖挂载（≤TTL）。
// 变量而非常量：测试可缩短以验证过期重算。
var denyCoverCacheTTL = 30 * time.Second

// denyCoverCacheEntry 是最近一次实例化结果的快照（键 = 模式列表）。
type denyCoverCacheEntry struct {
	key     string
	at      time.Time
	targets []string
	err     error
}

var (
	denyCoverCacheMu sync.Mutex
	denyCoverCache   *denyCoverCacheEntry
)

// denyCoverAllCached 是 denyCoverAll 的带缓存版本（生产路径使用：windows
// ensureDenyACEs、linux planConfined；测试直接调 denyCoverAll，与文件系统
// 实时对齐、不受缓存影响）。缓存以 deny 模式集为键、TTL 为界；锁覆盖整段
// 计算以合并并发的相同请求（并发不同策略仍串行——单次遍历时长量级，可接受）。
// cached 报告本次是否命中缓存：windows 侧据此只在重算时做 ACE 校验对账
// （缓存命中的稳态调用不做任何 ACL 读）。返回的切片是缓存内部快照，调用方
// 不得修改。err 一并缓存：不可实例化形态与超预算都是确定性判定，复用不改变
// fail-closed 行为。
func denyCoverAllCached(pats []string, logf func(string, ...any)) (targets []string, cached bool, err error) {
	key := strings.Join(pats, "\x00")
	denyCoverCacheMu.Lock()
	defer denyCoverCacheMu.Unlock()
	if e := denyCoverCache; e != nil && e.key == key {
		if age := time.Since(e.at); age < denyCoverCacheTTL {
			if logf != nil {
				logf("sandbox: deny instantiate cache hit: targets=%d age=%s", len(e.targets), age.Round(time.Millisecond))
			}
			return e.targets, true, e.err
		}
	}
	start := time.Now()
	targets, err = denyCoverAll(pats)
	denyCoverCache = &denyCoverCacheEntry{key: key, at: time.Now(), targets: targets, err: err}
	if logf != nil {
		logf("sandbox: deny instantiate: walk=%s targets=%d err=%v", time.Since(start).Round(time.Millisecond), len(targets), err)
	}
	return targets, false, err
}

// ---- darwin: Seatbelt (sandbox-exec) ----

// macosSeatbeltExecutable 是 sandbox-exec 的固定路径（防 PATH 注入：
// 若 /usr/bin/sandbox-exec 被篡改，攻击者已 root——codex 同策略）。
const macosSeatbeltExecutable = "/usr/bin/sandbox-exec"

// seatbeltArgs 将文件规则表逆序映射到 SBPL，保持 first-wins 语义。
func seatbeltArgs(spec confineSpec) []string {
	forms := []string{
		"(version 1)",
		"(allow default)",
		"(deny file-write*)",
		`(allow file-write* (literal "/dev/null"))`,
	}
	if spec.fsRules.DefaultWrite == EffRW {
		// fs_policy=open：写全放（表内 deny 行在后输出，继续生效）。
		forms = append(forms, "(allow file-write*)")
	}
	forms = append(forms, seatbeltNetForms(spec)...)
	{
		// first-wins → SBPL 逆序输出。AF_UNIX connect 不走 file-* 判定（实测
		// 2026-09-05）——deny/allow 行都带 network-outbound (remote unix) 形态，
		// socket 覆盖与文件路径同口径（2026-09-23 探针复核）。写放行只看规则行。
		rows := spec.fsRules.Rules
		for i := len(rows) - 1; i >= 0; i-- {
			r := rows[i]
			if r.Pattern == "" {
				continue
			}
			filter := sbplFilter(r.Pattern)
			switch r.Effect {
			case EffDeny:
				forms = append(forms,
					"(deny file-read* "+filter+")",
					"(deny file-write* "+filter+")",
					"(deny network-outbound (remote unix "+filter+"))")
			case EffRO:
				// ro = 写拒读放：写拒必须显式下沉——否则可写根内的宽写放行（后
				// 输出、后命中）会把 ro 洞盖掉（2026-10-01 探针实测：仅 allow
				// file-read* 时，可写根内 ro 路径的写照常放行）。
				forms = append(forms,
					"(allow file-read* "+filter+")",
					"(deny file-write* "+filter+")",
					"(allow network-outbound (remote unix "+filter+"))")
			case EffRW:
				forms = append(forms,
					"(allow file-read* "+filter+")",
					"(allow network-outbound (remote unix "+filter+"))",
					"(allow file-write* "+filter+")")
			}
		}
	}
	return append([]string{macosSeatbeltExecutable, "-p", stringsJoin(forms), "--"}, spec.argv...)
}

// sbplFilter 把 vbox 规则模式转为 SBPL 过滤形：裸模式（无 *?）= subpath 字面
// （语义 ≡ 自身+子树，与 vbox matcher 裸路径口径一致）；glob = regex。
func sbplFilter(pat string) string {
	if strings.ContainsAny(pat, "*?") {
		return "(regex " + sbplString(globToSBPLRegex(pat)) + ")"
	}
	return "(subpath " + sbplString(pat) + ")"
}

// seatbeltNetForms 先消除被前序规则覆盖的端口，再输出 Seatbelt 规则。
// Seatbelt 网络过滤器的具体端口优先于通配端口，不能仅靠逆序输出实现 first-wins。
// 本后端仅能区分 loopback 端口；其他目标在启动前校验中拒绝。
func seatbeltNetForms(spec confineSpec) []string {
	var forms []string
	if !spec.netRules.Default {
		forms = append(forms, "(deny network-inbound)", "(deny network-outbound)")
	}
	seen := map[string]bool{}
	var effective []NetRule
	for _, r := range spec.netRules.Rules {
		e, err := ParseEntry(r.HostPort)
		if err != nil || !isLoopbackHost(e.Host) || seen[e.Port] {
			continue
		}
		seen[e.Port] = true
		effective = append(effective, r)
		if e.Port == "*" {
			break
		}
	}
	for i := len(effective) - 1; i >= 0; i-- {
		r := effective[i]
		e, _ := ParseEntry(r.HostPort)
		verb := "deny"
		if r.Allow {
			verb = "allow"
		}
		forms = append(forms, seatbeltEntryForms(e, verb)...)
	}
	return forms
}

func seatbeltEntryForms(e Entry, verb string) []string {
	if !isLoopbackHost(e.Host) {
		return nil
	}
	addr := sbplString("localhost:" + e.Port)
	return []string{
		"(" + verb + " network-outbound (remote tcp " + addr + "))",
		"(" + verb + " network-inbound (local tcp " + addr + "))",
	}
}

// isLoopbackHost 判定 loopback 条目（localhost 字面或 IPv4/IPv6 loopback）。
func isLoopbackHost(h string) bool {
	if h == "localhost" {
		return true
	}
	if ip, err := netip.ParseAddr(h); err == nil {
		return ip.IsLoopback()
	}
	return false
}

func stringsJoin(forms []string) string {
	return strings.Join(forms, " ")
}

// existingDirs 过滤掉空串与不存在的目录（bwrap --bind / windows grantDirWrite
// 都要求源存在；seatbelt subpath 不强制，统一过滤保持三端一致）。
func existingDirs(dirs ...string) []string {
	out := make([]string, 0, len(dirs))
	for _, d := range dirs {
		if d == "" {
			continue
		}
		if st, err := os.Stat(d); err == nil && st.IsDir() {
			out = append(out, d)
		}
	}
	return out
}

// sbplString 转义一个路径为 SBPL 字符串字面量。
func sbplString(p string) string {
	return `"` + strings.ReplaceAll(strings.ReplaceAll(p, `\`, `\\`), `"`, `\"`) + `"`
}

// globToSBPLRegex 把 fsauth glob 模式（matchPattern 语义）转 SBPL POSIX ERE
// （SBPL 无 glob filter；regex 对完整路径字符串匹配，锚定 ^ 有效，实测 2026-09-05）。
// 转换规则：
//   - ** → 跨段（保 fsauth 的零段语义，吸收紧邻的分隔符）：
//   - ** 段首（无前导 /）→ (.*)?（零/多段，可跨 /）
//   - ** 段尾（前导 / 被吸收）→ (/.*)?（零段 = 自身，其后任意）
//   - ** 段中（前导 / 吸收且**後跟 / 一并消费）→ /(.*/)?（零段 = 单分隔，多段 = 跨段）
//   - *  → [^/]*       段内任意字符（不含 /）
//   - ?  → [^/]        段内单字符
//   - 其余字符 → 转义字面（regexp 特殊字符加 \）
//
// 整串锚定（^...$）保证与 fsauth 段匹配同为「全路径匹配」：正因 ^...$ 锚定，
// .ssh2 类粘连名不会命中 **/.ssh/**（字面段后必须是串尾或 /）。残余偏差仅
// 一处：段内 **（a**b 非标准形态）经 (.*)? 展开可跨段，而 fsauth matchOne
// 不跨段 → 超集拒绝（安全方向，该形态本身即非法输入）。
func globToSBPLRegex(pat string) string {
	pat = filepath.ToSlash(pat)
	var b strings.Builder
	b.WriteByte('^')
	for i := 0; i < len(pat); {
		if strings.HasPrefix(pat[i:], "**") {
			if i > 0 && pat[i-1] == '/' {
				// 吸收已输出的前导 '/'：** 零段 = 无该分隔符
				s := b.String()
				b.Reset()
				b.WriteString(s[:len(s)-1])
				if i+2 >= len(pat) {
					b.WriteString("(/.*)?") // 尾段 **
				} else if pat[i+2] == '/' {
					b.WriteString("/(.*/)?") // 中段 **：消费紧随的 /（零段=单分隔）
					i++
				} else {
					b.WriteString("/(.*)?") // 中段 ** 无尾 /（非标准分隔形态）
				}
				i += 2
				continue
			}
			b.WriteString("(.*)?")
			i += 2
			continue
		}
		switch pat[i] {
		case '*':
			b.WriteString("[^/]*")
		case '?':
			b.WriteString("[^/]")
		default:
			b.WriteString(regexEscape(pat[i]))
		}
		i++
	}
	b.WriteByte('$')
	return b.String()
}

// regexEscape 转义一个字节为 POSIX ERE 字面量（返回非空串）。
func regexEscape(c byte) string {
	if c == '\\' || strings.ContainsRune(".+*?()[]{}^$|", rune(c)) {
		return "\\" + string(rune(c))
	}
	return string(rune(c))
}

// validateProcessPolicy fails before execution when a backend cannot enforce the
// requested scope. Never approximate host rules by opening all hosts or paths.
func validateProcessPolicy(spec confineSpec, platform string) error {
	fail := func(why string) error { return &DeniedError{Reason: "sandbox cannot enforce host policy: " + why} }
	for _, r := range spec.fsRules.Rules {
		if r.Pattern == "" || r.Effect > EffRW {
			return fail("invalid file rule")
		}
	}
	if spec.fsRules.DefaultWrite != EffDeny && spec.fsRules.DefaultWrite != EffRW {
		return fail("invalid default file permission")
	}
	if platform == "windows" && spec.fsRules.DefaultWrite == EffRW {
		return fail("this Windows backend cannot enforce fs_policy=open writable-everything")
	}
	if platform == "windows" && !spec.netRules.Default {
		return fail("this Windows backend does not implement network rules")
	}
	for _, r := range spec.netRules.Rules {
		e, err := ParseEntry(r.HostPort)
		if err != nil {
			return fail(err.Error())
		}
		// 全开放时 allow 不收紧权限，无需平台表达；deny 和锁定模式中的 allow 必须落实。
		if r.Allow && spec.netRules.Default {
			hasDeny := false
			for _, other := range spec.netRules.Rules {
				if !other.Allow {
					hasDeny = true
					break
				}
			}
			if !hasDeny {
				continue
			}
		}
		if platform != "darwin" || !isLoopbackHost(e.Host) {
			return fail("selective network rule is unsupported by this backend")
		}
	}
	if platform == "linux" {
		for _, r := range spec.fsRules.Rules {
			if r.Effect == EffRW && strings.ContainsAny(strings.TrimSuffix(r.Pattern, "/**"), "*?") {
				return fail("Linux mount confinement cannot enforce this path glob: " + r.Pattern)
			}
		}
	}
	return nil
}
