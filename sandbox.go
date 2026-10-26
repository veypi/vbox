// Native processes enforce an ordered file/network policy snapshot.
// Cwd grants no access. Unsupported restrictions fail before execution.
package vbox

import (
	"fmt"
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
	argv      []string
	token     uintptr
	job       uintptr
	env       []string
	forcedEnv []string
	cleanup   func()
}

var (
	sandboxMu      sync.Mutex
	sandboxVerdict sandboxBackend = -1 // -1 = 未探测
)

// confineSpec 是一次沙箱包装的完整输入（三域授权模型快照 + 等级/工作区/argv）。
// 快照语义：每次 Start 读当次值（set_config/grant 动态生效），已启动进程不回溯。
type confineSpec struct {
	workdir   string
	argv      []string
	fsRules   FSRuleSet
	netRules  NetRuleSet
	logf      func(string, ...any)
	resources *resourceCache
	egress    *egressLease
}

func processSpec(opts StartOptions, logf func(string, ...any)) confineSpec {
	return confineSpec{workdir: opts.Workdir, argv: opts.Exec, fsRules: opts.Policy.FS, netRules: opts.Policy.Net, logf: logf}
}

func (s confineSpec) denyPatterns() []string {
	dead := ineffectiveRuleSet(s.fsRules.Rules)
	var out []string
	for i, r := range s.fsRules.Rules {
		if r.Effect == EffDeny && !dead[i] {
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
		if strings.ContainsAny(p, "*?") {
			continue
		}
		decision := s.fsRules.Match(p, OpWrite)
		if decision.Allow && decision.Effect == EffRW {
			out = append(out, p)
		}
	}
	return out
}

func ineffectiveRuleSet(rules []Rule) map[int]bool {
	rows := IneffectiveRows(rules)
	if len(rows) == 0 {
		return nil
	}
	out := make(map[int]bool, len(rows))
	for _, i := range rows {
		out[i] = true
	}
	return out
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
// prlimitArgs 构建 Linux 资源限制参数段（prlimit --AS=... -- ...）。
// bwrap 本身没有 --rlimit 选项（0.11~0.13 实测均报 Unknown option），
// 故限制由 util-linux prlimit 在 exec 前对 bwrap 及其子孙进程落实
// （soft=hard，跨 exec 继承）；与文件隔离正交、read-only 与
// workspace-write 同限（resourceLimit* 常量统一语义）。
func prlimitArgs() []string {
	return []string{
		"prlimit",
		"--as=" + strconv.FormatUint(uint64(resourceLimitAS), 10),
		"--nofile=" + strconv.Itoa(resourceLimitNoFile),
		"--cpu=" + strconv.Itoa(resourceLimitCPU),
		"--fsize=" + strconv.FormatUint(uint64(resourceLimitFSize), 10),
		"--core=0",
		"--",
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

// evaluateFSPolicy 是「先求值后落措施」（W3，aic/docs/reference/permission.md「内核层映射」）的单一
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
	dead := ineffectiveRuleSet(rules.Rules)
	for i, r := range rules.Rules {
		if r.Effect == EffDeny || dead[i] {
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

// ---- darwin: Seatbelt (sandbox-exec) ----

// macosSeatbeltExecutable 是 sandbox-exec 的固定路径（防 PATH 注入：
// 若 /usr/bin/sandbox-exec 被篡改，攻击者已 root）。
const macosSeatbeltExecutable = "/usr/bin/sandbox-exec"

// seatbeltArgs 将文件与网络规则映射到 SBPL，保持 level + 原表序语义。
func seatbeltArgs(spec confineSpec) ([]string, error) {
	netForms, err := seatbeltNetForms(spec)
	if err != nil {
		return nil, err
	}
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
	forms = append(forms, netForms...)
	{
		// level + 原表序 → SBPL 后命中胜：低 level 先输出，同 level 原表
		// 后行先输出。AF_UNIX connect 不走 file-* 判定（实测 2026-09-05）。
		type indexedRule struct {
			rule  Rule
			index int
		}
		rows := make([]indexedRule, len(spec.fsRules.Rules))
		for i, r := range spec.fsRules.Rules {
			rows[i] = indexedRule{rule: r, index: i}
		}
		sort.Slice(rows, func(i, j int) bool {
			if rows[i].rule.Level != rows[j].rule.Level {
				return rows[i].rule.Level < rows[j].rule.Level
			}
			return rows[i].index > rows[j].index
		})
		for _, row := range rows {
			r := row.rule
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
	return append([]string{macosSeatbeltExecutable, "-p", stringsJoin(forms), "--"}, spec.argv...), nil
}

// sbplFilter 把 vbox 规则模式转为 SBPL 过滤形：裸模式（无 *?）= subpath 字面
// （语义 ≡ 自身+子树，与 vbox matcher 裸路径口径一致）；glob = regex。
func sbplFilter(pat string) string {
	if strings.ContainsAny(pat, "*?") {
		return "(regex " + sbplString(globToSBPLRegex(pat)) + ")"
	}
	return "(subpath " + sbplString(pat) + ")"
}

// seatbeltNetForms 与 CheckNetPolicy 共用 compileNetPlan；这里只负责把
// 计划中的 loopback 内核项转成 SBPL，不重写优先级或能力判断。
func seatbeltNetForms(spec confineSpec) ([]string, error) {
	var transport []string
	if spec.egress != nil && spec.egress.endpoint != nil {
		transport = append(transport, spec.egress.endpoint.httpAddr, spec.egress.endpoint.socksAddr)
	}
	plan, err := compileNetPlan("darwin", spec.netRules, netCapsForPlatform("darwin"), transport...)
	if err != nil {
		return nil, err
	}
	var forms []string
	if !spec.netRules.Default {
		forms = append(forms, "(deny network-inbound)", "(deny network-outbound)")
	}
	for _, r := range plan.kernelRules {
		e, err := ParseRuleEntry(r.HostPort)
		if err != nil {
			return nil, err
		}
		verb := "deny"
		if r.Allow {
			verb = "allow"
		}
		forms = append(forms, seatbeltEntryForms(e, verb)...)
	}
	return forms, nil
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
	h = CanonicalNetHost(h)
	return h == "localhost" || h == "*.localhost"
}

func stringsJoin(forms []string) string {
	return strings.Join(forms, " ")
}

// grantRootSIDs 逐根独立授权：任一目录授不上只降级该根（该根在沙箱内只读），
// 不中断整个 exec。sidOf/grant 是平台细节（Windows = 能力 SID + ACL 授权），
// 逻辑本身（逐根重试、去重、失败只告警一次、不给负缓存）与平台无关，因此放在
// 本文件——无 Windows 的机器与 CI 也能覆盖这段语义。
//
// 判据：写白名单的失败方向是「更严」——能力 SID 少一个只让写更多被拒
// （restricting 列表只收不放）；反向的「更宽」失败（deny ACE 落不下、令牌/
// 私有临时目录不可用）在调用方仍然 fatal。把一个本地目录问题放大成「所有 exec
// 全废」是过度惩罚，也让可查的问题变成不可查。
//
// 每次调用都仍尝试授权（不引入负缓存）：目录被删重建、或 ACL 事后修好时自动
// 恢复；日志按目录去重，避免热路径刷屏。
func grantRootSIDs[T any](dirs []string, sidOf func(string) (T, error),
	grant func(string, T) error, logf func(string, ...any)) []T {
	var sids []T
	seen := make(map[string]bool, len(dirs))
	for _, d := range dirs {
		if d == "" || seen[d] {
			continue
		}
		seen[d] = true
		sid, err := sidOf(d)
		if err == nil {
			err = grant(d, sid)
		}
		if err != nil {
			logWriteRootUnavailable(d, err, logf)
			continue
		}
		sids = append(sids, sid)
	}
	return sids
}

// logWriteRootUnavailable 记录一个授不上/不可授的可写根（每个目录只告警一次）。
// 标记固定，便于现场按 "write-root unavailable in sandbox" 检索——降级是静默
// 的，可发现性只能靠这条日志与 grant fs / grant status 的提示。
var (
	writeRootWarnMu   sync.Mutex
	writeRootWarnSeen = map[string]bool{}
)

func logWriteRootUnavailable(dir string, err error, logf func(string, ...any)) {
	if logf == nil {
		return
	}
	writeRootWarnMu.Lock()
	if writeRootWarnSeen[dir] {
		writeRootWarnMu.Unlock()
		return
	}
	writeRootWarnSeen[dir] = true
	writeRootWarnMu.Unlock()
	logf("vbox: write-root unavailable in sandbox: %s — writes under it will be denied inside the sandbox: %v", dir, err)
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
	if spec.fsRules.Err != nil {
		return fail("file authorization configuration: " + spec.fsRules.Err.Error())
	}
	for _, r := range spec.fsRules.Rules {
		if r.Pattern == "" || r.Effect > EffRW {
			return fail("invalid file rule")
		}
		// 动态行（Resolve 回调）是进程内判定，OS 后端只能表达静态效果——
		// 拿 Effect 当终局会与真实判定不一致（可能更宽松），必须拒启。
		if r.Resolve != nil {
			return fail("dynamic (resolve) file rule is process-local only: " + r.Pattern)
		}
	}
	if spec.fsRules.DefaultWrite != EffDeny && spec.fsRules.DefaultWrite != EffRW {
		return fail("invalid default file permission")
	}
	if platform == "windows" && spec.fsRules.DefaultWrite == EffRW {
		return fail("this Windows backend cannot enforce fs_policy=open writable-everything")
	}
	// net 域按平台能力分类（CheckNetPolicy）：不可落实且不可吸收的行拒启
	//（永不比策略更宽）；被吸收的行记日志（收窄方向的 no-op 说明）。
	landings, err := CheckNetPolicy(platform, spec.netRules)
	if err != nil {
		if IsUnsupported(err) {
			return fail(err.Error())
		}
		return err
	}
	for _, l := range landings {
		if l.Absorbed && spec.logf != nil {
			spec.logf("net rule absorbed by launch plan: %s — %s", l.Rule.String(), l.Reason)
		}
	}
	if platform == "linux" {
		dead := ineffectiveRuleSet(spec.fsRules.Rules)
		for i, r := range spec.fsRules.Rules {
			if !dead[i] && r.Effect == EffRW && strings.ContainsAny(strings.TrimSuffix(r.Pattern, "/**"), "*?") {
				return fail("Linux mount confinement cannot enforce this path glob: " + r.Pattern)
			}
		}
	}
	return nil
}
