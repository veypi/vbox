// Native processes enforce the host execution policy independently of runtime
// approval. Reads are open (deny always wins); writes are additive allow scopes,
// and cwd grants no access. A backend that cannot enforce a rule rejects execution.
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

// protectedMetadataNames 是工作区可写时仍保持只读的敏感子路径名
// （借鉴 codex：.git 防 AI 破坏仓库元数据/历史；可扩展 .agents 等）。
// 沙箱内 git 写操作（add/commit）会失败——AI 可经审批 9 免沙箱执行。
// linux 有效性实测（2026-08-14，bwrap / Debian 13）：沙箱内嵌套
// `unshare -rm` 后 umount ro-bind 覆盖、re-bind 工作区两种逃逸均被内核
// 挂载归属规则拒绝（挂载属于父 userns，嵌套 ns 内无 CAP_SYS_ADMIN 可操作）
// ——ro-bind 覆盖是有效边界，非纸面加固。
var protectedMetadataNames = []string{".git"}

// publicRoots 返回公共可写区（pod 侧 $HOME/.aic，经 PublicRootsFn 注入）：
// workspace-write 白名单成员之一，与工作区/缓存/临时区并列——AI 跨会话保存产物
// 与工具状态落盘（browser state save 等）共用；未注入返回 nil（白名单宁缺毋滥）。
// 实现见 hooks.go。

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
//     exec_procs 关闭——子进程持有令牌副本）
//   - job：windows Job Object 句柄（资源限制：内存/进程数；其他平台恒 0；
//     spawn 成功后由 exec_procs assign 子进程，进程结束后随 cleanup 关闭）
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
	workdir    string               // 进程 cwd，不授予目录权限
	extra      []string             // 追加可写根（nil = 仅基础白名单；fsRules 非空时 darwin 不消费）
	argv       []string             // 被包装命令
	deny       []string             // fs deny 预展开模式（fsauth.DenyPatterns 快照；fsRules 为空时使用）
	fsRules    *FSRuleSet           // fs 域 vbox 快照（first-wins；darwin 逆序输出映射 SBPL 后规则胜，nil = 旧 deny 全量 fail-closed）
	writeAllow []string             // 展开的可写 glob（裸路径由 extra 传入；fsRules 非空时 darwin 不消费）
	fsOpen     bool                 // fs_policy=open：写除 deny 全放（darwin allow file-write* / bwrap 整机 rw）
	netOpen    bool                 // net_policy=open：不加网络规则
	netDeny    []Entry              // net_deny 快照（恒优先于 allow）
	netAllow   []Entry              // net allow 快照（含内建 localhost:* 与 sid 临时 grant）
	logf       func(string, ...any) // 沙箱阶段计时日志注入（nil = 静默；SetLogf → 生产注入）
}

// Confine 将 argv 包装为沙箱执行形态（返回替换 argv；windows 的实际
// confined 路径走 planConfined 的令牌注入，本函数仅供非 windows 调用与
// 统一测试）。沙箱 profile 由 rules 派生（hosts-vsh-redesign：数字等级
// 已删除）；免沙箱不经本函数表达（StartOptions.NoSandbox）。
// 无可用后端返回错误（fail-closed），绝不返回未包装 argv。
// deny/net 快照恒零值：现调用方仅测试；生产路径必须走 Start（StartOptions
// 授权快照字段），否则 deny 隔离与网络管控静默缺失。
func Confine(workdir string, argv []string) ([]string, error) {
	plan, err := planConfined(confineSpec{workdir: workdir, argv: argv, netOpen: true})
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
//   - protectedReadonly：可写根下的敏感子路径（.git 等）以 --ro-bind 覆盖
//     为只读（bwrap 后绑定覆盖前绑定）
//   - denyTargets：deny 模式实例化后的覆盖目标（不存在的目标已在实例化时
//     跳过）
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
// EINVAL（实测 2026-08-28）——大内存分配由 exec_procs 进程组 RSS 监控
// 兜底（rss_darwin.go）。不设 -u（RLIMIT_NPROC 按 UID 全系统计数，桌面
// 常驻进程即超限，见常量块注释）。单位：-n fd、-t CPU 秒、-f 512B 块、-c core。
func confineRlimits(argv []string) []string {
	script := fmt.Sprintf(
		"ulimit -n %d -t %d -f %d -c 0 2>/dev/null || exit 1; exec \"$@\"",
		resourceLimitNoFile, resourceLimitCPU, resourceLimitFSize>>9)
	return append([]string{"/bin/sh", "-c", script, "sh"}, argv...)
}

func bwrapArgs(spec confineSpec, cacheDirs []string, protectedReadonly []string, denyTargets []string) []string {
	// 读默认开放：整机 ro-bind 读视图；fs_policy=open（写级）整机 rw bind。
	// deny 覆盖挂载在末尾追加，恒优先。
	args := []string{"bwrap"}
	flag := "--ro-bind"
	if spec.fsOpen {
		flag = "--bind"
	}
	args = append(args, flag, "/", "/")
	args = append(args, "--dev", "/dev", "--proc", "/proc", "--die-with-parent")
	if !spec.netOpen {
		// net_policy=deny：--unshare-net 全断（新 net ns 仅 loopback 且未配置——
		// loopback 也不可用）。bwrap 无 per-destination 规则引擎，白名单粒度
		// linux 不生效（近似层，net_allow 仅 darwin 落地；见 host_sandbox.md）。
		args = append(args, "--unshare-net")
	}
	args = append(args, rlimitArgs()...)
	// 沙箱 profile 由 rules 派生（数字等级已删除）：临时区/缓存/可写根一律放行。
	args = append(args, "--tmpfs", "/tmp")
	for _, d := range append(append([]string{}, cacheDirs...), literalWriteRoots(spec.writeAllow)...) {
		if d != "" {
			args = append(args, "--bind", d, d)
		}
	}
	for _, p := range protectedReadonly {
		if p != "" {
			args = append(args, "--ro-bind", p, p)
		}
	}
	// deny 隔离覆盖（§5.10）：后挂载优先（bwrap 后绑定覆盖前绑定），
	// 追加在全部 bind 之后；read-only 与 workspace-write 同隔离。
	args = append(args, bwrapDenyArgs(denyTargets)...)
	return append(append(args, "--"), spec.argv...)
}

// bwrapDenyArgs overlays pre-instantiated deny targets after allow mounts.
func bwrapDenyArgs(targets []string) []string {
	var args []string
	for _, p := range targets {
		if p == "" {
			continue
		}
		args = append(args, overlayArgs(p)...)
	}
	return args
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

// seatbeltArgs locks writes to the granted scopes (reads stay open) and emits
// the fs rule table. SBPL 后规则胜（last matching rule wins；2026-09-23 探针
// 复核）：fsRules（vbox first-wins 快照）非空时**逆序**逐行输出（表尾先行）
// ——首命中语义与 SBPL 后命中等价（temp 行最后输出 = 内核最先生效；便利根最
// 先输出，builtin/cfg deny 在其上，"便利不压 deny"保持）；空则退回旧口径
// （deny 行全量 fail-closed，仅非生产直调路径使用）。
func seatbeltArgs(spec confineSpec) []string {
	forms := []string{
		"(version 1)",
		"(allow default)",
		"(deny file-write*)",
		`(allow file-write* (literal "/dev/null"))`,
	}
	if spec.fsOpen {
		// fs_policy=open：写全放（表内 deny 行在后输出，继续生效）。
		forms = append(forms, "(allow file-write*)")
	} else if spec.fsRules == nil {
		// legacy 直调路径：fsRules 非空时 extra/writeAllow 已编码在快照
		// （便利根/cfg 行）内，不重复输出。
		for _, root := range spec.extra {
			forms = append(forms, "(allow file-write* (subpath "+sbplString(root)+"))")
		}
		for _, pat := range spec.writeAllow {
			forms = append(forms, "(allow file-write* (regex "+sbplString(globToSBPLRegex(pat))+"))")
		}
	}
	forms = append(forms, seatbeltNetForms(spec)...)
	if spec.fsRules != nil {
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
				forms = append(forms,
					"(allow file-read* "+filter+")",
					"(allow network-outbound (remote unix "+filter+"))")
			case EffRW:
				forms = append(forms,
					"(allow file-read* "+filter+")",
					"(allow network-outbound (remote unix "+filter+"))",
					"(allow file-write* "+filter+")")
			}
		}
	} else {
		for _, pat := range spec.deny {
			if pat == "" {
				continue
			}
			re := sbplString(globToSBPLRegex(pat))
			forms = append(forms, "(deny file-read* (regex "+re+"))")
			forms = append(forms, "(deny file-write* (regex "+re+"))")
			forms = append(forms, "(deny network-outbound (remote unix (regex "+re+")))")
		}
	}
	if spec.workdir != "" && !isGitArgv(spec.argv) {
		for _, name := range protectedMetadataNames {
			p := filepath.Join(spec.workdir, name)
			forms = append(forms, "(deny file-write* (subpath "+sbplString(canonicalRoot(p))+"))")
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

// seatbeltNetForms 生成网络管控段（net_policy=deny 锁定模式时；open 模式零规则，
// allow default 兜底）：
//
//	(deny network-inbound)(deny network-outbound) 打底
//	→ net_allow 逐条放行（2026-09-07 实测：seatbelt 网络过滤器 host 只支持
//	  */localhost——按目标 IP/域名的内核级放行不存在；loopback 条目发
//	  localhost 两形态（remote tcp 连通 + local tcp inbound bind/listen）；
//	  非 loopback 条目退化为 *:port 按端口粗放行；port=* 不可表达跳过——
//	  精细 host:port 判定由 curl 虚拟指令工具层承担（shellCurlFetcher 前置
//	  netauth.Allowed 闸 + --resolve 钉住，见 fetcher.go））
//	→ net_deny 逐条 deny（恒优先——过滤规则与兜底 deny 共存实测互不干扰）；
//	  仅 loopback 条目落地（对抗内建 localhost:* allow）；非 loopback deny
//	  不输出（基线全拒已覆盖，host 粒度内核不可表达，工具层 curl 闸精判
//	  兜底——避免 *:port 株连同端口 allow 目标，见 seatbeltEntryForms）
//
// 实测纪律（2026-09-07 探针）：
//   - `(allow network-outbound (local tcp "localhost:*"))` 是毒形态——其语义
//     覆盖一切出站连接（本地端恒命中），等于拆掉整个 deny outbound，严禁输出；
//   - `(remote unix ...)` 必须 regex 形态（裸字符串参数非法）；
//   - deny network* 下系统 DNS（mDNSResponder/dnssd mach+XPC+unix socket
//     组合）实测多轮放行均不生效——锁定模式等于无沙箱内 DNS，FQDN 目标由
//     工具层 pod 侧解析 + curl --resolve 钉住补偿；
//   - 规则顺序对本段不重要（过滤规则与兜底 deny 各测其序），但 deny 表（文件/
//     unix socket）仍在本段之后输出（旧教训不回收）。
func seatbeltNetForms(spec confineSpec) []string {
	if spec.netOpen {
		var forms []string
		for _, e := range spec.netDeny {
			forms = append(forms, seatbeltEntryForms(e, "deny")...)
		}
		return forms
	}
	forms := []string{
		"(deny network-inbound)",
		"(deny network-outbound)",
	}
	for _, e := range spec.netAllow {
		forms = append(forms, seatbeltEntryForms(e, "allow")...)
	}
	for _, e := range spec.netDeny {
		forms = append(forms, seatbeltEntryForms(e, "deny")...)
	}
	return forms
}

// seatbeltEntryForms 把一条 netauth 条目实例化为 SBPL 规则（粒度限制与实测
// 纪律见 seatbeltNetForms 注释）：
//   - loopback（localhost/127.0.0.1/::1）：allow 发 remote tcp（连通）+
//     local tcp inbound（bind/listen，本机服务场景）两形态；deny 仅 remote tcp
//     （对抗内建 localhost:* allow，localhost 内核可精判）；
//   - 非 loopback allow：退化为 *:port（host 必须为 */localhost，按端口放行）；
//     port=* 内核不可表达，跳过（工具层 curl 闸仍按 host:port 精判）；
//   - 非 loopback deny：不输出内核规则——锁定模式基线本就是全拒，此类规则
//     唯一作用是对抗同端口 allow 的 *:port 粗放行，但内核无 host 粒度必然
//     株连同端口的 allow 目标（显式放行被无关 deny 打死，2026-09-07 评审）；
//     精细 host 判定由工具层 curl 闸承担，不假装内核能表达。
func seatbeltEntryForms(e Entry, verb string) []string {
	if isLoopbackHost(e.Host) {
		addr := sbplString("localhost:" + e.Port)
		if verb == "deny" {
			return []string{"(deny network-outbound (remote tcp " + addr + "))"}
		}
		return []string{
			"(allow network-outbound (remote tcp " + addr + "))",
			"(allow network-inbound (local tcp " + addr + "))",
		}
	}
	if verb == "deny" || e.Port == "*" {
		return nil
	}
	return []string{"(allow network-outbound (remote tcp " + sbplString("*:"+e.Port) + "))"}
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

// canonicalRoot 消解路径到真实文件系统身份（symlink/.. 展开；失败回落绝对路径）。
func canonicalRoot(p string) string {
	if r, err := filepath.EvalSymlinks(p); err == nil {
		return r
	}
	if abs, err := filepath.Abs(p); err == nil {
		return abs
	}
	return p
}

// isGitArgv 判定被包装命令是否为 git 自身（argv[0] basename 匹配）。
// .git 只读覆盖的保护对象是 bash/rm 等通用命令，git 不应被误伤；
// bash -c "git ..." 不豁免（走 git 命令本身，或审批 9 免沙箱）。
func isGitArgv(argv []string) bool {
	if len(argv) == 0 {
		return false
	}
	base := filepath.Base(argv[0])
	return base == "git" || base == "git.exe"
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

// mergeEnv 把附加环境并入继承环境：同名键以附加值为准（替换而非追加——
// Windows CreateProcess 对重复变量名取首个，必须过滤；unix 平台 plan.env
// 恒 nil，本函数仅 windows 受限令牌的 TMP/TEMP 注入使用）。
func mergeEnv(extra []string) []string {
	if len(extra) == 0 {
		return nil
	}
	drop := map[string]bool{}
	for _, kv := range extra {
		if i := strings.IndexByte(kv, '='); i > 0 {
			drop[kv[:i]] = true
		}
	}
	base := os.Environ()
	env := make([]string, 0, len(base)+len(extra))
	for _, kv := range base {
		if i := strings.IndexByte(kv, '='); i > 0 && drop[kv[:i]] {
			continue
		}
		env = append(env, kv)
	}
	return append(env, extra...)
}

// validateProcessPolicy fails before execution when a backend cannot enforce the
// requested scope. Never approximate host rules by opening all hosts or paths.
func validateProcessPolicy(spec confineSpec, platform string) error {
	fail := func(why string) error {
		return &DeniedError{Reason: "sandbox cannot enforce host policy: " + why}
	}
	if platform == "windows" {
		// 受限令牌 + ACL 模型：写白名单（fs_policy=deny）与 deny ACE 均可落地；
		// 写全放（fs_policy=open 写级）与网络规则无法表达 → 拒绝执行。
		if spec.fsOpen {
			return fail("this Windows backend cannot enforce fs_policy=open writable-everything")
		}
		if !spec.netOpen || len(spec.netDeny) > 0 {
			return fail("this Windows backend does not implement network rules")
		}
	}
	for _, e := range spec.netDeny {
		if platform != "darwin" || !isLoopbackHost(e.Host) {
			return fail("selective network deny is unsupported by this backend")
		}
	}
	if !spec.netOpen {
		for _, e := range spec.netAllow {
			if platform != "darwin" || !isLoopbackHost(e.Host) {
				return fail("selective network allow is unsupported by this backend")
			}
		}
	}
	if platform == "linux" {
		// 写 glob 需可实例化为 bind 目标；deny 的形态可实例化性由
		// denyCoverAll（planConfined 内）判定——不可实例化即拒绝执行。
		for _, p := range spec.writeAllow {
			if strings.ContainsAny(strings.TrimSuffix(p, "/**"), "*?") {
				return fail("Linux mount confinement cannot enforce this path glob: " + p)
			}
		}
	}
	return nil
}

func literalWriteRoots(patterns []string) []string {
	roots := make([]string, 0, len(patterns))
	for _, p := range patterns {
		roots = append(roots, strings.TrimSuffix(p, "/**"))
	}
	return roots
}
