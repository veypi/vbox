package vbox

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"time"
)

type StartOptions struct {
	Workdir string   // 进程 cwd（空 = 继承），不授予目录权限
	Exec    []string // argv：Exec[0] = 程序名
	// NoSandbox 是免沙箱执行标记（hosts-vsh-redesign §3.3），合法来源：
	//   - 内部管控调用方（ssh/scp、browser，由执行环境自身管控）；
	//   - 外部请求显式携带 nosandbox（发送前审批；审批本身不免沙箱，
	//     仅放行该标记）；
	//   - 全局 no_sandbox 配置（Manager.NoSandbox）。
	NoSandbox bool
	// WriteRoots 是追加可写根（统一授权模型 fs 域）：沙箱 bind 白名单成员，
	// 与 fsauth 基础白名单（工作区/临时区/会话区/公共区/缓存）并集。
	// 来源 = Policy.WriteRootsFor(sid)（cfg fs_allow + grant fs 临时授权）
	// ——fs 与 exec 共用同一份名单。每次运行读当次值（配置动态生效）；
	// nil = 仅基础白名单。
	WriteRoots []string
	// DenyPaths 是预展开的拒绝模式（deny 隔离，读写双拒）：deny 表（fsauth
	// defaultDenyPaths + cfg fs_deny）经本字段进入沙箱 profile——fs 工具与
	// exec 进程共用同一份名单。darwin 为 regex 规则；linux 为覆盖挂载
	//（目录 tmpfs / 文件与 socket 以 /dev/null 覆盖；形态不可实例化时
	// 启动前拒绝执行）。来源 = Policy.DenyPatterns()（快照，每次运行读当次值）。
	// nil = 无拒绝（仅测试/无策略场景；生产调用方恒传）。
	DenyPaths []string
	// FSRules 是 fs 域 vbox 规则表快照（first-wins：temp→cfg 反转→builtin deny
	// →便利根）：darwin 消费——逆序输出映射 SBPL 后规则胜，cfg/permanent grant
	// 的 ro/rw 洞在内核真实生效；nil = 旧 deny 全量 fail-closed 路径
	// （linux/windows 与直调探针）。来源 = fsauth.Policy.Snapshot(sid)。
	FSRules *FSRuleSet
	// WritePaths 是展开的可写 glob（fs_allow 通配条目；裸路径走 WriteRoots）。
	// 读方向无白名单：读默认开放（除 deny）。
	WritePaths []string
	// FsOpen 是 fs_policy=open 快照：写除 deny 全放（darwin allow file-write*
	// 打底 / bwrap 整机 rw bind），deny 覆盖仍生效。
	FsOpen bool
	// NetOpen 是 net_policy=open 快照：沙箱不加网络规则（现状语义）。
	NetOpen bool
	// NetDeny/NetAllow 是 net 域目标快照（netauth.Entry；allow 含内建
	// localhost:* 与 sid 临时 grant）。netOpen=false 时生效：darwin 生成
	// per-目标 allow/deny 规则（deny 恒优先）；linux --unshare-net 全断
	//（bwrap 无 per-destination 引擎，白名单粒度不生效，近似层）；
	// windows no-op。来源 = netauth.Policy.Snapshot(sid)。
	NetDeny  []Entry
	NetAllow []Entry
}

// RunProcess runs exactly one child process under the caller's context.
// stdio 全接通：stdin 供管道/载荷输入，stdout/stderr 分流写入各自 writer
// （双流日志契约——stderr 不混入 stdout；nil 表示丢弃对应流）。
// 运行期限与取消全部由 ctx 承担（exec 外层墙钟/取消句柄）。
func (m *Manager) RunProcess(ctx context.Context, opts StartOptions, stdin io.Reader, stdout, stderr io.Writer) (int, error) {
	if len(opts.Exec) == 0 {
		return 0, fmt.Errorf("exec: program required")
	}
	if _, err := exec.LookPath(opts.Exec[0]); err != nil {
		return 0, fmt.Errorf("exec: unknown action %q", opts.Exec[0])
	}
	// 沙箱包装（§3.3）：未显式免沙箱（NoSandbox）且全局未禁用（m.NoSandbox）
	// 的进程调用一律进沙箱；无可用后端时 fail-closed 返回错误
	//（命令不执行，绝不静默裸跑）。
	execArgv := opts.Exec
	var plan launchPlan
	logf := m.logFunc()
	confined := !opts.NoSandbox && !m.noSandbox.Load()
	if confined {
		var err error
		plan, err = planConfined(confineSpec{
			workdir: opts.Workdir, extra: opts.WriteRoots, argv: opts.Exec,
			deny: opts.DenyPaths, fsRules: opts.FSRules, fsOpen: opts.FsOpen,
			writeAllow: opts.WritePaths,
			netOpen:    opts.NetOpen, netDeny: opts.NetDeny, netAllow: opts.NetAllow,
			logf: logf,
		})
		if err != nil {
			return 0, err
		}
		execArgv = plan.argv
	}

	cmd := exec.CommandContext(ctx, execArgv[0], execArgv[1:]...)
	cmd.Dir = opts.Workdir
	cmd.Env = mergeEnv(plan.env)
	if confined {
		// env 清洗（v0.14.5 §2）：沙箱进程继承 host 全部环境变量，敏感变量
		//（KEY/SECRET/TOKEN/PASS/CRED 等整词标记）在此剥离——nosandbox 不清洗
		//（语义自洽：免沙箱 = 用户显式信任本次执行）。
		if cmd.Env == nil {
			cmd.Env = os.Environ()
		}
		cmd.Env = ScrubEnv(cmd.Env)
	}
	// Windows 上经逐行转码（GBK→UTF-8）后落盘，其余平台原样直写；
	// stdout/stderr 分流（诊断不污染 stdout 的 --json 契约与管道数据）。
	cmd.Stdin = stdin
	if stdout == nil {
		stdout = io.Discard
	}
	if stderr == nil {
		stderr = io.Discard
	}
	out := newOutputWriter(stdout)
	errOut := newOutputWriter(stderr)
	cmd.Stdout = out
	cmd.Stderr = errOut
	SetSysProcAttr(cmd)
	cmd.Cancel = func() error { killProcessTree(cmd.Process.Pid); return nil }
	cmd.WaitDelay = 5 * time.Second
	if plan.token != 0 {
		if err := applyToken(cmd, plan.token); err != nil {
			closeToken(plan.token)
			if plan.cleanup != nil {
				plan.cleanup()
			}
			return 0, fmt.Errorf("exec: apply token: %v", err)
		}
	}

	h := &procHandle{done: make(chan struct{})}
	defer close(h.done)
	if err := m.track(h); err != nil {
		return 0, err
	}
	defer m.untrack(h)

	spawnStart := time.Now()
	if err := cmd.Start(); err != nil {
		closeToken(plan.token)
		if plan.cleanup != nil {
			plan.cleanup()
		}
		return 0, fmt.Errorf("exec: %v", err)
	}
	// spawn 成功后令牌句柄可释放（子进程持有副本）
	closeToken(plan.token)

	// 资源限制（§5.10）：windows 立即把子进程关联进 Job Object（内存/进程数
	// 上限生效）。关联失败必须 fail-closed——杀掉已启动进程并返回错误，
	// 绝不裸跑（linux bwrap --rlimit / darwin sh ulimit 在 argv 包装内已生效）。
	if plan.job != 0 {
		if err := assignJob(cmd.Process.Pid, plan.job); err != nil {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
			if plan.cleanup != nil {
				plan.cleanup()
			}
			return 0, fmt.Errorf("exec: assign job object: %v", err)
		}
	}
	if confined && logf != nil {
		logf("exec: spawn=%s", time.Since(spawnStart).Round(time.Millisecond))
	}

	if plan.cleanup != nil {
		defer plan.cleanup()
	}
	h.pid.Store(int64(cmd.Process.Pid))
	if limit := rssLimitBytes(); limit > 0 {
		go monitorGroupRSS(h, limit)
	}
	err := cmd.Wait()
	if closer, ok := out.(interface{ Close() error }); ok {
		_ = closer.Close()
	}
	if closer, ok := errOut.(interface{ Close() error }); ok {
		_ = closer.Close()
	}
	code := 0
	if ee, ok := err.(*exec.ExitError); ok {
		code = ee.ExitCode()
		err = nil
	}
	if ctx.Err() != nil {
		err = ctx.Err()
	}
	return code, err
}
