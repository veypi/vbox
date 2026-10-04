package vbox

import (
	"context"
	"fmt"
	"io"
	"os/exec"
	"runtime"
	"time"
)

type StartOptions struct {
	Workdir string   // 进程 cwd（空 = 继承），不授予目录权限
	Exec    []string // argv：Exec[0] = 程序名
	// Argv0 changes argv[0] only. Confined Unix launchers reject overrides.
	Argv0 *string
	// Env 追加/覆盖环境变量（KEY=VALUE，同名以本字段为准）：在沙箱 env
	// 清洗之后应用——skill service 的 SKILLPROC_SOCKET 等协议变量经此
	// 下发，保证沙箱内外都存活。ReplaceEnv=false 时 nil = 继承现状。
	Env []string
	// ReplaceEnv makes Env authoritative, including an intentionally empty environment.
	ReplaceEnv bool
	// RawOutput preserves bytes and write errors without line buffering or
	// Windows code-page conversion. Protocol pipes and binary tools require it.
	RawOutput bool
	// NoSandbox 是免沙箱执行标记（hosts-vsh-redesign §3.3），合法来源：
	//   - 内部管控调用方（ssh/scp、browser，由执行环境自身管控）；
	//   - 外部请求显式携带 nosandbox（发送前审批；审批本身不免沙箱，
	//     仅放行该标记）；
	//   - 全局 no_sandbox 配置（Manager.NoSandbox）。
	NoSandbox bool
	Policy    Policy // 文件与网络权限的唯一输入
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
	if confined && opts.Argv0 != nil && runtime.GOOS != "windows" {
		return 0, fmt.Errorf("exec: custom argv0 is not supported by this sandbox launcher")
	}
	if confined {
		var err error
		plan, err = planConfined(processSpec(opts, logf))
		if err != nil {
			return 0, err
		}
		execArgv = plan.argv
	}

	cmd := exec.CommandContext(ctx, execArgv[0], execArgv[1:]...)
	if opts.Argv0 != nil {
		cmd.Args[0] = *opts.Argv0
	}
	cmd.Dir = opts.Workdir
	inherited := cmd.Environ()
	if opts.ReplaceEnv {
		inherited = []string{}
	}
	cmd.Env = processEnv(inherited, plan.env, opts.Env, confined)
	// Windows 上经逐行转码（GBK→UTF-8）后落盘，其余平台原样直写；
	// stdout/stderr 分流（诊断不污染 stdout 的 --json 契约与管道数据）。
	cmd.Stdin = stdin
	if stdout == nil {
		stdout = io.Discard
	}
	if stderr == nil {
		stderr = io.Discard
	}
	out, errOut := stdout, stderr
	if !opts.RawOutput {
		out, errOut = newOutputWriter(stdout), newOutputWriter(stderr)
	}
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
	if plan.cleanup != nil {
		defer plan.cleanup()
	}
	h.pid.Store(int64(cmd.Process.Pid))
	if limit := rssLimitBytes(); limit > 0 {
		go monitorGroupRSS(h, limit)
	}
	err := cmd.Wait()
	// Caller-owned streams must remain open; only flush wrappers we created.
	if !opts.RawOutput && runtime.GOOS == "windows" {
		if closer, ok := out.(interface{ Close() error }); ok {
			_ = closer.Close()
		}
		if closer, ok := errOut.(interface{ Close() error }); ok {
			_ = closer.Close()
		}
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
