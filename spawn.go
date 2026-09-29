package vbox

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"sync"
)

// Spawn 以统一沙箱形态启动子进程并返回其 stdout 流（vcore curl 改道 shell curl
// 等进程内消费场景）：与 Start 共享沙箱包装/env 清洗/令牌注入，但不经任务托管
// （无日志落盘/无后台化/无 RSS 监控）——生命周期由 ctx 控制（ctx 取消即杀进程）。
// 调用方必须消费 Body 至 EOF 或调 Abort（否则子进程僵尸）。
func (m *Manager) Spawn(ctx context.Context, opts StartOptions) (*Spawned, error) {
	if len(opts.Exec) == 0 || strings.TrimSpace(opts.Exec[0]) == "" {
		return nil, fmt.Errorf("exec: program name is required")
	}
	if _, err := exec.LookPath(opts.Exec[0]); err != nil {
		return nil, fmt.Errorf("exec: unknown action %q", opts.Exec[0])
	}

	plan := launchPlan{}
	execArgv := opts.Exec
	confined := !opts.NoSandbox && !m.noSandbox.Load()
	if confined {
		var err error
		plan, err = planConfined(confineSpec{
			workdir: opts.Workdir, extra: opts.WriteRoots, argv: opts.Exec,
			deny: opts.DenyPaths, fsOpen: opts.FsOpen,
			writeAllow: opts.WritePaths,
			netOpen:    opts.NetOpen, netDeny: opts.NetDeny, netAllow: opts.NetAllow,
		})
		if err != nil {
			return nil, err
		}
		execArgv = plan.argv
	}

	cmd := exec.CommandContext(ctx, execArgv[0], execArgv[1:]...)
	cmd.Dir = opts.Workdir
	cmd.Env = mergeEnv(plan.env)
	if confined {
		// env 清洗：与 Start 同语义（沙箱进程剥离敏感变量；nosandbox 不清洗）。
		if cmd.Env == nil {
			cmd.Env = os.Environ()
		}
		cmd.Env = ScrubEnv(cmd.Env)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("exec: stdout pipe: %v", err)
	}
	stderr := &tailBuffer{limit: 4096}
	cmd.Stderr = stderr
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, fmt.Errorf("exec: stdin pipe: %v", err)
	}
	SetSysProcAttr(cmd)
	if plan.token != 0 {
		if err := applyToken(cmd, plan.token); err != nil {
			closeToken(plan.token)
			if plan.cleanup != nil {
				plan.cleanup()
			}
			return nil, fmt.Errorf("exec: apply token: %v", err)
		}
	}
	if err := cmd.Start(); err != nil {
		_ = stdin.Close() // Start 失败路径管道由调用方兜底（Wait 不会跑）
		_ = stdout.Close()
		closeToken(plan.token)
		if plan.cleanup != nil {
			plan.cleanup()
		}
		return nil, fmt.Errorf("exec: %v", err)
	}
	closeToken(plan.token) // spawn 成功后令牌句柄可释放（子进程持有副本）
	if plan.job != 0 {
		if err := assignJob(cmd.Process.Pid, plan.job); err != nil {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
			if plan.cleanup != nil {
				plan.cleanup()
			}
			return nil, fmt.Errorf("exec: assign job object: %v", err)
		}
	}
	return &Spawned{Stdin: stdin, stdout: stdout, stderr: stderr, cmd: cmd, plan: plan}, nil
}

// Spawned 是 Spawn 返回的管道进程句柄。
type Spawned struct {
	Stdin  io.WriteCloser
	stdout io.ReadCloser
	stderr *tailBuffer
	cmd    *exec.Cmd
	plan   launchPlan
	waited bool
	wmu    sync.Mutex
}

// Body 返回进程的 stdout 流：读至 EOF 时若进程非零退出，Read 返回带 stderr
// 摘要的退出错误（而非 io.EOF）——流式消费方（io.Copy）据此感知失败。
func (s *Spawned) Body() io.ReadCloser { return &spawnBody{s: s} }

// Wait 等待进程结束（幂等）：非零退出返回带 stderr 摘要的错误。
func (s *Spawned) Wait() error {
	s.wmu.Lock()
	if s.waited {
		s.wmu.Unlock()
		return nil
	}
	s.waited = true
	s.wmu.Unlock()
	err := s.cmd.Wait()
	if s.plan.cleanup != nil {
		s.plan.cleanup()
	}
	if err == nil {
		return nil
	}
	tail := strings.TrimSpace(s.stderr.String())
	if tail == "" {
		return err
	}
	return fmt.Errorf("%v: %s", err, tail)
}

// Abort 提前终止进程（调用方超限中止等）；幂等。
func (s *Spawned) Abort() {
	if s.cmd.Process != nil {
		_ = s.cmd.Process.Kill()
	}
	_ = s.Wait()
}

// spawnBody 包装 stdout：EOF 时汇合退出状态。
type spawnBody struct {
	s     *Spawned
	eof   bool
	close bool
}

func (b *spawnBody) Read(p []byte) (int, error) {
	if b.close {
		return 0, io.EOF
	}
	if b.eof {
		// EOF 后必须持续返回 io.EOF：把 Wait 的 nil 当作错误返回会给出 (0, nil)，
		// 消费端（io.Copy）会无限空转（短体量 curl 任务永不完成、回包拖到 wait 到期的回归）。
		if err := b.s.Wait(); err != nil {
			return 0, err
		}
		return 0, io.EOF
	}
	n, err := b.s.stdout.Read(p)
	if err == io.EOF {
		b.eof = true
		if werr := b.s.Wait(); werr != nil {
			return n, werr
		}
	}
	return n, err
}

// Close 提前关闭：进程仍在运行则终止（Abort 幂等）。
func (b *spawnBody) Close() error {
	b.close = true
	b.s.Abort()
	return nil
}

// tailBuffer 是限额尾部缓冲（stderr 诊断摘要：只留最后 limit 字节）。
type tailBuffer struct {
	mu    sync.Mutex
	buf   []byte
	limit int
}

func (t *tailBuffer) Write(p []byte) (int, error) {
	t.mu.Lock()
	t.buf = append(t.buf, p...)
	if len(t.buf) > t.limit {
		t.buf = t.buf[len(t.buf)-t.limit:]
	}
	t.mu.Unlock()
	return len(p), nil
}

func (t *tailBuffer) String() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return string(t.buf)
}
