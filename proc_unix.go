//go:build unix

package vbox

import (
	"io"
	"os/exec"
	"syscall"
	"time"
)

// newOutputWriter 非 Windows 平台原样直写（子进程输出本就是 UTF-8）。
func newOutputWriter(w io.Writer) io.Writer { return w }

// SetSysProcAttr 设置子进程属性：独立进程组（killEntry 按进程组终止）。
func SetSysProcAttr(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
}

// applyToken 无令牌注入（非 windows 平台恒 0，no-op）。
func applyToken(cmd *exec.Cmd, token uintptr) error { return nil }

// closeToken 无句柄可关（非 windows 平台恒 0，no-op）。
func closeToken(token uintptr) {}

// assignJob 无 Job Object（非 windows 平台恒 no-op；资源限制由 prlimit
// 包装 bwrap / sh ulimit 承担）。
func assignJob(pid int, job uintptr) error { return nil }

// closeJob 无句柄可关（非 windows 平台恒 no-op）。
func closeJob(job uintptr) {}

// killProc 终止一次运行：子进程先对整个进程组发 SIGTERM，5s 未退出补
// SIGKILL。尚未 spawn（pid=0）时无进程可杀——调用方 ctx 取消由
// CommandContext 承担。
func killProc(h *procHandle) {
	if h.PID() > 0 {
		// 进程组杀死（Setpgid 使 pgid == pid）
		_ = syscall.Kill(-h.PID(), syscall.SIGTERM)
		go func() {
			timer := time.NewTimer(5 * time.Second)
			<-timer.C
			select {
			case <-h.done:
			default:
				_ = syscall.Kill(-h.PID(), syscall.SIGKILL)
			}
		}()
	}
}

func killProcessTree(pid int) { _ = syscall.Kill(-pid, syscall.SIGKILL) }
