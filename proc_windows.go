//go:build windows

package vbox

import (
	"io"
	"os"
	"os/exec"
	"strconv"
	"syscall"
)

// SetSysProcAttr 抑制子进程控制台窗口（本包直连起进程点用）：
// GUI 进程（-H windowsgui）无控制台，Windows 会为 CUI 子进程（bash/git/node）
// 新分配一个控制台窗口（每执行一次命令闪一次黑框）——CREATE_NO_WINDOW 不为
// 子进程分配控制台窗口（输出本就重定向到日志文件，无影响），HideWindow 双保险。
// 0x08000000 = CREATE_NO_WINDOW（stdlib syscall 不导出该常量，用字面量避免引入依赖）。
func SetSysProcAttr(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{
		HideWindow:    true,
		CreationFlags: 0x08000000,
	}
}

// newOutputWriter Windows 上经逐行转码（UTF-8 直写 / GBK 解码）后落盘，
// 解决中文系统 cmd/PowerShell 输出乱码（见 output.go 注释）。
func newOutputWriter(w io.Writer) io.Writer {
	return &windowsOutputWriter{w: w}
}

// killProc 终止一次运行（Windows 用 TerminateProcess 进程树）。
func killProc(h *procHandle) {
	if h.PID() > 0 {
		killProcessTree(h.PID())
	}
}

func killProcessTree(pid int) {
	// taskkill /T also terminates descendants of unsandboxed commands.
	cmd := exec.Command("taskkill.exe", "/PID", strconv.Itoa(pid), "/T", "/F")
	SetSysProcAttr(cmd)
	if cmd.Run() == nil {
		return
	}
	if p, err := os.FindProcess(pid); err == nil {
		_ = p.Kill()
	}
}
