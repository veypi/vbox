//go:build !windows && !unix

package vbox

import (
	"io"
	"os/exec"
)

// 本平台（既不是 windows 也不是 unix）没有进程组/信号语义：这里只提供编译期
// 需要的空实现，让包能编过；实际启动进程时由引擎层报错（fail-closed，不静默
// 降级成"不沙箱"）。支持的平台见 README「平台支持」。

// newOutputWriter 原样直写。
func newOutputWriter(w io.Writer) io.Writer { return w }

// SetSysProcAttr 无平台子进程属性可设（no-op）。
func SetSysProcAttr(cmd *exec.Cmd) {}

// applyToken 无令牌注入（恒 0，no-op）。
func applyToken(cmd *exec.Cmd, token uintptr) error { return nil }

// closeToken 无句柄可关（no-op）。
func closeToken(token uintptr) {}

// assignJob 无 Job Object（no-op）。
func assignJob(pid int, job uintptr) error { return nil }

// closeJob 无句柄可关（no-op）。
func closeJob(job uintptr) {}

// killProc 本平台无信号语义：只置位完成状态（进程若真在跑，由 ctx 取消承担）。
func killProc(h *procHandle) {}

// killProcessTree 本平台无进程组：无法按树终止（no-op）。
func killProcessTree(pid int) {}
