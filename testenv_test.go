package vbox

import (
	"os"
	"os/exec"
	"runtime"
	"testing"
)

// 环境能力探测 helper：用例需要宿主提供某项能力时，缺失即 skip（说明原因），
// 而不是把环境差异报成用例失败。

// requirePOSIXShell 返回本机可用的 POSIX shell（sh → bash 顺序探测）。
// 部分用例以 shell 见证子进程的退出码/输出/取消；Windows 无自带 sh，
// 未安装 Git-Bash/WSL 等环境时跳过（2026-10-07 win 实机：exec: unknown action "sh"）。
func requirePOSIXShell(t *testing.T) string {
	t.Helper()
	for _, name := range []string{"sh", "bash"} {
		if p, err := exec.LookPath(name); err == nil {
			return p
		}
	}
	t.Skip("host has no POSIX shell (sh/bash); case needs a shell to witness child exit/output")
	return ""
}

// requireSymlink 探测能否创建符号链接（Windows 需 SeCreateSymbolicLinkPrivilege
// 或开发者模式；受限令牌子进程/"以管理员身份但未提权"的会话通常没有）。
// 不可用则跳过用例——链接语义本身由 TestMatchPathKeepsLogicalNamespace 覆盖。
func requireSymlink(t *testing.T, target, link string) {
	t.Helper()
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlink unavailable in this environment: %v", err)
	}
}

// trivialArgv 返回一个「跑完即退」的原生子命令 argv：windows 用 cmd.exe，
// 其余平台用 POSIX shell；都没有时跳过用例。用于只关心执行/规划路径（不关心
// 子进程输出）的用例，让它们在三平台都能真跑。
func trivialArgv(t *testing.T) []string {
	t.Helper()
	if runtime.GOOS == "windows" {
		if p, err := exec.LookPath("cmd"); err == nil {
			return []string{p, "/c", "exit 0"}
		}
		t.Skip("no cmd.exe on this host")
	}
	return []string{requirePOSIXShell(t), "-c", "true"}
}
