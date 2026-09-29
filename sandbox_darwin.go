//go:build darwin

package vbox

import (
	"context"
	"os"
	"os/exec"
)

// probeBackend（darwin）：sandbox-exec（Seatbelt）功能性探测——真跑一次
// read-only profile，exit 0 = profile 被内核接受并强制。固定 /usr/bin 路径
// （防 PATH 注入）；Apple 标记该 CLI deprecated 但仍随系统提供，若未来
// 移除，此探测即 fail-closed。
func probeBackend() sandboxBackend {
	if _, err := os.Stat(macosSeatbeltExecutable); err != nil {
		return backendUnavailable
	}
	ctx, cancel := context.WithTimeout(context.Background(), probeTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, macosSeatbeltExecutable,
		"-p", "(version 1)(allow default)(deny file-write*)(allow file-write* (literal \"/dev/null\"))",
		"--", "true")
	if cmd.Run() != nil {
		return backendUnavailable
	}
	return backendSeatbelt
}

// planConfined（darwin）：sandbox-exec argv 包装 + sh ulimit 资源限制，无令牌。
// Seatbelt（SBPL）不支持资源限制，用 confineRlimits 包一层 /bin/sh（
// RLIMIT 跨 exec 继承，子进程只能降低不能提高；ulimit 失败即 fail-closed）。
func planConfined(spec confineSpec) (launchPlan, error) {
	if err := validateProcessPolicy(spec, "darwin"); err != nil {
		return launchPlan{}, err
	}
	if selectBackend() == backendUnavailable {
		return launchPlan{}, sandboxUnavailable()
	}
	return launchPlan{argv: confineRlimits(seatbeltArgs(spec))}, nil
}
