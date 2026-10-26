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

// CheckFSGrantTarget（darwin）：恒 nil——seatbelt 按路径 profile 放行可写根，
// unix 后端没有「能不能授上写权限」这一前置条件（不铸 ACL）。
//
// 已知不对称：unix 上给一个当前用户不可写的目录 grant fs 同样是空授权（工具
// 层与子进程都写不了），但判据与 Windows 不同——unix 上不存在「能改 ACL 就能
// 在沙箱内写」的等价权限，且「目录不可写、其中文件可写」的授权仍有意义
// （改文件内容不需要目录写权限），故不在此做硬判定。
func CheckFSGrantTarget(string) error { return nil }

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
	var lease *egressLease
	var err error
	if !spec.netRules.Default {
		lease, err = acquireEgressEndpoint(spec.resources, spec.netRules)
		if err != nil {
			return launchPlan{}, err
		}
		spec.egress = lease
	}
	argv, err := seatbeltArgs(spec)
	if err != nil {
		lease.release()
		return launchPlan{}, err
	}
	plan := launchPlan{argv: confineRlimits(argv)}
	if lease != nil {
		plan.forcedEnv = lease.endpoint.proxyEnv()
		plan.cleanup = lease.release
	}
	return plan, nil
}
