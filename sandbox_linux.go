//go:build linux

package vbox

import (
	"context"
	"fmt"
	"os/exec"
)

// probeBackend（linux）：bwrap 功能性探测——真跑一次最小只读 profile，
// exit 0 = 内核接受并强制（bwrap 的 mount profile 按构造即 full enforcement）。
func probeBackend() sandboxBackend {
	if _, err := exec.LookPath("bwrap"); err != nil {
		return backendUnavailable
	}
	ctx, cancel := context.WithTimeout(context.Background(), probeTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "bwrap",
		"--ro-bind", "/", "/", "--dev", "/dev", "--proc", "/proc", "--die-with-parent", "--", "true")
	if cmd.Run() != nil {
		return backendUnavailable
	}
	return backendBwrap
}

// CheckFSGrantTarget（linux）：恒 nil——bwrap 在挂载层落实可写根（bindIfExists），
// 不存在「能不能授上写权限」这一前置条件；不存在的根本就被静默跳过。
//
// 已知不对称：unix 上给一个当前用户不可写的目录 grant fs 同样是空授权（工具
// 层与子进程都写不了），但判据与 Windows 不同——unix 上不存在「能改 ACL 就能
// 在沙箱内写」的等价权限，且「目录不可写、其中文件可写」的授权仍有意义
// （改文件内容不需要目录写权限），故不在此做硬判定。
func CheckFSGrantTarget(string) error { return nil }

// planConfined（linux）：bwrap argv 包装，无令牌。
// deny 模式先实例化为覆盖目标（形态不可实例化 → 拒绝执行）；工作区元数据
// 保护（.git/.aws）已收敛为 pod 侧内置 ro 行，经 evaluateFSPolicy 回补 ro-bind。
func planConfined(spec confineSpec) (launchPlan, error) {
	if selectBackend() == backendUnavailable {
		return launchPlan{}, sandboxUnavailable()
	}
	if err := validateProcessPolicy(spec, "linux"); err != nil {
		return launchPlan{}, err
	}
	denyTargets, _, err := denyCoverAllCached(spec.denyPatterns(), spec.logf)
	if err != nil {
		return launchPlan{}, err
	}
	// W3：授权快照经 first-wins 统一求值后落挂载（覆盖/ro/rw 洞与独立 ro
	// 收紧同出一口）；不可精确表达的 ro 通配行在此拒绝执行。
	plan, err := evaluateFSPolicy(denyTargets, &spec.fsRules, writableMountRoots(spec), spec.fsRules.DefaultWrite == EffRW)
	if err != nil {
		return launchPlan{}, err
	}
	// 资源限制：bwrap 无 --rlimit（上游至今未提供），改用 util-linux prlimit
	// 包装在 exec 前落限制，再由 bwrap 挂沙箱；缺 prlimit 即 fail-closed。
	if _, err := exec.LookPath("prlimit"); err != nil {
		return launchPlan{}, fmt.Errorf("sandbox: prlimit not found (util-linux required for resource limits): %w", err)
	}
	argv := append(prlimitArgs(), bwrapArgs(spec, spec.writeRoots(), plan)...)
	return launchPlan{argv: argv}, nil
}
