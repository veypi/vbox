//go:build linux

package vbox

import (
	"context"
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
	return launchPlan{argv: bwrapArgs(spec, spec.writeRoots(), plan)}, nil
}
