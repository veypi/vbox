//go:build linux

package vbox

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
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
// 可写根下的敏感子路径（.git 等）存在时收集为只读覆盖；git 自身豁免
// （保护对象是 bash/rm 等通用命令，git 等级由 vcore 子命令表承担）。
// deny 模式先实例化为覆盖目标（形态不可实例化 → 拒绝执行）。
func planConfined(spec confineSpec) (launchPlan, error) {
	if selectBackend() == backendUnavailable {
		return launchPlan{}, sandboxUnavailable()
	}
	var protected []string
	if spec.workdir != "" && !isGitArgv(spec.argv) {
		for _, name := range protectedMetadataNames {
			p := filepath.Join(spec.workdir, name)
			if st, err := os.Stat(p); err == nil && st.IsDir() {
				protected = append(protected, p)
			}
		}
	}
	if err := validateProcessPolicy(spec, "linux"); err != nil {
		return launchPlan{}, err
	}
	denyTargets, _, err := denyCoverAllCached(spec.deny, spec.logf)
	if err != nil {
		return launchPlan{}, err
	}
	// W3：实例化目标按 vbox 快照（first-wins）求值后落措施——ro/rw 洞回补。
	return launchPlan{argv: bwrapArgs(spec, spec.extra, protected, evaluateDenyTargets(denyTargets, spec.fsRules))}, nil
}
