//go:build !linux && !darwin && !windows

package vbox

// probeBackend（其他平台）：无可用后端，fail-closed。
func probeBackend() sandboxBackend {
	return backendUnavailable
}

// CheckFSGrantTarget（其他平台）：无沙箱后端，无可探测的授权前置条件。
func CheckFSGrantTarget(string) error { return nil }

// planConfined（其他平台）：fail-closed——confined 模式拒绝执行。
func planConfined(spec confineSpec) (launchPlan, error) {
	return launchPlan{}, sandboxUnavailable()
}
