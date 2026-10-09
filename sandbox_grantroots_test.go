package vbox

import (
	"fmt"
	"strings"
	"testing"
)

// 可写根逐根降级（2026-10-10：管理员属主目录 grant fs 打死全部 exec）。
//
// 判据：写白名单的失败方向是「更严」（少一个能力 SID 只让写更多被拒），所以
// 逐根降级并在日志里留痕；收紧方向（deny 不可表达）仍然拒绝执行——Windows 侧
// 的 TestPlanConfinedDenyFailureStaysFatal 锁这条不变量。
//
// 这些用例用假 SID 类型（string）覆盖 grantRootSIDs 的逻辑，因此在没有 Windows
// 的机器与 CI 上同样运行；真实能力 SID / ACL 路径的用例见
// sandbox_windows_test.go（需实机）。

// resetWriteRootWarnState 清空告警去重状态（用例隔离）。
func resetWriteRootWarnState() {
	writeRootWarnMu.Lock()
	writeRootWarnSeen = map[string]bool{}
	writeRootWarnMu.Unlock()
}

// 授不上一个根不致命：其余根照旧授权，失败根只告警一次，且不留负缓存。
func TestGrantRootSIDsSkipsUngrantable(t *testing.T) {
	resetWriteRootWarnState()
	var logs []string
	logf := func(format string, args ...any) { logs = append(logs, fmt.Sprintf(format, args...)) }
	bad := "C:/models/llama"
	good := []string{"C:/ComfyUI", "C:/Users/v/Desktop"}
	sidOf := func(d string) (string, error) { return "sid:" + d, nil }
	grant := func(dir string, _ string) error {
		if dir == bad {
			return fmt.Errorf("Access is denied.")
		}
		return nil
	}
	dirs := append([]string{bad}, good...)
	sids := grantRootSIDs(dirs, sidOf, grant, logf)
	if len(sids) != len(good) {
		t.Fatalf("ungrantable root must not drop the others: sids=%d want=%d", len(sids), len(good))
	}
	if len(logs) != 1 || !strings.Contains(logs[0], "write-root unavailable in sandbox") || !strings.Contains(logs[0], bad) {
		t.Fatalf("want one precise warning for %s, got %q", bad, logs)
	}
	// 无负缓存：每次都仍尝试授权（目录重建 / ACL 事后修好即恢复），日志不重复。
	sids = grantRootSIDs(dirs, sidOf, grant, logf)
	if len(sids) != len(good) || len(logs) != 1 {
		t.Fatalf("retry must re-attempt and warn once: sids=%d logs=%q", len(sids), logs)
	}
	// ACL 修好后同一目录立即恢复可写（不经目录重建）。
	if got := grantRootSIDs([]string{bad}, sidOf, func(string, string) error { return nil }, logf); len(got) != 1 {
		t.Fatalf("recovered root must be granted again: %v", got)
	}
}

// 全部失败：不报错、不返回 SID（进程以只读跑，降级方向恒为更严）。
func TestGrantRootSIDsAllFail(t *testing.T) {
	resetWriteRootWarnState()
	sids := grantRootSIDs([]string{"C:/a", "C:/b"},
		func(d string) (string, error) { return d, nil },
		func(string, string) error { return fmt.Errorf("Access is denied.") }, nil)
	if len(sids) != 0 {
		t.Fatalf("all-fail must yield no sid: %v", sids)
	}
}

// SID 派生失败（本平台内部错误）同样只降级该根，不中断其余根。
func TestGrantRootSIDsSIDErrorSkips(t *testing.T) {
	resetWriteRootWarnState()
	var logs []string
	logf := func(format string, args ...any) { logs = append(logs, fmt.Sprintf(format, args...)) }
	granted := []string{}
	sids := grantRootSIDs([]string{"/x", "/y"},
		func(d string) (string, error) {
			if d == "/x" {
				return "", fmt.Errorf("sid: bad path")
			}
			return "sid:" + d, nil
		},
		func(d string, _ string) error { granted = append(granted, d); return nil }, logf)
	if len(sids) != 1 || len(granted) != 1 || granted[0] != "/y" {
		t.Fatalf("sid error must skip only that root: sids=%v granted=%v", sids, granted)
	}
	if len(logs) != 1 || !strings.Contains(logs[0], "/x") {
		t.Fatalf("want one warning naming /x, got %q", logs)
	}
}

// 同一路径只授权一次（同一目录可同时来自 workdir / 缓存根 / extra，或 temp 行
// 与 cfg 行重合；Windows 侧 createRestrictedToken 还会再去重一次 SID）。
func TestGrantRootSIDsDedupes(t *testing.T) {
	resetWriteRootWarnState()
	calls := 0
	grant := func(string, string) error { calls++; return nil }
	sids := grantRootSIDs([]string{"C:/x", "C:/x", "", "C:/x"},
		func(d string) (string, error) { return d, nil }, grant, nil)
	if len(sids) != 1 || calls != 1 {
		t.Fatalf("duplicate roots must grant once: calls=%d sids=%v", calls, sids)
	}
}
