package vbox

import (
	"context"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"testing"
)

// TestShadowedRowsLogged：执行路径（Manager.RunProcess + SetLogf）对「被更高
// 优先级 rw 行完全覆盖、永不生效」的 deny/ro 行打日志——死行在执行端是安静的
// （Windows 只有一句 deny ACE skip rw-hole），这条日志是使用者唯一的线索。
// 只断言日志，不断言子进程结果：后端可用性不是本用例的验证目标。
func TestShadowedRowsLogged(t *testing.T) {
	argv := trivialArgv(t)
	dir := t.TempDir()

	var logs []string
	m := NewManager()
	m.SetLogf(func(format string, args ...any) { logs = append(logs, fmt.Sprintf(format, args...)) })
	defer m.Close(context.Background())

	pol := Policy{
		FS: NewFSRuleSet([]Rule{
			{Pattern: dir, Effect: EffRW},                                // 外层 rw 覆盖整棵子树
			{Pattern: filepath.Join(dir, "secret.key"), Effect: EffDeny}, // 死行
		}, EffDeny),
		Net: NetRuleSet{Default: true},
	}
	_, _ = m.RunProcess(context.Background(), StartOptions{
		Exec: argv, Workdir: dir, Policy: pol,
	}, nil, io.Discard, io.Discard)

	for _, l := range logs {
		if strings.Contains(l, "shadowed by a higher-priority rw row") {
			return
		}
	}
	t.Fatalf("shadowed-row log missing; logs = %v", logs)
}
