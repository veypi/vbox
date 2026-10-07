package vbox

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCompileFSRulesRejectsIncompleteTable(t *testing.T) {
	t.Setenv("AIC_EMPTY_RULE_ROOT", "")
	for _, bad := range []string{"deny:$AIC_MISSING_RULE_ROOT/**", "deny:$AIC_EMPTY_RULE_ROOT/**", "deny:", "rw:~"} {
		rows, err := CompileFSRules([]string{"rw:/workspace", bad}, ClassCfg)
		if err == nil || rows != nil {
			t.Fatalf("partially compiled %q: %+v, %v", bad, rows, err)
		}
	}
}

// TestExpandVarsHomeMatchesTilde：$HOME 与 ~ 同义（两者都回退 os.UserHomeDir()）。
// Windows 的 GUI/schtasks 进程没有 HOME（只有 USERPROFILE），此前内置 deny 表的
// $HOME 条目无法展开，整张表编译失败、host 起不来
// （2026-10-04 win 实机：rule 30: cannot expand "$HOME/.cache/browser/**"）。
// 在 HOME 缺失的环境上跑本测试即覆盖那条路径（windows 另有显式 unset 用例）。
func TestExpandVarsHomeMatchesTilde(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		t.Skipf("no home dir: %v", err)
	}
	for _, pat := range []string{"$HOME", "$HOME/.cache/browser/**", "$HOME/.cache/sessions/s1/x.txt"} {
		tilde := "~" + strings.TrimPrefix(pat, "$HOME")
		eHome, okHome := ExpandVars(pat)
		eTilde, okTilde := ExpandVars(tilde)
		if !okHome || !okTilde {
			t.Fatalf("ExpandVars(%q)=%v, ExpandVars(%q)=%v, want both true", pat, okHome, tilde, okTilde)
		}
		if eHome != eTilde {
			t.Fatalf("ExpandVars(%q)=%q, ExpandVars(%q)=%q, want equal", pat, eHome, tilde, eTilde)
		}
		if want := filepath.ToSlash(home) + strings.TrimPrefix(pat, "$HOME"); eHome != want {
			t.Fatalf("ExpandVars(%q)=%q, want %q", pat, eHome, want)
		}
	}
}

// TestIneffectiveRows：first-wins 下被上方 rw 行完全覆盖的 deny/ro 行（死行）
// 能被报出；同时不得误报活行（外层带通配、段边界不同、ro 在前等）。
func TestIneffectiveRows(t *testing.T) {
	set := NewFSRuleSet([]Rule{
		{Pattern: "/work", Effect: EffRW},                // 0
		{Pattern: "/work/secret.key", Effect: EffDeny},   // 1 死：裸路径 rw 覆盖子树
		{Pattern: "/work/sub/**", Effect: EffRO},         // 2 死
		{Pattern: "/work/x/*.key", Effect: EffRW},        // 3 rw 行本身不判
		{Pattern: "/other/secret.key", Effect: EffDeny},  // 4 活
		{Pattern: "/wild/*/secret.key", Effect: EffDeny}, // 5 活：外层带通配不能断定
		{Pattern: "/worked/file", Effect: EffDeny},       // 6 活：段边界不同（/work != /worked）
		{Pattern: "/a/**", Effect: EffRW},                // 7
		{Pattern: "/a", Effect: EffDeny},                 // 8 死：/** 含零段（含根目录）
		{Pattern: "/a/b/c", Effect: EffDeny},             // 9 死
		{Pattern: "/b", Effect: EffDeny},                 // 10 活：上方无 rw 覆盖
		{Pattern: "/c/**", Effect: EffRO},                // 11 活：ro 行在外层但不是 rw
		{Pattern: "/c/inside", Effect: EffDeny},          // 12 活：仅 rw 覆盖算死行
	}, EffDeny)

	got := IneffectiveRows(set.Rules)
	want := []int{1, 2, 8, 9}
	if len(got) != len(want) {
		t.Fatalf("IneffectiveRows = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("IneffectiveRows = %v, want %v", got, want)
		}
	}

	// 空表/无 rw 表不报。
	if rows := IneffectiveRows(nil); len(rows) != 0 {
		t.Fatalf("nil table: %v", rows)
	}
	if rows := IneffectiveRows([]Rule{{Pattern: "/x", Effect: EffDeny}}); len(rows) != 0 {
		t.Fatalf("deny-only table: %v", rows)
	}
}

func TestMatchPathKeepsLogicalNamespace(t *testing.T) {
	root := t.TempDir()
	target, link := filepath.Join(root, "real"), filepath.Join(root, "alias")
	if err := os.Mkdir(target, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Skip(err)
	}
	logical := filepath.ToSlash(link)
	rules := FSRuleSet{Rules: []Rule{{Pattern: logical, Effect: EffRW}}}
	if !rules.MatchPath(logical+"/new", OpWrite).Allow {
		t.Fatal("logical path followed host symlink")
	}
	if rules.Match(logical+"/new", OpWrite).Allow {
		t.Fatal("OS query failed to follow symlink")
	}
}
