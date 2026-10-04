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
// （2026-10-04 win 实机：rule 30: cannot expand "$HOME/.aic/browser/**"）。
// 在 HOME 缺失的环境上跑本测试即覆盖那条路径（windows 另有显式 unset 用例）。
func TestExpandVarsHomeMatchesTilde(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		t.Skipf("no home dir: %v", err)
	}
	for _, pat := range []string{"$HOME", "$HOME/.aic/browser/**", "$HOME/.aic/sessions/s1/x.txt"} {
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
