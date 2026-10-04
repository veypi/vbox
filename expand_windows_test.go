//go:build windows

package vbox

import (
	"os"
	"path/filepath"
	"testing"
)

// TestExpandVarsHomeWithoutEnv：Windows 的 GUI/schtasks 启动进程只有
// USERPROFILE、没有 HOME。此时 $HOME/... 与 ~/... 都必须落到 USERPROFILE
// （os.UserHomeDir 口径），否则内置 deny 表无法编译、host 起不来
// （2026-10-04 win 实机：rule 30: cannot expand "$HOME/.aic/browser/**"）。
func TestExpandVarsHomeWithoutEnv(t *testing.T) {
	prev, had := os.LookupEnv("HOME")
	if err := os.Unsetenv("HOME"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if had {
			os.Setenv("HOME", prev)
		}
	})
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		t.Skipf("no home dir: %v", err)
	}
	want := filepath.ToSlash(home) + "/.aic/browser/**"
	for _, pat := range []string{"$HOME/.aic/browser/**", "~/.aic/browser/**"} {
		got, ok := ExpandVars(pat)
		if !ok {
			t.Fatalf("ExpandVars(%q) failed with HOME unset", pat)
		}
		if got != want {
			t.Fatalf("ExpandVars(%q)=%q, want %q", pat, got, want)
		}
	}
	if _, err := CompileFSRules([]string{"deny:$HOME/.aic/browser/**", "deny:~/.aic/browser/**"}, ClassCfg); err != nil {
		t.Fatalf("builtin deny rows must compile with HOME unset: %v", err)
	}
}
