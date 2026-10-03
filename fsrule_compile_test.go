package vbox

import (
	"os"
	"path/filepath"
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
