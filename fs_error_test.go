package vbox

import (
	"errors"
	"strings"
	"testing"
)

func TestFSRuleSetErrorFailsClosed(t *testing.T) {
	set := FSRuleSet{
		Rules:        []Rule{{Pattern: "/work", Effect: EffRW, Level: 255}},
		DefaultWrite: EffRW,
		Err:          errors.New("invalid fs_rules"),
	}
	for _, op := range []FileOp{OpRead, OpWrite} {
		decision := set.Match("/work/secret", op)
		if decision.Allow || decision.Matched != -1 || decision.Effect != EffDeny {
			t.Fatalf("op=%v decision=%+v, want fail-closed", op, decision)
		}
		if !strings.Contains(decision.Reason, "invalid fs_rules") {
			t.Fatalf("op=%v reason=%q, want source error", op, decision.Reason)
		}
	}
}

func TestValidateProcessPolicyFSErrorPrecedesBackend(t *testing.T) {
	for _, platform := range []string{"darwin", "linux", "windows"} {
		t.Run(platform, func(t *testing.T) {
			err := validateProcessPolicy(confineSpec{
				fsRules:  FSRuleSet{Err: errors.New("bad fs config")},
				netRules: NetRuleSet{Default: true},
			}, platform)
			if err == nil || !strings.Contains(err.Error(), "bad fs config") {
				t.Fatalf("validateProcessPolicy error=%v, want source error", err)
			}
		})
	}
}

func TestFSnapshotCacheKeyIncludesError(t *testing.T) {
	valid := FSRuleSet{DefaultWrite: EffDeny}
	invalid := valid
	invalid.Err = errors.New("bad fs config")
	if fsSnapshotCacheKey(valid) == fsSnapshotCacheKey(invalid) {
		t.Fatal("FS error missing from snapshot cache key")
	}
}
