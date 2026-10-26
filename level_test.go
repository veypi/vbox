package vbox

import (
	"reflect"
	"strings"
	"testing"
)

func TestParseFSRuleLevel(t *testing.T) {
	t.Parallel()
	cases := []struct {
		raw     string
		effect  Effect
		pattern string
		level   uint8
	}{
		{"deny:/tmp/!important", EffDeny, "/tmp/!important", 0},
		{"!ro:/usr", EffRO, "/usr", 1},
		{"!!rw:/work", EffRW, "/work", 2},
		{strings.Repeat("!", 255) + "deny:/max", EffDeny, "/max", 255},
	}
	for _, tc := range cases {
		effect, pattern, level, err := ParseFSRule(tc.raw)
		if err != nil {
			t.Fatalf("ParseFSRule(%q): %v", tc.raw, err)
		}
		if effect != tc.effect || pattern != tc.pattern || level != tc.level {
			t.Fatalf("ParseFSRule(%q) = %v %q %d, want %v %q %d", tc.raw, effect, pattern, level, tc.effect, tc.pattern, tc.level)
		}
	}
	if _, _, _, err := ParseFSRule(strings.Repeat("!", 256) + "deny:/overflow"); err == nil {
		t.Fatal("level overflow must be rejected")
	}
	rows, err := CompileFSRules([]string{"!!deny:/protected"}, ClassCfg)
	if err != nil || len(rows) == 0 || rows[0].Level != 2 || rows[0].Class != ClassCfg {
		t.Fatalf("CompileFSRules level = %+v, %v", rows, err)
	}
}

func TestFSRuleSetLevelPriority(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		rules   []Rule
		path    string
		matched int
		effect  Effect
		level   uint8
		allow   bool
	}{
		{
			name: "higher level later row wins",
			rules: []Rule{
				{Pattern: "/work", Effect: EffRW},
				{Pattern: "/work/secret", Effect: EffDeny, Level: 1},
			},
			path: "/work/secret/file", matched: 1, effect: EffDeny, level: 1,
		},
		{
			name: "same level keeps original order",
			rules: []Rule{
				{Pattern: "/work", Effect: EffDeny, Level: 1},
				{Pattern: "/work", Effect: EffRW, Level: 1},
			},
			path: "/work/file", matched: 0, effect: EffDeny, level: 1,
		},
		{
			name: "class does not infer level",
			rules: []Rule{
				{Pattern: "/work", Effect: EffDeny, Class: ClassTemp},
				{Pattern: "/work", Effect: EffRW, Class: ClassBuiltin},
			},
			path: "/work/file", matched: 0, effect: EffDeny,
		},
		{
			name: "specificity does not beat level",
			rules: []Rule{
				{Pattern: "/work", Effect: EffDeny, Level: 1},
				{Pattern: "/work/secret", Effect: EffRW},
			},
			path: "/work/secret", matched: 0, effect: EffDeny, level: 1,
		},
		{
			name: "higher level rw revives a lower deny",
			rules: []Rule{
				{Pattern: "/work", Effect: EffDeny},
				{Pattern: "/work/open", Effect: EffRW, Level: 1},
			},
			path: "/work/open/file", matched: 1, effect: EffRW, level: 1, allow: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			original := append([]Rule(nil), tc.rules...)
			set := NewFSRuleSet(tc.rules, EffDeny)
			decision := set.Match(tc.path, OpWrite)
			if decision.Matched != tc.matched || decision.Effect != tc.effect || decision.Level != tc.level || decision.Allow != tc.allow {
				t.Fatalf("decision=%+v, want matched=%d effect=%v level=%d allow=%v", decision, tc.matched, tc.effect, tc.level, tc.allow)
			}
			for i := range original {
				if set.Rules[i].Pattern != original[i].Pattern || set.Rules[i].Level != original[i].Level {
					t.Fatalf("rule table reordered: before=%+v after=%+v", original, set.Rules)
				}
			}
		})
	}
	decision := (FSRuleSet{DefaultWrite: EffRW}).Match("/unmatched", OpWrite)
	if decision.Matched != -1 || decision.Level != 0 || !decision.Allow {
		t.Fatalf("default decision=%+v", decision)
	}
}

func TestFSRuleSetResolvesOnlyWinningRow(t *testing.T) {
	t.Parallel()
	lowCalls, winnerCalls, trailingCalls := 0, 0, 0
	set := NewFSRuleSet([]Rule{
		{Pattern: "/x", Effect: EffRW, Resolve: func(string, FileOp) Resolution {
			lowCalls++
			return Resolution{Handled: true, Effect: EffRW}
		}},
		{Pattern: "/x", Effect: EffDeny, Level: 1, Resolve: func(string, FileOp) Resolution {
			winnerCalls++
			return Resolution{}
		}},
		{Pattern: "/x", Effect: EffRW, Level: 1, Resolve: func(string, FileOp) Resolution {
			trailingCalls++
			return Resolution{Handled: true, Effect: EffRW}
		}},
	}, EffDeny)
	decision := set.Match("/x", OpWrite)
	if decision.Matched != 1 || decision.Effect != EffDeny || decision.Level != 1 || decision.Allow {
		t.Fatalf("decision=%+v", decision)
	}
	if lowCalls != 0 || winnerCalls != 1 || trailingCalls != 0 {
		t.Fatalf("resolver calls: low=%d winner=%d trailing=%d", lowCalls, winnerCalls, trailingCalls)
	}
}

func TestIneffectiveRowsUnderstandsLevel(t *testing.T) {
	t.Parallel()
	rules := []Rule{
		{Pattern: "/dead-low", Effect: EffDeny},
		{Pattern: "/dead-low", Effect: EffRW, Level: 1},
		{Pattern: "/live-high", Effect: EffDeny, Level: 2},
		{Pattern: "/live-high", Effect: EffRW, Level: 1},
		{Pattern: "/same", Effect: EffRW, Level: 1},
		{Pattern: "/same", Effect: EffDeny, Level: 1},
		{Pattern: "/later", Effect: EffDeny, Level: 1},
		{Pattern: "/later", Effect: EffRW, Level: 1},
	}
	if got, want := IneffectiveRows(rules), []int{0, 5}; !reflect.DeepEqual(got, want) {
		t.Fatalf("IneffectiveRows=%v, want %v", got, want)
	}
}

func TestConfineSpecUsesTerminalRulesForRootsAndDenyPatterns(t *testing.T) {
	t.Parallel()
	spec := confineSpec{fsRules: NewFSRuleSet([]Rule{
		{Pattern: "/blocked", Effect: EffRW},
		{Pattern: "/blocked", Effect: EffDeny, Level: 1},
		{Pattern: "/dead", Effect: EffDeny},
		{Pattern: "/dead", Effect: EffRW, Level: 1},
		{Pattern: "/live", Effect: EffDeny},
	}, EffDeny)}
	if got, want := spec.writeRoots(), []string{"/dead"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("writeRoots=%v, want %v", got, want)
	}
	if got, want := spec.denyPatterns(), []string{"/blocked", "/live"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("denyPatterns=%v, want %v", got, want)
	}
}

func TestSeatbeltArgsUsesLevelAndOriginalOrder(t *testing.T) {
	t.Parallel()
	rules := []Rule{
		{Pattern: "/low-first", Effect: EffRW},
		{Pattern: "/high", Effect: EffDeny, Level: 1},
		{Pattern: "/low-second", Effect: EffRO},
	}
	original := append([]Rule(nil), rules...)
	profile := mustSeatbeltArgs(t, confineSpec{argv: []string{"true"}, fsRules: FSRuleSet{Rules: rules}, netRules: NetRuleSet{Default: true}})[2]
	lowSecond := strings.Index(profile, `subpath "/low-second"`)
	lowFirst := strings.Index(profile, `subpath "/low-first"`)
	high := strings.Index(profile, `subpath "/high"`)
	if lowSecond < 0 || lowFirst < 0 || high < 0 || !(lowSecond < lowFirst && lowFirst < high) {
		t.Fatalf("wrong Seatbelt priority order: lowSecond=%d lowFirst=%d high=%d\n%s", lowSecond, lowFirst, high, profile)
	}
	if !reflect.DeepEqual(rules, original) {
		t.Fatalf("Seatbelt compilation mutated input: before=%+v after=%+v", original, rules)
	}
}
