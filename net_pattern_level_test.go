package vbox

import (
	"strings"
	"testing"
)

func TestParseRuleEntryWildcardAndConcreteBoundary(t *testing.T) {
	t.Parallel()
	for input, want := range map[string]string{"*.example.com": "*.example.com:*", "*.example.com:443": "*.example.com:443", "*.com": "*.com:*"} {
		entry, err := ParseRuleEntry(input)
		if err != nil {
			t.Fatalf("ParseRuleEntry(%q): %v", input, err)
		}
		if got := entry.String(); got != want {
			t.Fatalf("String round trip = %q, want %q", got, want)
		}
		if _, err := ParseEntry(input); err == nil {
			t.Fatalf("ParseEntry(%q) accepted a rule wildcard", input)
		}
	}
	for _, raw := range []string{"*", "*:443", "foo.*.example.com", "example.*", "**.example.com", "!example.com", "bad:ipv6:443", strings.Repeat("a", 64) + ".com"} {
		if _, err := ParseRuleEntry(raw); err == nil {
			t.Fatalf("ParseRuleEntry(%q) should fail", raw)
		}
	}
	for _, raw := range []string{" example.com", "example.com\t", "example.com\n:443", "not:ipv6:443"} {
		if _, err := ParseEntry(raw); err == nil {
			t.Fatalf("ParseEntry(%q) should fail", raw)
		}
	}
	if _, _, err := ParseTargetRule("allow:*.example.com:443"); err == nil {
		t.Fatal("concrete ParseTargetRule accepted a wildcard")
	}
	rule, err := ParseNetRule("!!allow:*.Example.COM:443")
	if err != nil || rule.Level != 2 || rule.HostPort != "*.example.com:443" || rule.String() != "!!allow:*.example.com:443" {
		t.Fatalf("ParseNetRule wildcard level = %+v, %v", rule, err)
	}
	if _, err := ParseNetRule(strings.Repeat("!", 256) + "deny:example.com"); err == nil {
		t.Fatal("net level overflow must fail")
	}
}

func TestNetRuleSetWildcardAndLevel(t *testing.T) {
	t.Parallel()
	set := NetRuleSet{
		Default: true,
		Rules: []NetRule{
			{HostPort: "a.example.com:443", Allow: true},
			{HostPort: "*.example.com:*", Allow: false, Level: 1},
			{HostPort: "a.example.com:443", Allow: true, Level: 1},
		},
	}
	for _, target := range []string{"a.example.com:443", "b.example.com:443", "a.b.example.com:80"} {
		if set.Match(target) {
			t.Fatalf("Match(%q) = true, want high-level wildcard deny", target)
		}
	}
	for _, target := range []string{"example.com:443", "badexample.com:443", "203.0.113.1:443"} {
		if !set.Match(target) {
			t.Fatalf("Match(%q) = false, want default open", target)
		}
	}

	sameLevel := NetRuleSet{Rules: []NetRule{
		{HostPort: "example.com:443", Allow: false, Level: 2},
		{HostPort: "example.com:443", Allow: true, Level: 2},
	}}
	if sameLevel.Match("example.com:443") {
		t.Fatal("same-level later row replaced the first match")
	}

	invalid := NetRuleSet{Default: true, Rules: []NetRule{
		{HostPort: "example.com:443", Allow: true, Level: 2},
		{HostPort: "bad host", Allow: true},
	}}
	if allow, matched := invalid.Resolve("example.com:443"); allow || matched != 1 {
		t.Fatalf("invalid table must fail closed: allow=%v matched=%d", allow, matched)
	}
}

func TestNetRuleSetLoopbackCanonicalization(t *testing.T) {
	t.Parallel()
	for _, ruleHost := range []string{"localhost:*", "127.0.0.1:*", "[::1]:*", "*.localhost:*"} {
		rule, err := ParseNetRule("allow:" + ruleHost)
		if err != nil {
			t.Fatalf("ParseNetRule(%q): %v", ruleHost, err)
		}
		set := NetRuleSet{Rules: []NetRule{rule}, Default: false}
		for _, target := range []string{"localhost:8080", "127.0.0.1:8080", "[::1]:8080", "a.localhost:8080"} {
			if !set.Match(target) {
				t.Fatalf("rule %q should match loopback target %q (canonical rule=%+v)", ruleHost, target, rule)
			}
		}
		if set.Match("203.0.113.1:8080") {
			t.Fatalf("rule %q matched a non-loopback target", ruleHost)
		}
	}
}
