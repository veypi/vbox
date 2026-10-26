package vbox

import (
	"reflect"
	"strings"
	"testing"
)

func TestCompileNetPlanLoopbackWinnersAndOrder(t *testing.T) {
	t.Parallel()
	set := NetRuleSet{Default: true, Rules: []NetRule{
		{HostPort: "localhost:8080", Allow: true},
		{HostPort: "localhost:*"},
		{HostPort: "localhost:8080", Allow: true, Level: 1},
		{HostPort: "localhost:9090"},
		{HostPort: "127.0.0.1:9090", Allow: true, Level: 1},
	}}
	original := append([]NetRule(nil), set.Rules...)
	plan, err := compileNetPlan("darwin", set, netCapsForPlatform("darwin"))
	if err != nil {
		t.Fatal(err)
	}
	wantIndexes := []int{1, 4, 2}
	if len(plan.kernelRules) != len(wantIndexes) {
		t.Fatalf("kernelRules=%+v, want indexes %v", plan.kernelRules, wantIndexes)
	}
	for i, index := range wantIndexes {
		if plan.kernelRules[i] != original[index] {
			t.Fatalf("kernelRules[%d]=%+v, want original[%d]=%+v", i, plan.kernelRules[i], index, original[index])
		}
	}
	for i, landing := range plan.landings {
		wantKernel := i == 1 || i == 2 || i == 4
		if landing.Kernel != wantKernel || landing.Absorbed == wantKernel {
			t.Fatalf("landing %d = %+v, want kernel=%v", i, landing, wantKernel)
		}
	}
	if !reflect.DeepEqual(set.Rules, original) {
		t.Fatalf("compile mutated input: before=%+v after=%+v", original, set.Rules)
	}

	forms, err := seatbeltNetForms(confineSpec{netRules: set})
	if err != nil {
		t.Fatal(err)
	}
	if len(forms) != 2*len(plan.kernelRules) {
		t.Fatalf("Seatbelt forms=%d, want %d from the same plan: %v", len(forms), 2*len(plan.kernelRules), forms)
	}
	for _, rule := range plan.kernelRules {
		entry, err := ParseRuleEntry(rule.HostPort)
		if err != nil {
			t.Fatal(err)
		}
		verb := "deny"
		if rule.Allow {
			verb = "allow"
		}
		for _, form := range seatbeltEntryForms(entry, verb) {
			found := false
			for _, actual := range forms {
				if actual == form {
					found = true
					break
				}
			}
			if !found {
				t.Fatalf("planned form %q missing from %v", form, forms)
			}
		}
	}
}

func TestCompileNetPlanProxyOwnsDeepCopiedSnapshot(t *testing.T) {
	t.Parallel()
	set := NetRuleSet{Default: false, Rules: []NetRule{
		{HostPort: "example.com:443", Allow: true, Level: 1},
		{HostPort: "localhost:8080", Allow: true},
	}}
	plan, err := compileNetPlan("darwin", set, NetCaps{DenyPosture: true, LoopbackRules: true, EgressProxy: true})
	if err != nil {
		t.Fatal(err)
	}
	if plan.proxyPolicy == nil || len(plan.proxyPolicy.Rules) != len(set.Rules) {
		t.Fatalf("proxyPolicy=%+v", plan.proxyPolicy)
	}
	if !plan.landings[0].Proxy || plan.landings[0].Absorbed {
		t.Fatalf("non-loopback landing=%+v, want proxy", plan.landings[0])
	}
	set.Rules[0].HostPort = "mutated.example:443"
	if plan.proxyPolicy.Rules[0].HostPort != "example.com:443" {
		t.Fatalf("proxy snapshot aliases caller input: %+v", plan.proxyPolicy.Rules[0])
	}
}

func TestCompileNetPlanOpenSkipsOnlyProvenDeadDeny(t *testing.T) {
	t.Parallel()
	set := NetRuleSet{Default: true, Rules: []NetRule{
		{HostPort: "example.com:443", Allow: true, Level: 1},
		{HostPort: "example.com:443"},
	}}
	if _, err := compileNetPlan("linux", set, netCapsForPlatform("linux")); err != nil {
		t.Fatalf("covered deny must not reject: %v", err)
	}
	set.Rules = append(set.Rules, NetRule{HostPort: "other.example:443"})
	_, err := compileNetPlan("linux", set, netCapsForPlatform("linux"))
	if err == nil || !IsUnsupported(err) || !strings.Contains(err.Error(), "other.example") {
		t.Fatalf("live deny error=%v, want UnsupportedError for other.example", err)
	}
}
