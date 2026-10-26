package vbox

// Net 规则平台能力 conformance：CheckNetPolicy 与 compileNetPlan 是纯判定层，
// platform 只用于选择真实能力，不需要对应宿主后端。

import (
	"fmt"
	"strings"
	"testing"
)

func allowRule(hostport string) NetRule { return NetRule{HostPort: hostport, Allow: true} }
func denyRule(hostport string) NetRule  { return NetRule{HostPort: hostport} }

type landingWant struct {
	kernel   bool
	proxy    bool
	absorbed bool
}

var (
	wantKernel   = landingWant{kernel: true}
	wantProxy    = landingWant{proxy: true}
	wantAbsorbed = landingWant{absorbed: true}
)

func TestCheckNetPolicyConformance(t *testing.T) {
	cases := []struct {
		name     string
		platform string
		def      bool
		rules    []NetRule
		wantErr  string
		want     []landingWant
	}{
		{"linux deny + localhost allow absorbed", "linux", false,
			[]NetRule{allowRule("localhost:*")}, "", []landingWant{wantAbsorbed}},
		{"darwin deny + localhost allow kernel", "darwin", false,
			[]NetRule{allowRule("localhost:*")}, "", []landingWant{wantKernel}},
		{"windows deny posture unsupported", "windows", false, nil, "does not implement network rules", nil},
		{"linux deny + non-loopback allow absorbed", "linux", false,
			[]NetRule{allowRule("api.example.com:443")}, "", []landingWant{wantAbsorbed}},
		{"linux deny + deny absorbed", "linux", false,
			[]NetRule{denyRule("169.254.169.254:*")}, "", []landingWant{wantAbsorbed}},
		{"darwin deny + non-loopback allow proxied", "darwin", false,
			[]NetRule{allowRule("api.example.com:443")}, "", []landingWant{wantProxy}},
		{"darwin deny + loopback allow kernel", "darwin", false,
			[]NetRule{allowRule("localhost:8080")}, "", []landingWant{wantKernel}},
		{"linux open + localhost allow absorbed", "linux", true,
			[]NetRule{allowRule("localhost:*")}, "", []landingWant{wantAbsorbed}},
		{"linux open + allow absorbed", "linux", true,
			[]NetRule{allowRule("api.example.com:443")}, "", []landingWant{wantAbsorbed}},
		{"linux open + deny unsupported", "linux", true,
			[]NetRule{denyRule("169.254.169.254:*")}, "selective network rule", nil},
		{"linux open + deny + allow unsupported", "linux", true,
			[]NetRule{allowRule("api.example.com:443"), denyRule("169.254.169.254:*")}, "selective network rule", nil},
		{"darwin open + non-loopback deny unsupported", "darwin", true,
			[]NetRule{denyRule("169.254.169.254:*")}, "selective network rule", nil},
		{"darwin open + loopback deny kernel", "darwin", true,
			[]NetRule{denyRule("localhost:6666")}, "", []landingWant{wantKernel}},
		{"darwin open + loopback deny + non-loopback allow", "darwin", true,
			[]NetRule{denyRule("localhost:6666"), allowRule("api.example.com:443")}, "",
			[]landingWant{wantKernel, wantAbsorbed}},
		{"darwin deny + mixed loopback allow first", "darwin", false,
			[]NetRule{allowRule("127.0.0.1:8080"), denyRule("localhost:8080")}, "",
			[]landingWant{wantKernel, wantAbsorbed}},
		{"darwin deny + mixed loopback deny first", "darwin", false,
			[]NetRule{denyRule("localhost:8080"), allowRule("127.0.0.1:8080")}, "",
			[]landingWant{wantKernel, wantAbsorbed}},
		{"darwin open + mixed loopback allow first", "darwin", true,
			[]NetRule{allowRule("127.0.0.1:8080"), denyRule("localhost:8080")}, "",
			[]landingWant{wantKernel, wantAbsorbed}},
		{"darwin deny + same-host conflicting rows resolved", "darwin", false,
			[]NetRule{allowRule("localhost:8080"), denyRule("localhost:8080")}, "",
			[]landingWant{wantKernel, wantAbsorbed}},
		{"darwin deny + duplicate allow", "darwin", false,
			[]NetRule{allowRule("127.0.0.1:8080"), allowRule("localhost:8080")}, "",
			[]landingWant{wantKernel, wantAbsorbed}},
		{"darwin deny + wildcard allow closes lower deny", "darwin", false,
			[]NetRule{allowRule("localhost:*"), denyRule("127.0.0.1:8080")}, "",
			[]landingWant{wantKernel, wantAbsorbed}},
		{"darwin deny + specific deny and wildcard allow", "darwin", false,
			[]NetRule{denyRule("localhost:6666"), allowRule("localhost:*"), allowRule("127.0.0.1:8080")}, "",
			[]landingWant{wantKernel, wantKernel, wantAbsorbed}},
		{"windows open + localhost allow absorbed", "windows", true,
			[]NetRule{allowRule("localhost:*")}, "", []landingWant{wantAbsorbed}},
		{"windows open + deny unsupported", "windows", true,
			[]NetRule{denyRule("10.0.0.1:443")}, "selective network rule", nil},
		{"darwin deny + higher-level later allow wins", "darwin", false,
			[]NetRule{denyRule("localhost:8080"), {HostPort: "localhost:8080", Allow: true, Level: 1}}, "",
			[]landingWant{wantAbsorbed, wantKernel}},
		{"darwin open + higher-level later deny wins", "darwin", true,
			[]NetRule{allowRule("localhost:8080"), {HostPort: "localhost:8080", Level: 1}}, "",
			[]landingWant{wantAbsorbed, wantKernel}},
		{"invalid entry is a syntax error", "darwin", true,
			[]NetRule{{HostPort: "bad host!!:xx"}}, "invalid", nil},
		{"freebsd open + deny unsupported", "freebsd", true,
			[]NetRule{denyRule("10.0.0.1:443")}, "selective network rule", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out, err := CheckNetPolicy(tc.platform, NetRuleSet{Rules: tc.rules, Default: tc.def})
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("want error containing %q, got %v", tc.wantErr, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(out) != len(tc.want) {
				t.Fatalf("landings len = %d, want %d (%+v)", len(out), len(tc.want), out)
			}
			for i, w := range tc.want {
				if out[i].Kernel != w.kernel || out[i].Proxy != w.proxy || out[i].Absorbed != w.absorbed {
					t.Fatalf("row %d (%s): got kernel=%v proxy=%v absorbed=%v, want %+v (reason: %s)",
						i, out[i].Rule.String(), out[i].Kernel, out[i].Proxy, out[i].Absorbed, w, out[i].Reason)
				}
			}
		})
	}
}

func TestCheckNetPolicySeparatesSyntaxAndCapabilityErrors(t *testing.T) {
	_, err := CheckNetPolicy("linux", NetRuleSet{Default: true, Rules: []NetRule{denyRule("example.com:443")}})
	if !IsUnsupported(err) {
		t.Fatalf("capability error = %v, want UnsupportedError", err)
	}
	_, err = CheckNetPolicy("darwin", NetRuleSet{Default: true, Rules: []NetRule{{HostPort: "bad host"}}})
	if err == nil || IsUnsupported(err) {
		t.Fatalf("syntax error = %v, want non-UnsupportedError", err)
	}
}

func TestValidateProcessPolicyNetAbsorbed(t *testing.T) {
	spec := confineSpec{
		fsRules: FSRuleSet{},
		netRules: NetRuleSet{
			Rules:   []NetRule{allowRule("localhost:*")},
			Default: false,
		},
	}
	if err := validateProcessPolicy(spec, "linux"); err != nil {
		t.Fatalf("linux deny posture + builtin localhost allow must not refuse: %v", err)
	}
	var logs []string
	spec.logf = func(format string, args ...any) {
		logs = append(logs, fmt.Sprintf(format, args...))
	}
	if err := validateProcessPolicy(spec, "linux"); err != nil {
		t.Fatal(err)
	}
	if len(logs) != 1 || !strings.Contains(logs[0], "absorbed") {
		t.Fatalf("want one absorbed log line, got %v", logs)
	}
}

func TestValidateProcessPolicyNetSelectiveDenyRejected(t *testing.T) {
	spec := confineSpec{
		fsRules: FSRuleSet{DefaultWrite: EffDeny},
		netRules: NetRuleSet{
			Rules:   []NetRule{denyRule("169.254.169.254:*")},
			Default: true,
		},
	}
	if err := validateProcessPolicy(spec, "linux"); err == nil {
		t.Fatal("linux accepted an unenforceable selective deny")
	}
	if err := validateProcessPolicy(spec, "windows"); err == nil {
		t.Fatal("windows accepted an unenforceable selective deny")
	}
}
