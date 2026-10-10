package vbox

// net 规则平台能力分类的 conformance 矩阵（2026-10-10，OpenShell 调研后固化）。
// 纯判定层（CheckNetPolicy / validateProcessPolicy 的 platform 是参数），不需要
// 真实平台能力，CI 全平台可跑。
//
// 契约口径（docs 见 net.go CheckNetPolicy 注释）：
//   - deny 行不可落实即报错（跳过 = 比策略更宽，永不发生）；
//   - allow 行在 deny 姿态下被吸收（目标本不可达，收窄与 fail-closed 同向）；
//   - 被吸收的 no-op 行（Noop=true）不改变语义；
//   - tool: 行不参与内核落地，也不触发失败。

import (
	"fmt"
	"strings"
	"testing"
)

func allowRule(hostport string) NetRule { return NetRule{HostPort: hostport, Allow: true} }
func denyRule(hostport string) NetRule  { return NetRule{HostPort: hostport} }
func toolDeny(hostport string) NetRule  { return NetRule{HostPort: hostport, ToolOnly: true} }
func toolAllow(hostport string) NetRule {
	return NetRule{HostPort: hostport, Allow: true, ToolOnly: true}
}

// landingWant 是单行的分类预期。
type landingWant struct {
	landed bool
	noop   bool
}

func TestCheckNetPolicyConformance(t *testing.T) {
	cases := []struct {
		name     string
		platform string
		def      bool // NetRuleSet.Default（true=open 姿态）
		rules    []NetRule
		wantErr  string // 子串匹配；空 = 不报错
		want     []landingWant
	}{
		// ---- 缺陷 A 探针固化：deny 姿态 + 内建 localhost allow ----
		{"linux deny + 内建 localhost allow", "linux", false,
			[]NetRule{allowRule("localhost:*")}, "",
			[]landingWant{{landed: false, noop: false}}}, // 被吸收且收窄（沙箱内不可达）
		{"darwin deny + 内建 localhost allow", "darwin", false,
			[]NetRule{allowRule("localhost:*")}, "",
			[]landingWant{{landed: true}}},
		{"windows deny 姿态整体拒", "windows", false, nil, "does not implement network rules", nil},
		// ---- deny 姿态下的吸收 ----
		{"linux deny + 非 loopback allow 被吸收", "linux", false,
			[]NetRule{allowRule("api.example.com:443")}, "",
			[]landingWant{{landed: false, noop: false}}},
		{"linux deny + deny 行被吸收(no-op)", "linux", false,
			[]NetRule{denyRule("169.254.169.254:*")}, "",
			[]landingWant{{landed: false, noop: true}}},
		{"darwin deny + 非 loopback allow 被吸收", "darwin", false,
			[]NetRule{allowRule("api.example.com:443")}, "",
			[]landingWant{{landed: false, noop: false}}},
		{"darwin deny + loopback allow 落实", "darwin", false,
			[]NetRule{allowRule("localhost:8080")}, "",
			[]landingWant{{landed: true}}},
		// ---- 缺陷 B 探针固化：open 姿态下的选择性规则 ----
		{"linux open + 内建（无 deny）", "linux", true,
			[]NetRule{allowRule("localhost:*")}, "",
			[]landingWant{{landed: false, noop: true}}},
		{"linux open + allow（无 deny）", "linux", true,
			[]NetRule{allowRule("api.example.com:443")}, "",
			[]landingWant{{landed: false, noop: true}}},
		{"linux open + deny 拒启", "linux", true,
			[]NetRule{denyRule("169.254.169.254:*")}, "selective network rule", nil},
		{"linux open + deny + allow 拒启（deny 先行）", "linux", true,
			[]NetRule{allowRule("api.example.com:443"), denyRule("169.254.169.254:*")}, "selective network rule", nil},
		{"darwin open + 非 loopback deny 拒启", "darwin", true,
			[]NetRule{denyRule("169.254.169.254:*")}, "selective network rule", nil},
		{"darwin open + loopback deny 落实", "darwin", true,
			[]NetRule{denyRule("localhost:6666")}, "",
			[]landingWant{{landed: true}}},
		// grant 暴雷边：open + loopback deny + 非 loopback allow（与可落地 deny 不相交 → no-op）
		{"darwin open + loopback deny + 非 loopback allow 被吸收", "darwin", true,
			[]NetRule{denyRule("localhost:6666"), allowRule("api.example.com:443")}, "",
			[]landingWant{{landed: true}, {landed: false, noop: true}}},
		// ---- darwin loopback 端口坍缩（内核按端口落地、不区分拼写，首个 * 行截断）----
		{"darwin deny + 同端口混合拼写 allow 先 deny 后 = 更宽拒启", "darwin", false,
			[]NetRule{allowRule("127.0.0.1:8080"), denyRule("localhost:8080")}, "conflict", nil},
		{"darwin deny + 同端口混合拼写 deny 先 allow 后 = 收窄吸收", "darwin", false,
			[]NetRule{denyRule("localhost:8080"), allowRule("127.0.0.1:8080")}, "",
			[]landingWant{{landed: false, noop: true}, {landed: false, noop: false}}},
		{"darwin open + 同端口混合拼写冲突拒启", "darwin", true,
			[]NetRule{allowRule("127.0.0.1:8080"), denyRule("localhost:8080")}, "conflict", nil},
		{"darwin deny + 同拼写同端口冲突拒启（死行也拒，矛盾表不留）", "darwin", false,
			[]NetRule{allowRule("localhost:8080"), denyRule("localhost:8080")}, "conflict", nil},
		{"darwin deny + 同端口同效果重复 = no-op", "darwin", false,
			[]NetRule{allowRule("127.0.0.1:8080"), allowRule("localhost:8080")}, "",
			[]landingWant{{landed: true}, {landed: false, noop: true}}},
		{"darwin deny + 端口 * 行后 deny 被截断 = 拒启", "darwin", false,
			[]NetRule{allowRule("localhost:*"), denyRule("127.0.0.1:8080")}, "closed", nil},
		{"darwin deny + 端口 * 行后 allow 被截断 = 收窄吸收", "darwin", false,
			[]NetRule{denyRule("localhost:6666"), allowRule("localhost:*"), allowRule("127.0.0.1:8080")}, "",
			[]landingWant{{landed: false, noop: true}, {landed: true}, {landed: false, noop: false}}},
		{"windows open + 内建 localhost allow", "windows", true,
			[]NetRule{allowRule("localhost:*")}, "",
			[]landingWant{{landed: false, noop: true}}},
		{"windows open + deny 拒启", "windows", true,
			[]NetRule{denyRule("10.0.0.1:443")}, "selective network rule", nil},
		// ---- tool: 行 ----
		{"linux open + tool deny 跳过", "linux", true,
			[]NetRule{toolDeny("169.254.169.254:*")}, "", nil},
		{"windows deny 姿态 + tool deny 仍整体拒", "windows", false,
			[]NetRule{toolDeny("169.254.169.254:*")}, "does not implement network rules", nil},
		{"linux deny + tool allow 跳过", "linux", false,
			[]NetRule{toolAllow("api.example.com:443")}, "", nil},
		{"tool deny 不算 hasDeny（open 姿态 allow 仍 no-op）", "linux", true,
			[]NetRule{toolDeny("169.254.169.254:*"), allowRule("api.example.com:443")}, "",
			[]landingWant{{landed: false, noop: true}}},
		// ---- 非法行 ----
		{"非法条目报错", "darwin", true,
			[]NetRule{{HostPort: "bad host!!:xx"}}, "invalid", nil},
		// ---- 未列名平台：无逐条能力 ----
		{"freebsd open + deny 拒启", "freebsd", true,
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
				if out[i].Landed != w.landed || out[i].Noop != w.noop {
					t.Fatalf("row %d (%s): got landed=%v noop=%v, want landed=%v noop=%v (reason: %s)",
						i, out[i].Rule.String(), out[i].Landed, out[i].Noop, w.landed, w.noop, out[i].Reason)
				}
			}
		})
	}
}

// TestValidateProcessPolicyNetAbsorbed 固化缺陷 A 的修复：linux deny 姿态 + 内建
// localhost allow 不再拒启（探针原结果 err=selective network rule is unsupported）。
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
	// 收窄方向的吸收行应有 logf 记录（可发现性）。
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

// TestValidateProcessPolicyNetToolOnly tool-only 行不触发拒启。
func TestValidateProcessPolicyNetToolOnly(t *testing.T) {
	spec := confineSpec{
		fsRules: FSRuleSet{DefaultWrite: EffDeny},
		netRules: NetRuleSet{
			Rules:   []NetRule{toolDeny("169.254.169.254:*")},
			Default: true,
		},
	}
	if err := validateProcessPolicy(spec, "linux"); err != nil {
		t.Fatalf("tool-only deny must not refuse: %v", err)
	}
	if err := validateProcessPolicy(spec, "windows"); err != nil {
		t.Fatalf("tool-only deny must not refuse on windows: %v", err)
	}
}
