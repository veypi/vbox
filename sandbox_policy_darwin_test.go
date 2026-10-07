package vbox

import (
	"context"
	"net"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// darwin seatbelt 的 vbox 快照消费（W2b，2026-09-29）：first-wins 快照逆序
// 输出映射 SBPL 后规则胜。替代原 fsauth 耦合的 M3 行序映射测试（输入已从
// legacy last-wins 表切换为 vbox first-wins 快照）。

// seatbeltProfile 渲染 seatbeltArgs 的 profile 段（去掉可执行文件前缀与 argv）。
func seatbeltProfile(spec confineSpec) string {
	argv := seatbeltArgs(spec)
	// [sandbox-exec, -p, profile, --, argv...]
	if len(argv) < 4 {
		return ""
	}
	return argv[2]
}

func TestSeatbeltFSRulesReversedEmission(t *testing.T) {
	t.Parallel()
	snap := FSRuleSet{Rules: []Rule{
		{Pattern: "/tmp/granted", Effect: EffRW, Class: ClassTemp},
		{Pattern: "/Users/v/.cache/**", Effect: EffRW, Class: ClassCfg},
		{Pattern: "**/.ssh/**", Effect: EffDeny, Class: ClassBuiltin},
		{Pattern: "/Users/v/work", Effect: EffRW, Class: ClassConvenience},
	}, DefaultWrite: EffDeny}
	profile := seatbeltProfile(confineSpec{argv: []string{"/bin/echo", "hi"}, fsRules: snap, netRules: NetRuleSet{Default: true}})
	idx := func(sub string) int { return strings.Index(profile, sub) }
	// 逆序：便利根（表尾）最先输出，temp（表头）最后输出。
	iConv := idx(`(allow file-write* (subpath "/Users/v/work"))`)
	iDeny := idx(`(deny file-write* (regex "^(.*)?/\\.ssh(/.*)?$"))`)
	iCfg := idx(`(allow file-write* (regex "^/Users/v/\\.cache(/.*)?$"))`)
	iTemp := idx(`(allow file-write* (subpath "/tmp/granted"))`)
	if iConv < 0 || iDeny < 0 || iCfg < 0 || iTemp < 0 {
		t.Fatalf("形态缺失：conv=%d deny=%d cfg=%d temp=%d\n%s", iConv, iDeny, iCfg, iTemp, profile)
	}
	if !(iConv < iDeny && iDeny < iCfg && iCfg < iTemp) {
		t.Fatalf("输出未逆序（SBPL 后规则胜 ⇒ first-wins 语义颠倒）：conv=%d deny=%d cfg=%d temp=%d", iConv, iDeny, iCfg, iTemp)
	}
}

func TestSeatbeltFSRulesHoleSemantics(t *testing.T) {
	t.Parallel()
	// ro 洞（表中在 deny 前 = 首命中优先生效）→ SBPL 中 ro 的 allow 必须在
	// 对应 deny 之后输出才被内核命中。
	snap := FSRuleSet{Rules: []Rule{
		{Pattern: "/Users/v/.ssh/known_hosts", Effect: EffRO, Class: ClassCfg},
		{Pattern: "/Users/v/.ssh/**", Effect: EffDeny, Class: ClassCfg},
	}, DefaultWrite: EffDeny}
	profile := seatbeltProfile(confineSpec{argv: []string{"/bin/echo"}, fsRules: snap, netRules: NetRuleSet{Default: true}})
	iRo := strings.Index(profile, `(allow file-read* (subpath "/Users/v/.ssh/known_hosts"))`)
	iDeny := strings.Index(profile, `(deny file-read* (regex "^/Users/v/\\.ssh(/.*)?$"))`)
	if iRo < 0 || iDeny < 0 {
		t.Fatalf("形态缺失：ro=%d deny=%d\n%s", iRo, iDeny, profile)
	}
	if iRo < iDeny {
		t.Fatalf("ro 洞必须先于 deny 输出被后命中覆盖：ro=%d deny=%d（逆序应 ro 在后）", iRo, iDeny)
	}
	// ro 行不开写；写拒必须显式下沉（可写根内宽写放行不会盖掉它；2026-10-01 探针）。
	if strings.Contains(profile, `(allow file-write* (subpath "/Users/v/.ssh/known_hosts"))`) {
		t.Fatalf("ro 行不得放行写")
	}
	if !strings.Contains(profile, `(deny file-write* (subpath "/Users/v/.ssh/known_hosts"))`) {
		t.Fatalf("ro 行缺显式写拒\n%s", profile)
	}
}

func TestSeatbeltOpenWithDeny(t *testing.T) {
	// fsOpen 与快照行共存：open 打底写全放，deny 行仍生效。
	snapOpen := FSRuleSet{Rules: []Rule{
		{Pattern: "**/.ssh/**", Effect: EffDeny, Class: ClassBuiltin},
	}, DefaultWrite: EffRW}
	profile := seatbeltProfile(confineSpec{argv: []string{"/bin/echo"}, fsRules: snapOpen, netRules: NetRuleSet{Default: true}})
	if !strings.Contains(profile, "(allow file-write*)") {
		t.Fatalf("fsOpen 缺打底放行：\n%s", profile)
	}
	if !strings.Contains(profile, "(deny file-write*") {
		t.Fatalf("fsOpen 下 deny 行仍须生效：\n%s", profile)
	}
}

func TestSeatbeltNetworkRulePriority(t *testing.T) {
	nc, err := exec.LookPath("nc")
	if err != nil {
		t.Skip("nc unavailable")
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	allow := NetRule{HostPort: "localhost:" + port, Allow: true}
	deny := NetRule{HostPort: "localhost:*"}
	for _, tc := range []struct {
		rules []NetRule
		allow bool
	}{{[]NetRule{allow, deny}, true}, {[]NetRule{deny, allow}, false}} {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		code, err := NewManager().RunProcess(ctx, StartOptions{Exec: []string{nc, "-z", "-G", "1", "127.0.0.1", port}, Policy: Policy{Net: NetRuleSet{Rules: tc.rules}}}, nil, nil, nil)
		cancel()
		if err != nil && strings.Contains(err.Error(), "no sandbox backend") {
			t.Skip(err)
		}
		if err != nil || (code == 0) != tc.allow {
			t.Fatalf("rules=%+v: exit=%d err=%v, want allowed=%v", tc.rules, code, err, tc.allow)
		}
	}
}
