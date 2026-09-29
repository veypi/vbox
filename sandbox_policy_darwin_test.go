package vbox

import (
	"strings"
	"testing"
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
		{Pattern: "/Users/v/aic", Effect: EffRW, Class: ClassConvenience},
	}, DefaultWrite: EffDeny}
	profile := seatbeltProfile(confineSpec{
		argv: []string{"/bin/echo", "hi"}, fsRules: &snap, netOpen: true,
	})
	idx := func(sub string) int { return strings.Index(profile, sub) }
	// 逆序：便利根（表尾）最先输出，temp（表头）最后输出。
	iConv := idx(`(allow file-write* (subpath "/Users/v/aic"))`)
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
	profile := seatbeltProfile(confineSpec{
		argv: []string{"/bin/echo"}, fsRules: &snap, netOpen: true,
	})
	iRo := strings.Index(profile, `(allow file-read* (subpath "/Users/v/.ssh/known_hosts"))`)
	iDeny := strings.Index(profile, `(deny file-read* (regex "^/Users/v/\\.ssh(/.*)?$"))`)
	if iRo < 0 || iDeny < 0 {
		t.Fatalf("形态缺失：ro=%d deny=%d\n%s", iRo, iDeny, profile)
	}
	if iRo < iDeny {
		t.Fatalf("ro 洞必须先于 deny 输出被后命中覆盖：ro=%d deny=%d（逆序应 ro 在后）", iRo, iDeny)
	}
	// ro 行不开写。
	if strings.Contains(profile, `(allow file-write* (subpath "/Users/v/.ssh/known_hosts"))`) {
		t.Fatalf("ro 行不得放行写")
	}
}

func TestSeatbeltFSRulesSkipsLegacyBase(t *testing.T) {
	t.Parallel()
	// fsRules 非空时 legacy extra/writeAllow 不重复输出（已编码在快照行内）。
	snap := FSRuleSet{Rules: []Rule{
		{Pattern: "/Users/v/aic", Effect: EffRW, Class: ClassConvenience},
	}, DefaultWrite: EffDeny}
	profile := seatbeltProfile(confineSpec{
		argv: []string{"/bin/echo"}, fsRules: &snap, netOpen: true,
		extra: []string{"/legacy/extra"}, writeAllow: []string{"/legacy/glob/**"},
	})
	if strings.Contains(profile, "/legacy/extra") || strings.Contains(profile, "legacy/glob") {
		t.Fatalf("fsRules 非空时 legacy base 不得输出：\n%s", profile)
	}
	// fsOpen 与快照行共存：open 打底写全放，deny 行仍生效。
	snapOpen := FSRuleSet{Rules: []Rule{
		{Pattern: "**/.ssh/**", Effect: EffDeny, Class: ClassBuiltin},
	}, DefaultWrite: EffRW}
	profile = seatbeltProfile(confineSpec{
		argv: []string{"/bin/echo"}, fsRules: &snapOpen, fsOpen: true, netOpen: true,
	})
	if !strings.Contains(profile, "(allow file-write*)") {
		t.Fatalf("fsOpen 缺打底放行：\n%s", profile)
	}
	if !strings.Contains(profile, "(deny file-write*") {
		t.Fatalf("fsOpen 下 deny 行仍须生效：\n%s", profile)
	}
}
