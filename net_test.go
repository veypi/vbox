package vbox

import "testing"

func TestParseEntry(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in         string
		host, port string
	}{
		{"example.com", "example.com", "*"},
		{"Example.COM:443", "example.com", "443"},
		{"user@host.cn:22", "host.cn", "22"},
		{"8.8.8.8:53", "8.8.8.8", "53"},
		{"[::1]:8080", "::1", "8080"},
		{"::1", "::1", "*"},
		{"example.com.:443", "example.com", "443"},
		{"host:0443", "host", "443"},
	}
	for _, c := range cases {
		e, err := ParseEntry(c.in)
		if err != nil {
			t.Fatalf("ParseEntry(%q) err = %v", c.in, err)
		}
		if e.Host != c.host || e.Port != c.port {
			t.Fatalf("ParseEntry(%q) = %v, want %s:%s", c.in, e, c.host, c.port)
		}
	}
	bad := []string{"", "a b", "a/b", "host:0", "host:65536", "host:abc", "*.example.com", "[]:80"}
	for _, in := range bad {
		if _, err := ParseEntry(in); err == nil {
			t.Fatalf("ParseEntry(%q) 应报错", in)
		}
	}
}

func TestNetRuleSetFirstMatchWins(t *testing.T) {
	t.Parallel()
	set := NetRuleSet{
		Rules: []NetRule{
			{HostPort: "example.com:443", Allow: false}, // 表头 deny
			{HostPort: "example.com:*", Allow: true},    // 靠后 allow
		},
		Default: true,
	}
	// 首命中生效：443 deny 压住行序靠后的 * allow。
	if set.Match("example.com:443") {
		t.Fatalf("Match(example.com:443) = true, want false（首命中 deny）")
	}
	// 其他端口命中第二行 allow。
	if !set.Match("example.com:80") {
		t.Fatalf("Match(example.com:80) = false, want true")
	}
	// 未命中走兜底。
	if !set.Match("other.com:443") {
		t.Fatalf("Match(other.com:443) = false, want true（Default open）")
	}
}

func TestNetRuleSetDefaultDeny(t *testing.T) {
	t.Parallel()
	set := NetRuleSet{
		Rules:   []NetRule{{HostPort: "api.internal:*", Allow: true}},
		Default: false,
	}
	if !set.Match("api.internal:8080") {
		t.Fatalf("allow row miss")
	}
	if set.Match("evil.com:443") {
		t.Fatalf("unmatched under deny default = true, want false")
	}
	// 查询端口为 * 时取保守交集（重叠即命中）。
	if !set.Match("api.internal") {
		t.Fatalf("wildcard query port should overlap-match allow row")
	}
	// 非法目标 fail-closed。
	if set.Match("bad host:80") {
		t.Fatalf("invalid target = true, want false")
	}
}

func TestParseTargetRule(t *testing.T) {
	t.Parallel()
	allow, e, err := ParseTargetRule("allow:example.com:443")
	if err != nil || !allow || e.Host != "example.com" || e.Port != "443" {
		t.Fatalf("ParseTargetRule allow = %v %v %v", allow, e, err)
	}
	allow, _, err = ParseTargetRule("deny:10.0.0.1:*")
	if err != nil || allow {
		t.Fatalf("ParseTargetRule deny = %v %v", allow, err)
	}
	if _, _, err := ParseTargetRule("example.com:443"); err == nil {
		t.Fatalf("缺前缀应报错")
	}
	if _, _, err := ParseTargetRule("allow:*"); err == nil {
		t.Fatalf("全域行应报错")
	}
}

func TestScrubEnv(t *testing.T) {
	t.Parallel()
	env := []string{
		"PATH=/usr/bin",
		"HOME=/home/u",
		"NPM_TOKEN=abc",
		"AWS_SECRET_ACCESS_KEY=xyz",
		"GPG_PASSPHRASE=p",
		"PASSWORD=hunter2",
		"MONKEY=keep", // 含 KEY 子串但非整词
		"TURKEY=keep", // 同上
		"APIKEY=keep", // 已知残余缺口：无边界连写不剥离（保守优于漏放的反向——文档化）
		"MY_CREDENTIALS=x",
	}
	out := ScrubEnv(env)
	got := map[string]bool{}
	for _, kv := range out {
		name, _, _ := cutEq(kv)
		got[name] = true
	}
	for _, want := range []string{"PATH", "HOME", "MONKEY", "TURKEY", "APIKEY"} {
		if !got[want] {
			t.Fatalf("ScrubEnv 丢了 %s: %v", want, out)
		}
	}
	for _, drop := range []string{"NPM_TOKEN", "AWS_SECRET_ACCESS_KEY", "GPG_PASSPHRASE", "PASSWORD", "MY_CREDENTIALS"} {
		if got[drop] {
			t.Fatalf("ScrubEnv 留了 %s: %v", drop, out)
		}
	}
}

func cutEq(s string) (string, string, bool) {
	for i := 0; i < len(s); i++ {
		if s[i] == '=' {
			return s[:i], s[i+1:], true
		}
	}
	return s, "", false
}

func TestInvalidPolicyRejectedAtLaunch(t *testing.T) {
	for _, pol := range []Policy{
		{Net: NetRuleSet{Rules: []NetRule{{HostPort: "bad host"}}}},
		{FS: FSRuleSet{Rules: []Rule{{Pattern: ""}}}},
	} {
		if err := validateProcessPolicy(processSpec(StartOptions{Policy: pol}, nil), "darwin"); err == nil {
			t.Fatal("invalid policy accepted")
		}
	}
}
