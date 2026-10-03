package vbox

import (
	"runtime"
	"testing"
)

// TestMatchDoubleStar：跨段 ** 语义（todo S7 向量）。
func TestImportedMatchDoubleStar(t *testing.T) {
	cases := []struct {
		pat  string
		path string
		want bool
	}{
		{"/etc/ssh/**", "/etc/ssh/sshd_config", true},
		{"/etc/ssh/**", "/etc/ssh", true}, // /** 含零段匹配：deny 连根目录一并拒（ls 也不给）
		{"**/.env", "/a/b/.env", true},
		{"**/.env", "/a/b/c.txt", false},
		{"**/id_rsa*", "/tmp/id_rsa", true},
		{"**/id_rsa*", "/tmp/id_rsa.pub", true},
		{"**/id_rsa*", "/tmp/my_id_rsa", false}, // * 不跨段前缀：段内匹配 id_rsa* 需以 id_rsa 起头
		{"**/.ssh/**", "/home/u/.ssh/id_rsa", true},
		{"**/.ssh/**", "/home/u/.ssh", true}, // 尾 ** 零段：连 .ssh 目录自身一并拒（ls 也不给）
		{"/etc/sudoers*", "/etc/sudoers.d", true},
		{"/etc/sudoers*", "/etc/sudoers", true},
		{"/etc/sudoers*", "/etc/sudoers.d/x", false}, // * 不含 /
		{"**/*.pem", "/x/y/z.pem", true},
		{"**/*.pem", "/x/y/z.PEM", runtime.GOOS != "linux"},
		{"**/.git-credentials", "/repo/.git-credentials", true},
		{"/var/run/docker.sock", "/var/run/docker.sock", true},
		{"/var/run/docker.sock", "/var/run/other.sock", false},
		{"/abs/path", "/abs/path", true},
		{"/abs/path", "/abs/path2", false},
		{"/abs/path/**", "/abs/path", true}, // 零段匹配（deny 语义含根）
		{"/abs/path/**", "/abs/path/sub/f", true},
		{"/a/[b]/c", "/a/[b]/c", true}, // [ 按字面匹配（不支持字符类，与 canonicalPattern 检测集同口径）
		{"/a/[b]/c", "/a/b/c", false},
	}
	for _, c := range cases {
		if got := MatchPattern(c.pat, c.path); got != c.want {
			t.Errorf("MatchPattern(%q, %q) = %v, want %v", c.pat, c.path, got, c.want)
		}
	}
}

// TestMatchCaseFold：win/mac 大小写折叠、linux 敏感（平台分支向量）。
func TestImportedMatchCaseFold(t *testing.T) {
	got := MatchPattern("**/*.KEY", "/a/b.key")
	want := runtime.GOOS != "linux"
	if got != want {
		t.Errorf("fold = %v on %s, want %v", got, runtime.GOOS, want)
	}
}
