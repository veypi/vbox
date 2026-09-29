package vbox

import (
	"errors"
	"runtime"
)

// 三段式接口：规则模型（vbox.go/net.go）→ 编译（Compile，
// fail-closed——当前平台不可表达的规则启动前拒绝）→ 执行（Manager，
// 见 manager.go/process.go——自 aic-pod exec_procs 迁入的 OS 落地：
// seatbelt/bwrap/受限令牌）。

// Policy 一份完整的沙箱策略快照（fs + net）。
type Policy struct {
	FS  FSRuleSet
	Net NetRuleSet
}

// Caps 平台沙箱表达能力。
type Caps struct {
	// OrderedFSRules：内核可表达完整行序（ro/rw 洞真实生效——darwin seatbelt
	// M3 行序映射）；false = 仅能 fail-closed 落全量 deny（linux/windows 现状，
	// ro/rw 洞仅进程内门放行）。
	OrderedFSRules bool
	// NetPerProcess：可在子进程粒度表达网络规则（darwin 仅 loopback 精确，
	// 不可表达条目启动前拒绝——沿用 pod 现状语义）。
	NetPerProcess bool
}

// Capabilities 返回当前平台的沙箱表达能力。
func Capabilities() Caps {
	switch runtime.GOOS {
	case "darwin":
		return Caps{OrderedFSRules: true, NetPerProcess: true}
	case "linux", "windows":
		return Caps{OrderedFSRules: false, NetPerProcess: true}
	default:
		return Caps{}
	}
}

// Spec 编译产物（每次调用构造，随规则表快照失效）。
type Spec struct {
	Policy Policy
	Caps   Caps
}

// Compile 校验策略快照并返回 Spec。fail-closed 原则：当前平台不可表达的规则
// 应在启动前拒绝——表达性检查随各平台后端（sandbox_*.go）在 plan 时执行；
// 本函数做数据校验（规则模式可编译性）。
func Compile(p Policy) (*Spec, error) {
	for i, r := range p.FS.Rules {
		if r.Pattern == "" {
			return nil, errors.New("vbox: empty fs rule pattern at row " + itoa(i))
		}
	}
	for i, r := range p.Net.Rules {
		if _, err := ParseEntry(r.HostPort); err != nil {
			return nil, errors.New("vbox: invalid net rule at row " + itoa(i) + ": " + err.Error())
		}
	}
	return &Spec{Policy: p, Caps: Capabilities()}, nil
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b [8]byte
	n := 0
	for i > 0 {
		b[n] = byte('0' + i%10)
		i /= 10
		n++
	}
	out := make([]byte, n)
	for i := 0; i < n; i++ {
		out[i] = b[n-1-i]
	}
	return string(out)
}

