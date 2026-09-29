package vbox

import (
	"context"
	"errors"
	"io"
	"runtime"
	"time"
)

// 三段式接口：规则模型（vbox.go/net.go）→ 编译（Compile，
// fail-closed——当前平台不可表达的规则启动前拒绝）→ 执行（Box）。
//
// 阶段二说明（迁移计划见 vsh/docs/todo.md 4.4）：OS 落地（sandbox_*.go：seatbelt/bwrap/受限令牌）
// 在 M4 后从 aic-pod exec_procs 物理迁入；当前 Compile 做规则数据校验并返回
// Spec，NewBox 返回 ErrOSLoweringPending——原生子进程执行暂由 pod exec_procs
// 承担（native.go 直接调它），接口形状以此为准对齐。

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

// ErrOSLoweringPending 标记 OS 落地未迁入（阶段二）。
var ErrOSLoweringPending = errors.New("vbox: OS sandbox lowering pending (阶段二；当前由 aic-pod exec_procs 执行)")

// Spec 编译产物（每次调用构造，随规则表快照失效）。
type Spec struct {
	Policy Policy
	Caps   Caps
}

// Compile 校验策略快照并返回 Spec。fail-closed 原则：当前平台不可表达的规则
// 应在启动前拒绝——阶段二迁入 OS 落地时在此执行表达性检查；现阶段做数据校验
// （规则模式可编译性）。
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

// Request 原生子进程执行请求。
type Request struct {
	Argv           []string
	Env            map[string]string
	Dir            string
	Stdin          io.Reader
	Stdout, Stderr io.Writer
	WallClock      time.Duration
	MaxOutputBytes int64
	NoSandbox      bool // 免沙箱须亮明身份（调用方已走 Critical(4) 审批）
}

// Result 原生子进程执行结果。
type Result struct {
	ExitCode int
	TimedOut bool // 墙钟到期被杀（调用方映射 124）
}

// Box 原生子进程沙箱执行器（进程组终止 / 墙钟 / 输出上限 收进 Box）。
type Box interface {
	Run(ctx context.Context, req *Request) (*Result, error)
}

// NewBox 构造执行器。阶段二前返回 ErrOSLoweringPending——调用方（native.go）
// 暂经 aic-pod exec_procs 执行原生子进程，接口形状与本定义对齐。
func NewBox(spec *Spec) (Box, error) {
	return nil, ErrOSLoweringPending
}
