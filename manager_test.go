package vbox

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"
)

// RunProcess 正常完成：输出进调用方 writer，退出码透传。
func TestRunProcessNormalCompletion(t *testing.T) {
	m := NewManager()
	// 与沙箱无关：全局免沙箱隔离环境差异
	m.SetNoSandbox(true)
	var out bytes.Buffer
	code, err := m.RunProcess(context.Background(), StartOptions{Exec: []string{"bash", "-c", "printf 'a\\nb\\nc\\n'"}, Policy: Policy{FS: FSRuleSet{DefaultWrite: EffRW}, Net: NetRuleSet{Default: true}}}, nil, &out, &out)
	if err != nil {
		t.Fatal(err)
	}
	if code != 0 || out.String() != "a\nb\nc\n" {
		t.Errorf("code = %d, out = %q", code, out.String())
	}
}

// ctx 取消终止进程（取消句柄由 exec 外层持有，本包认 ctx）。
func TestRunProcessCancel(t *testing.T) {
	m := NewManager()
	m.SetNoSandbox(true)
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	var out bytes.Buffer
	start := time.Now()
	_, err := m.RunProcess(ctx, StartOptions{Exec: []string{"bash", "-c", "printf 'partial\\n'; sleep 30"}, Policy: Policy{FS: FSRuleSet{DefaultWrite: EffRW}, Net: NetRuleSet{Default: true}}}, nil, &out, &out)
	if err == nil {
		t.Fatal("cancelled process should report ctx error")
	}
	if time.Since(start) > 10*time.Second {
		t.Fatal("cancellation did not terminate the process")
	}
	if !strings.Contains(out.String(), "partial") {
		t.Errorf("partial output = %q", out.String())
	}
}

func TestRunProcessUnknownProgram(t *testing.T) {
	m := NewManager()
	_, err := m.RunProcess(context.Background(), StartOptions{Exec: []string{"definitely-not-a-program-xyz"}, Policy: Policy{FS: FSRuleSet{DefaultWrite: EffRW}, Net: NetRuleSet{Default: true}}}, nil, &bytes.Buffer{}, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "unknown action") {
		t.Errorf("err = %v", err)
	}
}

// Close 终止仍在运行的子进程。
func TestManagerCloseKillsRunning(t *testing.T) {
	m := NewManager()
	m.SetNoSandbox(true)
	done := make(chan struct{})
	go func() {
		defer close(done)
		var out bytes.Buffer
		_, _ = m.RunProcess(context.Background(), StartOptions{Exec: []string{"bash", "-c", "sleep 30"}, Policy: Policy{FS: FSRuleSet{DefaultWrite: EffRW}, Net: NetRuleSet{Default: true}}}, nil, &out, &out)
	}()
	// 等进程起来
	time.Sleep(300 * time.Millisecond)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := m.Close(ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
	case <-ctx.Done():
		t.Fatal("RunProcess did not return after Close")
	}
	// 关闭后新运行被拒
	if _, err := m.RunProcess(context.Background(), StartOptions{
		Exec: []string{"true"},
	}, nil, &bytes.Buffer{}, &bytes.Buffer{}); err == nil {
		t.Fatal("RunProcess accepted after Close")
	}
}
