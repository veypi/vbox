package vbox

import (
	"context"
	"io"
	"strings"
	"testing"
	"time"
)

// spawnOrSkip 启动管道进程；沙箱后端不可用时跳过（嵌套 seatbelt 环境——
// 与 TestConfine* 同约定）。
func spawnOrSkip(t *testing.T, m *Manager, ctx context.Context, opts StartOptions) *Spawned {
	t.Helper()
	opts.NetOpen = true // 测试不经网络规则（嵌套 seatbelt 带 network 规则会 EPERM）
	sp, err := m.Spawn(ctx, opts)
	if err != nil {
		if strings.Contains(err.Error(), "no sandbox backend") {
			t.Skipf("sandbox backend unavailable (nested sandbox): %v", err)
		}
		t.Fatalf("Spawn: %v", err)
	}
	return sp
}

// Spawn 管道语义：stdout 流式读、EOF 汇合退出状态、Abort 提前终止。
// netOpen=true（测试不经网络规则；嵌套 seatbelt 带 network 规则会 EPERM，
// 见 host_sandbox.md 嵌套限制）。
func TestSpawnEcho(t *testing.T) {
	m := NewManager(time.Minute)
	sp := spawnOrSkip(t, m, context.Background(), StartOptions{FsOpen: true, NetOpen: true,
		Exec: []string{"sh", "-c", "printf hello"},
	})
	body, err := io.ReadAll(sp.Body())
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if string(body) != "hello" {
		t.Fatalf("body = %q, want hello", body)
	}
	if err := sp.Wait(); err != nil {
		t.Fatalf("Wait after EOF should be nil: %v", err)
	}
}

// 非零退出：Body 读至 EOF 时返回带 stderr 摘要的错误（而非 io.EOF）。
func TestSpawnExitError(t *testing.T) {
	m := NewManager(time.Minute)
	sp := spawnOrSkip(t, m, context.Background(), StartOptions{FsOpen: true, NetOpen: true,
		Exec: []string{"sh", "-c", "echo out; echo boom-err >&2; exit 3"},
	})
	_, err := io.ReadAll(sp.Body())
	if err == nil || !strings.Contains(err.Error(), "boom-err") {
		t.Fatalf("EOF should surface exit error with stderr tail, got: %v", err)
	}
	// Wait 幂等（第二次调用返回 nil）
	if err := sp.Wait(); err != nil {
		t.Fatalf("second Wait should be nil: %v", err)
	}
}

// 短输出（小体量响应）下 EOF 后的 Read 必须持续返回 io.EOF：
// curl 无 -o 路径先经 LimitReader 嗅探窗（短体直接吃到 EOF），其后 io.Copy 若再读到
// (0, nil) 会无限空转——执行条目永不完成、回包被拖到请求 wait 到期的回归。
// 本用例只验证管道流语义，不经沙箱（NoSandbox），嵌套沙箱环境亦可运行。
func TestSpawnBodyEOFAfterSniffTerminatesCopy(t *testing.T) {
	m := NewManager(time.Minute)
	sp, err := m.Spawn(context.Background(), StartOptions{NoSandbox: true,
		Exec: []string{"sh", "-c", "printf hi"}})
	if err != nil {
		t.Fatalf("Spawn: %v", err)
	}
	body := sp.Body()
	// 模拟 curlToContent 的二进制嗅探窗：LimitReader 读满 8KB（短体在 EOF 处提前结束）
	head := make([]byte, 8192)
	n, _ := io.ReadFull(io.LimitReader(body, 8192), head)
	if n != 2 {
		t.Fatalf("sniff read = %d bytes, want 2", n)
	}
	// 其后 io.Copy 必须在 EOF 处终止（旧实现返回 (0, nil) → 永久空转）
	done := make(chan error, 1)
	go func() {
		_, err := io.Copy(io.Discard, io.LimitReader(body, 1<<30))
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("copy after sniff: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Read after EOF returned (0, nil): io.Copy spins forever")
	}
}

// Abort：提前终止（大输出场景调用方中止），Abort 幂等。
func TestSpawnAbort(t *testing.T) {
	m := NewManager(time.Minute)
	sp := spawnOrSkip(t, m, context.Background(), StartOptions{FsOpen: true, NetOpen: true,
		Exec: []string{"sh", "-c", "yes"},
	})
	buf := make([]byte, 64)
	if _, err := sp.Body().Read(buf); err != nil {
		t.Fatalf("read: %v", err)
	}
	sp.Abort()
	sp.Abort()
	if err := sp.Body().Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
}

// ctx 取消即杀进程。
func TestSpawnCtxCancel(t *testing.T) {
	m := NewManager(time.Minute)
	ctx, cancel := context.WithCancel(context.Background())
	sp := spawnOrSkip(t, m, ctx, StartOptions{FsOpen: true, NetOpen: true,
		Exec: []string{"sh", "-c", "sleep 30"},
	})
	cancel()
	done := make(chan struct{})
	go func() { sp.Abort(); close(done) }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("ctx cancel did not kill process")
	}
}
