// Package vbox 原生子进程沙箱库：规则模型 + 纯判定 + OS 落地（Seatbelt/bwrap/
// 受限令牌）+ 进程生命周期（Manager/RunProcess/Spawn）。不知道 shell、审批、
// grant 持久化——配置解析与 grant 生命周期在调用方（aic-pod libs/host），
// 每次调用编译快照传入。本文件是进程托管层（自 aic-pod libs/exec_procs 迁入，
// 2026-09-29 W2）。
package vbox

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
)

var errClosed = errors.New("vbox: manager closed")

// procHandle 是一次原生进程运行的内部句柄（进程组终止与 RSS 监控用）。
type procHandle struct {
	pid  atomic.Int64
	done chan struct{}
}

func (h *procHandle) PID() int { return int(h.pid.Load()) }

type Manager struct {
	mu        sync.Mutex
	noSandbox atomic.Bool
	logf      atomic.Value // func(string, ...any)
	closed    bool
	running   map[*procHandle]struct{}
}

func NewManager() *Manager {
	return &Manager{running: map[*procHandle]struct{}{}}
}

func (m *Manager) SetNoSandbox(value bool) { m.noSandbox.Store(value) }

// SetLogf 注入沙箱/执行阶段计时日志（pod 侧接 host 的 OnLog；nil 忽略）。
// 不注入则全链路静默（测试与库内直用）。
func (m *Manager) SetLogf(fn func(string, ...any)) {
	if fn != nil {
		m.logf.Store(fn)
	}
}

// logFunc 返回注入的日志函数（未注入 = nil）。
func (m *Manager) logFunc() func(string, ...any) {
	if v := m.logf.Load(); v != nil {
		return v.(func(string, ...any))
	}
	return nil
}

// track 登记运行句柄（Close 时统一终止）。
func (m *Manager) track(h *procHandle) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return errClosed
	}
	m.running[h] = struct{}{}
	return nil
}

func (m *Manager) untrack(h *procHandle) {
	m.mu.Lock()
	delete(m.running, h)
	m.mu.Unlock()
}

// Close 终止全部仍在运行的子进程并等待退出。
func (m *Manager) Close(ctx context.Context) error {
	m.mu.Lock()
	m.closed = true
	handles := make([]*procHandle, 0, len(m.running))
	for h := range m.running {
		handles = append(handles, h)
	}
	m.mu.Unlock()
	for _, h := range handles {
		select {
		case <-h.done:
		default:
			killProc(h)
		}
	}
	for _, h := range handles {
		select {
		case <-h.done:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return nil
}
