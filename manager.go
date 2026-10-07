// 本文件是进程托管层：Manager 负责进程启动（沙箱包装由 sandbox_*.go 提供）、
// 取消与期限（ctx）、输出分流、在跑进程登记与 Close 统一回收。
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

// stateDirOverride 是调用方显式指定的沙箱持久状态目录（空 = 平台默认目录）。
var stateDirOverride atomic.Value // string

// SetStateDir 指定沙箱持久状态目录（Windows 的 deny ACE 对账状态文件所在目录；
// 默认 `{UserConfigDir}/vbox/sandbox`）。该状态是机器级的（同一台机器只有一份
// ACE 对账记录），进程内多次设置以后者为准；只影响之后的对账写入与读取。
func (m *Manager) SetStateDir(dir string) { stateDirOverride.Store(dir) }

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
