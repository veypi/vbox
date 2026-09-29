//go:build darwin

package vbox

import (
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// rssLimitBytes：darwin 的进程组 RSS 上限（字节）。
// macOS 内核不支持 RLIMIT_AS（setrlimit 恒 EINVAL，实测 2026-08-28），
// 大内存分配只能靠外部监控兜底：取 min(8GiB, 物理内存/2)——低于系统
// 总内存一半，避免单条沙箱命令把系统拖入内存压力假死（死机事故根因）。
func rssLimitBytes() uint64 {
	var mem uint64 = 16 << 30
	if s, err := syscall.Sysctl("hw.memsize"); err == nil {
		if v, err2 := strconv.ParseUint(strings.TrimSpace(s), 10, 64); err2 == nil && v > 0 {
			mem = v
		}
	}
	limit := mem / 2
	if limit > 8<<30 {
		limit = 8 << 30
	}
	return limit
}

// groupRSSKB 返回进程组全部进程的 RSS 合计（KB）。ps 输出每行一个数字
// （-o rss= 无表头）。沙箱命令及其子孙默认同进程组（Setpgid，pgid==pid）；
// 自行 setsid 脱离的进程不在覆盖内（与 --die-with-parent 同边界）。
func groupRSSKB(pgid int) (uint64, error) {
	out, err := exec.Command("ps", "-o", "rss=", "-g", strconv.Itoa(pgid)).Output()
	if err != nil {
		return 0, err
	}
	var total uint64
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if v, err := strconv.ParseUint(line, 10, 64); err == nil {
			total += v
		}
	}
	return total, nil
}

// monitorGroupRSS 轮询进程组 RSS，超限按 killProc 语义终止
// （SIGTERM → 5s SIGKILL）。进程结束（h.done）即退出。
func monitorGroupRSS(h *procHandle, limit uint64) {
	limitKB := limit / 1024
	if limitKB == 0 {
		return
	}
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-h.done:
			return
		case <-ticker.C:
			if h.PID() <= 0 {
				return
			}
			kb, err := groupRSSKB(h.PID())
			if err != nil {
				continue
			}
			if kb > limitKB {
				killProc(h)
				return
			}
		}
	}
}
