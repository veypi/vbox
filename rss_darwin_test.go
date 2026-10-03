//go:build darwin

package vbox

import (
	"bytes"
	"context"
	"os"
	"strings"
	"syscall"
	"testing"
)

// groupRSSKB 对**本进程实际进程组**返回非零 RSS（组内必有进程，物理内存
// 非零）。注：不能用 os.Getpid() 直接当 pgid——go test 下测试二进制继承
// go 命令的进程组（job control 以 go 为组长），自身并非组长，ps -g <pid>
// 匹配不到组即 exit 1（2026-08-31 实测踩坑）；生产路径 pgid==pid 是
// vbox spawn 置 Setpgid 的产物（见 rss_darwin.go 注释）。
// 注：CI/沙箱环境可能禁止 fork ps（operation not permitted），skip。
func TestGroupRSSKB(t *testing.T) {
	pgid, err := syscall.Getpgid(os.Getpid())
	if err != nil {
		t.Fatalf("getpgid: %v", err)
	}
	kb, err := groupRSSKB(pgid)
	if err != nil {
		if strings.Contains(err.Error(), "operation not permitted") {
			t.Skipf("environment forbids ps: %v", err)
		}
		t.Fatalf("groupRSSKB: %v", err)
	}
	if kb == 0 {
		t.Fatal("groupRSSKB(self) = 0, want > 0")
	}
}

// rssLimitBytes：非零且在 [1GiB, 8GiB]（min(8GiB, mem/2)）。
func TestRssLimitBytes(t *testing.T) {
	limit := rssLimitBytes()
	if limit < 1<<30 || limit > 8<<30 {
		t.Fatalf("rssLimitBytes = %d, want in [1GiB, 8GiB]", limit)
	}
}

// 集成：正常进程（分配 ~200MB，远低于上限）经沙箱 RunProcess 不被 RSS 监控
// 误杀，exit 0 且输出正确。嵌套沙箱环境（无后端 fail-closed）skip。
func TestMonitorDoesNotKillNormalProcess(t *testing.T) {
	m := NewManager()
	var out bytes.Buffer
	code, err := m.RunProcess(context.Background(), StartOptions{Exec: []string{"python3", "-c", "import time; x=bytearray(200*1024*1024); time.sleep(0.2); print(len(x))"}, Policy: Policy{FS: FSRuleSet{DefaultWrite: EffRW}, Net: NetRuleSet{Default: true}}}, nil, &out, &out)
	if err != nil {
		if strings.Contains(err.Error(), "no sandbox backend") {
			t.Skipf("nested sandbox unavailable: %v", err)
		}
		t.Fatalf("run: %v", err)
	}
	if code != 0 {
		t.Fatalf("exit = %d, want 0 (should not be killed): %s", code, out.String())
	}
	if !strings.Contains(out.String(), "209715200") {
		t.Fatalf("output missing alloc size: %q", out.String())
	}
}
