//go:build !darwin

package vbox

// rssLimitBytes：非 darwin 平台不启用 RSS 监控——linux 由 bwrap --rlimit AS
// 承担（exec 前 setrlimit，强限制）、windows 由 Job Object 内存限制承担
// （进程 4GiB / job 8GiB，超限分配失败）。返回 0 = 关闭监控。
func rssLimitBytes() uint64 { return 0 }

// monitorGroupRSS 非 darwin 平台不可达（rssLimitBytes 恒 0），stub 仅满足
// exec_procs.RunProcess 的跨平台编译引用。
func monitorGroupRSS(h *procHandle, limit uint64) {}
