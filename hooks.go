package vbox

// hooks.go — vbox 需要的调用方状态注入点（vbox 不自持配置/持久化）。
// 由嵌入方装配（aic-pod libs/host）；nil = 无对应根（白名单宁缺毋滥，
// 不可写比错误可写安全）。

// PublicRootsFn 返回公共可写区根（pod 侧 = $HOME/.aic，cfg.PublicDir）：
// workspace-write 白名单成员，AI 跨会话保存产物与工具状态落盘共用。
var PublicRootsFn func() []string

// CacheRootsFn 返回依赖缓存目录根（pod 侧 = fsauth.CacheRoots：GOCACHE/
// npm/pip 等）——windows 沙箱可写名单成员。
var CacheRootsFn func() []string

// publicRoots 公共可写区（注入源；未接线返回 nil）。
func publicRoots() []string {
	if PublicRootsFn == nil {
		return nil
	}
	return PublicRootsFn()
}

// cacheRoots 依赖缓存目录（注入源；未接线返回 nil）。
func cacheRoots() []string {
	if CacheRootsFn == nil {
		return nil
	}
	return CacheRootsFn()
}
