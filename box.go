package vbox

// Policy 是一次原生进程调用的完整权限快照。规则首命中生效；
// 配置、会话授权和默认规则由调用方组合，平台后端只负责落实。
type Policy struct {
	FS  FSRuleSet
	Net NetRuleSet
}
