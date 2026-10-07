package vbox

import (
	"regexp"
	"strings"
)

// processEnv 是两个进程入口共用的环境装配：先清洗继承环境，再应用
// 平台环境和调用方显式覆盖。显式传入的凭据不属于隐式继承的秘密。
// os/exec 负责同名键去重（后值优先，也处理 Windows 的大小写）。
func processEnv(env, platform, explicit []string, confined bool) []string {
	if confined {
		env = ScrubEnv(env)
	}
	return append(append(env, platform...), explicit...)
}

// 沙箱 env 清洗：
// /proc/*/environ mask 不可行且是假安全感——沙箱进程继承 host 全部环境变量，
// env 即见；正式对策 = 启动时剥离敏感变量。
//
// 匹配规则：变量名按 `_` 分词后整词命中敏感标记（boundary regex）——
// 子串匹配会误伤 MONKEY/TURKEY（含 "KEY" 子串）。NPM_TOKEN、AWS_SECRET_ACCESS_KEY、
// GPG_PASSPHRASE、PASSWORD 等全部命中；APIKEY 这类无边界连写为已知残余缺口
// （保守优于漏放；确有需求走 nosandbox 或追加 cfg 方案）。
// nosandbox 不清洗（语义自洽：免沙箱 = 用户显式信任本次执行）。
var sensitiveEnvRe = regexp.MustCompile(
	`(^|_)(KEY|SECRET|TOKEN|PASS|PASSWORD|PASSWD|PASSPHRASE|CRED|CREDS|CREDENTIAL|CREDENTIALS|AUTH)(_|$)`)

// ScrubEnv 剥离名字命中敏感标记的环境变量，返回可传给沙箱子进程的环境。
// PATH/HOME/LANG 等工具链必需变量天然不命中标记，无需显式保留表。
func ScrubEnv(env []string) []string {
	out := make([]string, 0, len(env))
	for _, kv := range env {
		name, _, _ := strings.Cut(kv, "=")
		if sensitiveEnvRe.MatchString(strings.ToUpper(name)) {
			continue
		}
		out = append(out, kv)
	}
	return out
}
