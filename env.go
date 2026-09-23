package vbox

import (
	"regexp"
	"strings"
)

// 沙箱 env 清洗（自 fsauth env_scrub.go 移植，语义不变）：
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
