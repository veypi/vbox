//go:build plan9

package vbox

// vbox 是原生子进程沙箱库：需要进程组、信号、文件系统与内核沙箱语义（见 README
// 「平台支持」：darwin / linux / windows），plan9 不具备这些能力，不做支持。
//
// 这个刻意不存在的 import 让构建在包边界上直接失败（报错即包名），而不是在依赖链
// 深处报一堆 undefined: syscall.XXX。仅在 plan9 下参与编译。
import _ "vbox/unsupported-platform-plan9"
