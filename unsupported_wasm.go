//go:build js || wasip1

package vbox

// vbox 是原生子进程沙箱库：需要真实的进程/文件系统与内核沙箱能力（见 README
// 「平台支持」：darwin / linux / windows），js/wasm 与 wasip1 不具备，不做支持。
//
// 这个刻意不存在的 import 让构建在包边界上直接失败（报错即包名）。仅在 js/wasip1
// 下参与编译。
import _ "vbox/unsupported-platform-js-wasm"
