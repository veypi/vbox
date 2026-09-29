package vbox

import (
	"io"
	"strings"
	"sync"
	"unicode/utf8"

	"golang.org/x/text/encoding/simplifiedchinese"
)

// windowsOutputWriter 将子进程输出字节流转码为 UTF-8 后落盘（仅 Windows 使用）。
//
// 背景：中文 Windows 的 cmd/PowerShell 默认代码页 936（GBK），子进程输出中文字节
// 不是合法 UTF-8；若原样落盘，日志文件/工具结果里中文全部变成 U+FFFD 替换符
// （��Ϣ 乱码）。而 wsl.exe 等程序输出 UTF-8，不能一律按 GBK 解码。
//
// 策略：逐行判定——整行是合法 UTF-8 则原样直写（wsl 等），否则整行按 GBK 解码
// （cmd/PowerShell）。ASCII 在两种编码下字节一致，同一输出流中不同行可以不同编码；
// 换行符 0x0A 不属于 GBK 双字节尾字节（0x40-0xFE），按行切分不会切断中文字节对。
//
// stdout/stderr 合并重定向到同一 writer（加锁保证行不交错）。
type windowsOutputWriter struct {
	mu  sync.Mutex
	w   io.Writer
	buf []byte // 未遇换行的残留字节
}

func (o *windowsOutputWriter) Write(p []byte) (int, error) {
	o.mu.Lock()
	defer o.mu.Unlock()

	start := 0
	for i, b := range p {
		if b == '\n' {
			o.flushLine(p[start : i+1])
			start = i + 1
		}
	}
	if start < len(p) {
		o.buf = append(o.buf, p[start:]...)
	}
	return len(p), nil
}

// Close flush 残留的行尾数据（进程结束无换行结尾时）。
func (o *windowsOutputWriter) Close() error {
	o.mu.Lock()
	defer o.mu.Unlock()
	if len(o.buf) > 0 {
		line := o.buf
		o.buf = nil
		if _, err := o.w.Write(transcodeLine(line)); err != nil {
			return err
		}
	}
	return nil
}

func (o *windowsOutputWriter) flushLine(line []byte) {
	if len(o.buf) > 0 {
		line = append(o.buf, line...)
		o.buf = o.buf[:0]
	}
	// 忽略写错误：文件已打开，日志尽力而为（与旧行为一致）
	_, _ = o.w.Write(transcodeLine(line))
}

// transcodeLine 单行转码：合法 UTF-8 直写，否则 GBK 解码，兜底替换非法字节。
func transcodeLine(line []byte) []byte {
	if utf8.Valid(line) {
		return line
	}
	decoded, err := simplifiedchinese.GBK.NewDecoder().Bytes(line)
	if err == nil {
		return decoded
	}
	return []byte(strings.ToValidUTF8(string(line), "\uFFFD"))
}
