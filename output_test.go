package vbox

import (
	"bytes"
	"strings"
	"testing"

	"golang.org/x/text/encoding/simplifiedchinese"
)

// gbk 将中文文本编码为 GBK 字节（模拟中文 Windows 子进程输出）。
func gbk(t *testing.T, s string) []byte {
	t.Helper()
	b, err := simplifiedchinese.GBK.NewEncoder().Bytes([]byte(s))
	if err != nil {
		t.Fatalf("gbk encode %q: %v", s, err)
	}
	return b
}

func TestWindowsOutputWriterUTF8Passthrough(t *testing.T) {
	// wsl 等程序输出 UTF-8：原样直写
	var buf bytes.Buffer
	w := &windowsOutputWriter{w: &buf}
	w.Write([]byte("Version: 2.0\nDistributionName: Ubuntu\n"))
	w.Close()
	want := "Version: 2.0\nDistributionName: Ubuntu\n"
	if buf.String() != want {
		t.Fatalf("got %q, want %q", buf.String(), want)
	}
}

func TestWindowsOutputWriterGBK(t *testing.T) {
	// 中文 Windows PowerShell 错误输出（GBK）→ UTF-8
	raw := gbk(t, "找不到“nvm”的有效路径。\n所在位置 行:1 字符: 61\n")
	var buf bytes.Buffer
	w := &windowsOutputWriter{w: &buf}
	w.Write(raw)
	w.Close()
	want := "找不到“nvm”的有效路径。\n所在位置 行:1 字符: 61\n"
	if buf.String() != want {
		t.Fatalf("got %q, want %q", buf.String(), want)
	}
}

func TestWindowsOutputWriterMixedLines(t *testing.T) {
	// where.exe 输出 ASCII 路径 + PowerShell 错误信息 GBK：逐行切换编码
	var buf bytes.Buffer
	w := &windowsOutputWriter{w: &buf}
	w.Write([]byte("C:\\node\\node.exe\n"))
	w.Write(gbk(t, "信息: 无法找到文件。\n"))
	w.Close()
	want := "C:\\node\\node.exe\n信息: 无法找到文件。\n"
	if buf.String() != want {
		t.Fatalf("got %q, want %q", buf.String(), want)
	}
}

func TestWindowsOutputWriterChunkBoundary(t *testing.T) {
	// GBK 行被跨 Write 调用切分：缓冲残留必须完整拼接后再转码
	raw := gbk(t, "信息: 无法找到文件。\n")
	var buf bytes.Buffer
	w := &windowsOutputWriter{w: &buf}
	half := len(raw) / 2
	w.Write(raw[:half])
	w.Write(raw[half:])
	w.Close()
	want := "信息: 无法找到文件。\n"
	if buf.String() != want {
		t.Fatalf("got %q, want %q", buf.String(), want)
	}
}

func TestWindowsOutputWriterNoTrailingNewline(t *testing.T) {
	// 无换行结尾：Close 时 flush 残留
	raw := gbk(t, "信息: 无法找到文件。")
	var buf bytes.Buffer
	w := &windowsOutputWriter{w: &buf}
	w.Write(raw)
	w.Close()
	want := "信息: 无法找到文件。"
	if buf.String() != want {
		t.Fatalf("got %q, want %q", buf.String(), want)
	}
}

func TestTranscodeLineInvalidFallback(t *testing.T) {
	// 既非合法 UTF-8 又无法 GBK 解码（如 0xFF 孤立字节）：保底替换，不产生 NUL/非法字节
	got := string(transcodeLine([]byte{'a', 0xff, 'b'}))
	if strings.ContainsRune(got, 0xff) {
		t.Fatalf("invalid bytes not replaced: %q", got)
	}
}
