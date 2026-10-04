package vbox

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"testing"
	"time"
)

func TestRawProcessChild(t *testing.T) {
	if os.Getenv("VBOX_RAW_TEST_CHILD") == "error" {
		_, _ = os.Stdout.Write([]byte{0, 0xff, 0x81, '\n', 0, 0xfe})
		os.Exit(0)
	}
	if os.Getenv("VBOX_RAW_TEST_CHILD") == "stderr" {
		_, _ = os.Stdout.WriteString("out\n")
		_, _ = os.Stderr.WriteString("err\n")
		os.Exit(0)
	}
	if os.Getenv("VBOX_RAW_TEST_CHILD") != "1" {
		return
	}
	_, _ = os.Stdout.Write([]byte{0, 0xff, 0x81}) // deliberately no newline
	var ack [1]byte
	_, _ = os.Stdin.Read(ack[:])
	_, _ = os.Stdout.Write([]byte{'\n', 0, 0xfe})
	os.Exit(0)
}

type rawHandshakeWriter struct {
	buffer bytes.Buffer
	input  *io.PipeWriter
	closed bool
	sent   bool
}

func (w *rawHandshakeWriter) Write(p []byte) (int, error) {
	if !w.sent {
		w.sent = true
		go func() { w.input.Write([]byte{1}); w.input.Close() }()
	}
	return w.buffer.Write(p)
}
func (w *rawHandshakeWriter) Bytes() []byte { return w.buffer.Bytes() }
func (w *rawHandshakeWriter) Close() error  { w.closed = true; return nil }

func TestRunProcessRawBinaryHandshakeAndOwnership(t *testing.T) {
	in, out := io.Pipe()
	defer in.Close()
	defer out.Close()
	w := &rawHandshakeWriter{input: out}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	stop := context.AfterFunc(ctx, func() { in.Close(); out.Close() })
	defer stop()
	m := NewManager()
	defer m.Close(context.Background())
	code, err := m.RunProcess(ctx, StartOptions{Exec: []string{os.Args[0], "-test.run=^TestRawProcessChild$"}, Env: []string{"VBOX_RAW_TEST_CHILD=1"}, NoSandbox: true, RawOutput: true}, in, w, io.Discard)
	if err != nil || code != 0 || !bytes.Equal(w.Bytes(), []byte{0, 0xff, 0x81, '\n', 0, 0xfe}) {
		t.Fatalf("code=%d bytes=%x err=%v", code, w.Bytes(), err)
	}
	if w.closed {
		t.Fatal("process closed caller-owned output")
	}
}

type failingRawWriter struct{ err error }

func (w failingRawWriter) Write([]byte) (int, error) { return 0, w.err }

// RawOutput 模式必须双流都送达（协议管道要 stderr 诊断）。现有用例只校验 stdout，
// stderr 传 io.Discard，掩盖了“RawOutput 下 stderr 丢失”（2026-10-05 Windows 上
// 托管 ssh 静默 255 的嫌疑点）。
func TestRunProcessRawStderrDelivered(t *testing.T) {
	var outBuf, errBuf bytes.Buffer
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	m := NewManager()
	defer m.Close(context.Background())
	code, err := m.RunProcess(ctx, StartOptions{
		Exec:      []string{os.Args[0], "-test.run=^TestRawProcessChild$"},
		Env:       []string{"VBOX_RAW_TEST_CHILD=stderr"},
		NoSandbox: true, RawOutput: true,
	}, nil, &outBuf, &errBuf)
	if err != nil || code != 0 {
		t.Fatalf("code=%d err=%v", code, err)
	}
	if got := outBuf.String(); got != "out\n" {
		t.Fatalf("stdout=%q, want %q", got, "out\n")
	}
	if got := errBuf.String(); got != "err\n" {
		t.Fatalf("RawOutput 下 stderr 未送达: %q, want %q", got, "err\n")
	}
}

func TestRunProcessRawWriteError(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	m := NewManager()
	defer m.Close(context.Background())
	want := errors.New("protocol consumer failed")
	_, err := m.RunProcess(ctx, StartOptions{Exec: []string{os.Args[0], "-test.run=^TestRawProcessChild$"}, Env: []string{"VBOX_RAW_TEST_CHILD=error"}, NoSandbox: true, RawOutput: true}, nil, failingRawWriter{want}, io.Discard)
	if !errors.Is(err, want) {
		t.Fatalf("write error lost: %v", err)
	}
}
