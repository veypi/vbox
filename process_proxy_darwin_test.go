//go:build darwin

package vbox

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestRunProcessUsesForcedEgressProxy(t *testing.T) {
	listener := listenNonLoopback(t)
	if listener == nil {
		t.Skip("no non-loopback IPv4 interface available")
	}
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "through-vbox-proxy")
	})}
	go func() { _ = server.Serve(listener) }()
	defer server.Close()

	manager := NewManager()
	defer manager.Close(context.Background())
	var stdout, stderr bytes.Buffer
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	target := "http://" + listener.Addr().String() + "/"
	code, err := manager.RunProcess(ctx, StartOptions{
		Exec: []string{"/usr/bin/curl", "--noproxy", "", "--max-time", "8", "-fsS", target},
		Policy: Policy{
			FS:  FSRuleSet{DefaultWrite: EffRW},
			Net: NetRuleSet{Default: false, Rules: []NetRule{{HostPort: listener.Addr().String(), Allow: true}}},
		},
	}, nil, &stdout, &stderr)
	if err != nil {
		if strings.Contains(err.Error(), "no sandbox backend") {
			t.Skipf("Seatbelt unavailable: %v", err)
		}
		t.Fatalf("RunProcess: %v (stderr=%s)", err, stderr.String())
	}
	if code != 0 || stdout.String() != "through-vbox-proxy" {
		t.Fatalf("exit=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
}

func listenNonLoopback(t *testing.T) net.Listener {
	t.Helper()
	addresses, err := net.InterfaceAddrs()
	if err != nil {
		return nil
	}
	for _, address := range addresses {
		ip, _, err := net.ParseCIDR(address.String())
		if err != nil || ip.To4() == nil || ip.IsLoopback() {
			continue
		}
		listener, err := net.Listen("tcp", fmt.Sprintf("%s:0", ip.String()))
		if err == nil {
			return listener
		}
	}
	return nil
}
