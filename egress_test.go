package vbox

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestEgressHTTPAbsoluteFormAndAuthentication(t *testing.T) {
	var hits atomic.Int32
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.URL.Path != "/hello" {
			t.Errorf("origin path = %q", r.URL.Path)
		}
		_, _ = io.WriteString(w, "origin-response")
	}))
	defer origin.Close()
	endpoint := newTestEgress(t, origin.Listener.Addr().String(), "")
	proxy := &url.URL{Scheme: "http", Host: endpoint.httpAddr, User: url.UserPassword("vbox", endpoint.token)}
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxy)}}
	response, err := client.Get(origin.URL + "/hello")
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if err != nil || string(body) != "origin-response" {
		t.Fatalf("response body=%q err=%v", body, err)
	}
	if hits.Load() != 1 {
		t.Fatalf("origin hits=%d", hits.Load())
	}

	unauthenticated := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(&url.URL{Scheme: "http", Host: endpoint.httpAddr})}}
	response, err = unauthenticated.Get(origin.URL + "/hello")
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusProxyAuthRequired {
		t.Fatalf("unauthenticated status=%d", response.StatusCode)
	}
	if hits.Load() != 1 {
		t.Fatalf("unauthenticated request reached origin")
	}
}

func TestEgressHTTPLocalhostRetriesAuthorizedAddresses(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "localhost-ok")
	}))
	defer origin.Close()
	_, port, err := net.SplitHostPort(origin.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	endpoint := newTestEgress(t, "localhost:"+port, "")
	proxy := &url.URL{Scheme: "http", Host: endpoint.httpAddr, User: url.UserPassword("vbox", endpoint.token)}
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxy)}}
	response, err := client.Get("http://localhost:" + port)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if string(body) != "localhost-ok" {
		t.Fatalf("localhost response=%q", body)
	}
}

func TestEgressHTTPConnectTunnel(t *testing.T) {
	address, echoDone := startEchoServer(t)
	endpoint := newTestEgress(t, address, "")
	conn, err := net.Dial("tcp", endpoint.httpAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	auth := basicAuth("vbox", endpoint.token)
	_, _ = fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\nProxy-Authorization: Basic %s\r\n\r\n", address, address, auth)
	reader := bufio.NewReader(conn)
	status, err := reader.ReadString('\n')
	if err != nil || !strings.Contains(status, " 200 ") {
		t.Fatalf("CONNECT status=%q err=%v", status, err)
	}
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		if line == "\r\n" {
			break
		}
	}
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	var reply [4]byte
	if _, err := io.ReadFull(reader, reply[:]); err != nil || string(reply[:]) != "ping" {
		t.Fatalf("tunnel reply=%q err=%v", reply, err)
	}
	_ = conn.Close()
	select {
	case <-echoDone:
	case <-time.After(2 * time.Second):
		t.Fatal("echo server did not finish")
	}
}

func TestEgressSOCKSTunnelAndAuthentication(t *testing.T) {
	address, echoDone := startEchoServer(t)
	endpoint := newTestEgress(t, address, "")
	conn, err := net.Dial("tcp", endpoint.socksAddr)
	if err != nil {
		t.Fatal(err)
	}
	if err := socks5ClientHandshake(conn, address, "vbox", endpoint.token); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write([]byte("sock")); err != nil {
		t.Fatal(err)
	}
	var reply [4]byte
	if _, err := io.ReadFull(conn, reply[:]); err != nil || string(reply[:]) != "sock" {
		t.Fatalf("SOCKS reply=%q err=%v", reply, err)
	}
	_ = conn.Close()
	select {
	case <-echoDone:
	case <-time.After(2 * time.Second):
		t.Fatal("echo server did not finish")
	}

	bad, err := net.Dial("tcp", endpoint.socksAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer bad.Close()
	if err := socks5ClientHandshake(bad, address, "vbox", "wrong"); err == nil {
		t.Fatal("wrong SOCKS password was accepted")
	}
}

func TestEgressSelfTargetVariants(t *testing.T) {
	endpoint := newTestEgress(t, "", "")
	_, port, err := net.SplitHostPort(endpoint.httpAddr)
	if err != nil {
		t.Fatal(err)
	}
	for _, host := range []string{"127.0.0.1", "localhost", "::1", "::ffff:127.0.0.1"} {
		if !endpoint.isSelfTarget(net.JoinHostPort(host, port)) {
			t.Errorf("self target %q was not rejected", host)
		}
	}
}

func TestEgressPolicyDeniesBeforeOrigin(t *testing.T) {
	var hits atomic.Int32
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer origin.Close()
	endpoint := newTestEgress(t, "", "")
	proxy := &url.URL{Scheme: "http", Host: endpoint.httpAddr, User: url.UserPassword("vbox", endpoint.token)}
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxy)}}
	response, err := client.Get(origin.URL)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("denied status=%d", response.StatusCode)
	}
	if hits.Load() != 0 {
		t.Fatal("denied request reached origin")
	}
}

func TestEgressExplicitHTTPUpstream(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !r.URL.IsAbs() {
			t.Error("upstream request was not absolute-form")
		}
		if r.URL.Hostname() == "localhost" || r.URL.Hostname() == "" {
			t.Errorf("upstream host=%q, want authorized concrete IP", r.URL.Host)
		}
		_, _ = io.WriteString(w, "from-upstream")
	}))
	defer upstream.Close()
	endpoint := newTestEgress(t, "localhost:12345", upstream.URL)
	proxy := &url.URL{Scheme: "http", Host: endpoint.httpAddr, User: url.UserPassword("vbox", endpoint.token)}
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxy)}}
	response, err := client.Get("http://localhost:12345/resource")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if string(body) != "from-upstream" {
		t.Fatalf("upstream body=%q", body)
	}
}

func TestEgressHTTPUpstreamPreservesRawHost(t *testing.T) {
	upstream, rawRequest := startRawHTTPUpstream(t)
	endpoint := newTestEgress(t, "localhost:12345", upstream)
	proxy := &url.URL{Scheme: "http", Host: endpoint.httpAddr, User: url.UserPassword("vbox", endpoint.token)}
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxy)}}
	response, err := client.Get("http://localhost:12345/resource")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if string(body) != "from-upstream" {
		t.Fatalf("upstream body=%q", body)
	}
	raw := <-rawRequest
	if !strings.Contains(raw, "GET http://") || !strings.Contains(raw, ":12345/resource HTTP/1.1") {
		t.Fatalf("upstream request line=%q", raw)
	}
	if !strings.Contains(raw, "Host: localhost:12345\r\n") {
		t.Fatalf("upstream raw Host header=%q", raw)
	}
}

func TestEgressExplicitUpstreamConnectChains(t *testing.T) {
	for _, scheme := range []string{"http", "socks5"} {
		t.Run(scheme, func(t *testing.T) {
			address, echoDone := startEchoServer(t)
			inner := newTestEgress(t, address, "")
			upstream := scheme + "://vbox:" + inner.token + "@" + map[string]string{"http": inner.httpAddr, "socks5": inner.socksAddr}[scheme]
			outer := newTestEgress(t, address, upstream)
			conn, err := net.Dial("tcp", outer.socksAddr)
			if err != nil {
				t.Fatal(err)
			}
			if err := socks5ClientHandshake(conn, address, "vbox", outer.token); err != nil {
				t.Fatal(err)
			}
			if _, err := conn.Write([]byte("chai")); err != nil {
				t.Fatal(err)
			}
			var reply [4]byte
			if _, err := io.ReadFull(conn, reply[:]); err != nil || string(reply[:]) != "chai" {
				t.Fatalf("upstream chain reply=%q err=%v", reply, err)
			}
			_ = conn.Close()
			select {
			case <-echoDone:
			case <-time.After(2 * time.Second):
				t.Fatal("upstream chain echo did not finish")
			}
		})
	}
}

func TestEgressHTTPUpstreamFailureDoesNotPanic(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer upstream.Close()
	endpoint := newTestEgress(t, "127.0.0.1:12345", upstream.URL)
	conn, err := endpoint.dialer.dialContext(context.Background(), "127.0.0.1:12345")
	if conn != nil {
		_ = conn.Close()
	}
	if err == nil {
		t.Fatal("failed upstream CONNECT unexpectedly succeeded")
	}
}

func TestEgressResolverGuardsAndRulePriority(t *testing.T) {
	policy := NetRuleSet{Rules: []NetRule{{HostPort: "example.com:443", Allow: true}}, Default: false}
	dialer := &egressDialer{policy: policy}
	allowed, err := dialer.authorizeIP("example.com", netip.MustParseAddr("127.0.0.1"), "443", nil)
	if err != nil || allowed {
		t.Fatalf("private DNS result allowed=%v err=%v", allowed, err)
	}
	allowed, err = dialer.authorizeIP("example.com", netip.MustParseAddr("203.0.113.10"), "443", nil)
	if err != nil || !allowed {
		t.Fatalf("public DNS result allowed=%v err=%v", allowed, err)
	}
	policy.Rules = append(policy.Rules, NetRule{HostPort: "203.0.113.10:443", Allow: false, Level: 1})
	dialer.policy = policy
	allowed, err = dialer.authorizeIP("example.com", netip.MustParseAddr("203.0.113.10"), "443", nil)
	if err != nil || allowed {
		t.Fatalf("higher-priority IP deny allowed=%v err=%v", allowed, err)
	}
}

func TestEgressDomainAndIPRulesKeepOriginalOrder(t *testing.T) {
	ip := netip.MustParseAddr("203.0.113.10")
	denyIP := NetRule{HostPort: "203.0.113.10:443", Allow: false}
	allowIP := NetRule{HostPort: "203.0.113.10:443", Allow: true}
	denyDomain := NetRule{HostPort: "example.com:443", Allow: false}
	allowDomain := NetRule{HostPort: "example.com:443", Allow: true}
	for _, tc := range []struct {
		name  string
		rules []NetRule
		want  bool
	}{
		{name: "first IP deny wins", rules: []NetRule{denyIP, allowDomain}, want: false},
		{name: "first domain allow wins", rules: []NetRule{allowDomain, denyIP}, want: true},
		{name: "first IP allow wins", rules: []NetRule{allowIP, denyDomain}, want: true},
		{name: "first domain deny wins", rules: []NetRule{denyDomain, allowIP}, want: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dialer := &egressDialer{policy: NetRuleSet{Rules: tc.rules}}
			got, err := dialer.authorizeIP("example.com", ip, "443", nil)
			if err != nil {
				t.Fatal(err)
			}
			if got != tc.want {
				t.Fatalf("authorizeIP=%v, want %v; rules=%v", got, tc.want, tc.rules)
			}
		})
	}
}

func TestValidateUpstreamProxy(t *testing.T) {
	for _, raw := range []string{"http://127.0.0.1:7897", "socks5://127.0.0.1:1080", "socks5h://proxy.example:1080"} {
		if err := ValidateUpstreamProxy(raw); err != nil {
			t.Errorf("ValidateUpstreamProxy(%q) error=%v", raw, err)
		}
	}
	for _, raw := range []string{"ftp://127.0.0.1:21", "http://127.0.0.1:99999", "http://127.0.0.1:7897/path"} {
		if err := ValidateUpstreamProxy(raw); err == nil {
			t.Errorf("ValidateUpstreamProxy(%q) unexpectedly succeeded", raw)
		}
	}
}

func TestEgressCacheAndTransportReservation(t *testing.T) {
	cache := newResourceCache()
	snapshot := NetRuleSet{Rules: []NetRule{{HostPort: "127.0.0.1:12345", Allow: true}}, Default: false}
	first, err := acquireEgressEndpoint(cache, snapshot)
	if err != nil {
		t.Fatal(err)
	}
	second, err := acquireEgressEndpoint(cache, snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if first.endpoint != second.endpoint {
		t.Fatal("same net snapshot did not reuse endpoint")
	}
	first.release()
	second.release()
	other := cloneNetRuleSet(snapshot)
	other.UpstreamProxy = "http://127.0.0.1:1"
	third, err := acquireEgressEndpoint(cache, other)
	if err != nil {
		t.Fatal(err)
	}
	if third.endpoint == first.endpoint {
		t.Fatal("different upstream proxy shared endpoint")
	}
	third.release()
	if err := cache.Close(); err != nil {
		t.Fatal(err)
	}

	reservedSnapshot := NetRuleSet{Rules: []NetRule{{HostPort: "localhost:23456", Allow: false, Level: 255}}, Default: false}
	plan, err := compileNetPlan("darwin", reservedSnapshot, netCapsForPlatform("darwin"), "127.0.0.1:23456", "127.0.0.1:23457")
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.kernelRules) != 2 || !plan.kernelRules[0].Allow || plan.kernelRules[0].HostPort != "localhost:23456" {
		t.Fatalf("reserved kernel rules=%+v", plan.kernelRules)
	}
	if !plan.landings[0].Absorbed || plan.landings[0].Kernel {
		t.Fatalf("user transport collision was not absorbed: %+v", plan.landings[0])
	}
	if len(plan.landings) != 3 || !plan.landings[1].Reserved || !plan.landings[2].Reserved {
		t.Fatalf("reserved landings=%+v", plan.landings)
	}
}

func TestEgressForcedEnvironment(t *testing.T) {
	env := processEnv(
		[]string{"HTTP_PROXY=inherited", "NO_PROXY=example.com", "PATH=/bin"},
		nil,
		[]string{"HTTP_PROXY=explicit", "NO_PROXY=example.org"},
		true,
		[]string{"HTTP_PROXY=forced", "HTTPS_PROXY=forced-tls"},
	)
	values := map[string]string{}
	for _, item := range env {
		key, value, _ := strings.Cut(item, "=")
		values[key] = value
	}
	if values["HTTP_PROXY"] != "forced" || values["HTTPS_PROXY"] != "forced-tls" {
		t.Fatalf("forced proxy env=%v", values)
	}
	if values["NO_PROXY"] != "127.0.0.1,localhost,::1,example.com,example.org" {
		t.Fatalf("NO_PROXY=%q", values["NO_PROXY"])
	}
}

func startRawHTTPUpstream(t *testing.T) (string, <-chan string) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	rawRequest := make(chan string, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		reader := bufio.NewReader(conn)
		var raw strings.Builder
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				return
			}
			raw.WriteString(line)
			if line == "\r\n" {
				break
			}
		}
		rawRequest <- raw.String()
		body := "from-upstream"
		_, _ = fmt.Fprintf(conn, "HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", len(body), body)
	}()
	t.Cleanup(func() { _ = listener.Close() })
	return "http://" + listener.Addr().String(), rawRequest
}

func newTestEgress(t *testing.T, allowed, upstream string) *egressEndpoint {
	t.Helper()
	snapshot := NetRuleSet{Default: false, UpstreamProxy: upstream}
	if allowed != "" {
		snapshot.Rules = []NetRule{{HostPort: allowed, Allow: true}}
	}
	endpoint, err := newEgressEndpoint(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = endpoint.Close() })
	return endpoint
}

func startEchoServer(t *testing.T) (string, <-chan struct{}) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		var data [4]byte
		if _, err := io.ReadFull(conn, data[:]); err == nil {
			_, _ = conn.Write(data[:])
		}
	}()
	t.Cleanup(func() { _ = listener.Close() })
	return listener.Addr().String(), done
}

func TestEgressEndpointCloseCancelsDial(t *testing.T) {
	endpoint := newTestEgress(t, "203.0.113.1:443", "")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := endpoint.dialer.dialContext(ctx, "203.0.113.1:443")
	if err == nil {
		t.Fatal("canceled dial unexpectedly succeeded")
	}
}
