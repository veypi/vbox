package vbox

import (
	"bufio"
	"context"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type egressHTTPHandler struct {
	endpoint  *egressEndpoint
	transport *http.Transport
}

func newEgressHTTPHandler(endpoint *egressEndpoint) *egressHTTPHandler {
	transport := &http.Transport{
		DialContext:            (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		MaxIdleConns:           16,
		MaxIdleConnsPerHost:    4,
		MaxConnsPerHost:        32,
		MaxResponseHeaderBytes: 1 << 20,
		IdleConnTimeout:        30 * time.Second,
		ResponseHeaderTimeout:  30 * time.Second,
		ExpectContinueTimeout:  time.Second,
	}
	// No ambient proxy is consulted. Direct requests use this policy-aware
	// dialer; explicit upstream requests use roundTripUpstream below instead.
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		return endpoint.dialer.dialContext(ctx, address)
	}
	return &egressHTTPHandler{endpoint: endpoint, transport: transport}
}

func (h *egressHTTPHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !h.endpoint.beginHandler() {
		http.Error(w, "proxy is closing", http.StatusServiceUnavailable)
		return
	}
	defer h.endpoint.endHandler()
	ctx, cancel := h.endpoint.requestContext(r.Context())
	defer cancel()
	r = r.WithContext(ctx)
	if !h.authenticated(r) {
		w.Header().Set("Proxy-Authenticate", "Basic realm=\"vbox\"")
		http.Error(w, "proxy authentication required", http.StatusProxyAuthRequired)
		return
	}
	if !h.endpoint.acquireRequest() {
		http.Error(w, "proxy connection limit reached", http.StatusServiceUnavailable)
		return
	}
	defer h.endpoint.releaseRequest()
	if r.Method == http.MethodConnect {
		h.handleConnect(w, r)
		return
	}
	h.handleHTTP(w, r)
}

func (h *egressHTTPHandler) authenticated(r *http.Request) bool {
	value := r.Header.Get("Proxy-Authorization")
	if len(value) < 6 || !strings.EqualFold(value[:6], "Basic ") {
		return false
	}
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(value[6:]))
	if err != nil {
		return false
	}
	username, password, ok := strings.Cut(string(decoded), ":")
	if !ok {
		return false
	}
	userOK := subtle.ConstantTimeCompare([]byte(username), []byte("vbox"))
	passwordOK := subtle.ConstantTimeCompare([]byte(password), []byte(h.endpoint.token))
	return userOK&passwordOK == 1
}

func basicAuth(username, password string) string {
	return base64.StdEncoding.EncodeToString([]byte(username + ":" + password))
}

func (h *egressHTTPHandler) handleConnect(w http.ResponseWriter, r *http.Request) {
	authority := r.Host
	if authority == "" {
		authority = r.URL.Host
	}
	address, err := authorityAddress(authority, "443")
	if err != nil || h.endpoint.isSelfTarget(address) {
		http.Error(w, "invalid proxy target", http.StatusBadRequest)
		return
	}
	if !h.endpoint.acquireTunnel() {
		http.Error(w, "proxy tunnel limit reached", http.StatusServiceUnavailable)
		return
	}
	defer h.endpoint.releaseTunnel()
	remote, err := h.endpoint.dialer.dialContext(r.Context(), address)
	if err != nil {
		http.Error(w, "proxy target denied or unreachable", http.StatusForbidden)
		return
	}
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		_ = remote.Close()
		http.Error(w, "hijacking is unavailable", http.StatusInternalServerError)
		return
	}
	client, rw, err := hijacker.Hijack()
	if err != nil {
		_ = remote.Close()
		return
	}
	if _, err := rw.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		_ = client.Close()
		_ = remote.Close()
		return
	}
	if err := rw.Flush(); err != nil {
		_ = client.Close()
		_ = remote.Close()
		return
	}
	h.endpoint.tunnel(r.Context(), client, remote)
}

func (h *egressHTTPHandler) handleHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL == nil || !r.URL.IsAbs() || r.URL.Scheme != "http" || r.URL.User != nil {
		http.Error(w, "only absolute-form plain HTTP is supported", http.StatusBadRequest)
		return
	}
	address, err := authorityAddress(r.URL.Host, "80")
	if err != nil || h.endpoint.isSelfTarget(address) {
		http.Error(w, "invalid proxy target", http.StatusBadRequest)
		return
	}
	targets, err := h.endpoint.dialer.resolve(r.Context(), address)
	if err != nil {
		http.Error(w, "proxy target denied", http.StatusForbidden)
		return
	}
	if len(targets) == 0 {
		http.Error(w, "proxy target denied", http.StatusForbidden)
		return
	}
	out := r.Clone(r.Context())
	out.URL = cloneURL(r.URL)
	originalHost := r.URL.Host
	out.URL.Host = targets[0].address
	out.Host = originalHost
	out.RequestURI = ""
	stripProxyHeaders(out.Header)
	var response *http.Response
	if h.endpoint.dialer.upstream != nil {
		response, err = h.roundTripUpstream(out, targets[0].address)
	} else {
		transport := h.transport.Clone()
		transport.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
			return h.endpoint.dialer.dialResolved(ctx, address, targets)
		}
		defer transport.CloseIdleConnections()
		response, err = transport.RoundTrip(out)
	}
	if err != nil {
		http.Error(w, "proxy upstream request failed", http.StatusBadGateway)
		return
	}
	defer response.Body.Close()
	copyResponseHeaders(w.Header(), response.Header)
	w.WriteHeader(response.StatusCode)
	_, _ = io.Copy(w, response.Body)
}

// roundTripUpstream deliberately writes the upstream protocol itself. The
// stdlib Transport uses one host value for both absolute-form and Host in its
// proxy path; here they must differ so the upstream receives an authorized IP
// without losing the origin's virtual host. Connections are closed per request.
func (h *egressHTTPHandler) roundTripUpstream(out *http.Request, target string) (*http.Response, error) {
	upstream := h.endpoint.dialer.upstream
	var conn net.Conn
	var err error
	if upstream.Scheme == "http" {
		dialer := net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
		conn, err = dialer.DialContext(out.Context(), "tcp", upstreamAddress(upstream))
	} else {
		conn, err = h.endpoint.dialer.dialUpstream(out.Context(), target)
	}
	if err != nil {
		return nil, err
	}
	stop := context.AfterFunc(out.Context(), func() { _ = conn.Close() })
	ok := false
	defer func() {
		if !ok {
			_ = stop()
			_ = conn.Close()
		}
	}()
	if err := conn.SetDeadline(time.Now().Add(60 * time.Second)); err != nil {
		return nil, err
	}
	out.Close = true
	if upstream.Scheme == "http" {
		if username, password := upstreamCredentials(upstream); username != "" {
			out.Header.Set("Proxy-Authorization", "Basic "+basicAuth(username, password))
		}
		path := out.URL.EscapedPath()
		if path == "" {
			path = "/"
		}
		out.URL.Opaque = "//" + target + path
		err = out.WriteProxy(conn)
	} else {
		out.URL.Opaque = ""
		err = out.Write(conn)
	}
	if err != nil {
		return nil, err
	}
	reader := bufio.NewReader(conn)
	var response *http.Response
	for {
		response, err = http.ReadResponse(reader, out)
		if err != nil {
			return nil, err
		}
		if response.StatusCode < 100 || response.StatusCode >= 200 || response.StatusCode == http.StatusSwitchingProtocols {
			break
		}
		_ = response.Body.Close()
	}
	response.Request = out
	response.Body = &egressResponseBody{ReadCloser: response.Body, conn: conn, stop: stop}
	ok = true
	return response, nil
}

type egressResponseBody struct {
	io.ReadCloser
	conn net.Conn
	stop func() bool
}

func (b *egressResponseBody) Close() error {
	_ = b.stop()
	err := b.ReadCloser.Close()
	_ = b.conn.Close()
	return err
}

func cloneURL(input *url.URL) *url.URL {
	output := *input
	output.User = nil
	return &output
}

func authorityAddress(authority, defaultPort string) (string, error) {
	if authority == "" || strings.ContainsAny(authority, "\r\n\x00") {
		return "", fmt.Errorf("empty or invalid authority")
	}
	if _, _, err := net.SplitHostPort(authority); err == nil {
		return authority, nil
	}
	if strings.HasPrefix(authority, "[") {
		if !strings.HasSuffix(authority, "]") {
			return "", fmt.Errorf("invalid IPv6 authority")
		}
		return net.JoinHostPort(strings.TrimSuffix(strings.TrimPrefix(authority, "["), "]"), defaultPort), nil
	}
	if strings.Count(authority, ":") == 0 {
		return net.JoinHostPort(authority, defaultPort), nil
	}
	if strings.Count(authority, ":") == 1 {
		return "", fmt.Errorf("invalid authority port")
	}
	return net.JoinHostPort(authority, defaultPort), nil
}

func (e *egressEndpoint) isSelfTarget(address string) bool {
	host, port, err := splitTarget(address)
	if err != nil || CanonicalNetHost(host) != "localhost" {
		return false
	}
	_, httpPort, _ := net.SplitHostPort(e.httpAddr)
	_, socksPort, _ := net.SplitHostPort(e.socksAddr)
	return port == httpPort || port == socksPort
}

var hopHeaders = []string{
	"Connection", "Proxy-Connection", "Keep-Alive", "Proxy-Authenticate",
	"Proxy-Authorization", "TE", "Trailer", "Transfer-Encoding", "Upgrade",
}

func stripProxyHeaders(header http.Header) {
	for _, connection := range []string{"Connection", "Proxy-Connection"} {
		for _, value := range header.Values(connection) {
			for _, name := range strings.Split(value, ",") {
				header.Del(strings.TrimSpace(name))
			}
		}
	}
	for _, name := range hopHeaders {
		header.Del(name)
	}
}

func copyResponseHeaders(dst, src http.Header) {
	connectionHeaders := map[string]bool{}
	for _, value := range src.Values("Connection") {
		for _, name := range strings.Split(value, ",") {
			connectionHeaders[strings.ToLower(strings.TrimSpace(name))] = true
		}
	}
	for key, values := range src {
		hop := connectionHeaders[strings.ToLower(key)]
		for _, name := range hopHeaders {
			if strings.EqualFold(key, name) {
				hop = true
				break
			}
		}
		if hop {
			continue
		}
		for _, value := range values {
			dst.Add(key, value)
		}
	}
}
