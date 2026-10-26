package vbox

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sync"
	"sync/atomic"
	"time"
)

type egressLease struct {
	cache    *resourceCache
	key      cacheKey
	endpoint *egressEndpoint
	once     sync.Once
}

func (l *egressLease) release() {
	if l == nil {
		return
	}
	l.once.Do(func() {
		if l.cache != nil {
			l.cache.release(l.key)
		} else if l.endpoint != nil {
			_ = l.endpoint.Close()
		}
	})
}

func acquireEgressEndpoint(cache *resourceCache, snapshot NetRuleSet) (*egressLease, error) {
	snapshot = cloneNetRuleSet(snapshot)
	if cache == nil {
		endpoint, err := newEgressEndpoint(snapshot)
		if err != nil {
			return nil, err
		}
		return &egressLease{endpoint: endpoint}, nil
	}
	key := netSnapshotCacheKey(snapshot, snapshot.UpstreamProxy)
	value, _, err := cache.acquire(key, func() (cacheResource, error) {
		endpoint, err := newEgressEndpoint(snapshot)
		if err != nil {
			return cacheResource{}, err
		}
		return cacheResource{
			value: endpoint,
			close: endpoint.Close,
			dead:  endpoint.dead,
			busy:  endpoint.busy,
		}, nil
	})
	if err != nil {
		return nil, fmt.Errorf("start egress proxy: %w", err)
	}
	endpoint, ok := value.(*egressEndpoint)
	if !ok {
		cache.release(key)
		return nil, fmt.Errorf("start egress proxy: invalid cached endpoint")
	}
	return &egressLease{cache: cache, key: key, endpoint: endpoint}, nil
}

const (
	maxEgressRequests = 128
	maxEgressTunnels  = 64
	egressTunnelIdle  = 60 * time.Second
)

type egressEndpoint struct {
	policy    NetRuleSet
	dialer    *egressDialer
	token     string
	httpAddr  string
	socksAddr string

	httpListener  net.Listener
	socksListener net.Listener
	httpServer    *http.Server
	httpHandler   *egressHTTPHandler
	ctx           context.Context
	cancel        context.CancelFunc
	closed        chan struct{}
	closeOnce     sync.Once
	wg            sync.WaitGroup
	deadFlag      atomic.Bool
	requests      chan struct{}
	tunnels       chan struct{}
	activeRequest atomic.Int64
	activeTunnel  atomic.Int64
	handlerMu     sync.Mutex
	handlerClosed bool
	handlers      sync.WaitGroup
	connMu        sync.Mutex
	conns         map[net.Conn]struct{}
}

func newEgressEndpoint(snapshot NetRuleSet) (*egressEndpoint, error) {
	snapshot = cloneNetRuleSet(snapshot)
	for i, rule := range snapshot.Rules {
		if _, err := ParseRuleEntry(rule.HostPort); err != nil {
			return nil, fmt.Errorf("invalid net rule %d: %w", i+1, err)
		}
	}
	var upstream *url.URL
	var err error
	if snapshot.UpstreamProxy != "" {
		upstream, err = parseUpstreamProxy(snapshot.UpstreamProxy)
		if err != nil {
			return nil, err
		}
	}
	httpListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("listen HTTP egress proxy: %w", err)
	}
	socksListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		_ = httpListener.Close()
		return nil, fmt.Errorf("listen SOCKS5 egress proxy: %w", err)
	}
	token, err := newEgressToken()
	if err != nil {
		_ = httpListener.Close()
		_ = socksListener.Close()
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	endpoint := &egressEndpoint{
		policy:        snapshot,
		token:         token,
		httpAddr:      httpListener.Addr().String(),
		socksAddr:     socksListener.Addr().String(),
		httpListener:  httpListener,
		socksListener: socksListener,
		ctx:           ctx,
		cancel:        cancel,
		closed:        make(chan struct{}),
		requests:      make(chan struct{}, maxEgressRequests),
		tunnels:       make(chan struct{}, maxEgressTunnels),
		conns:         make(map[net.Conn]struct{}),
	}
	endpoint.dialer = &egressDialer{policy: snapshot, upstream: upstream}
	endpoint.httpHandler = newEgressHTTPHandler(endpoint)
	endpoint.httpServer = &http.Server{
		Handler:           endpoint.httpHandler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}
	endpoint.wg.Add(2)
	go endpoint.serveHTTP()
	go endpoint.serveSOCKS()
	return endpoint, nil
}

func newEgressToken() (string, error) {
	var value [32]byte
	if _, err := io.ReadFull(rand.Reader, value[:]); err != nil {
		return "", fmt.Errorf("generate egress proxy token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(value[:]), nil
}

func (e *egressEndpoint) serveHTTP() {
	defer e.wg.Done()
	err := e.httpServer.Serve(e.httpListener)
	if err != nil && !errors.Is(err, http.ErrServerClosed) && !e.isClosed() {
		e.deadFlag.Store(true)
		e.cancel()
	}
}

func (e *egressEndpoint) serveSOCKS() {
	defer e.wg.Done()
	for {
		conn, err := e.socksListener.Accept()
		if err != nil {
			if e.isClosed() {
				return
			}
			e.deadFlag.Store(true)
			e.cancel()
			return
		}
		if !e.trackConn(conn) {
			continue
		}
		if !e.acquireRequest() {
			_ = conn.Close()
			e.untrackConn(conn)
			continue
		}
		e.wg.Add(1)
		go func() {
			defer e.wg.Done()
			defer e.releaseRequest()
			defer e.untrackConn(conn)
			e.handleSOCKS(conn)
		}()
	}
}

func (e *egressEndpoint) isClosed() bool {
	select {
	case <-e.closed:
		return true
	default:
		return false
	}
}

func (e *egressEndpoint) dead() bool { return e.deadFlag.Load() }

func (e *egressEndpoint) beginHandler() bool {
	e.handlerMu.Lock()
	defer e.handlerMu.Unlock()
	if e.handlerClosed {
		return false
	}
	e.handlers.Add(1)
	return true
}

func (e *egressEndpoint) endHandler() { e.handlers.Done() }

func (e *egressEndpoint) requestContext(parent context.Context) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(parent)
	stop := context.AfterFunc(e.ctx, cancel)
	return ctx, func() {
		_ = stop()
		cancel()
	}
}

func (e *egressEndpoint) busy() bool {
	return e.activeRequest.Load() > 0 || e.activeTunnel.Load() > 0
}

func (e *egressEndpoint) acquireRequest() bool {
	e.activeRequest.Add(1)
	select {
	case e.requests <- struct{}{}:
		return true
	case <-e.closed:
		e.activeRequest.Add(-1)
		return false
	default:
		e.activeRequest.Add(-1)
		return false
	}
}

func (e *egressEndpoint) releaseRequest() {
	<-e.requests
	e.activeRequest.Add(-1)
}

func (e *egressEndpoint) acquireTunnel() bool {
	e.activeTunnel.Add(1)
	select {
	case e.tunnels <- struct{}{}:
		return true
	case <-e.closed:
		e.activeTunnel.Add(-1)
		return false
	default:
		e.activeTunnel.Add(-1)
		return false
	}
}

func (e *egressEndpoint) releaseTunnel() {
	<-e.tunnels
	e.activeTunnel.Add(-1)
}

func (e *egressEndpoint) Close() error {
	e.closeOnce.Do(func() {
		close(e.closed)
		e.cancel()
		e.handlerMu.Lock()
		e.handlerClosed = true
		e.handlerMu.Unlock()
		_ = e.httpServer.Close()
		e.httpHandler.transport.CloseIdleConnections()
		_ = e.socksListener.Close()
		e.closeConns()
	})
	e.handlers.Wait()
	e.wg.Wait()
	return nil
}

func (e *egressEndpoint) trackConn(conn net.Conn) bool {
	e.connMu.Lock()
	defer e.connMu.Unlock()
	if e.isClosed() {
		_ = conn.Close()
		return false
	}
	e.conns[conn] = struct{}{}
	return true
}

func (e *egressEndpoint) untrackConn(conn net.Conn) {
	e.connMu.Lock()
	delete(e.conns, conn)
	e.connMu.Unlock()
}

func (e *egressEndpoint) closeConns() {
	e.connMu.Lock()
	connections := make([]net.Conn, 0, len(e.conns))
	for conn := range e.conns {
		connections = append(connections, conn)
	}
	e.connMu.Unlock()
	for _, conn := range connections {
		_ = conn.Close()
	}
}

func (e *egressEndpoint) proxyEnv() []string {
	credentials := url.UserPassword("vbox", e.token).String()
	httpProxy := "http://" + credentials + "@" + e.httpAddr
	socksProxy := "socks5h://" + credentials + "@" + e.socksAddr
	return []string{
		"HTTP_PROXY=" + httpProxy,
		"HTTPS_PROXY=" + httpProxy,
		"ALL_PROXY=" + socksProxy,
		"http_proxy=" + httpProxy,
		"https_proxy=" + httpProxy,
		"all_proxy=" + socksProxy,
	}
}

func (e *egressEndpoint) tunnel(ctx context.Context, client, remote net.Conn) {
	if !e.trackConn(client) {
		_ = client.Close()
		_ = remote.Close()
		return
	}
	if !e.trackConn(remote) {
		e.untrackConn(client)
		_ = client.Close()
		_ = remote.Close()
		return
	}
	defer e.untrackConn(client)
	defer e.untrackConn(remote)
	client = &idleDeadlineConn{Conn: client, idle: egressTunnelIdle}
	remote = &idleDeadlineConn{Conn: remote, idle: egressTunnelIdle}
	deadline := time.Now().Add(egressTunnelIdle)
	_ = client.SetDeadline(deadline)
	_ = remote.SetDeadline(deadline)
	copyDone := make(chan struct{}, 2)
	go proxyCopy(client, remote, copyDone)
	go proxyCopy(remote, client, copyDone)
	remaining := 2
	for remaining > 0 {
		select {
		case <-copyDone:
			remaining--
		case <-ctx.Done():
			_ = client.Close()
			_ = remote.Close()
		case <-e.closed:
			_ = client.Close()
			_ = remote.Close()
		}
	}
	_ = client.Close()
	_ = remote.Close()
}

func proxyCopy(dst, src net.Conn, done chan<- struct{}) {
	_, _ = io.Copy(dst, src)
	if writer, ok := dst.(interface{ CloseWrite() error }); ok {
		_ = writer.CloseWrite()
	}
	done <- struct{}{}
}

type idleDeadlineConn struct {
	net.Conn
	idle time.Duration
}

func (c *idleDeadlineConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		_ = c.Conn.SetDeadline(time.Now().Add(c.idle))
	}
	return n, err
}

func (c *idleDeadlineConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	if n > 0 {
		_ = c.Conn.SetDeadline(time.Now().Add(c.idle))
	}
	return n, err
}

func (c *idleDeadlineConn) CloseWrite() error {
	if writer, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return writer.CloseWrite()
	}
	return nil
}
