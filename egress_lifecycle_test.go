package vbox

import (
	"net"
	"sync"
	"testing"
	"time"
)

func TestEgressConcurrentAcquireAndSnapshotIsolation(t *testing.T) {
	cache := newResourceCache()
	snapshot := NetRuleSet{Rules: []NetRule{{HostPort: "127.0.0.1:12345", Allow: true}}, Default: false}
	const count = 8
	leases := make([]*egressLease, count)
	errs := make([]error, count)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := range leases {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			leases[i], errs[i] = acquireEgressEndpoint(cache, snapshot)
		}()
	}
	close(start)
	wg.Wait()
	for i, lease := range leases {
		if errs[i] != nil {
			t.Fatal(errs[i])
		}
		if lease.endpoint != leases[0].endpoint {
			t.Fatal("concurrent acquire created distinct endpoints")
		}
	}
	snapshot.Rules[0].Allow = false
	if !leases[0].endpoint.dialer.policy.Rules[0].Allow {
		t.Fatal("caller mutation changed the cached policy snapshot")
	}
	for _, lease := range leases {
		lease.release()
	}
	_ = cache.Close()
}

func TestEgressDeadListenerRebuilds(t *testing.T) {
	cache := newResourceCache()
	snapshot := NetRuleSet{Default: false}
	lease, err := acquireEgressEndpoint(cache, snapshot)
	if err != nil {
		t.Fatal(err)
	}
	old := lease.endpoint
	oldToken := old.token
	_ = old.httpListener.Close()
	deadline := time.Now().Add(2 * time.Second)
	for !old.dead() && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if !old.dead() {
		t.Fatal("listener death was not reported")
	}
	lease.release()
	rebuilt, err := acquireEgressEndpoint(cache, snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if rebuilt.endpoint == old || rebuilt.endpoint.token == oldToken {
		t.Fatal("dead endpoint was not rebuilt with a fresh token")
	}
	rebuilt.release()
	_ = cache.Close()
}

func TestEgressBusyEndpointIsNotIdleEvicted(t *testing.T) {
	cache := newResourceCache()
	cache.idleTTL = 0
	lease, err := acquireEgressEndpoint(cache, NetRuleSet{Default: false})
	if err != nil {
		t.Fatal(err)
	}
	endpoint := lease.endpoint
	if !endpoint.acquireTunnel() {
		t.Fatal("could not reserve tunnel")
	}
	lease.release()
	cache.mu.Lock()
	expired := cache.reapLocked()
	cache.mu.Unlock()
	closeCacheResources(expired)
	if len(expired) != 0 {
		t.Fatal("busy endpoint was idle-evicted")
	}
	endpoint.releaseTunnel()
	cache.mu.Lock()
	expired = cache.reapLocked()
	cache.mu.Unlock()
	closeCacheResources(expired)
	if len(expired) != 1 {
		t.Fatalf("idle endpoint eviction count=%d, want 1", len(expired))
	}
	_ = cache.Close()
}

func TestEgressCloseInterruptsTunnel(t *testing.T) {
	address, echoDone := startEchoServer(t)
	endpoint := newTestEgress(t, address, "")
	conn, err := net.Dial("tcp", endpoint.socksAddr)
	if err != nil {
		t.Fatal(err)
	}
	if err := socks5ClientHandshake(conn, address, "vbox", endpoint.token); err != nil {
		t.Fatal(err)
	}
	closed := make(chan struct{})
	go func() {
		_ = endpoint.Close()
		close(closed)
	}()
	select {
	case <-closed:
	case <-time.After(3 * time.Second):
		t.Fatal("endpoint Close blocked on an active tunnel")
	}
	_ = conn.SetReadDeadline(time.Now().Add(time.Second))
	var one [1]byte
	if _, err := conn.Read(one[:]); err == nil {
		t.Fatal("client tunnel remained readable after endpoint Close")
	}
	_ = conn.Close()
	select {
	case <-echoDone:
	case <-time.After(2 * time.Second):
		t.Fatal("remote tunnel was not closed")
	}
}
