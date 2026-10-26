package vbox

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestResourceCacheSingleflightAndClose(t *testing.T) {
	cache := newResourceCache()
	key := newCacheKey("test", "singleflight")
	var builds atomic.Int32
	var closes atomic.Int32
	started := make(chan struct{})
	unblock := make(chan struct{})
	factory := func() (cacheResource, error) {
		if builds.Add(1) == 1 {
			close(started)
			<-unblock
		}
		return cacheResource{value: "shared", close: func() error { closes.Add(1); return nil }}, nil
	}
	const workers = 8
	var wg sync.WaitGroup
	values := make(chan any, workers)
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			value, _, err := cache.acquire(key, factory)
			if err != nil {
				t.Errorf("acquire: %v", err)
				return
			}
			values <- value
			cache.release(key)
		}()
	}
	<-started
	close(unblock)
	wg.Wait()
	close(values)
	if builds.Load() != 1 {
		t.Fatalf("factory calls=%d, want 1", builds.Load())
	}
	for value := range values {
		if value != "shared" {
			t.Fatalf("value=%v", value)
		}
	}
	if err := cache.Close(); err != nil {
		t.Fatal(err)
	}
	if closes.Load() != 1 {
		t.Fatalf("resource close calls=%d, want 1", closes.Load())
	}
}

func TestResourceCacheDeadResourceRebuild(t *testing.T) {
	cache := newResourceCache()
	key := newCacheKey("test", "dead")
	var builds, oldCloses atomic.Int32
	factory := func() (cacheResource, error) {
		n := builds.Add(1)
		return cacheResource{
			value: n,
			dead:  func() bool { return n == 1 },
			close: func() error { oldCloses.Add(1); return nil },
		}, nil
	}
	first, _, err := cache.acquire(key, factory)
	if err != nil {
		t.Fatal(err)
	}
	cache.release(key)
	second, _, err := cache.acquire(key, factory)
	if err != nil {
		t.Fatal(err)
	}
	cache.release(key)
	if first != int32(1) || second != int32(2) || builds.Load() != 2 || oldCloses.Load() != 1 {
		t.Fatalf("first=%v second=%v builds=%d closes=%d", first, second, builds.Load(), oldCloses.Load())
	}
}

func TestResourceCacheIdleExpiry(t *testing.T) {
	cache := newResourceCache()
	cache.idleTTL = 5 * time.Millisecond
	key := newCacheKey("test", "expiry")
	var builds atomic.Int32
	factory := func() (cacheResource, error) {
		return cacheResource{value: builds.Add(1)}, nil
	}
	for i := 0; i < 2; i++ {
		if _, _, err := cache.acquire(key, factory); err != nil {
			t.Fatal(err)
		}
		cache.release(key)
		if i == 0 {
			time.Sleep(10 * time.Millisecond)
		}
	}
	if builds.Load() != 2 {
		t.Fatalf("factory calls=%d, want 2 after idle expiry", builds.Load())
	}
}

func TestResourceCacheKeysPreserveSemantics(t *testing.T) {
	net := NetRuleSet{Default: false, Rules: []NetRule{{HostPort: "example.com:443", Allow: true, Level: 1}}}
	base := netSnapshotCacheKey(net, "")
	if got := netSnapshotCacheKey(net, "http://127.0.0.1:7897"); got == base {
		t.Fatal("upstream proxy missing from netKey")
	}
	net.Rules[0].Level = 2
	if got := netSnapshotCacheKey(net, ""); got == base {
		t.Fatal("level missing from netKey")
	}
	net.Rules[0].Level = 1
	net.Rules = append(net.Rules, NetRule{HostPort: "other.example:443"})
	ordered := netSnapshotCacheKey(net, "")
	net.Rules[0], net.Rules[1] = net.Rules[1], net.Rules[0]
	if got := netSnapshotCacheKey(net, ""); got == ordered {
		t.Fatal("rule order missing from netKey")
	}

	fs := FSRuleSet{Rules: []Rule{{Pattern: "/x", Effect: EffRW, Class: ClassTemp}}}
	fsBase := fsSnapshotCacheKey(fs)
	fs.Rules[0].Class = ClassBuiltin
	if got := fsSnapshotCacheKey(fs); got != fsBase {
		t.Fatal("Class must not affect fsKey")
	}
	fs.Rules[0].Level = 1
	if got := fsSnapshotCacheKey(fs); got == fsBase {
		t.Fatal("level missing from fsKey")
	}
	if fsDenyCacheKey([]string{"/a", "/b"}) == fsDenyCacheKey([]string{"/b", "/a"}) {
		t.Fatal("deny pattern order missing from key")
	}
}

func TestCloneNetRuleSetDoesNotAliasCaller(t *testing.T) {
	original := NetRuleSet{Rules: []NetRule{{HostPort: "example.com:443", Allow: true}}}
	clone := cloneNetRuleSet(original)
	original.Rules[0].HostPort = "mutated.example:443"
	if clone.Rules[0].HostPort != "example.com:443" {
		t.Fatalf("snapshot aliases caller input: %+v", clone.Rules[0])
	}
}

func TestResourceCacheDoesNotEvictActiveEntries(t *testing.T) {
	cache := newResourceCache()
	cache.capacity = 1
	factory := func() (cacheResource, error) { return cacheResource{value: true}, nil }
	first := newCacheKey("test", "active-a")
	second := newCacheKey("test", "active-b")
	if _, _, err := cache.acquire(first, factory); err != nil {
		t.Fatal(err)
	}
	if _, _, err := cache.acquire(second, factory); err != nil {
		t.Fatalf("active entry blocked another acquire: %v", err)
	}
	cache.release(first)
	cache.release(second)
}

func TestDenyCoverAllCachedErrorsUseTTL(t *testing.T) {
	cache := newResourceCache()
	patterns := []string{"/*/**/x"}
	if _, cached, err := denyCoverAllCached(cache, patterns, nil); err == nil || cached {
		t.Fatalf("first error: cached=%v err=%v", cached, err)
	}
	if _, cached, err := denyCoverAllCached(cache, patterns, nil); err == nil || !cached {
		t.Fatalf("second error should hit the TTL cache: cached=%v err=%v", cached, err)
	}
}

func TestManagerCloseClosesCacheResources(t *testing.T) {
	m := NewManager()
	key := newCacheKey("test", "manager-close")
	var closed atomic.Int32
	if _, _, err := m.cache.acquire(key, func() (cacheResource, error) {
		return cacheResource{value: true, close: func() error { closed.Add(1); return nil }}, nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := m.Close(t.Context()); err != nil {
		t.Fatal(err)
	}
	if closed.Load() != 1 {
		t.Fatalf("resource close calls=%d, want 1", closed.Load())
	}
}
