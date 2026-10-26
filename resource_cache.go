package vbox

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	resourceCacheCapacity = 16
	resourceCacheIdleTTL  = 30 * time.Second
	denyCoverCacheTTL     = resourceCacheIdleTTL
)

type cacheKey struct {
	domain    string
	digest    string
	canonical string
}

func newCacheKey(domain string, parts ...string) cacheKey {
	var b strings.Builder
	write := func(s string) {
		b.WriteString(strconv.Itoa(len(s)))
		b.WriteByte(':')
		b.WriteString(s)
		b.WriteByte('|')
	}
	write(domain)
	for _, part := range parts {
		write(part)
	}
	canonical := b.String()
	sum := sha256.Sum256([]byte(canonical))
	return cacheKey{domain: domain, digest: hex.EncodeToString(sum[:]), canonical: canonical}
}

func fsDenyCacheKey(patterns []string) cacheKey {
	parts := []string{"fs-deny-v1", runtime.GOOS}
	parts = append(parts, patterns...)
	return newCacheKey("fs-deny", parts...)
}

func netSnapshotCacheKey(snapshot NetRuleSet, upstreamProxy string) cacheKey {
	parts := []string{
		"net-v1", "address-guard-v1", "loopback-v1", runtime.GOOS,
		strconv.FormatBool(snapshot.Default), upstreamProxy,
	}
	for _, rule := range snapshot.Rules {
		parts = append(parts, rule.HostPort, strconv.FormatBool(rule.Allow), strconv.Itoa(int(rule.Level)))
	}
	return newCacheKey("net", parts...)
}

func fsSnapshotCacheKey(snapshot FSRuleSet) cacheKey {
	parts := []string{"fs-v1", runtime.GOOS, snapshot.DefaultWrite.String()}
	if snapshot.Err != nil {
		parts = append(parts, "error", snapshot.Err.Error())
	}
	for _, rule := range snapshot.Rules {
		parts = append(parts, rule.Pattern, rule.Effect.String(), strconv.Itoa(int(rule.Level)))
	}
	return newCacheKey("fs", parts...)
}

func cloneNetRuleSet(snapshot NetRuleSet) NetRuleSet {
	return NetRuleSet{
		Rules:         append([]NetRule(nil), snapshot.Rules...),
		Default:       snapshot.Default,
		UpstreamProxy: snapshot.UpstreamProxy,
	}
}

type cacheResource struct {
	value any
	close func() error
	dead  func() bool
	busy  func() bool
}

type cacheEntry struct {
	resource cacheResource
	err      error
	refs     int
	lastUsed time.Time
	building *cacheBuild
}

type cacheBuild struct{ done chan struct{} }

type resourceCache struct {
	mu       sync.Mutex
	entries  map[cacheKey]*cacheEntry
	closed   bool
	capacity int
	idleTTL  time.Duration
	now      func() time.Time
}

func newResourceCache() *resourceCache {
	return &resourceCache{
		entries:  map[cacheKey]*cacheEntry{},
		capacity: resourceCacheCapacity,
		idleTTL:  denyCoverCacheTTL,
		now:      time.Now,
	}
}

func (c *resourceCache) acquire(key cacheKey, factory func() (cacheResource, error)) (any, bool, error) {
	for {
		c.mu.Lock()
		if c.closed {
			c.mu.Unlock()
			return nil, false, errClosed
		}
		expired := c.reapLocked()
		c.mu.Unlock()
		closeCacheResources(expired)

		c.mu.Lock()
		if c.closed {
			c.mu.Unlock()
			return nil, false, errClosed
		}
		if entry := c.entries[key]; entry != nil {
			if entry.building != nil {
				build := entry.building
				c.mu.Unlock()
				<-build.done
				continue
			}
			if entry.err != nil {
				err := entry.err
				c.mu.Unlock()
				return nil, true, err
			}
			if entry.resource.dead != nil && entry.resource.dead() {
				delete(c.entries, key)
				resource := entry.resource
				c.mu.Unlock()
				closeCacheResource(resource)
				continue
			}
			entry.refs++
			entry.lastUsed = c.now()
			value := entry.resource.value
			c.mu.Unlock()
			return value, true, nil
		}

		entry := &cacheEntry{building: &cacheBuild{done: make(chan struct{})}}
		c.entries[key] = entry
		c.mu.Unlock()

		resource, buildErr := factory()

		c.mu.Lock()
		build := entry.building
		entry.building = nil
		close(build.done)
		if c.closed {
			c.mu.Unlock()
			closeCacheResource(resource)
			return nil, false, errClosed
		}
		if buildErr != nil {
			entry.err = buildErr
			entry.lastUsed = c.now()
			c.mu.Unlock()
			return nil, false, buildErr
		}
		entry.resource = resource
		entry.refs = 1
		entry.lastUsed = c.now()
		c.mu.Unlock()
		return resource.value, false, nil
	}
}

func (c *resourceCache) release(key cacheKey) {
	c.mu.Lock()
	if entry := c.entries[key]; entry != nil {
		if entry.refs > 0 {
			entry.refs--
		}
		entry.lastUsed = c.now()
	}
	expired := c.reapLocked()
	c.mu.Unlock()
	closeCacheResources(expired)
}

// reapLocked removes expired idle entries and then the oldest idle entries over
// capacity. Active references and in-flight builds are never evicted.
func (c *resourceCache) reapLocked() []cacheResource {
	if len(c.entries) == 0 {
		return nil
	}
	type candidate struct {
		key      cacheKey
		lastUsed time.Time
	}
	candidates := make([]candidate, 0, len(c.entries))
	for key, entry := range c.entries {
		if entry.building != nil || entry.refs > 0 {
			continue
		}
		if entry.resource.busy != nil && entry.resource.busy() {
			continue
		}
		if c.idleTTL >= 0 && c.now().Sub(entry.lastUsed) >= c.idleTTL {
			candidates = append(candidates, candidate{key: key, lastUsed: entry.lastUsed})
		}
	}
	resources := make([]cacheResource, 0, len(candidates))
	for _, item := range candidates {
		resources = append(resources, c.entries[item.key].resource)
		delete(c.entries, item.key)
	}

	over := len(c.entries) - c.capacity
	if over > 0 {
		idle := make([]candidate, 0, len(c.entries))
		for key, entry := range c.entries {
			if entry.building == nil && entry.refs == 0 &&
				(entry.resource.busy == nil || !entry.resource.busy()) {
				idle = append(idle, candidate{key: key, lastUsed: entry.lastUsed})
			}
		}
		sort.Slice(idle, func(i, j int) bool { return idle[i].lastUsed.Before(idle[j].lastUsed) })
		if over > len(idle) {
			over = len(idle)
		}
		for _, item := range idle[:over] {
			resources = append(resources, c.entries[item.key].resource)
			delete(c.entries, item.key)
		}
	}
	return resources
}

func closeCacheResource(resource cacheResource) {
	if resource.close != nil {
		_ = resource.close()
	}
}

func closeCacheResources(resources []cacheResource) {
	for _, resource := range resources {
		closeCacheResource(resource)
	}
}

func (c *resourceCache) Close() error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	c.closed = true
	resources := make([]cacheResource, 0, len(c.entries))
	for key, entry := range c.entries {
		resources = append(resources, entry.resource)
		delete(c.entries, key)
	}
	c.mu.Unlock()
	var errs []error
	for _, resource := range resources {
		if resource.close != nil {
			if err := resource.close(); err != nil {
				errs = append(errs, err)
			}
		}
	}
	return errors.Join(errs...)
}

func denyCoverAllCached(cache *resourceCache, patterns []string, logf func(string, ...any)) (targets []string, cached bool, err error) {
	if cache == nil {
		targets, err = denyCoverAll(patterns)
		return targets, false, err
	}
	key := fsDenyCacheKey(patterns)
	value, cached, err := cache.acquire(key, func() (cacheResource, error) {
		start := time.Now()
		targets, err := denyCoverAll(patterns)
		if logf != nil {
			logf("sandbox: deny instantiate: walk=%s targets=%d err=%v", time.Since(start).Round(time.Millisecond), len(targets), err)
		}
		return cacheResource{value: targets}, err
	})
	if err != nil {
		return nil, cached, err
	}
	cache.release(key)
	if cached && logf != nil {
		logf("sandbox: deny instantiate cache hit: targets=%d", len(value.([]string)))
	}
	return append([]string(nil), value.([]string)...), cached, nil
}
