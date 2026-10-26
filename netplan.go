package vbox

import (
	"fmt"
	"sort"
	"strings"
)

// NetCaps describes the network enforcement capabilities of one backend.
type NetCaps struct {
	DenyPosture   bool
	LoopbackRules bool
	EgressProxy   bool
}

func netCapsForPlatform(platform string) NetCaps {
	switch platform {
	case "darwin":
		return NetCaps{DenyPosture: true, LoopbackRules: true, EgressProxy: true}
	case "linux":
		return NetCaps{DenyPosture: true}
	default:
		return NetCaps{}
	}
}

type netPlan struct {
	// kernelRules are ordered for SBPL: lower priority first, and later rows at
	// the same level first. The original policy snapshot is never reordered.
	kernelRules []NetRule
	proxyPolicy *NetRuleSet
	landings    []NetRowLanding
}

// transport contains the internal loopback proxy listener addresses. Reserved
// transport rows are appended last so they win even over level-255 user rows.
func compileNetPlan(platform string, s NetRuleSet, caps NetCaps, transport ...string) (netPlan, error) {
	plan := netPlan{landings: make([]NetRowLanding, len(s.Rules))}
	if s.UpstreamProxy != "" {
		if _, err := parseUpstreamProxy(s.UpstreamProxy); err != nil {
			return plan, err
		}
	}
	entries := make([]Entry, len(s.Rules))
	for i, rule := range s.Rules {
		entry, err := ParseRuleEntry(rule.HostPort)
		if err != nil {
			return plan, fmt.Errorf("invalid net rule %d: %w", i+1, err)
		}
		entries[i] = entry
		plan.landings[i].Rule = rule
	}
	absorb := func(i int, reason string) {
		plan.landings[i].Absorbed = true
		plan.landings[i].Reason = reason
	}
	if !s.Default && !caps.DenyPosture {
		if platform == "windows" {
			return plan, &UnsupportedError{Reason: "this Windows backend does not implement network rules"}
		}
		return plan, &UnsupportedError{Reason: fmt.Sprintf("this %s backend does not implement network deny posture", platform)}
	}
	if !s.Default && caps.EgressProxy {
		rules := append([]NetRule(nil), s.Rules...)
		plan.proxyPolicy = &NetRuleSet{Rules: rules, Default: s.Default, UpstreamProxy: s.UpstreamProxy}
	}

	dead := ineffectiveNetRows(s.Rules, entries)
	var loopbackKernel map[int]bool
	var loopbackAbsorbed map[int]string
	if caps.LoopbackRules {
		loopbackKernel, loopbackAbsorbed = analyzeLoopbackRules(s.Rules, entries)
	}
	kernelIndexes := make([]int, 0)
	for i, rule := range s.Rules {
		if dead[i] {
			absorb(i, "covered by a higher-priority rule")
			continue
		}
		if isLoopbackHost(entries[i].Host) {
			if caps.LoopbackRules {
				if loopbackKernel[i] {
					plan.landings[i].Kernel = true
					plan.landings[i].Reason = "kernel-enforced loopback rule"
					kernelIndexes = append(kernelIndexes, i)
				} else if reason := loopbackAbsorbed[i]; reason != "" {
					absorb(i, reason)
				}
				continue
			}
			if s.Default && !rule.Allow {
				return plan, &UnsupportedError{Reason: fmt.Sprintf("selective network rule %s is unsupported by this backend", rule.String())}
			}
			if s.Default {
				absorb(i, "omitting an allow rule can only narrow the open posture")
			} else {
				absorb(i, "deny posture already makes this loopback target unreachable")
			}
			continue
		}

		if !s.Default && caps.EgressProxy {
			plan.landings[i].Proxy = true
			plan.landings[i].Reason = "proxy-enforced using the complete net snapshot"
			continue
		}
		if !s.Default {
			absorb(i, "deny posture already makes this non-loopback target unreachable")
			continue
		}
		if !rule.Allow {
			return plan, &UnsupportedError{Reason: fmt.Sprintf("selective network rule %s is unsupported by this backend", rule.String())}
		}
		absorb(i, "omitting an allow rule can only narrow the open posture")
	}

	// SBPL uses last-match semantics within a port and gives specific ports
	// precedence over wildcard ports. compileNetPlan has already removed every
	// row that cannot affect the result; only priority ordering remains.
	sort.Slice(kernelIndexes, func(i, j int) bool {
		a, b := kernelIndexes[i], kernelIndexes[j]
		if s.Rules[a].Level != s.Rules[b].Level {
			return s.Rules[a].Level < s.Rules[b].Level
		}
		return a > b
	})
	for _, i := range kernelIndexes {
		plan.kernelRules = append(plan.kernelRules, s.Rules[i])
	}
	if len(transport) > 0 {
		if plan.proxyPolicy == nil {
			return plan, fmt.Errorf("internal proxy transport requires a deny-posture proxy policy")
		}
		if err := plan.addTransportRules(s.Rules, entries, transport); err != nil {
			return plan, err
		}
	}
	return plan, nil
}

func (p *netPlan) addTransportRules(rules []NetRule, entries []Entry, transport []string) error {
	for _, address := range transport {
		entry, err := ParseRuleEntry(address)
		if err != nil || !isLoopbackHost(entry.Host) || entry.Port == "*" {
			return fmt.Errorf("invalid internal proxy transport %q", address)
		}
		reserved := NetRule{HostPort: "localhost:" + entry.Port, Allow: true, Level: 255}
		filtered := p.kernelRules[:0]
		for _, rule := range p.kernelRules {
			candidate, parseErr := ParseRuleEntry(rule.HostPort)
			if parseErr != nil {
				return parseErr
			}
			if candidate.Port == entry.Port && isLoopbackHost(candidate.Host) {
				continue
			}
			filtered = append(filtered, rule)
		}
		p.kernelRules = filtered
		for i := range rules {
			if entries[i].Port != entry.Port || !isLoopbackHost(entries[i].Host) || !p.landings[i].Kernel {
				continue
			}
			p.landings[i].Kernel = false
			p.landings[i].Absorbed = true
			p.landings[i].Reason = "reserved internal proxy transport overrides the direct loopback rule"
		}
		p.kernelRules = append(p.kernelRules, reserved)
		p.landings = append(p.landings, NetRowLanding{
			Rule: reserved, Kernel: true, Reserved: true,
			Reason: "reserved internal proxy transport",
		})
	}
	return nil
}

// analyzeLoopbackRules computes exact winners for every mentioned port plus a
// representative port covered only by wildcard-port rows. Every winning row is
// retained; removing a non-winning row cannot change the resolved policy.
func analyzeLoopbackRules(rules []NetRule, entries []Entry) (map[int]bool, map[int]string) {
	type portCase struct {
		port  string
		other bool
	}
	cases := make([]portCase, 0, len(rules)+1)
	seenPorts := map[string]bool{}
	for i := range rules {
		if !isLoopbackHost(entries[i].Host) || entries[i].Port == "*" {
			continue
		}
		port := entries[i].Port
		if !seenPorts[port] {
			seenPorts[port] = true
			cases = append(cases, portCase{port: port})
		}
	}
	cases = append(cases, portCase{other: true})
	winner := func(tc portCase) int {
		best := -1
		var bestLevel uint8
		for i, rule := range rules {
			if !isLoopbackHost(entries[i].Host) {
				continue
			}
			port := entries[i].Port
			matches := port == "*" || (!tc.other && port == tc.port)
			if !matches || (best >= 0 && rule.Level <= bestLevel) {
				continue
			}
			best, bestLevel = i, rule.Level
		}
		return best
	}

	effective := map[int]bool{}
	for _, tc := range cases {
		if winning := winner(tc); winning >= 0 {
			effective[winning] = true
		}
	}
	kernel := map[int]bool{}
	absorbed := map[int]string{}
	for i := range rules {
		if !isLoopbackHost(entries[i].Host) {
			continue
		}
		if effective[i] {
			kernel[i] = true
		} else {
			absorbed[i] = "no loopback target selects this row"
		}
	}
	return kernel, absorbed
}

func ineffectiveNetRows(rules []NetRule, entries []Entry) map[int]bool {
	out := map[int]bool{}
	for i := range rules {
		for j := range rules {
			if i == j || rules[j].Level < rules[i].Level || (rules[j].Level == rules[i].Level && j > i) {
				continue
			}
			if netPatternCovers(entries[j], entries[i]) {
				out[i] = true
				break
			}
		}
	}
	return out
}

func netPatternCovers(outer, inner Entry) bool {
	if outer.Port != "*" && outer.Port != inner.Port {
		return false
	}
	outer.Host, inner.Host = CanonicalNetHost(outer.Host), CanonicalNetHost(inner.Host)
	if outer.Host == "localhost" || outer.Host == "*.localhost" {
		return inner.Host == "localhost" || inner.Host == "*.localhost"
	}
	if strings.HasPrefix(outer.Host, "*.") {
		base := strings.TrimPrefix(outer.Host, "*.")
		innerBase := strings.TrimPrefix(inner.Host, "*.")
		if innerBase == base {
			return strings.HasPrefix(inner.Host, "*.")
		}
		return strings.HasSuffix(innerBase, "."+base)
	}
	return outer.Host == inner.Host
}
