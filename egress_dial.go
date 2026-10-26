package vbox

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const maxResolvedTargets = 4

type resolvedTarget struct {
	address string
}

type egressDialer struct {
	policy   NetRuleSet
	upstream *url.URL
}

// ValidateUpstreamProxy reports whether raw is a supported explicit upstream proxy URL.
func ValidateUpstreamProxy(raw string) error {
	_, err := parseUpstreamProxy(raw)
	return err
}

func parseUpstreamProxy(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("invalid upstream proxy: %w", err)
	}
	u.Scheme = strings.ToLower(u.Scheme)
	if u.Scheme != "http" && u.Scheme != "socks5" && u.Scheme != "socks5h" {
		return nil, fmt.Errorf("invalid upstream proxy: scheme must be http, socks5 or socks5h")
	}
	if u.Host == "" || u.Hostname() == "" || u.RawQuery != "" || u.Fragment != "" {
		return nil, fmt.Errorf("invalid upstream proxy: host is required and query/fragment are not allowed")
	}
	if u.Path != "" && u.Path != "/" {
		return nil, fmt.Errorf("invalid upstream proxy: path is not allowed")
	}
	if strings.ContainsAny(u.Host, "\r\n\x00") {
		return nil, fmt.Errorf("invalid upstream proxy: control character in host")
	}
	if port := u.Port(); port != "" {
		if err := validateTargetPort(port); err != nil {
			return nil, fmt.Errorf("invalid upstream proxy: %w", err)
		}
	}
	return u, nil
}

func upstreamAddress(u *url.URL) string {
	port := u.Port()
	if port == "" {
		if u.Scheme == "http" {
			port = "80"
		} else {
			port = "1080"
		}
	}
	return net.JoinHostPort(u.Hostname(), port)
}

func validateTargetPort(port string) error {
	value, err := strconv.Atoi(port)
	if err != nil || value < 1 || value > 65535 {
		return fmt.Errorf("invalid TCP port %q", port)
	}
	return nil
}

func splitTarget(address string) (host, port string, err error) {
	host, port, err = net.SplitHostPort(address)
	if err != nil {
		return "", "", fmt.Errorf("invalid TCP target %q", address)
	}
	if err := validateTargetPort(port); err != nil {
		return "", "", err
	}
	if host == "" || strings.ContainsAny(host, "\r\n\x00") {
		return "", "", fmt.Errorf("invalid TCP target host")
	}
	host = NormalizeHost(host)
	if strings.Contains(host, "%") {
		return "", "", fmt.Errorf("scoped IPv6 targets are not supported")
	}
	return host, port, nil
}

// resolve authorizes concrete addresses, not just the requested hostname. Domain
// rules apply to public results (and the explicit localhost class); a private or
// local result must be authorized by an IP/loopback rule. Once authorized, only
// the concrete IP is used downstream, so an upstream proxy cannot re-resolve it.
func (d *egressDialer) resolve(ctx context.Context, address string) ([]resolvedTarget, error) {
	host, port, err := splitTarget(address)
	if err != nil {
		return nil, err
	}
	local, err := localInterfaceIPs()
	if err != nil {
		return nil, fmt.Errorf("enumerate local addresses: %w", err)
	}
	if ip, parseErr := netip.ParseAddr(host); parseErr == nil {
		allowed, err := d.authorizeIP("", ip, port, local)
		if err != nil {
			return nil, err
		}
		if !allowed {
			return nil, fmt.Errorf("network policy denied %s", net.JoinHostPort(host, port))
		}
		return []resolvedTarget{{address: net.JoinHostPort(ip.Unmap().String(), port)}}, nil
	}

	ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("resolve %s: %w", host, err)
	}
	targets := make([]resolvedTarget, 0, len(ips))
	seen := map[string]bool{}
	for _, candidate := range ips {
		if candidate.Zone != "" {
			continue
		}
		ip, ok := netip.AddrFromSlice(candidate.IP)
		if !ok {
			continue
		}
		ip = ip.Unmap()
		allowed, err := d.authorizeIP(host, ip, port, local)
		if err != nil {
			return nil, err
		}
		if !allowed {
			continue
		}
		target := net.JoinHostPort(ip.String(), port)
		if seen[target] {
			continue
		}
		seen[target] = true
		targets = append(targets, resolvedTarget{address: target})
	}
	if len(targets) == 0 {
		return nil, fmt.Errorf("network policy denied %s", net.JoinHostPort(host, port))
	}
	return targets, nil
}

func (d *egressDialer) authorizeIP(domain string, ip netip.Addr, port string, local map[netip.Addr]bool) (bool, error) {
	ip = ip.Unmap()
	external, err := isExternalIP(ip, local)
	if err != nil {
		return false, err
	}
	_, ipRule := d.policy.Resolve(net.JoinHostPort(ip.String(), port))
	domainRule := -1
	if domain != "" && (external || NormalizeHost(domain) == "localhost") {
		_, domainRule = d.policy.Resolve(net.JoinHostPort(domain, port))
	}
	winner := ipRule
	if ipRule < 0 || (domainRule >= 0 && higherNetRule(domainRule, ipRule, d.policy.Rules)) {
		winner = domainRule
	}
	if winner < 0 {
		return d.policy.Default, nil
	}
	return d.policy.Rules[winner].Allow, nil
}

func higherNetRule(a, b int, rules []NetRule) bool {
	if rules[a].Level != rules[b].Level {
		return rules[a].Level > rules[b].Level
	}
	return a < b
}

func localInterfaceIPs() (map[netip.Addr]bool, error) {
	addresses, err := net.InterfaceAddrs()
	if err != nil {
		return nil, err
	}
	out := make(map[netip.Addr]bool, len(addresses))
	for _, address := range addresses {
		prefix, err := netip.ParsePrefix(address.String())
		if err != nil {
			continue
		}
		out[prefix.Addr().Unmap()] = true
	}
	return out, nil
}

var nonPublicPrefixes = []netip.Prefix{
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("64:ff9b::/96"),
	netip.MustParsePrefix("64:ff9b:1::/48"),
	netip.MustParsePrefix("2002::/16"),
	netip.MustParsePrefix("2001::/32"),
}

func isExternalIP(ip netip.Addr, local map[netip.Addr]bool) (bool, error) {
	ip = ip.Unmap()
	if !ip.IsValid() || !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() ||
		ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified() {
		return false, nil
	}
	for _, prefix := range nonPublicPrefixes {
		if prefix.Contains(ip) {
			return false, nil
		}
	}
	if local[ip] {
		return false, nil
	}
	return true, nil
}

func (d *egressDialer) dialContext(ctx context.Context, address string) (net.Conn, error) {
	targets, err := d.resolve(ctx, address)
	if err != nil {
		return nil, err
	}
	return d.dialResolved(ctx, address, targets)
}

func (d *egressDialer) dialResolved(ctx context.Context, address string, targets []resolvedTarget) (net.Conn, error) {
	if len(targets) > maxResolvedTargets {
		targets = targets[:maxResolvedTargets]
	}
	var dialErrs []error
	var err error
	for _, target := range targets {
		var conn net.Conn
		if d.upstream == nil {
			dialer := net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
			conn, err = dialer.DialContext(ctx, "tcp", target.address)
		} else {
			conn, err = d.dialUpstream(ctx, target.address)
		}
		if err == nil {
			return conn, nil
		}
		dialErrs = append(dialErrs, err)
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
	}
	return nil, fmt.Errorf("connect %s: %w", address, joinDialErrors(dialErrs))
}

func joinDialErrors(errs []error) error {
	if len(errs) == 0 {
		return fmt.Errorf("no authorized address")
	}
	return errs[len(errs)-1]
}

func (d *egressDialer) dialUpstream(ctx context.Context, target string) (net.Conn, error) {
	dialer := net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	conn, err := dialer.DialContext(ctx, "tcp", upstreamAddress(d.upstream))
	if err != nil {
		return nil, err
	}
	rawConn := conn
	ok := false
	defer func() {
		if !ok {
			_ = rawConn.Close()
		}
	}()
	if d.upstream.Scheme == "http" {
		conn, err = dialHTTPConnect(rawConn, d.upstream, target)
	} else {
		username, password := upstreamCredentials(d.upstream)
		err = socks5ClientHandshake(rawConn, target, username, password)
	}
	if err != nil {
		return nil, err
	}
	ok = true
	return conn, nil
}

func upstreamCredentials(u *url.URL) (string, string) {
	if u.User == nil {
		return "", ""
	}
	password, _ := u.User.Password()
	return u.User.Username(), password
}

func dialHTTPConnect(conn net.Conn, upstream *url.URL, target string) (net.Conn, error) {
	if err := conn.SetDeadline(time.Now().Add(15 * time.Second)); err != nil {
		return nil, err
	}
	if _, err := fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n", target, target); err != nil {
		return nil, err
	}
	if username, password := upstreamCredentials(upstream); username != "" {
		if _, err := fmt.Fprintf(conn, "Proxy-Authorization: Basic %s\r\n", basicAuth(username, password)); err != nil {
			return nil, err
		}
	}
	if _, err := fmt.Fprint(conn, "\r\n"); err != nil {
		return nil, err
	}
	reader := bufio.NewReader(conn)
	response, err := http.ReadResponse(reader, &http.Request{Method: http.MethodConnect})
	if err != nil {
		return nil, err
	}
	if response.StatusCode != http.StatusOK {
		_ = response.Body.Close()
		return nil, fmt.Errorf("upstream CONNECT returned %s", response.Status)
	}
	if err := conn.SetDeadline(time.Time{}); err != nil {
		return nil, err
	}
	return &bufferedConn{Conn: conn, reader: reader}, nil
}

type bufferedConn struct {
	net.Conn
	reader *bufio.Reader
}

func (c *bufferedConn) Read(p []byte) (int, error) { return c.reader.Read(p) }

func (c *bufferedConn) CloseWrite() error {
	if writer, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return writer.CloseWrite()
	}
	return nil
}
