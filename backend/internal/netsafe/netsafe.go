// Package netsafe provides SSRF-resistant outbound HTTP helpers: an HTTP client
// whose dialer refuses to connect to private / loopback / link-local / metadata
// addresses, re-checked on every redirect hop. Used for operator-supplied URLs
// (e.g. OOB notification webhooks) so they cannot be pointed at internal
// services or the cloud metadata endpoint.
package netsafe

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// IsPublicIP reports whether ip is a globally-routable public address. Rejects
// loopback, RFC1918 private, link-local, unspecified, multicast, IPv6 ULA,
// 0.0.0.0/8 and 100.64.0.0/10 (CGNAT).
func IsPublicIP(ip net.IP) bool {
	if ip == nil {
		return false
	}
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsUnspecified() ||
		ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsInterfaceLocalMulticast() || ip.IsMulticast() {
		return false
	}
	if v4 := ip.To4(); v4 != nil {
		if v4[0] == 0 {
			return false
		}
		if v4[0] == 100 && v4[1] >= 64 && v4[1] <= 127 {
			return false
		}
	}
	return true
}

// ValidateURL checks an operator-supplied URL is an http(s) URL whose host does
// not (currently) resolve to a private address. This is a best-effort set-time
// guard; the dial-time guard in Client() is the real enforcement (TOCTOU-safe).
func ValidateURL(raw string) error {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return fmt.Errorf("invalid URL: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("only http(s) URLs are allowed")
	}
	host := u.Hostname()
	if host == "" {
		return fmt.Errorf("URL has no host")
	}
	// If it's a literal IP, validate it directly.
	if ip := net.ParseIP(host); ip != nil {
		if !IsPublicIP(ip) {
			return fmt.Errorf("URL points at a non-public address")
		}
		return nil
	}
	// Resolve and ensure at least one address and all are public.
	ips, err := net.LookupIP(host)
	if err != nil || len(ips) == 0 {
		return fmt.Errorf("cannot resolve host %q", host)
	}
	for _, ip := range ips {
		if !IsPublicIP(ip) {
			return fmt.Errorf("host %q resolves to a non-public address", host)
		}
	}
	return nil
}

// Client returns an *http.Client that refuses to dial non-public addresses
// (re-validated after DNS resolution and on every redirect), with the given
// total timeout. Redirects are capped at 5 hops.
func Client(timeout time.Duration) *http.Client {
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			ips, err := net.DefaultResolver.LookupIP(ctx, "ip", host)
			if err != nil || len(ips) == 0 {
				return nil, fmt.Errorf("netsafe: cannot resolve %q", host)
			}
			// Dial only public IPs; reject if any resolved address is private
			// (defends against DNS-rebinding returning a mix).
			for _, ip := range ips {
				if !IsPublicIP(ip) {
					return nil, fmt.Errorf("netsafe: refusing to dial non-public address %s", ip)
				}
			}
			return dialer.DialContext(ctx, network, net.JoinHostPort(ips[0].String(), port))
		},
		TLSHandshakeTimeout: 10 * time.Second,
	}
	return &http.Client{
		Timeout:   timeout,
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return fmt.Errorf("netsafe: too many redirects")
			}
			if req.URL.Scheme != "http" && req.URL.Scheme != "https" {
				return fmt.Errorf("netsafe: redirect to non-http scheme blocked")
			}
			return nil
		},
	}
}
