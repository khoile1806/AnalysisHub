package osint

import "testing"

func TestIsProviderDomain(t *testing.T) {
	providers := []string{
		"gmail.com", "yahoo.com", "proton.me", "outlook.com",
		"foo.amazonaws.com", "d123.cloudfront.net", "myapp.herokuapp.com",
		"site.netlify.app", "user.github.io", "x.fastly.net", "facebook.com",
		"sub.medium.com", "t.me",
	}
	for _, d := range providers {
		if !isProviderDomain(d) {
			t.Errorf("expected %q to be a provider/free-mail/platform domain", d)
		}
	}
	owned := []string{"acmecorp.com", "bank.example", "victim.org", "shop.acme.co.uk"}
	for _, d := range owned {
		if isProviderDomain(d) {
			t.Errorf("expected %q to NOT be a provider domain", d)
		}
	}
}

// TestInPivotScopeNonDomainRoots guards the out-of-scope hardening: IP and
// person roots must not pivot into shared infrastructure / free-mail / platforms.
func TestInPivotScopeNonDomainRoots(t *testing.T) {
	// IP root pivoting into a CDN tenant must be rejected.
	if ok, _ := inPivotScope("1.2.3.4", TargetIP, "d999.cloudfront.net", TargetDomain); ok {
		t.Error("IP root should not pivot into a CDN domain")
	}
	// IP root pivoting into a real co-hosted domain is allowed.
	if ok, _ := inPivotScope("1.2.3.4", TargetIP, "realcorp.com", TargetDomain); !ok {
		t.Error("IP root should pivot into a non-provider co-hosted domain")
	}
	// Email root: free-mail domain pivot rejected, company domain allowed.
	if ok, _ := inPivotScope("a@gmail.com", TargetEmail, "alice@gmail.com", TargetEmail); ok {
		t.Error("email root should not pivot into a free-mail domain")
	}
	if ok, _ := inPivotScope("a@x.com", TargetEmail, "bob@acmecorp.com", TargetEmail); !ok {
		t.Error("email root should pivot into a company-domain e-mail")
	}
}

// TestIsGenericReverseDNS guards the false-positive/out-of-scope fix: ISP and
// hosting auto-generated PTR names must be recognised so an IP root doesn't
// pivot into the provider's addressing scheme, while a real asset hostname is
// left investigable.
func TestIsGenericReverseDNS(t *testing.T) {
	generic := []struct{ host, ip string }{
		{"static.5.6.7.8.clients.your-host.de", "5.6.7.8"},
		{"dynamic-203-0-113-9.dsl.example-isp.net", "203.0.113.9"},
		{"dsl-189-160-12-34.prod-infinitum.com.mx", ""},
		{"host-198-51-100-2.pool.example.net", "198.51.100.2"},
		{"203.0.113.9.in-addr.arpa", "203.0.113.9"},
	}
	for _, g := range generic {
		if !isGenericReverseDNS(g.host, g.ip) {
			t.Errorf("expected %q (ip %q) to be generic reverse-DNS", g.host, g.ip)
		}
	}
	real := []struct{ host, ip string }{
		{"api.victimcorp.com", "5.6.7.8"},
		{"mail.acme.org", ""},
		{"shop.example.co.uk", "198.51.100.2"},
	}
	for _, r := range real {
		if isGenericReverseDNS(r.host, r.ip) {
			t.Errorf("expected %q (ip %q) to NOT be generic reverse-DNS", r.host, r.ip)
		}
	}
}

// TestInPivotScopeIPRootGenericRDNS confirms an IP root rejects a pivot into a
// generic ISP/hosting reverse-DNS host.
func TestInPivotScopeIPRootGenericRDNS(t *testing.T) {
	if ok, _ := inPivotScope("5.6.7.8", TargetIP, "static.5.6.7.8.clients.your-host.de", TargetDomain); ok {
		t.Error("IP root should not pivot into a generic reverse-DNS host")
	}
	if ok, _ := inPivotScope("5.6.7.8", TargetIP, "api.victimcorp.com", TargetDomain); !ok {
		t.Error("IP root should still pivot into a real co-hosted asset")
	}
}

// TestInPivotScopeDomainRootUnchanged confirms the (already tight) domain-root
// namespace rule still holds and is not loosened by the provider logic.
func TestInPivotScopeDomainRootUnchanged(t *testing.T) {
	if ok, _ := inPivotScope("acme.com", TargetDomain, "api.acme.com", TargetDomain); !ok {
		t.Error("subdomain of root should stay in scope")
	}
	if ok, _ := inPivotScope("acme.com", TargetDomain, "evil.org", TargetDomain); ok {
		t.Error("unrelated domain should be out of scope for a domain root")
	}
}
