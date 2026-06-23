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
