package osint

import "testing"

func TestCloudBucketCandidates(t *testing.T) {
	cands := cloudBucketCandidates("acme", "acme.com")
	set := map[string]bool{}
	for _, c := range cands {
		if len(c) < 3 || len(c) > 63 {
			t.Fatalf("candidate %q out of S3 length bounds", c)
		}
		for _, r := range c {
			if r == '_' || (r >= 'A' && r <= 'Z') {
				t.Fatalf("candidate %q must be lowercase, no underscores", c)
			}
		}
		if set[c] {
			t.Fatalf("duplicate candidate %q", c)
		}
		set[c] = true
	}
	for _, want := range []string{"acme", "acme-backup", "backup-acme", "acme-com", "acme-prod"} {
		if !set[want] {
			t.Errorf("expected candidate %q in set", want)
		}
	}
}

func TestMatchSensitiveKey(t *testing.T) {
	hits := []string{"backups/db.sql", "prod/.env", "secret/id_rsa", "wp-config.php", "infra/terraform.tfstate"}
	for _, k := range hits {
		if _, ok := matchSensitiveKey(k); !ok {
			t.Errorf("expected %q to be flagged sensitive", k)
		}
	}
	misses := []string{"index.html", "assets/logo.png", "readme.md"}
	for _, k := range misses {
		if m, ok := matchSensitiveKey(k); ok {
			t.Errorf("did not expect %q flagged (matched %q)", k, m)
		}
	}
}
