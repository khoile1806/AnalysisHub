package osint

import (
	"context"
	"encoding/xml"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/analysishub/backend/internal/models"
)

// cloudMaxCandidatesDefault bounds how many bucket-name candidates are probed
// when config supplies no override. Each candidate costs up to two HTTP probes
// (S3 + GCS), so the cap keeps the active surface predictable.
const cloudMaxCandidatesDefault = 120

// cloudProbeConcurrency limits simultaneous bucket probes.
const cloudProbeConcurrency = 24

// cloudListCap is the most object keys recorded per open bucket.
const cloudListCap = 50

// cloudAffixes are the tokens brand buckets are most often suffixed/prefixed
// with. Combined with the registrable name they generate the candidate set.
var cloudAffixes = []string{
	"backup", "backups", "bak", "dev", "development", "prod", "production",
	"stage", "staging", "test", "testing", "qa", "uat", "assets", "static",
	"media", "data", "files", "file", "db", "sql", "logs", "log", "config",
	"private", "public", "internal", "uploads", "upload", "images", "img",
	"web", "www", "cdn", "s3", "storage", "store", "bucket", "app", "api",
	"docs", "downloads", "archive", "tmp", "temp", "secret", "secrets",
}

// sensitiveFileMarkers flag object keys whose presence in a public bucket is a
// likely credential / data-at-rest leak. Matched case-insensitively as a
// substring of the object key.
var sensitiveFileMarkers = []string{
	".env", ".sql", ".sql.gz", ".bak", ".dump", "dump.", ".pem", ".key",
	"id_rsa", ".pfx", ".p12", ".pkcs12", ".kdbx", ".ovpn", "credentials",
	"secret", "password", "passwd", ".htpasswd", "config.yml", "config.yaml",
	".git/", ".tfstate", "backup", ".bacpac", ".mdf", ".pst", "wp-config",
}

// cloudListResult mirrors the (S3-compatible) XML bucket listing returned by
// both AWS S3 and Google Cloud Storage when anonymous listing is allowed.
type cloudListResult struct {
	XMLName  xml.Name `xml:"ListBucketResult"`
	Name     string   `xml:"Name"`
	Contents []struct {
		Key  string `xml:"Key"`
		Size int64  `xml:"Size"`
	} `xml:"Contents"`
}

// collectCloud (domain target) hunts for misconfigured public cloud storage
// belonging to the target organisation. It permutes the registrable name into
// likely bucket names and probes AWS S3 and Google Cloud Storage for buckets
// that exist, distinguishing OPEN (anonymously listable) buckets from private
// ones, and flags any exposed object whose name looks sensitive (.env, .sql,
// backups, keys). It is intentionally read-only: it lists keys but never
// downloads object contents - the analyst decides what to pull. A lighter probe
// reports Azure Blob storage accounts that exist under the name. Candidate count
// and concurrency are bounded so the active surface stays predictable.
func collectCloud(ctx context.Context, env *collectorEnv) ([]models.OsintFinding, error) {
	if env.ttype != TargetDomain {
		return nil, nil
	}
	host := strings.ToLower(strings.TrimSpace(env.target))
	name, _ := splitRegistrable(host)
	if name == "" {
		return nil, nil
	}

	maxCand := cloudMaxCandidatesDefault
	if env.cfg != nil && env.cfg.OsintCloudMaxCandidates > 0 {
		maxCand = env.cfg.OsintCloudMaxCandidates
	}
	candidates := cloudBucketCandidates(name, host)
	if len(candidates) > maxCand {
		candidates = candidates[:maxCand]
	}
	env.emit(fmt.Sprintf("[*] cloud: probing %d bucket candidate(s) on S3/GCS", len(candidates)))

	var (
		mu      sync.Mutex
		out     []models.OsintFinding
		open    int64
		private int64
	)
	jobs := make(chan string, 64)
	var wg sync.WaitGroup
	for i := 0; i < cloudProbeConcurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for bucket := range jobs {
				if ctx.Err() != nil {
					return
				}
				fs, isOpen, exists := probeBucket(ctx, bucket)
				if !exists {
					continue
				}
				if isOpen {
					atomic.AddInt64(&open, 1)
				} else {
					atomic.AddInt64(&private, 1)
				}
				mu.Lock()
				out = append(out, fs...)
				mu.Unlock()
			}
		}()
	}
	for _, b := range candidates {
		select {
		case jobs <- b:
		case <-ctx.Done():
		}
	}
	close(jobs)
	wg.Wait()

	// Azure accounts are name-keyed (not affix-permuted the same way); a light
	// existence probe surfaces accounts worth manual container enumeration.
	out = append(out, probeAzureAccounts(ctx, name, host)...)

	if len(out) == 0 {
		env.emit("[*] cloud: no public cloud buckets discovered for the target")
		return nil, nil
	}
	sort.SliceStable(out, func(i, j int) bool { return severityRank(out[i].Severity) < severityRank(out[j].Severity) })
	env.emit(fmt.Sprintf("[+] cloud: %d open / %d private bucket(s) discovered", open, private))
	return out, nil
}

// cloudBucketCandidates builds the de-duplicated bucket-name candidate set from
// the registrable name and full host. S3/GCS bucket names are lowercase, 3-63
// chars, no underscores; dots are dropped to a hyphen-joined form.
func cloudBucketCandidates(name, host string) []string {
	seen := map[string]bool{}
	var out []string
	add := func(b string) {
		b = strings.Trim(strings.ToLower(b), "-.")
		b = strings.ReplaceAll(b, "_", "-")
		if len(b) < 3 || len(b) > 63 || seen[b] {
			return
		}
		seen[b] = true
		out = append(out, b)
	}

	dotted := strings.ReplaceAll(host, ".", "-") // company.com -> company-com
	bases := []string{name, dotted}
	for _, base := range bases {
		add(base)
		for _, a := range cloudAffixes {
			add(base + "-" + a)
			add(a + "-" + base)
			add(base + a)
		}
	}
	return out
}

// probeBucket checks one bucket name against AWS S3 then Google Cloud Storage.
// It returns the findings, whether the bucket is anonymously listable (open),
// and whether it exists at all.
func probeBucket(ctx context.Context, bucket string) (fs []models.OsintFinding, isOpen, exists bool) {
	for _, p := range []struct{ provider, url string }{
		{"AWS S3", "https://" + bucket + ".s3.amazonaws.com/"},
		{"Google Cloud Storage", "https://storage.googleapis.com/" + bucket + "/"},
	} {
		body, status, err := httpGetBody(ctx, nil, p.url, nil)
		if err != nil {
			continue
		}
		switch {
		case status >= 200 && status < 300:
			var list cloudListResult
			if xml.Unmarshal(body, &list) == nil {
				exists = true
				isOpen = true
				fs = append(fs, bucketFindings(p.provider, bucket, p.url, &list)...)
				return fs, isOpen, exists // first open hit wins
			}
		case status == http.StatusForbidden:
			// Bucket exists but anonymous listing is denied.
			exists = true
			f := newFinding("cloud", "cloud_exposure", "Cloud bucket exists (private)",
				fmt.Sprintf("%s bucket %q exists but blocks anonymous listing", p.provider, bucket))
			f.Severity = "low"
			fs = append(fs, withSource(f, p.url))
		}
	}
	return fs, isOpen, exists
}

// bucketFindings turns an open (listable) bucket into a summary finding plus a
// finding per exposed sensitive object key.
func bucketFindings(provider, bucket, url string, list *cloudListResult) []models.OsintFinding {
	out := make([]models.OsintFinding, 0, 4)
	summary := newFinding("cloud", "cloud_exposure", "Public cloud bucket (open listing)",
		fmt.Sprintf("%s bucket %q is publicly listable (%d object(s) enumerated)", provider, bucket, len(list.Contents)))
	summary.Severity = "high"
	summary.Data = toJSON(map[string]interface{}{"provider": provider, "bucket": bucket, "objects": len(list.Contents)})
	out = append(out, withSource(summary, url))

	flagged := 0
	for _, c := range list.Contents {
		if flagged >= cloudListCap {
			break
		}
		if marker, ok := matchSensitiveKey(c.Key); ok {
			f := newFinding("cloud", "cloud_exposure", "Sensitive file exposed in public bucket",
				fmt.Sprintf("%s/%s (matched %q)", bucket, c.Key, marker))
			f.Severity = "critical"
			f.Data = toJSON(map[string]interface{}{"provider": provider, "bucket": bucket, "key": c.Key, "size": c.Size})
			out = append(out, withSource(f, strings.TrimRight(url, "/")+"/"+c.Key))
			flagged++
		}
	}
	return out
}

// matchSensitiveKey reports whether an object key looks sensitive.
func matchSensitiveKey(key string) (string, bool) {
	lk := strings.ToLower(key)
	for _, m := range sensitiveFileMarkers {
		if strings.Contains(lk, m) {
			return m, true
		}
	}
	return "", false
}

// probeAzureAccounts does a light existence check for Azure Blob storage
// accounts named after the target. Anonymous account-level listing is not
// permitted, so this only reports that an account exists (a starting point for
// manual container enumeration), never its contents.
func probeAzureAccounts(ctx context.Context, name, host string) []models.OsintFinding {
	seen := map[string]bool{}
	var accounts []string
	for _, cand := range []string{name, strings.ReplaceAll(host, ".", ""), strings.ReplaceAll(host, ".", "-")} {
		a := strings.Map(func(r rune) rune {
			if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
				return r
			}
			return -1
		}, strings.ToLower(cand))
		if len(a) < 3 || len(a) > 24 || seen[a] {
			continue
		}
		seen[a] = true
		accounts = append(accounts, a)
	}

	var out []models.OsintFinding
	for _, acct := range accounts {
		if ctx.Err() != nil {
			break
		}
		url := "https://" + acct + ".blob.core.windows.net/"
		_, status, err := httpGetBody(ctx, nil, url, nil)
		if err != nil {
			continue // no such account => DNS/connection failure
		}
		// A live Azure storage endpoint answers (400 InvalidQueryParameterValue on
		// the bare root, 200/403 otherwise); a missing account fails to resolve.
		if status > 0 {
			f := newFinding("cloud", "cloud_exposure", "Azure storage account exists",
				fmt.Sprintf("Azure Blob account %q is live - enumerate containers for exposure", acct))
			f.Severity = "low"
			f.Data = toJSON(map[string]interface{}{"provider": "Azure Blob", "account": acct})
			out = append(out, withSource(f, url))
		}
	}
	return out
}
