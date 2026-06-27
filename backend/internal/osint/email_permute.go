package osint

import (
	"context"
	"net"
	"net/smtp"
	"strings"
	"time"
	"unicode"
)

// email_permute.go — "given a person's name + their company domain, what is
// their e-mail?" is one of the most common OSINT/red-team tasks. This generates
// the standard corporate address patterns for a name, then validates each at the
// domain's MX (with catch-all detection so a catch-all domain doesn't make every
// guess look real). Free, no third-party API.

// EmailCandidate is one generated address plus its validation verdict.
type EmailCandidate struct {
	Email      string `json:"email"`
	Pattern    string `json:"pattern"`    // e.g. "first.last"
	Status     string `json:"status"`     // deliverable | rejected | catch_all | unverified
	Confidence string `json:"confidence"` // high | medium | low
	Note       string `json:"note,omitempty"`
}

// GenerateEmailCandidates produces the common corporate e-mail patterns for a
// full name at a domain. The list is de-duplicated and ordered most-likely-first.
func GenerateEmailCandidates(fullName, domain string) []EmailCandidate {
	first, last := splitName(fullName)
	domain = strings.ToLower(strings.TrimSpace(domain))
	if domain == "" || first == "" {
		return nil
	}
	fi := first[:1]
	li := ""
	if last != "" {
		li = last[:1]
	}

	type pat struct{ name, local string }
	pats := []pat{
		{"first.last", join(first, last, ".")},
		{"firstlast", first + last},
		{"flast", fi + last},
		{"first", first},
		{"first_last", join(first, last, "_")},
		{"firstl", first + li},
		{"f.last", join(fi, last, ".")},
		{"lastfirst", last + first},
		{"last.first", join(last, first, ".")},
		{"last", last},
		{"firstlastinitial", first + li},
	}

	seen := map[string]bool{}
	out := make([]EmailCandidate, 0, len(pats))
	for _, p := range pats {
		local := strings.Trim(p.local, "._")
		if local == "" || seen[local] {
			continue
		}
		seen[local] = true
		out = append(out, EmailCandidate{
			Email:   local + "@" + domain,
			Pattern: p.name,
			Status:  "unverified",
		})
	}
	return out
}

// ValidateEmailCandidates checks each candidate against the domain MX and folds
// in catch-all detection: it probes one improbable mailbox first; if the MX
// accepts it, the domain is catch-all and individual "accepted" verdicts are not
// trustworthy. Validation stops early once a non-catch-all deliverable hit is
// found (that is almost certainly the address).
func ValidateEmailCandidates(ctx context.Context, cands []EmailCandidate) []EmailCandidate {
	if len(cands) == 0 {
		return cands
	}
	_, domain := emailParts(cands[0].Email)
	if domain == "" {
		return cands
	}

	mx := lookupBestMX(ctx, domain)
	if mx == "" {
		for i := range cands {
			cands[i].Status = "unverified"
			cands[i].Confidence = "low"
			cands[i].Note = "domain has no MX - cannot validate"
		}
		return cands
	}

	catchAll := smtpAccepts(ctx, mx, "zzq9x7k3vt1p-no-such-user@"+domain)
	for i := range cands {
		if err := ctx.Err(); err != nil {
			break
		}
		ok := smtpAccepts(ctx, mx, cands[i].Email)
		switch {
		case ok && catchAll:
			cands[i].Status = "catch_all"
			cands[i].Confidence = "low"
			cands[i].Note = "domain is catch-all - acceptance is not conclusive"
		case ok:
			cands[i].Status = "deliverable"
			cands[i].Confidence = "high"
			cands[i].Note = "MX accepted this mailbox (not catch-all)"
			return cands // strong hit — stop probing further patterns
		default:
			cands[i].Status = "rejected"
			cands[i].Confidence = "medium"
		}
	}
	return cands
}

// lookupBestMX returns the lowest-preference MX host for a domain, or "".
func lookupBestMX(ctx context.Context, domain string) string {
	r := &net.Resolver{}
	mxs, err := r.LookupMX(ctx, domain)
	if err != nil || len(mxs) == 0 {
		return ""
	}
	return strings.TrimRight(strings.ToLower(mxs[0].Host), ".")
}

// smtpAccepts reports whether the MX returns 250 to RCPT for the address.
func smtpAccepts(ctx context.Context, mx, email string) bool {
	d := &net.Dialer{Timeout: 5 * time.Second}
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(mx, "25"))
	if err != nil {
		return false
	}
	client, err := smtp.NewClient(conn, mx)
	if err != nil {
		conn.Close()
		return false
	}
	defer client.Close()
	if err := client.Hello("forensichub.local"); err != nil {
		return false
	}
	if err := client.Mail("ping@forensichub.local"); err != nil {
		return false
	}
	return client.Rcpt(email) == nil
}

// splitName lowercases and reduces a full name to (first, last), stripping
// diacritics and accents so "Nguyễn Văn A" → ("nguyen", "a")-style locals match
// how corporate mailboxes are usually spelled in ASCII.
func splitName(full string) (first, last string) {
	fields := strings.Fields(strings.ToLower(strings.TrimSpace(full)))
	clean := make([]string, 0, len(fields))
	for _, f := range fields {
		if a := asciiFold(f); a != "" {
			clean = append(clean, a)
		}
	}
	switch len(clean) {
	case 0:
		return "", ""
	case 1:
		return clean[0], ""
	default:
		return clean[0], clean[len(clean)-1]
	}
}

// asciiFold strips diacritics and keeps only ASCII letters.
func asciiFold(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z':
			b.WriteRune(r)
		case unicode.Is(unicode.Mn, r):
			// combining mark — drop
		default:
			if folded := foldRune(r); folded != 0 {
				b.WriteRune(folded)
			}
		}
	}
	return b.String()
}

// foldRune maps common accented Latin/Vietnamese letters to their base ASCII.
func foldRune(r rune) rune {
	switch r {
	case 'à', 'á', 'ạ', 'ả', 'ã', 'â', 'ầ', 'ấ', 'ậ', 'ẩ', 'ẫ', 'ă', 'ằ', 'ắ', 'ặ', 'ẳ', 'ẵ', 'ä', 'å':
		return 'a'
	case 'è', 'é', 'ẹ', 'ẻ', 'ẽ', 'ê', 'ề', 'ế', 'ệ', 'ể', 'ễ', 'ë':
		return 'e'
	case 'ì', 'í', 'ị', 'ỉ', 'ĩ', 'ï':
		return 'i'
	case 'ò', 'ó', 'ọ', 'ỏ', 'õ', 'ô', 'ồ', 'ố', 'ộ', 'ổ', 'ỗ', 'ơ', 'ờ', 'ớ', 'ợ', 'ở', 'ỡ', 'ö':
		return 'o'
	case 'ù', 'ú', 'ụ', 'ủ', 'ũ', 'ư', 'ừ', 'ứ', 'ự', 'ử', 'ữ', 'ü':
		return 'u'
	case 'ỳ', 'ý', 'ỵ', 'ỷ', 'ỹ':
		return 'y'
	case 'đ':
		return 'd'
	}
	return 0
}

func join(a, b, sep string) string {
	if a == "" {
		return b
	}
	if b == "" {
		return a
	}
	return a + sep + b
}
