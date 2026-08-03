package osint

import (
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/analysishub/backend/internal/config"
	"github.com/analysishub/backend/internal/models"
)

// sanctions.go — OFAC screening for crypto wallets and person/entity names.
//
// This upgrades the wallet_label and name collectors from "open this link and
// check yourself" deep-links into a real, parsed lookup: the U.S. Treasury OFAC
// Specially Designated Nationals (SDN) list is downloaded once, indexed, cached,
// and matched locally. A wallet address on the list is a *definite* critical hit
// (exact match); a name match is a strong lead that still needs identity
// confirmation (name collisions are possible). The list is public and keyless,
// so this is the safest high-value enrichment to add.

const (
	// defaultSDNURL is the OFAC SDN list in the documented legacy XML schema
	// (sdnList/sdnEntry). It carries every sanctioned individual/entity and, since
	// 2018, their published crypto addresses (idType "Digital Currency Address - …").
	defaultSDNURL = "https://www.treasury.gov/ofac/downloads/sdn.xml"
	// maxSDNBytes caps the download so a redirect to something huge can't exhaust
	// memory. The real list is ~30–40 MB; the shared 8 MB body cap is too small,
	// which is why this collector reads the stream directly instead of httpGetBody.
	maxSDNBytes = 256 << 20
	// sdnTTL is how long a parsed list is trusted before a refresh. OFAC updates
	// on business days; a day-old copy is fine for screening.
	sdnTTL = 24 * time.Hour
	// sdnFailTTL backs off after a failed fetch so a flaky network can't turn every
	// scan into a retry storm against treasury.gov.
	sdnFailTTL = 15 * time.Minute
)

// sdnID is one identifier row on an SDN entry (passport, tax id, or — the part we
// care about — a "Digital Currency Address - XBT/ETH/USDT/…").
type sdnID struct {
	Type   string `xml:"idType"`
	Number string `xml:"idNumber"`
}

// sdnAka is an alternate name ("also known as") for an entry.
type sdnAka struct {
	FirstName string `xml:"firstName"`
	LastName  string `xml:"lastName"`
}

// sdnEntry is one record in the OFAC SDN list.
type sdnEntry struct {
	UID       string   `xml:"uid"`
	FirstName string   `xml:"firstName"`
	LastName  string   `xml:"lastName"`
	SDNType   string   `xml:"sdnType"` // "Individual" | "Entity" | "Vessel" | …
	Programs  []string `xml:"programList>program"`
	IDs       []sdnID  `xml:"idList>id"`
	AKAs      []sdnAka `xml:"akaList>aka"`
}

// sanctionRecord is the flattened, UI-facing result of a match.
type sanctionRecord struct {
	Name     string
	Type     string
	Programs []string
	UID      string
}

// sdnIndex is the queryable form of the list: crypto address → record, and
// normalised name → records (a name can appear on more than one entry).
type sdnIndex struct {
	byAddr map[string]*sanctionRecord
	byName map[string][]*sanctionRecord
}

var (
	sdnMu       sync.Mutex
	sdnCached   *sdnIndex
	sdnLoadedAt time.Time
	sdnLastErr  error
	sdnLastTry  time.Time
)

// loadSDN returns the parsed OFAC SDN index, downloading and caching it on first
// use (and refreshing once past its TTL). It single-flights: a slow first fetch
// serialises concurrent callers rather than launching many downloads. On failure
// it serves a stale copy if one exists, otherwise returns the error.
func loadSDN(ctx context.Context, cfg *config.Config) (*sdnIndex, error) {
	sdnMu.Lock()
	defer sdnMu.Unlock()

	if sdnCached != nil && time.Since(sdnLoadedAt) < sdnTTL {
		return sdnCached, nil
	}
	// Recent failure with no usable cache: back off instead of hammering OFAC.
	if sdnCached == nil && sdnLastErr != nil && time.Since(sdnLastTry) < sdnFailTTL {
		return nil, sdnLastErr
	}

	url := defaultSDNURL
	if cfg != nil && strings.TrimSpace(cfg.OsintOFACSDNURL) != "" {
		url = strings.TrimSpace(cfg.OsintOFACSDNURL)
	}

	idx, err := fetchSDN(ctx, url)
	sdnLastTry = time.Now()
	if err != nil {
		sdnLastErr = err
		if sdnCached != nil {
			return sdnCached, nil // serve stale rather than fail the collector
		}
		return nil, err
	}
	sdnCached, sdnLoadedAt, sdnLastErr = idx, time.Now(), nil
	return idx, nil
}

// fetchSDN streams and parses the SDN XML entry-by-entry so the multi-MB file is
// never held in memory as one blob.
func fetchSDN(ctx context.Context, url string) (*sdnIndex, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Accept", "application/xml")

	resp, err := osintHTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("OFAC SDN download returned HTTP %d", resp.StatusCode)
	}
	return parseSDN(io.LimitReader(resp.Body, maxSDNBytes))
}

// parseSDN streams the SDN XML entry-by-entry into a queryable index. Split out
// from the network fetch so it can be unit-tested against a fixture.
func parseSDN(r io.Reader) (*sdnIndex, error) {
	idx := &sdnIndex{
		byAddr: make(map[string]*sanctionRecord),
		byName: make(map[string][]*sanctionRecord),
	}
	dec := xml.NewDecoder(r)
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("parse SDN XML: %w", err)
		}
		se, ok := tok.(xml.StartElement)
		if !ok || se.Name.Local != "sdnEntry" {
			continue
		}
		var e sdnEntry
		if err := dec.DecodeElement(&e, &se); err != nil {
			continue // skip a malformed entry, keep going
		}
		idx.add(&e)
	}
	if len(idx.byAddr) == 0 && len(idx.byName) == 0 {
		return nil, fmt.Errorf("OFAC SDN list parsed but empty (schema change?)")
	}
	return idx, nil
}

// add indexes one entry by its crypto addresses and by every name it carries.
func (idx *sdnIndex) add(e *sdnEntry) {
	primary := joinName(e.FirstName, e.LastName)
	rec := &sanctionRecord{Name: primary, Type: e.SDNType, Programs: e.Programs, UID: e.UID}

	for _, id := range e.IDs {
		if !strings.HasPrefix(strings.ToLower(id.Type), "digital currency address") {
			continue
		}
		if a := strings.ToLower(strings.TrimSpace(id.Number)); a != "" {
			idx.byAddr[a] = rec
		}
	}

	names := []string{primary}
	for _, aka := range e.AKAs {
		names = append(names, joinName(aka.FirstName, aka.LastName))
	}
	seen := map[string]bool{}
	for _, n := range names {
		k := normName(n)
		if k == "" || seen[k] {
			continue
		}
		seen[k] = true
		idx.byName[k] = append(idx.byName[k], rec)
	}
}

// joinName joins first and last name parts, tolerating either being empty
// (entities carry the whole name in lastName).
func joinName(first, last string) string {
	return strings.TrimSpace(strings.TrimSpace(first) + " " + strings.TrimSpace(last))
}

// normName canonicalises a name for exact-match lookup: lower-cased with runs of
// whitespace collapsed to one space.
func normName(s string) string {
	return strings.Join(strings.Fields(strings.ToLower(s)), " ")
}

// collectSanctions screens a crypto wallet or a person/entity name against the
// OFAC SDN list. Registered for TargetWallet and TargetName.
func collectSanctions(ctx context.Context, env *collectorEnv) ([]models.OsintFinding, error) {
	switch env.ttype {
	case TargetWallet, TargetName:
	default:
		return nil, nil
	}

	idx, err := loadSDN(ctx, env.cfg)
	if err != nil {
		return nil, err
	}

	switch env.ttype {
	case TargetWallet:
		rec := idx.byAddr[strings.ToLower(strings.TrimSpace(env.target))]
		if rec == nil {
			env.emit("[*] sanctions: wallet not on the OFAC SDN list")
			return nil, nil
		}
		detail := fmt.Sprintf("%s (%s) — OFAC programs: %s",
			rec.Name, strings.TrimSpace(rec.Type), programList(rec.Programs))
		f := newFinding("sanctions", "sanctions", "OFAC-sanctioned wallet", detail)
		f.Severity = "critical"
		f.Confidence = "verified"
		f.VerifyNote = "Exact match of the wallet address against the OFAC SDN Digital Currency Address list."
		f = withSource(f, sdnDetailsURL(rec.UID))
		env.emit("[!] sanctions: wallet is OFAC-sanctioned (" + rec.Name + ")")
		return []models.OsintFinding{f}, nil

	case TargetName:
		recs := idx.byName[normName(env.target)]
		if len(recs) == 0 {
			env.emit("[*] sanctions: no OFAC SDN entry with this exact name")
			return nil, nil
		}
		var out []models.OsintFinding
		for _, rec := range recs {
			detail := fmt.Sprintf("%s (%s) — OFAC programs: %s",
				rec.Name, strings.TrimSpace(rec.Type), programList(rec.Programs))
			f := newFinding("sanctions", "sanctions", "Possible OFAC-sanctioned match", detail)
			f.Severity = "high"
			f.Confidence = "likely"
			f.VerifyNote = "Name matches an OFAC SDN entry, but name collisions are common — confirm identity (nationality, DOB, aliases) before acting."
			f = withSource(f, sdnDetailsURL(rec.UID))
			out = append(out, f)
		}
		env.emit(fmt.Sprintf("[!] sanctions: %d OFAC SDN name match(es)", len(out)))
		return out, nil
	}
	return nil, nil
}

func programList(p []string) string {
	if len(p) == 0 {
		return "n/a"
	}
	return strings.Join(p, ", ")
}

// sdnDetailsURL links to the official OFAC record for verification.
func sdnDetailsURL(uid string) string {
	if strings.TrimSpace(uid) == "" {
		return "https://sanctionssearch.ofac.treas.gov/"
	}
	return "https://sanctionssearch.ofac.treas.gov/Details.aspx?id=" + uid
}
