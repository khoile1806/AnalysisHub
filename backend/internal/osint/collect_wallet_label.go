package osint

import (
	"context"
	"net/url"
	"strings"

	"github.com/analysishub/backend/internal/models"
)

// collect_wallet_label.go — reputation/attribution context for a crypto address.
// On-chain balance/tx history (collectBlockchain) tells you what the wallet DID;
// labeling tells you WHO/what it is — a known exchange, a sanctioned entity, or a
// reported scam. Free attribution APIs are scarce, so this surfaces the
// authoritative label/abuse databases as ready-to-open lookups (analyst-verified)
// plus a free ChainAbuse-style note where available.

// collectWalletLabel emits attribution/abuse lookups for a BTC/ETH address.
func collectWalletLabel(_ context.Context, env *collectorEnv) ([]models.OsintFinding, error) {
	if env.ttype != TargetWallet {
		return nil, nil
	}
	addr := strings.TrimSpace(env.target)
	if addr == "" {
		return nil, nil
	}
	isETH := ethRe.MatchString(addr)
	esc := url.PathEscape(addr)

	var out []models.OsintFinding
	add := func(title, link string) {
		f := newFinding("wallet_label", "reputation", title, link)
		f.Severity = "low" // assisted lookup — analyst confirms
		f.SourceURL = link
		out = append(out, f)
	}

	// Abuse / scam attribution (community-reported).
	add("ChainAbuse - scam/abuse reports", "https://www.chainabuse.com/address/"+esc)
	add("Scam-alert / community report search", "https://www.google.com/search?q="+url.QueryEscape("\""+addr+"\" scam OR fraud OR phishing"))

	if isETH {
		add("Etherscan - labels & token transfers", "https://etherscan.io/address/"+esc+"#analytics")
		add("Breadcrumbs - ETH wallet graph", "https://www.breadcrumbs.app/reports/new?address="+esc)
		add("OFAC SDN sanctions check", "https://sanctionssearch.ofac.treas.gov/")
	} else {
		add("Blockchair - BTC labels & cluster", "https://blockchair.com/bitcoin/address/"+esc)
		add("BitcoinAbuse / chainabuse reports", "https://www.chainabuse.com/address/"+esc)
		add("OXT / Walletexplorer clustering", "https://www.walletexplorer.com/address/"+esc)
	}

	env.emit("[*] wallet_label: attribution/abuse lookups prepared (open to verify)")
	return out, nil
}
