package osint

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/analysishub/backend/internal/models"
)

var rlBlockchain = newRateLimiter(1 * time.Second)

// collectBlockchain pulls basic on-chain activity for a BTC or ETH address - the
// money-trail starting point for ransomware / fraud DFIR. Uses keyless public
// explorers: blockstream.info for Bitcoin, ethplorer (freekey) for Ethereum.
func collectBlockchain(ctx context.Context, env *collectorEnv) ([]models.OsintFinding, error) {
	if strings.HasPrefix(env.target, "0x") {
		return collectEthplorer(ctx, env)
	}
	return collectBlockstream(ctx, env)
}

func collectBlockstream(ctx context.Context, env *collectorEnv) ([]models.OsintFinding, error) {
	u := "https://blockstream.info/api/address/" + url.PathEscape(env.target)
	var r struct {
		ChainStats struct {
			FundedSum int64 `json:"funded_txo_sum"`
			SpentSum  int64 `json:"spent_txo_sum"`
			TxCount   int   `json:"tx_count"`
		} `json:"chain_stats"`
	}
	status, err := httpGetJSON(ctx, rlBlockchain, u, nil, &r)
	if err != nil {
		return nil, err
	}
	if status == 400 || status == 404 {
		env.emit("[*] blockchain: address not found / invalid")
		return nil, nil
	}
	if status < 200 || status >= 300 {
		return nil, fmt.Errorf("blockstream returned HTTP %d", status)
	}

	recv := float64(r.ChainStats.FundedSum) / 1e8
	sent := float64(r.ChainStats.SpentSum) / 1e8
	bal := recv - sent
	f := newFinding("blockchain", "financial", "Bitcoin wallet activity",
		fmt.Sprintf("balance %.8f BTC - received %.8f - sent %.8f - %d tx",
			bal, recv, sent, r.ChainStats.TxCount))
	if r.ChainStats.TxCount == 0 {
		f.Severity = "info"
		env.emit("[*] blockchain: address has no transactions")
	} else {
		f.Severity = "low"
	}
	return []models.OsintFinding{withSource(f, "https://blockstream.info/address/"+url.PathEscape(env.target))}, nil
}

func collectEthplorer(ctx context.Context, env *collectorEnv) ([]models.OsintFinding, error) {
	u := "https://api.ethplorer.io/getAddressInfo/" + url.PathEscape(env.target) + "?apiKey=freekey"
	var r struct {
		ETH struct {
			Balance float64 `json:"balance"`
		} `json:"ETH"`
		CountTxs int `json:"countTxs"`
		Error    *struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	status, err := httpGetJSON(ctx, rlBlockchain, u, nil, &r)
	if err != nil {
		return nil, err
	}
	if status < 200 || status >= 300 {
		return nil, fmt.Errorf("ethplorer returned HTTP %d", status)
	}
	if r.Error != nil && r.Error.Message != "" {
		env.emit("[*] blockchain: " + r.Error.Message)
		return nil, nil
	}

	f := newFinding("blockchain", "financial", "Ethereum wallet activity",
		fmt.Sprintf("balance %.6f ETH - %d tx", r.ETH.Balance, r.CountTxs))
	if r.CountTxs == 0 {
		f.Severity = "info"
	} else {
		f.Severity = "low"
	}
	return []models.OsintFinding{withSource(f, "https://etherscan.io/address/"+url.PathEscape(env.target))}, nil
}
