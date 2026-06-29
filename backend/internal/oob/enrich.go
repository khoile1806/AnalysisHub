package oob

import (
	"encoding/json"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"github.com/forensichub/backend/internal/models"
	"github.com/forensichub/backend/internal/netsafe"
)

// Source-IP enrichment: look up geo / ASN / PTR / network-type for a captured
// callback's source IP and write it back. Runs through a bounded worker pool so
// a callback flood can't spawn unbounded outbound lookups; jobs are dropped
// (best effort) when the queue is full. Private / non-public IPs are skipped.

type enrichJob struct {
	db *gorm.DB
	id uuid.UUID
	ip string
}

var (
	enrichQueue  chan enrichJob
	enrichOnce   sync.Once
	enrichClient = &http.Client{Timeout: 8 * time.Second} // uses the proxy-aware default transport
)

// EnrichInteraction queues a best-effort enrichment of the interaction's source
// IP. Safe to call from the request path — it never blocks.
func EnrichInteraction(db *gorm.DB, interactionID uuid.UUID, ip string) {
	if ip == "" {
		return
	}
	if parsed := net.ParseIP(ip); parsed == nil || !netsafe.IsPublicIP(parsed) {
		return // skip private / loopback / unroutable sources
	}
	enrichOnce.Do(func() {
		enrichQueue = make(chan enrichJob, 256)
		for i := 0; i < 8; i++ {
			go enrichWorker()
		}
	})
	select {
	case enrichQueue <- enrichJob{db, interactionID, ip}:
	default:
		// queue saturated — drop this enrichment.
	}
}

func enrichWorker() {
	for job := range enrichQueue {
		func() {
			defer func() {
				if r := recover(); r != nil {
					slog.Error("oob enrich panic", "err", r)
				}
			}()
			runEnrich(job)
		}()
	}
}

func runEnrich(job enrichJob) {
	u := "http://ip-api.com/json/" + url.PathEscape(job.ip) +
		"?fields=status,country,city,as,isp,proxy,hosting,reverse"
	resp, err := enrichClient.Get(u)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	var r struct {
		Status  string `json:"status"`
		Country string `json:"country"`
		City    string `json:"city"`
		As      string `json:"as"`
		Isp     string `json:"isp"`
		Reverse string `json:"reverse"`
		Proxy   bool   `json:"proxy"`
		Hosting bool   `json:"hosting"`
	}
	if json.NewDecoder(resp.Body).Decode(&r) != nil || r.Status != "success" {
		return
	}

	job.db.Model(&models.OobInteraction{}).Where("id = ?", job.id).Updates(map[string]interface{}{
		"geo_country": r.Country,
		"geo_city":    r.City,
		"asn":         r.As,
		"isp":         r.Isp,
		"rdns":        r.Reverse,
		"is_proxy":    r.Proxy,
		"is_hosting":  r.Hosting,
	})
}
