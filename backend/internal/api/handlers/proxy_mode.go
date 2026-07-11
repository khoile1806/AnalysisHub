package handlers

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"github.com/analysishub/backend/internal/egress"
	"github.com/analysishub/backend/internal/models"
)

// proxy_mode.go — pool automation: manual (default), failover (switch off an
// unhealthy active proxy), or rotate (round-robin the exit identity on a timer).

func loadPoolSetting(db *gorm.DB) models.ProxyPoolSetting {
	var s models.ProxyPoolSetting
	if err := db.First(&s, 1).Error; err != nil {
		s = models.ProxyPoolSetting{ID: 1, Mode: "manual", IntervalSec: 300}
		db.Create(&s)
	}
	return s
}

// GetProxyMode GET /api/v1/system/proxies/mode
func GetProxyMode(c *gin.Context) {
	db, ok := mustGetDB(c)
	if !ok {
		return
	}
	c.JSON(http.StatusOK, gin.H{"success": true, "data": loadPoolSetting(db)})
}

// SetProxyMode POST /api/v1/system/proxies/mode {mode, interval_sec}
func SetProxyMode(c *gin.Context) {
	if !requireAdmin(c) {
		return
	}
	db, ok := mustGetDB(c)
	if !ok {
		return
	}
	var req struct {
		Mode        string `json:"mode"`
		IntervalSec int    `json:"interval_sec"`
		KillSwitch  *bool  `json:"kill_switch"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": err.Error()})
		return
	}
	if req.Mode != "" {
		switch req.Mode {
		case "manual", "failover", "rotate":
		default:
			c.JSON(http.StatusBadRequest, gin.H{"success": false, "error": "mode must be manual, failover, or rotate"})
			return
		}
	}
	s := loadPoolSetting(db)
	if req.Mode != "" {
		s.Mode = req.Mode
	}
	if req.IntervalSec >= 30 {
		s.IntervalSec = req.IntervalSec
	}
	if req.KillSwitch != nil {
		s.KillSwitch = *req.KillSwitch
		egress.SetKillSwitch(s.KillSwitch)
	}
	db.Save(&s)
	c.JSON(http.StatusOK, gin.H{"success": true, "data": s})
}

// activateProfileInternal switches the live egress + DB active flag to p. Shared
// by the Activate handler and the automation loop.
func activateProfileInternal(db *gorm.DB, p *models.ProxyProfile) {
	db.Transaction(func(tx *gorm.DB) error {
		tx.Model(&models.ProxyProfile{}).Where("id <> ?", p.ID).Update("is_active", false)
		return tx.Model(p).Update("is_active", true).Error
	})
	ApplyActiveProxyProfile(*p)
	egress.CheckNow()
}

// StartProxyPoolAutomation runs the failover/rotation loop. In manual mode it is
// a no-op. When active it also refreshes every pool member's health so failover
// has fresh data to act on.
func StartProxyPoolAutomation(db *gorm.DB) {
	go func() {
		var lastRotate time.Time
		runWorker("proxy-pool", 30*time.Second, func() { proxyPoolTick(db, &lastRotate) })
	}()
}

// proxyPoolTick runs one failover/rotation cycle. Extracted so the tick can be
// panic-recovered (a closure can't `continue` an outer loop, so `return` is used
// to skip a cycle).
func proxyPoolTick(db *gorm.DB, lastRotate *time.Time) {
	s := loadPoolSetting(db)
	if s.Mode == "manual" {
		return
	}

	var active models.ProxyProfile
	hasActive := db.Where("is_active = ?", true).First(&active).Error == nil

	// Failover: probe only the ACTIVE proxy each cycle (cheap). Fan out to the whole
	// pool to find a replacement ONLY when the active is down or absent.
	if s.Mode == "failover" {
		if hasActive {
			updateProfileHealth(db, &active, egress.Probe(active.URL))
			if active.Healthy {
				return // active still up — no pool scan needed
			}
		}
		var all []models.ProxyProfile
		db.Order("id asc").Find(&all)
		for i := range all {
			updateProfileHealth(db, &all[i], egress.Probe(all[i].URL))
			if all[i].Healthy {
				activateProfileInternal(db, &all[i])
				break
			}
		}
		return
	}

	// Rotate: every candidate's health must be fresh to pick the next exit.
	var all []models.ProxyProfile
	db.Find(&all)
	for i := range all {
		updateProfileHealth(db, &all[i], egress.Probe(all[i].URL))
	}
	var healthy []models.ProxyProfile
	db.Where("healthy = ?", true).Order("id asc").Find(&healthy)
	if len(healthy) == 0 {
		return
	}
	if time.Since(*lastRotate) < time.Duration(s.IntervalSec)*time.Second {
		return
	}
	next := healthy[0]
	if hasActive {
		for i, h := range healthy {
			if h.ID == active.ID {
				next = healthy[(i+1)%len(healthy)]
				break
			}
		}
	}
	activateProfileInternal(db, &next)
	*lastRotate = time.Now()
}
