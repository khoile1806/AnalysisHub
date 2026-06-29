package oob

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"gorm.io/gorm"

	"github.com/forensichub/backend/internal/models"
)

const (
	// maxBodyPreview caps how much of an HTTP body / SMTP transcript is stored.
	maxBodyPreview = 16 * 1024
	// soaSerial is a static zone serial — the zone is dynamic so the serial is
	// not meaningful; a fixed value avoids needless churn.
	soaSerial = 2026010100
)

// Options configures the interaction server (mirrors the OOB_* config fields).
type Options struct {
	Enabled    bool
	Domain     string
	PublicIP   string
	PublicIPv6 string
	NSName     string
	DNSPort    string
	HTTPPort   string
	HTTPSPort  string
	SMTPPort   string
	TLSCert    string
	TLSKey     string
	LDAPPort   string // JNDI/LDAP callback catcher (Log4Shell) — default 1389
	RMIPort    string // JNDI/RMI callback catcher — default 1099
}

// Server runs the OOB DNS/HTTP(S)/SMTP listeners and records correlated
// interactions to the database. All listeners are best-effort: a failure to
// bind one (e.g. port 53 in use) is logged and the others still run.
type Server struct {
	db  *gorm.DB
	opt Options

	hub *Hub // optional SSE broker; DNS/SMTP/HTTP-host captures push to it

	mu      sync.Mutex
	running bool
	listens []string

	dnsUDP   *dns.Server
	dnsTCP   *dns.Server
	httpSrv  *http.Server
	httpsSrv *http.Server
	httpLn   net.Listener
	httpsLn  net.Listener
	smtpLn   net.Listener
	tcpLns   []net.Listener // LDAP/RMI catchers
}

// SetHub wires an SSE broker so OAST (DNS/SMTP/HTTP-host) captures also push
// live events, not just the HTTP webhook path.
func (s *Server) SetHub(h *Hub) { s.hub = h }

// New builds a server. The NS hostname defaults to ns1.<domain> when unset.
func New(db *gorm.DB, opt Options) *Server {
	opt.Domain = strings.ToLower(strings.TrimSuffix(opt.Domain, "."))
	if opt.NSName == "" && opt.Domain != "" {
		opt.NSName = "ns1." + opt.Domain
	}
	opt.NSName = strings.TrimSuffix(opt.NSName, ".")
	return &Server{db: db, opt: opt}
}

// Domain returns the configured zone (lowercased, no trailing dot).
func (s *Server) Domain() string { return s.opt.Domain }

// Running reports whether the listeners have been started.
func (s *Server) Running() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.running
}

// Listeners returns the human-readable list of active listeners for the UI.
func (s *Server) Listeners() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.listens...)
}

// Start launches the configured listeners. No-op when disabled or no domain.
func (s *Server) Start() {
	if !s.opt.Enabled {
		slog.Info("oob: disabled (set OOB_ENABLED=true to start)")
		return
	}
	if s.opt.Domain == "" {
		slog.Warn("oob: OOB_DOMAIN not set — interaction server not started")
		return
	}

	s.mu.Lock()
	s.running = true
	s.mu.Unlock()

	s.startDNS()
	s.startHTTP()
	s.startHTTPS()
	s.startSMTP()
	s.startTCPCatch(s.opt.LDAPPort, "ldap")
	s.startTCPCatch(s.opt.RMIPort, "rmi")

	slog.Info("oob interaction server started",
		"domain", s.opt.Domain, "public_ip", s.opt.PublicIP, "listeners", s.Listeners())
	if s.opt.PublicIP == "" {
		slog.Warn("oob: OOB_PUBLIC_IP not set — DNS will not answer A records, HTTP callbacks won't resolve")
	}
}

// Shutdown stops every listener.
func (s *Server) Shutdown(ctx context.Context) {
	if s.dnsUDP != nil {
		_ = s.dnsUDP.ShutdownContext(ctx)
	}
	if s.dnsTCP != nil {
		_ = s.dnsTCP.ShutdownContext(ctx)
	}
	if s.httpSrv != nil {
		_ = s.httpSrv.Shutdown(ctx)
	}
	if s.httpsSrv != nil {
		_ = s.httpsSrv.Shutdown(ctx)
	}
	if s.smtpLn != nil {
		_ = s.smtpLn.Close()
	}
	for _, ln := range s.tcpLns {
		_ = ln.Close()
	}
	s.mu.Lock()
	s.running = false
	s.mu.Unlock()
}

func (s *Server) addListener(desc string) {
	s.mu.Lock()
	s.listens = append(s.listens, desc)
	s.mu.Unlock()
}

// ───────────────────────────── correlation + persistence ──────────────────

// record attributes an interaction to a client by its correlation prefix and
// persists it. Unknown correlation ids (internet background noise) are dropped.
func (s *Server) record(in models.OobInteraction) {
	corr, uniq, ok := splitLabel(in.FullHost, s.opt.Domain)
	if !ok {
		return
	}
	var client models.OobClient
	if err := s.db.Where("correlation_id = ?", corr).First(&client).Error; err != nil {
		return // unknown correlation — ignore noise
	}

	in.ClientID = client.ID
	in.CorrelationID = corr
	in.UniqueID = uniq
	if in.RemoteIP == "" && in.RemoteAddr != "" {
		if host, _, err := net.SplitHostPort(in.RemoteAddr); err == nil {
			in.RemoteIP = host
		} else {
			in.RemoteIP = in.RemoteAddr
		}
	}
	in.CreatedAt = time.Now()
	if len(in.RawRequest) > maxBodyPreview {
		in.RawRequest = in.RawRequest[:maxBodyPreview]
	}

	if err := s.db.Create(&in).Error; err != nil {
		slog.Error("oob: persist interaction", "err", err)
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
	slog.Info("oob interaction", "proto", in.Protocol, "host", in.FullHost, "from", in.RemoteIP)
}

// ───────────────────────────────────── DNS ────────────────────────────────

func (s *Server) startDNS() {
	if s.opt.DNSPort == "" || s.opt.DNSPort == "0" {
		return
	}
	addr := ":" + s.opt.DNSPort
	h := dns.HandlerFunc(s.handleDNS)
	s.dnsUDP = &dns.Server{Addr: addr, Net: "udp", Handler: h}
	s.dnsTCP = &dns.Server{Addr: addr, Net: "tcp", Handler: h}
	go func() {
		if err := s.dnsUDP.ListenAndServe(); err != nil {
			slog.Error("oob dns/udp", "err", err)
		}
	}()
	go func() {
		if err := s.dnsTCP.ListenAndServe(); err != nil {
			slog.Error("oob dns/tcp", "err", err)
		}
	}()
	s.addListener("dns/udp+tcp :" + s.opt.DNSPort)
}

func (s *Server) handleDNS(w dns.ResponseWriter, r *dns.Msg) {
	remote := w.RemoteAddr().String()
	// Response-rate-limit per source to blunt DNS reflection/amplification.
	if dnsRateLimited(remote) {
		return
	}

	m := new(dns.Msg)
	m.SetReply(r)
	m.Authoritative = true

	var toRecord []models.OobInteraction
	for _, q := range r.Question {
		name := q.Name
		qtype := dns.TypeToString[q.Qtype]
		toRecord = append(toRecord, models.OobInteraction{
			Protocol:   "dns",
			FullHost:   strings.TrimSuffix(name, "."),
			QueryType:  qtype,
			RemoteAddr: remote,
			RawRequest: fmt.Sprintf("DNS %s %s from %s", qtype, name, remote),
		})

		switch q.Qtype {
		case dns.TypeA:
			s.appendA(m, name, false)
		case dns.TypeAAAA:
			if s.opt.PublicIPv6 != "" {
				if rr, err := dns.NewRR(fmt.Sprintf("%s 60 IN AAAA %s", name, s.opt.PublicIPv6)); err == nil {
					m.Answer = append(m.Answer, rr)
				}
			}
		case dns.TypeNS:
			if rr, err := dns.NewRR(fmt.Sprintf("%s 3600 IN NS %s.", name, s.opt.NSName)); err == nil {
				m.Answer = append(m.Answer, rr)
			}
		case dns.TypeSOA:
			if rr, err := dns.NewRR(fmt.Sprintf("%s 3600 IN SOA %s. hostmaster.%s. %d 3600 600 86400 60",
				name, s.opt.NSName, s.opt.Domain, soaSerial)); err == nil {
				m.Answer = append(m.Answer, rr)
			}
		case dns.TypeTXT:
			if rr, err := dns.NewRR(fmt.Sprintf("%s 60 IN TXT \"forensichub-oob\"", name)); err == nil {
				m.Answer = append(m.Answer, rr)
			}
		default:
			// Always offer an A in the additional section so a follow-up HTTP
			// callback still resolves to us.
			s.appendA(m, name, true)
		}
	}
	// Reply FIRST so a slow DB write never delays (or drops) the DNS answer;
	// persistence happens after the response is on the wire.
	_ = w.WriteMsg(m)
	for _, in := range toRecord {
		s.record(in)
	}
}

// dnsRateLimited applies a coarse per-source fixed-window limit (queries/second)
// to mitigate using the authoritative server as a reflection/amplification
// vector. In-memory and best-effort.
var (
	dnsRLMu     sync.Mutex
	dnsRLCounts = map[string]int{}
	dnsRLWindow time.Time
)

func dnsRateLimited(remote string) bool {
	ip := remote
	if h, _, err := net.SplitHostPort(remote); err == nil {
		ip = h
	}
	dnsRLMu.Lock()
	defer dnsRLMu.Unlock()
	now := time.Now().Truncate(time.Second)
	if !now.Equal(dnsRLWindow) {
		dnsRLWindow = now
		dnsRLCounts = make(map[string]int)
	}
	dnsRLCounts[ip]++
	return dnsRLCounts[ip] > 100 // > 100 q/s from one source → drop
}

func (s *Server) appendA(m *dns.Msg, name string, additional bool) {
	if s.opt.PublicIP == "" {
		return
	}
	rr, err := dns.NewRR(fmt.Sprintf("%s 60 IN A %s", name, s.opt.PublicIP))
	if err != nil {
		return
	}
	if additional {
		m.Extra = append(m.Extra, rr)
	} else {
		m.Answer = append(m.Answer, rr)
	}
}

// ──────────────────────────────────── HTTP ────────────────────────────────

func (s *Server) startHTTP() {
	if s.opt.HTTPPort == "" || s.opt.HTTPPort == "0" {
		return
	}
	ln, err := net.Listen("tcp", ":"+s.opt.HTTPPort)
	if err != nil {
		slog.Error("oob http listen", "err", err)
		return
	}
	s.httpLn = ln
	s.httpSrv = &http.Server{
		Handler:           http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { s.handleHTTP(w, r, "http") }),
		ReadHeaderTimeout: 10 * time.Second,
	}
	go func() {
		if err := s.httpSrv.Serve(ln); err != nil && err != http.ErrServerClosed {
			slog.Error("oob http serve", "err", err)
		}
	}()
	s.addListener("http :" + s.opt.HTTPPort)
}

func (s *Server) startHTTPS() {
	if s.opt.TLSCert == "" || s.opt.TLSKey == "" {
		return
	}
	if s.opt.HTTPSPort == "" || s.opt.HTTPSPort == "0" {
		return
	}
	ln, err := net.Listen("tcp", ":"+s.opt.HTTPSPort)
	if err != nil {
		slog.Error("oob https listen", "err", err)
		return
	}
	s.httpsLn = ln
	s.httpsSrv = &http.Server{
		Handler:           http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { s.handleHTTP(w, r, "https") }),
		ReadHeaderTimeout: 10 * time.Second,
	}
	go func() {
		if err := s.httpsSrv.ServeTLS(ln, s.opt.TLSCert, s.opt.TLSKey); err != nil && err != http.ErrServerClosed {
			slog.Error("oob https serve", "err", err)
		}
	}()
	s.addListener("https :" + s.opt.HTTPSPort)
}

func (s *Server) handleHTTP(w http.ResponseWriter, r *http.Request, proto string) {
	host := r.Host
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}

	var body []byte
	if r.Body != nil {
		body, _ = io.ReadAll(io.LimitReader(r.Body, maxBodyPreview))
	}
	s.record(models.OobInteraction{
		Protocol:   proto,
		FullHost:   host,
		Method:     r.Method,
		Path:       r.URL.RequestURI(),
		UserAgent:  r.UserAgent(),
		RemoteAddr: r.RemoteAddr,
		RawRequest: dumpHTTP(r, body),
	})

	w.Header().Set("Server", "forensichub-oob")
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(w, "ok\n")
}

func dumpHTTP(r *http.Request, body []byte) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s %s %s\r\n", r.Method, r.URL.RequestURI(), r.Proto)
	fmt.Fprintf(&b, "Host: %s\r\n", r.Host)
	for k, vs := range r.Header {
		for _, v := range vs {
			fmt.Fprintf(&b, "%s: %s\r\n", k, v)
		}
	}
	b.WriteString("\r\n")
	if len(body) > 0 {
		b.Write(body)
	}
	return b.String()
}

// ──────────────────────────────────── SMTP ────────────────────────────────

func (s *Server) startSMTP() {
	if s.opt.SMTPPort == "" || s.opt.SMTPPort == "0" {
		return
	}
	ln, err := net.Listen("tcp", ":"+s.opt.SMTPPort)
	if err != nil {
		slog.Error("oob smtp listen", "err", err)
		return
	}
	s.smtpLn = ln
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return // listener closed
			}
			go s.handleSMTP(conn)
		}
	}()
	s.addListener("smtp :" + s.opt.SMTPPort)
}

// handleSMTP speaks just enough SMTP to capture MAIL FROM / RCPT TO / DATA. It
// always accepts so the sender completes delivery and the payload host (taken
// from RCPT TO) is recorded.
func (s *Server) handleSMTP(conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))

	br := bufio.NewReader(conn)
	wr := bufio.NewWriter(conn)
	reply := func(line string) {
		_, _ = wr.WriteString(line + "\r\n")
		_ = wr.Flush()
	}

	reply("220 " + s.opt.Domain + " ESMTP forensichub-oob")

	var from, to string
	var transcript strings.Builder
	inData := false

Loop:
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			break
		}
		if transcript.Len() < maxBodyPreview {
			transcript.WriteString(line)
		}
		trimmed := strings.TrimRight(line, "\r\n")

		if inData {
			if trimmed == "." {
				inData = false
				reply("250 2.0.0 OK: queued")
			}
			continue
		}

		up := strings.ToUpper(trimmed)
		switch {
		case strings.HasPrefix(up, "HELO"), strings.HasPrefix(up, "EHLO"):
			reply("250 " + s.opt.Domain + " Hello")
		case strings.HasPrefix(up, "MAIL FROM"):
			from = extractAngle(trimmed)
			reply("250 2.1.0 OK")
		case strings.HasPrefix(up, "RCPT TO"):
			to = extractAngle(trimmed)
			reply("250 2.1.5 OK")
		case up == "DATA":
			inData = true
			reply("354 End data with <CR><LF>.<CR><LF>")
		case up == "QUIT":
			reply("221 2.0.0 Bye")
			break Loop
		default:
			reply("250 2.0.0 OK")
		}
	}

	host := emailHost(to)
	if host == "" {
		host = emailHost(from)
	}
	if host == "" {
		return
	}
	s.record(models.OobInteraction{
		Protocol:   "smtp",
		FullHost:   host,
		SMTPFrom:   from,
		SMTPTo:     to,
		RemoteAddr: conn.RemoteAddr().String(),
		RawRequest: transcript.String(),
	})
}
