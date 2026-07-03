package offline

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/analysishub/agent/internal/executor"
)

//go:embed ui/index.html
var indexHTML []byte

// HTTPServer serves the embedded web UI and REST API for the offline agent.
type HTTPServer struct {
	manifest *BundleManifest
	runner   *Runner
	port     int
}

// NewHTTPServer creates an HTTPServer bound to the given port.
func NewHTTPServer(manifest *BundleManifest, runner *Runner, port int) *HTTPServer {
	return &HTTPServer{manifest: manifest, runner: runner, port: port}
}

// Start starts the HTTP server and blocks until it fails.
func (s *HTTPServer) Start() error {
	mux := http.NewServeMux()

	mux.HandleFunc("/", s.handleIndex)
	mux.HandleFunc("/api/sysinfo", s.handleSysinfo)
	mux.HandleFunc("/api/manifest", s.handleManifest)
	mux.HandleFunc("/api/tools", s.handleTools)
	mux.HandleFunc("/api/jobs/batch", s.handleBatch) // exact match wins over /api/jobs/
	mux.HandleFunc("/api/jobs", s.handleJobs)
	mux.HandleFunc("/api/jobs/", s.handleJob)
	mux.HandleFunc("/api/findings", s.handleFindings)
	mux.HandleFunc("/api/reference", s.handleReference)
	mux.HandleFunc("/api/elevate", s.handleElevate)
	mux.HandleFunc("/api/report", s.handleReport)
	mux.HandleFunc("/api/limits", s.handleLimits)

	// Serve the entire bundle directory under /artifacts/ so tools' outputs (like HTML reports) can be viewed
	if bDir, err := bundleDir(); err == nil {
		fs := http.FileServer(http.Dir(bDir))
		mux.Handle("/artifacts/", http.StripPrefix("/artifacts/", fs))
	}

	addr := fmt.Sprintf("127.0.0.1:%d", s.port)
	srv := &http.Server{Addr: addr, Handler: mux, ReadTimeout: 30 * time.Second}
	return srv.ListenAndServe()
}

// PickPort returns a free local port, preferring 7474.
func PickPort() int {
	preferred := []int{7474, 7475, 7476, 18080, 18081}
	for _, p := range preferred {
		ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", p))
		if err == nil {
			ln.Close()
			return p
		}
	}
	// Let OS assign a port.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 7474
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	return port
}

// ── Handlers ────────────────────────────────────────────────────────────────

func (s *HTTPServer) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(indexHTML)
}

func (s *HTTPServer) handleSysinfo(w http.ResponseWriter, r *http.Request) {
	hostname, _ := os.Hostname()
	writeJSON(w, map[string]interface{}{
		"hostname":       hostname,
		"ip":             localIP(),
		"os":             runtime.GOOS,
		"arch":           runtime.GOARCH,
		"elevated":       executor.IsElevated(),
		"requires_admin": s.manifest.RequiresAdmin(),
	})
}

func (s *HTTPServer) handleTools(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]interface{}{
		"bundle_name": s.manifest.Name,
		"tools":       s.manifest.Tools,
	})
}

// handleManifest returns the full bundle context the UI needs: playbooks, the
// admin/elevation state, and the tool list (with presets + report paths).
func (s *HTTPServer) handleManifest(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]interface{}{
		"name":           s.manifest.Name,
		"operator":       s.manifest.Operator,
		"case_name":      s.manifest.CaseName,
		"requires_admin": s.manifest.RequiresAdmin(),
		"elevated":       executor.IsElevated(),
		"playbooks":      s.manifest.EffectivePlaybooks(),
		"tools":          s.manifest.Tools,
	})
}

// handleBatch runs a playbook (?playbook_id) / a set of tools / or everything,
// sequentially in the background — the one-click "Collect" primitive.
func (s *HTTPServer) handleBatch(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	var body struct {
		PlaybookID string   `json:"playbook_id"`
		ToolIDs    []string `json:"tool_ids"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)

	var steps []PlaybookStep
	switch {
	case body.PlaybookID != "":
		for _, pb := range s.manifest.EffectivePlaybooks() {
			if pb.ID == body.PlaybookID {
				steps = pb.Steps
				break
			}
		}
	case len(body.ToolIDs) > 0:
		for _, id := range body.ToolIDs {
			steps = append(steps, PlaybookStep{ToolID: id})
		}
	default:
		for _, t := range s.manifest.Tools {
			steps = append(steps, PlaybookStep{ToolID: t.ID})
		}
	}
	n := s.runner.RunBatch(steps, s.manifest)
	writeJSON(w, map[string]interface{}{"started": n})
}

// handleFindings returns all triage findings, most-severe first.
func (s *HTTPServer) handleFindings(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]interface{}{"findings": s.runner.AllFindings()})
}

// handleReference returns the embedded checklists + playbooks (the hunting
// guide), or an empty object when none were baked into the bundle.
func (s *HTTPServer) handleReference(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if len(s.manifest.Reference) == 0 {
		_, _ = w.Write([]byte(`{"checklists":[],"playbooks":[]}`))
		return
	}
	_, _ = w.Write(s.manifest.Reference)
}

// handleElevate relaunches the agent elevated (one UAC) and exits, so all tools
// run with admin and no per-tool prompts. Windows only.
func (s *HTTPServer) handleElevate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	if executor.IsElevated() {
		writeJSON(w, map[string]interface{}{"already_elevated": true})
		return
	}
	if err := relaunchElevated(); err != nil {
		writeErr(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]interface{}{"relaunching": true})
	// Let the response flush, then exit so the elevated instance takes over.
	go func() {
		time.Sleep(600 * time.Millisecond)
		os.Exit(0)
	}()
}

func (s *HTTPServer) handleJobs(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.listJobs(w, r)
	case http.MethodPost:
		s.createJob(w, r)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *HTTPServer) listJobs(w http.ResponseWriter, _ *http.Request) {
	jobs := s.runner.ListJobs()
	out := make([]map[string]interface{}, 0, len(jobs))
	for _, j := range jobs {
		out = append(out, jobToMap(&j))
	}
	writeJSON(w, map[string]interface{}{"jobs": out})
}

func (s *HTTPServer) createJob(w http.ResponseWriter, r *http.Request) {
	var body struct {
		ToolID string `json:"tool_id"`
		Args   string `json:"args"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, "invalid body: "+err.Error(), http.StatusBadRequest)
		return
	}

	// Find tool in manifest.
	var tool *BundleTool
	for i, t := range s.manifest.Tools {
		if t.ID == body.ToolID {
			tool = &s.manifest.Tools[i]
			break
		}
	}
	if tool == nil {
		writeErr(w, "tool not found: "+body.ToolID, http.StatusNotFound)
		return
	}

	job, err := s.runner.StartJob(*tool, body.Args)
	if err != nil {
		writeErr(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
	writeJSON(w, jobToMap(job))
}

// handleLimits gets (GET) or sets (POST) the global resource throttle applied to
// every job. The cap is enforced by the executor's job-object (Windows) /
// cgroup (Linux) wrapping, so it actually governs the real tool tree.
func (s *HTTPServer) handleLimits(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		var body struct {
			CPULimit int    `json:"cpu_limit"`
			RAMLimit int    `json:"ram_limit"`
			Priority string `json:"priority"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeErr(w, "invalid body: "+err.Error(), http.StatusBadRequest)
			return
		}
		s.runner.SetLimits(body.CPULimit, body.RAMLimit, body.Priority)
	}
	cpu, ram, prio := s.runner.Limits()
	writeJSON(w, map[string]interface{}{
		"cpu_limit": cpu,
		"ram_limit": ram,
		"priority":  prio,
	})
}

// handleJob routes /api/jobs/<id> and /api/jobs/<id>/stream and /api/jobs/<id>/stop.
func (s *HTTPServer) handleJob(w http.ResponseWriter, r *http.Request) {
	// Strip /api/jobs/ prefix.
	path := strings.TrimPrefix(r.URL.Path, "/api/jobs/")
	parts := strings.SplitN(path, "/", 2)
	jobID := parts[0]
	sub := ""
	if len(parts) == 2 {
		sub = parts[1]
	}

	switch sub {
	case "stream":
		s.streamJob(w, r, jobID)
	case "stop":
		if r.Method != http.MethodPost {
			http.Error(w, "POST only", http.StatusMethodNotAllowed)
			return
		}
		s.runner.StopJob(jobID)
		writeJSON(w, map[string]string{"status": "stopping"})
	default:
		// GET /api/jobs/<id>
		job := s.runner.GetJob(jobID)
		if job == nil {
			http.NotFound(w, r)
			return
		}
		writeJSON(w, jobToMap(job))
	}
}

// streamJob implements Server-Sent Events for live output of a job.
func (s *HTTPServer) streamJob(w http.ResponseWriter, r *http.Request, jobID string) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming not supported", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	// Check if job already finished — replay full output then send __DONE__.
	job := s.runner.GetJob(jobID)
	if job != nil && job.Status != StatusRunning && job.Status != StatusPending {
		for _, line := range job.Output {
			fmt.Fprintf(w, "data: %s\n\n", line)
		}
		fmt.Fprintf(w, "data: __DONE__\n\n")
		flusher.Flush()
		return
	}

	// Subscribe to live output.
	history, ch := s.runner.Subscribe(jobID)
	defer s.runner.Unsubscribe(jobID, ch)

	// Replay history.
	for _, line := range history {
		fmt.Fprintf(w, "data: %s\n\n", line)
	}
	flusher.Flush()

	// Stream live lines.
	ctx := r.Context()
	for {
		select {
		case <-ctx.Done():
			return
		case line, open := <-ch:
			if !open {
				fmt.Fprintf(w, "data: __DONE__\n\n")
				flusher.Flush()
				return
			}
			fmt.Fprintf(w, "data: %s\n\n", line)
			flusher.Flush()
		}
	}
}

// handleReport generates and serves the HTML or JSON report as a download.
func (s *HTTPServer) handleReport(w http.ResponseWriter, r *http.Request) {
	format := r.URL.Query().Get("format")
	if format == "" {
		format = "html"
	}

	rep := BuildReport(s.manifest, s.runner)
	hostname, _ := os.Hostname()
	ts := time.Now().Format("20060102-150405")
	baseName := fmt.Sprintf("report-%s-%s", safeFilename(hostname), ts)

	// All evidence lands in ONE clean folder next to the launched .exe, and we
	// (re)write a SHA-256 manifest of everything in it for chain-of-custody.
	dir := collectionDir()
	defer writeCollectionManifest(dir)

	switch format {
	case "json":
		data, err := json.MarshalIndent(rep, "", "  ")
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		fname := baseName + ".json"
		_ = os.WriteFile(filepath.Join(dir, fname), data, 0o644)
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Disposition", `attachment; filename="`+fname+`"`)
		w.Write(data)
	default:
		htmlContent := renderHTML(rep)
		fname := baseName + ".html"
		_ = os.WriteFile(filepath.Join(dir, fname), []byte(htmlContent), 0o644)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="`+fname+`"`)
		w.Write([]byte(htmlContent))
	}
}

// ── Helpers ──────────────────────────────────────────────────────────────────

func jobToMap(j *Job) map[string]interface{} {
	m := map[string]interface{}{
		"id":        j.ID,
		"tool_id":   j.ToolID,
		"tool_name": j.ToolName,
		"args":      j.Args,
		"status":    string(j.Status),
		"output":    strings.Join(j.Output, "\n"),
	}
	if j.StartedAt != nil {
		m["started_at"] = j.StartedAt
		if j.FinishedAt != nil {
			m["finished_at"] = j.FinishedAt
			m["duration_seconds"] = j.FinishedAt.Sub(*j.StartedAt).Seconds()
		}
	}
	if j.Error != "" {
		m["error"] = j.Error
	}
	if len(j.Findings) > 0 {
		m["findings"] = j.Findings
	}
	return m
}

func writeJSON(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, msg string, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

func safeFilename(s string) string {
	var b strings.Builder
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
			b.WriteRune(r)
		} else {
			b.WriteRune('_')
		}
	}
	return b.String()
}
