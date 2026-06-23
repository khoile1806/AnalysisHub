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
	mux.HandleFunc("/api/tools", s.handleTools)
	mux.HandleFunc("/api/jobs", s.handleJobs)
	mux.HandleFunc("/api/jobs/", s.handleJob)
	mux.HandleFunc("/api/report", s.handleReport)

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
	writeJSON(w, map[string]string{
		"hostname": hostname,
		"ip":       localIP(),
		"os":       runtime.GOOS,
		"arch":     runtime.GOARCH,
	})
}

func (s *HTTPServer) handleTools(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]interface{}{
		"bundle_name": s.manifest.Name,
		"tools":       s.manifest.Tools,
	})
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

	// Persist next to the .exe the operator launched (a user-visible location),
	// not the temp extraction dir.
	dir := outputDir()
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
