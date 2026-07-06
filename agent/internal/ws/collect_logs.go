package ws

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"mime/multipart"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// handleCollectOSLogs auto-detects the host OS and gathers its important logs,
// uploading each to the backend's agent log-ingest endpoint. The backend runs
// them through the normal Log Ingest pipeline, tagged with this host, so the
// Log Ingest repository can present and manage logs per host.
//
// Windows: each event channel is exported to a standalone .evtx with wevtutil
// (safe on live/locked logs), bounded to the last N days.
// Linux: a curated set of /var/log files is uploaded as-is.
//
// Progress is streamed back under msg.JobID like any other job.

// windowsLogChannels is the curated set of high-value DFIR event channels. A
// channel that does not exist on the host is skipped silently.
var windowsLogChannels = []string{
	"Security",
	"System",
	"Application",
	"Setup",
	"Windows PowerShell",
	"Microsoft-Windows-Sysmon/Operational",
	"Microsoft-Windows-PowerShell/Operational",
	"Microsoft-Windows-TaskScheduler/Operational",
	"Microsoft-Windows-TerminalServices-LocalSessionManager/Operational",
	"Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational",
	"Microsoft-Windows-WinRM/Operational",
	"Microsoft-Windows-Windows Defender/Operational",
	"Microsoft-Windows-Bits-Client/Operational",
	"Microsoft-Windows-WMI-Activity/Operational",
	"Microsoft-Windows-DNS-Client/Operational",
}

// linuxLogFiles is the curated set of /var/log paths worth collecting. Only
// existing, non-empty regular files are uploaded.
var linuxLogFiles = []string{
	"/var/log/syslog",
	"/var/log/messages",
	"/var/log/auth.log",
	"/var/log/secure",
	"/var/log/kern.log",
	"/var/log/dmesg",
	"/var/log/dpkg.log",
	"/var/log/yum.log",
	"/var/log/audit/audit.log",
	"/var/log/cron",
	"/var/log/boot.log",
	"/var/log/faillog",
	"/var/log/apache2/access.log",
	"/var/log/apache2/error.log",
	"/var/log/nginx/access.log",
	"/var/log/nginx/error.log",
}

// collectMaxFileBytes caps a single collected log file to keep uploads sane.
const collectMaxFileBytes = 2 << 30 // 2 GB

func (c *Client) handleCollectOSLogs(msg inboundMsg) {
	jobID := msg.JobID
	if jobID == "" {
		log.Printf("[collect_logs] missing job_id")
		return
	}

	var opts struct {
		Case string `json:"case"`
		Days int    `json:"days"`
	}
	if strings.TrimSpace(msg.Args) != "" {
		_ = json.Unmarshal([]byte(msg.Args), &opts)
	}
	if opts.Days <= 0 || opts.Days > 365 {
		opts.Days = 7
	}
	caseName := strings.TrimSpace(opts.Case)
	if caseName == "" {
		caseName = "agent-collect"
	}

	host, _ := os.Hostname()
	if host == "" {
		host = "unknown-host"
	}
	osName := runtime.GOOS

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()

	c.sendOutput(jobID, fmt.Sprintf("[+] Collecting OS logs on %s (%s), window=%d days", host, osName, opts.Days), false)

	tmpDir, err := os.MkdirTemp("", "oslogs-")
	if err != nil {
		c.sendOutput(jobID, fmt.Sprintf("[agent error] temp dir: %v", err), false)
		c.sendOutput(jobID, "", true)
		return
	}
	defer os.RemoveAll(tmpDir)

	var uploaded, skipped, failed int
	upload := func(path, channel string) {
		if err := c.uploadLog(ctx, path, host, osName, channel, caseName); err != nil {
			failed++
			c.sendOutput(jobID, fmt.Sprintf("[!] upload failed (%s): %v", channel, err), false)
			return
		}
		uploaded++
		c.sendOutput(jobID, fmt.Sprintf("[+] uploaded %s", channel), false)
	}

	switch osName {
	case "windows":
		windowMs := int64(opts.Days) * 86400 * 1000
		for _, ch := range windowLogChannelsForHost() {
			outFile := filepath.Join(tmpDir, sanitizeChannel(ch)+".evtx")
			// /ow:true overwrites; the query restricts to the recent time window.
			query := fmt.Sprintf("*[System[TimeCreated[timediff(@SystemTime) <= %d]]]", windowMs)
			cmd := exec.CommandContext(ctx, "wevtutil.exe", "epl", ch, outFile, "/ow:true", "/q:"+query)
			if out, err := cmd.CombinedOutput(); err != nil {
				// Channel absent or access denied — skip quietly.
				skipped++
				log.Printf("[collect_logs] skip channel %q: %v (%s)", ch, err, strings.TrimSpace(string(out)))
				continue
			}
			if fi, statErr := os.Stat(outFile); statErr != nil || fi.Size() == 0 || fi.Size() > collectMaxFileBytes {
				skipped++
				continue
			}
			upload(outFile, ch)
		}
	default: // linux and other unix
		for _, p := range linuxLogFiles {
			fi, statErr := os.Stat(p)
			if statErr != nil || fi.IsDir() || fi.Size() == 0 {
				skipped++
				continue
			}
			if fi.Size() > collectMaxFileBytes {
				skipped++
				c.sendOutput(jobID, fmt.Sprintf("[!] skip %s (too large: %d bytes)", p, fi.Size()), false)
				continue
			}
			upload(p, p)
		}
	}

	c.sendOutput(jobID, fmt.Sprintf("[+] Done. uploaded=%d skipped=%d failed=%d — see Log Ingest → host %q", uploaded, skipped, failed, host), false)
	c.sendOutput(jobID, "", true)
}

// windowLogChannelsForHost returns the curated Windows channel list (kept as a
// function so a future version could enumerate the host's channels dynamically).
func windowLogChannelsForHost() []string {
	return windowsLogChannels
}

// sanitizeChannel turns an event-channel name into a safe file base name.
func sanitizeChannel(ch string) string {
	r := strings.NewReplacer("/", "_", "\\", "_", " ", "_", ":", "_")
	return r.Replace(ch)
}

// uploadLog streams one collected log file to the backend agent log-ingest
// endpoint as multipart form data, authenticated with the agent token.
func (c *Client) uploadLog(ctx context.Context, filePath, host, osName, channel, caseName string) error {
	f, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("open %s: %w", filePath, err)
	}
	defer f.Close()

	pr, pw := io.Pipe()
	w := multipart.NewWriter(pw)
	go func() {
		defer pw.Close()
		_ = w.WriteField("host", host)
		_ = w.WriteField("os", osName)
		_ = w.WriteField("channel", channel)
		_ = w.WriteField("case", caseName)
		part, cerr := w.CreateFormFile("file", filepath.Base(filePath))
		if cerr != nil {
			log.Printf("[collect_logs] form file error: %v", cerr)
			return
		}
		if _, cerr := io.Copy(part, f); cerr != nil {
			log.Printf("[collect_logs] copy error: %v", cerr)
		}
		w.Close()
	}()

	uploadURL := fmt.Sprintf("%s/api/v1/logsearch/agent-ingest", c.cfg.ServerURL)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, uploadURL, pr)
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", w.FormDataContentType())
	req.Header.Set("X-Agent-Token", c.cfg.AgentToken)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("dispatch: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusAccepted {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("server %s: %s", resp.Status, strings.TrimSpace(string(body)))
	}
	return nil
}
