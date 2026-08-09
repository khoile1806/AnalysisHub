package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/analysishub/backend/internal/logsearch"
)

// The Log Ingest tab exposes a power toggle for the built-in ELK containers
// (Elasticsearch + Kibana) so an analyst can free their ~3-4 GB of RAM when not
// hunting and spin them back up on demand. Control goes through the scoped
// docker-socket-proxy (DOCKER_API_URL) — the backend never touches the raw
// docker socket, and the proxy only permits container inspect/start/stop. The
// toggle auto-enables when the proxy is configured; otherwise the UI shows the
// manual `docker compose` command.

// Container names match the container_name values in docker-compose.yml.
const (
	elkESContainer     = "analysishub_elasticsearch"
	elkKibanaContainer = "analysishub_kibana"
	sandboxContainer   = "analysishub_volatility"
)

// dockerBase returns the trimmed Docker API base URL, or "" when control is off.
func (h *LogSearchHandler) dockerBase() string {
	return strings.TrimRight(strings.TrimSpace(h.DockerAPIURL), "/")
}

func (h *LogSearchHandler) controlEnabled() bool {
	return h.dockerBase() != ""
}

func dockerHTTP() *http.Client {
	return &http.Client{Timeout: 30 * time.Second}
}

type containerState struct {
	Name    string `json:"name"`
	Running bool   `json:"running"`
	Status  string `json:"status"` // running|exited|not_found|unknown
}

func (h *LogSearchHandler) inspect(client *http.Client, name string) containerState {
	st := containerState{Name: name, Status: "unknown"}
	resp, err := client.Get(h.dockerBase() + "/containers/" + name + "/json")
	if err != nil {
		return st
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		st.Status = "not_found"
		return st
	}
	if resp.StatusCode != http.StatusOK {
		return st
	}
	var body struct {
		State struct {
			Running bool   `json:"Running"`
			Status  string `json:"Status"`
		} `json:"State"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return st
	}
	st.Running = body.State.Running
	st.Status = body.State.Status
	return st
}

// action posts start/stop to a container; verb is "start" or "stop".
func (h *LogSearchHandler) action(client *http.Client, name, verb string) error {
	url := fmt.Sprintf("%s/containers/%s/%s", h.dockerBase(), name, verb)
	if verb == "stop" {
		url += "?t=20"
	}
	req, _ := http.NewRequest(http.MethodPost, url, nil)
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	// 204 = done, 304 = already in target state — both fine.
	if resp.StatusCode == http.StatusNoContent || resp.StatusCode == http.StatusNotModified {
		return nil
	}
	if resp.StatusCode == http.StatusNotFound {
		return fmt.Errorf("container %q not found — run: docker compose up -d", name)
	}
	return fmt.Errorf("%s %s: docker returned %d", verb, name, resp.StatusCode)
}

// ELKStatus GET /api/v1/logsearch/elk/status — power state of the ELK containers.
func (h *LogSearchHandler) ELKStatus(c *gin.Context) {
	out := gin.H{"control_enabled": h.controlEnabled()}
	if !h.controlEnabled() {
		out["hint"] = "In-app control unavailable (docker proxy not configured). Manual: docker compose stop elasticsearch kibana"
		c.JSON(http.StatusOK, out)
		return
	}
	client := dockerHTTP()
	out["elasticsearch"] = h.inspect(client, elkESContainer)
	out["kibana"] = h.inspect(client, elkKibanaContainer)
	out["auto_shutdown"] = h.autoShutdownInfo(svcELK)
	c.JSON(http.StatusOK, out)
}

// SandboxStatus GET /api/v1/logsearch/sandbox/status — power state of the
// volatility/kali sandbox container (frees RAM when idle, like the ELK toggle).
func (h *LogSearchHandler) SandboxStatus(c *gin.Context) {
	out := gin.H{"control_enabled": h.controlEnabled()}
	if !h.controlEnabled() {
		out["hint"] = "In-app control unavailable (docker proxy not configured). Manual: docker compose stop volatility_sandbox"
		c.JSON(http.StatusOK, out)
		return
	}
	out["sandbox"] = h.inspect(dockerHTTP(), sandboxContainer)
	out["auto_shutdown"] = h.autoShutdownInfo(svcSandbox)
	c.JSON(http.StatusOK, out)
}

// SandboxPower POST /api/v1/logsearch/sandbox/:verb (start|stop) — admin only.
func (h *LogSearchHandler) SandboxPower(c *gin.Context) {
	verb := c.Param("verb")
	if verb != "start" && verb != "stop" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "verb must be start or stop"})
		return
	}
	if !h.controlEnabled() {
		c.JSON(http.StatusPreconditionFailed, gin.H{"error": "sandbox control unavailable — docker proxy not configured"})
		return
	}
	if err := h.action(dockerHTTP(), sandboxContainer, verb); err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": err.Error()})
		return
	}
	// A manual STOP is respected by the reaper/keepalive (no auto-start until the
	// admin starts it again); a manual START clears that and resets the idle timer.
	idleState.mu.Lock()
	idleState.sandbox.manualOff = verb == "stop"
	idleState.sandbox.last = time.Now()
	idleState.mu.Unlock()
	c.JSON(http.StatusOK, gin.H{"ok": true, "verb": verb})
}

// ELKPower POST /api/v1/logsearch/elk/:verb  (verb = start|stop) — admin only.
func (h *LogSearchHandler) ELKPower(c *gin.Context) {
	verb := c.Param("verb")
	if verb != "start" && verb != "stop" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "verb must be start or stop"})
		return
	}
	if !h.controlEnabled() {
		c.JSON(http.StatusPreconditionFailed, gin.H{
			"error": "ELK control unavailable — docker proxy not configured",
		})
		return
	}
	client := dockerHTTP()
	// Start ES before Kibana; stop Kibana before ES.
	order := []string{elkESContainer, elkKibanaContainer}
	if verb == "stop" {
		order = []string{elkKibanaContainer, elkESContainer}
	}
	for _, name := range order {
		if err := h.action(client, name, verb); err != nil {
			c.JSON(http.StatusBadGateway, gin.H{"error": err.Error()})
			return
		}
	}
	// On start, (re)provision Kibana data views + threat searches/alerts once it
	// is up again — the boot-time provisioning gives up when ELK is off by default.
	if verb == "start" && h.KibanaURL != "" {
		go logsearch.EnsureKibanaDataView(h.KibanaURL)
	}
	idleState.mu.Lock()
	idleState.elk.manualOff = verb == "stop"
	idleState.elk.last = time.Now()
	idleState.mu.Unlock()
	c.JSON(http.StatusOK, gin.H{"ok": true, "verb": verb})
}
