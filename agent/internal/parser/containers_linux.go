//go:build linux

package parser

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os/exec"
	"strings"
	"time"
)

// ContainerMount is one bind/volume mount into a container.
type ContainerMount struct {
	Source string `json:"source"`
	Dest   string `json:"dest"`
	RW     bool   `json:"rw"`
}

// Container is a normalized view of a running/stopped container plus the
// misconfiguration signals that matter for a container-escape / compromise hunt.
type Container struct {
	ID          string          `json:"id"`
	Name        string          `json:"name"`
	Image       string          `json:"image"`
	ImageID     string          `json:"image_id"`
	Command     string          `json:"command"`
	State       string          `json:"state"`
	Status      string          `json:"status"`
	Runtime     string          `json:"runtime"` // docker | containerd | podman
	CreatedAt   string          `json:"created_at"`
	Pid         int             `json:"pid"` // host PID of the container init (links to Processes)
	Ports       []string        `json:"ports"`
	Networks    []string        `json:"networks"`
	Mounts      []ContainerMount `json:"mounts"`
	Privileged  bool            `json:"privileged"`
	HostPID     bool            `json:"host_pid"`
	HostNetwork bool            `json:"host_network"`
	HostIPC     bool            `json:"host_ipc"`
	CapAdd      []string        `json:"cap_add"`
	User        string          `json:"user"`
	SecretEnv   []string        `json:"secret_env"` // NAMES only of secret-looking env vars (values never captured)
	Suspicious  []string        `json:"suspicious"`
}

// ScanContainers enumerates containers on the host. It prefers the Docker Engine
// API over the unix socket (no external tool required), and degrades to the
// docker/podman/crictl CLIs, then to an empty result when no runtime is present.
func ScanContainers() ([]Container, error) {
	if cs, err := scanDockerSocket(); err == nil {
		return cs, nil
	}
	if cs, ok := scanDockerCLI(); ok {
		return cs, nil
	}
	if cs, ok := scanPodmanCLI(); ok {
		return cs, nil
	}
	// No container runtime detected — return an empty (not error) set so the UI
	// shows "no containers" rather than a failure.
	return []Container{}, nil
}

// ── Docker Engine API over /var/run/docker.sock ──────────────────────────────

func dockerSocketClient() *http.Client {
	return &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "unix", "/var/run/docker.sock")
			},
		},
	}
}

type dockerListItem struct {
	ID      string   `json:"Id"`
	Names   []string `json:"Names"`
	Image   string   `json:"Image"`
	ImageID string   `json:"ImageID"`
	Command string   `json:"Command"`
	State   string   `json:"State"`
	Status  string   `json:"Status"`
	Ports   []struct {
		PrivatePort int    `json:"PrivatePort"`
		PublicPort  int    `json:"PublicPort"`
		Type        string `json:"Type"`
		IP          string `json:"IP"`
	} `json:"Ports"`
}

type dockerInspect struct {
	ID     string `json:"Id"`
	Name   string `json:"Name"`
	State  struct {
		Pid int `json:"Pid"`
	} `json:"State"`
	Config struct {
		User string   `json:"User"`
		Env  []string `json:"Env"`
	} `json:"Config"`
	HostConfig struct {
		Privileged   bool     `json:"Privileged"`
		CapAdd       []string `json:"CapAdd"`
		Binds        []string `json:"Binds"`
		NetworkMode  string   `json:"NetworkMode"`
		PidMode      string   `json:"PidMode"`
		IpcMode      string   `json:"IpcMode"`
		SecurityOpt  []string `json:"SecurityOpt"`
	} `json:"HostConfig"`
	Mounts []struct {
		Source      string `json:"Source"`
		Destination string `json:"Destination"`
		RW          bool   `json:"RW"`
	} `json:"Mounts"`
	NetworkSettings struct {
		Networks map[string]any `json:"Networks"`
	} `json:"NetworkSettings"`
}

func scanDockerSocket() ([]Container, error) {
	cli := dockerSocketClient()
	resp, err := cli.Get("http://docker/containers/json?all=1")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("docker api status %d", resp.StatusCode)
	}
	var list []dockerListItem
	if err := json.NewDecoder(resp.Body).Decode(&list); err != nil {
		return nil, err
	}

	const maxContainers = 500
	out := make([]Container, 0, len(list))
	for i, li := range list {
		if i >= maxContainers {
			break
		}
		c := Container{
			ID:      shortID(li.ID),
			Name:    strings.TrimPrefix(firstOr(li.Names, ""), "/"),
			Image:   li.Image,
			ImageID: shortID(li.ImageID),
			Command: li.Command,
			State:   li.State,
			Status:  li.Status,
			Runtime: "docker",
		}
		for _, p := range li.Ports {
			if p.PublicPort > 0 {
				c.Ports = append(c.Ports, fmt.Sprintf("%s:%d->%d/%s", firstOr([]string{p.IP}, "0.0.0.0"), p.PublicPort, p.PrivatePort, p.Type))
			}
		}

		// Inspect for the security-relevant details.
		if ins, ierr := dockerInspectOne(cli, li.ID); ierr == nil {
			c.Pid = ins.State.Pid
			c.User = ins.Config.User
			c.Privileged = ins.HostConfig.Privileged
			c.HostNetwork = ins.HostConfig.NetworkMode == "host"
			c.HostPID = ins.HostConfig.PidMode == "host"
			c.HostIPC = ins.HostConfig.IpcMode == "host"
			c.CapAdd = ins.HostConfig.CapAdd
			for name := range ins.NetworkSettings.Networks {
				c.Networks = append(c.Networks, name)
			}
			for _, m := range ins.Mounts {
				c.Mounts = append(c.Mounts, ContainerMount{Source: m.Source, Dest: m.Destination, RW: m.RW})
			}
			c.SecretEnv = secretEnvNames(ins.Config.Env)
			c.Suspicious = containerRisks(&c, ins.HostConfig.SecurityOpt)
		}
		out = append(out, c)
	}
	return out, nil
}

func dockerInspectOne(cli *http.Client, id string) (*dockerInspect, error) {
	resp, err := cli.Get("http://docker/containers/" + id + "/json")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("inspect status %d", resp.StatusCode)
	}
	var ins dockerInspect
	if err := json.NewDecoder(resp.Body).Decode(&ins); err != nil {
		return nil, err
	}
	return &ins, nil
}

// containerRisks derives the misconfiguration flags that make a container a
// container-escape / lateral-movement risk.
func containerRisks(c *Container, securityOpt []string) []string {
	var s []string
	if c.Privileged {
		s = append(s, "privileged")
	}
	if c.HostNetwork {
		s = append(s, "host-network")
	}
	if c.HostPID {
		s = append(s, "host-pid")
	}
	if c.HostIPC {
		s = append(s, "host-ipc")
	}
	dangerCaps := map[string]bool{"SYS_ADMIN": true, "SYS_PTRACE": true, "SYS_MODULE": true, "DAC_READ_SEARCH": true, "NET_ADMIN": true, "ALL": true}
	for _, cap := range c.CapAdd {
		if dangerCaps[strings.ToUpper(strings.TrimPrefix(strings.ToUpper(cap), "CAP_"))] {
			s = append(s, "cap:"+strings.ToUpper(cap))
		}
	}
	for _, m := range c.Mounts {
		src := strings.ToLower(m.Source)
		if strings.Contains(src, "docker.sock") {
			s = append(s, "docker-socket-mounted")
		}
		switch src {
		case "/", "/etc", "/root", "/proc", "/sys", "/var/run", "/boot":
			s = append(s, "host-sensitive-mount:"+m.Source)
		}
	}
	if c.User == "" || c.User == "root" || c.User == "0" || strings.HasPrefix(c.User, "0:") {
		s = append(s, "runs-as-root")
	}
	for _, o := range securityOpt {
		lo := strings.ToLower(o)
		if strings.Contains(lo, "seccomp=unconfined") || strings.Contains(lo, "apparmor=unconfined") {
			s = append(s, "unconfined")
		}
	}
	if len(c.SecretEnv) > 0 {
		s = append(s, "secret-in-env")
	}
	return s
}

// ── CLI fallbacks (no socket access) ─────────────────────────────────────────

func scanDockerCLI() ([]Container, bool) {
	if _, err := exec.LookPath("docker"); err != nil {
		return nil, false
	}
	out, err := runShort("docker", "ps", "-a", "--no-trunc", "--format", "{{json .}}")
	if err != nil {
		return nil, false
	}
	return parseCLIJSONLines(out, "docker"), true
}

func scanPodmanCLI() ([]Container, bool) {
	if _, err := exec.LookPath("podman"); err != nil {
		return nil, false
	}
	out, err := runShort("podman", "ps", "-a", "--format", "{{json .}}")
	if err != nil {
		return nil, false
	}
	return parseCLIJSONLines(out, "podman"), true
}

// parseCLIJSONLines parses one-JSON-object-per-line output from docker/podman ps.
// Only basic fields are available without inspect; security flags stay empty.
func parseCLIJSONLines(out, runtime string) []Container {
	var res []Container
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var it struct {
			ID, Image, Names, Command, State, Status, Ports string
		}
		if json.Unmarshal([]byte(line), &it) != nil {
			continue
		}
		res = append(res, Container{
			ID: shortID(it.ID), Name: it.Names, Image: it.Image, Command: it.Command,
			State: firstOr([]string{it.State}, it.Status), Status: it.Status, Runtime: runtime,
			Ports: splitNonEmpty(it.Ports, ","),
		})
	}
	return res
}

// ── helpers ──────────────────────────────────────────────────────────────────

func secretEnvNames(env []string) []string {
	var names []string
	markers := []string{"password", "passwd", "secret", "token", "apikey", "api_key", "access_key", "private_key", "credential"}
	for _, e := range env {
		name := e
		if i := strings.IndexByte(e, '='); i >= 0 {
			name = e[:i]
		}
		ln := strings.ToLower(name)
		for _, m := range markers {
			if strings.Contains(ln, m) {
				names = append(names, name) // NAME only — never the value
				break
			}
		}
	}
	return names
}

func runShort(name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, name, args...).Output()
	return string(out), err
}

func shortID(id string) string {
	id = strings.TrimPrefix(id, "sha256:")
	if len(id) > 12 {
		return id[:12]
	}
	return id
}

func firstOr(ss []string, def string) string {
	if len(ss) > 0 && ss[0] != "" {
		return ss[0]
	}
	return def
}

func splitNonEmpty(s, sep string) []string {
	var out []string
	for _, p := range strings.Split(s, sep) {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
