//go:build linux

package parser

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path"
	"sort"
	"strconv"
	"strings"
	"time"
)

// ── tunables ─────────────────────────────────────────────────────────────────

const (
	maxContainers  = 500             // rows returned per scan
	maxChanges     = 200             // filesystem-diff entries kept per container
	maxProcesses   = 100             // in-container processes kept per container
	scanBudget     = 4 * time.Minute // overall wall-clock budget for one scan
	requestTimeout = 15 * time.Second
	enrichTimeout  = 10 * time.Second // best-effort runtime calls (changes/top/image)
	cliTimeout     = 20 * time.Second

	trivyTimeout   = 60 * time.Second // one image scan; far slower than the whole collection
	maxImageScans  = 10               // distinct images scanned per run
	maxTrivyOutput = 8 << 20          // bytes of scanner JSON accepted

	apiBase = "http://docker" // placeholder host; the transport dials a unix socket
)

// ── wire types ───────────────────────────────────────────────────────────────

// ContainerMount is one bind/volume mount into a container.
type ContainerMount struct {
	Source string `json:"source"`
	Dest   string `json:"dest"`
	RW     bool   `json:"rw"`
}

// ContainerDevice is one raw host device exposed into the container.
type ContainerDevice struct {
	Host      string `json:"host"`
	Container string `json:"container"`
	Perms     string `json:"perms"`
}

// ContainerChange is one entry of the container filesystem diff (docker diff).
// Kind is normalized to added | modified | deleted.
type ContainerChange struct {
	Path string `json:"path"`
	Kind string `json:"kind"`
}

// ContainerChangeSummary counts the full diff even when the stored entries are
// capped, so the UI can say "3 added / 900 modified" without the whole list.
type ContainerChangeSummary struct {
	Added     int  `json:"added"`
	Modified  int  `json:"modified"`
	Deleted   int  `json:"deleted"`
	Total     int  `json:"total"`
	Truncated bool `json:"truncated"`
}

// ContainerProcess is one process observed inside the container namespace.
type ContainerProcess struct {
	PID  int    `json:"pid"`
	PPID int    `json:"ppid"`
	User string `json:"user"`
	Cmd  string `json:"cmd"`
}

// ContainerStateDetail carries the lifecycle details needed for a timeline.
type ContainerStateDetail struct {
	ExitCode   int    `json:"exit_code"`
	OOMKilled  bool   `json:"oom_killed"`
	StartedAt  string `json:"started_at"`
	FinishedAt string `json:"finished_at"`
}

// Container is a normalized view of a running/stopped container plus the
// misconfiguration signals that matter for a container-escape / compromise hunt.
// InspectOK is false when only list-level data could be collected (CLI/crictl
// fallbacks, or a failed inspect) — the security fields are then meaningless and
// the UI must not render the row as "clean".
type Container struct {
	ID                  string                 `json:"id"`
	Name                string                 `json:"name"`
	Image               string                 `json:"image"`
	ImageID             string                 `json:"image_id"`     // 12-char short id (kept for the existing UI)
	ImageDigest         string                 `json:"image_digest"` // full sha256:… — the only form that can match an IOC
	ImageRepoDigest     string                 `json:"image_repo_digest"`
	ImageCreated        string                 `json:"image_created"`
	ImageAgeDays        int                    `json:"image_age_days"`    // 0 = unknown, not "fresh"
	ImageVulns          *ImageVulnSummary      `json:"image_vulns"`       // nil unless an image scan actually ran
	ImageScanStatus     string                 `json:"image_scan_status"` // why ImageVulns is nil — never render nil as "clean"
	Command             string                 `json:"command"`
	Entrypoint          []string               `json:"entrypoint"`
	Cmd                 []string               `json:"cmd"`
	State               string                 `json:"state"`
	Status              string                 `json:"status"`
	Runtime             string                 `json:"runtime"` // docker | containerd | podman
	CreatedAt           string                 `json:"created_at"`
	Pid                 int                    `json:"pid"` // host PID of the container init (links to Processes)
	Ports               []string               `json:"ports"`
	Networks            []string               `json:"networks"` // network names (kept as-is for the existing UI)
	IPs                 []string               `json:"ips"`
	NetworkMode         string                 `json:"network_mode"` // raw value: host | bridge | container:<id> | <custom>
	Mounts              []ContainerMount       `json:"mounts"`
	Devices             []ContainerDevice      `json:"devices"`
	Labels              map[string]string      `json:"labels"` // attribution labels only (compose project / k8s pod)
	Privileged          bool                   `json:"privileged"`
	HostPID             bool                   `json:"host_pid"`
	HostNetwork         bool                   `json:"host_network"`
	HostIPC             bool                   `json:"host_ipc"`
	CapAdd              []string               `json:"cap_add"`
	CapDrop             []string               `json:"cap_drop"`
	User                string                 `json:"user"`
	UsernsMode          string                 `json:"userns_mode"`
	AppArmor            string                 `json:"apparmor"`
	Seccomp             string                 `json:"seccomp"`
	ReadonlyRootfs      bool                   `json:"readonly_rootfs"`
	MaskedPathsCount    int                    `json:"masked_paths_count"`
	MaskedPathsDisabled bool                   `json:"masked_paths_disabled"`
	RestartPolicy       string                 `json:"restart_policy"`
	LogPath             string                 `json:"log_path"`
	UpperDir            string                 `json:"upper_dir"` // writable layer on the host — the key forensic path
	StateDetail         ContainerStateDetail   `json:"state_detail"`
	Changes             []ContainerChange      `json:"changes"`
	ChangesSummary      ContainerChangeSummary `json:"changes_summary"`
	Processes           []ContainerProcess     `json:"processes"`
	SecretEnv           []string               `json:"secret_env"` // NAMES only of secret-looking env vars (values never captured)
	Suspicious          []string               `json:"suspicious"`
	EscapePaths         []string               `json:"escape_paths"` // escape preconditions actually present (subset of Suspicious ids)
	InspectOK           bool                   `json:"inspect_ok"`   // false ⇒ security fields unavailable, do not treat as safe
	Truncated           bool                   `json:"truncated"`    // enrichment skipped (scan budget / container cap reached)
}

// ── entry point ──────────────────────────────────────────────────────────────

// ScanContainers enumerates containers on the host. It prefers the Docker Engine
// API over a unix socket (docker, rootless docker, podman's docker-compatible
// socket — no external tool required) and degrades to the docker/podman/crictl
// CLIs. A host with no runtime yields an empty set; a host where a runtime is
// present but unreachable yields an error so the operator does not read a
// permission problem as a clean host.
func ScanContainers() ([]Container, error) {
	return ScanContainersWithOptions(ContainerScanOptions{})
}

// ScanContainersWithOptions is ScanContainers plus the opt-in extras (image
// vulnerability scanning). ScanContainers keeps the parameterless signature the
// edge-scan entry point calls.
func ScanContainersWithOptions(opt ContainerScanOptions) ([]Container, error) {
	ctx, cancel := context.WithTimeout(context.Background(), scanBudget)
	defer cancel()

	vs := newVulnScanner(opt)

	var blocked []string
	for _, ep := range socketCandidates() {
		if _, err := os.Stat(ep.path); err != nil {
			if !os.IsNotExist(err) && isDenied(err) {
				blocked = append(blocked, ep.path+": "+err.Error())
			}
			continue
		}
		cs, err := scanDockerSocket(ctx, ep, vs)
		if err == nil {
			return cs, nil
		}
		log.Printf("[containers] %s socket %s unusable: %v", ep.runtime, ep.path, err)
		if isDenied(err) {
			blocked = append(blocked, ep.path+": "+err.Error())
		}
	}

	for _, scan := range []func(context.Context) ([]Container, string, bool){scanDockerCLI, scanPodmanCLI, scanCrictlCLI} {
		cs, reason, ok := scan(ctx)
		if ok {
			return cs, nil
		}
		if reason != "" {
			blocked = append(blocked, reason)
		}
	}

	if len(blocked) > 0 {
		return nil, fmt.Errorf("container runtime detected but not accessible (%s) - the agent likely needs root or docker-group membership", strings.Join(blocked, "; "))
	}
	// No container runtime detected — return an empty (not error) set so the UI
	// shows "no containers" rather than a failure.
	return []Container{}, nil
}

// ── runtime discovery ────────────────────────────────────────────────────────

// dockerEndpoint is one candidate API socket. Podman exposes a Docker-compatible
// API, so the same HTTP code drives both — only the path differs.
type dockerEndpoint struct {
	path    string
	runtime string
}

// socketCandidates lists the sockets to probe, most specific first: DOCKER_HOST,
// system docker, rootless docker, then podman.
func socketCandidates() []dockerEndpoint {
	var eps []dockerEndpoint
	seen := map[string]bool{}
	add := func(p, rt string) {
		if p == "" || seen[p] {
			return
		}
		seen[p] = true
		eps = append(eps, dockerEndpoint{path: p, runtime: rt})
	}

	if h := strings.TrimSpace(os.Getenv("DOCKER_HOST")); strings.HasPrefix(h, "unix://") {
		add(strings.TrimPrefix(h, "unix://"), "docker")
	}
	add("/var/run/docker.sock", "docker")
	add("/run/docker.sock", "docker")

	xdg := strings.TrimRight(os.Getenv("XDG_RUNTIME_DIR"), "/")
	if xdg != "" {
		add(xdg+"/docker.sock", "docker")
		add(xdg+"/podman/podman.sock", "podman")
	}
	if uid := os.Getuid(); uid > 0 {
		add(fmt.Sprintf("/run/user/%d/docker.sock", uid), "docker")
		add(fmt.Sprintf("/run/user/%d/podman/podman.sock", uid), "podman")
	}
	add("/run/podman/podman.sock", "podman")
	add("/var/run/podman/podman.sock", "podman")
	return eps
}

func dockerSocketClient(sock string) *http.Client {
	return &http.Client{
		Timeout: requestTimeout,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "unix", sock)
			},
		},
	}
}

// isDenied reports whether an error means "the runtime is there but we are not
// allowed to talk to it", as opposed to "there is no runtime".
func isDenied(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, fs.ErrPermission) {
		return true
	}
	le := strings.ToLower(err.Error())
	return strings.Contains(le, "permission denied") ||
		strings.Contains(le, "operation not permitted") ||
		strings.Contains(le, "status 401") ||
		strings.Contains(le, "status 403")
}

// ── Docker Engine API over a unix socket ─────────────────────────────────────

type dockerListItem struct {
	ID      string   `json:"Id"`
	Names   []string `json:"Names"`
	Image   string   `json:"Image"`
	ImageID string   `json:"ImageID"`
	Command string   `json:"Command"`
	Created int64    `json:"Created"`
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
	ID              string `json:"Id"`
	Name            string `json:"Name"`
	Created         string `json:"Created"`
	Image           string `json:"Image"`
	LogPath         string `json:"LogPath"`
	AppArmorProfile string `json:"AppArmorProfile"`
	State           struct {
		Pid        int    `json:"Pid"`
		Running    bool   `json:"Running"`
		Status     string `json:"Status"`
		ExitCode   int    `json:"ExitCode"`
		OOMKilled  bool   `json:"OOMKilled"`
		StartedAt  string `json:"StartedAt"`
		FinishedAt string `json:"FinishedAt"`
	} `json:"State"`
	Config struct {
		User       string            `json:"User"`
		Env        []string          `json:"Env"`
		Entrypoint []string          `json:"Entrypoint"`
		Cmd        []string          `json:"Cmd"`
		Labels     map[string]string `json:"Labels"`
	} `json:"Config"`
	GraphDriver struct {
		Name string `json:"Name"`
		Data struct {
			UpperDir string `json:"UpperDir"`
		} `json:"Data"`
	} `json:"GraphDriver"`
	HostConfig struct {
		Privileged     bool     `json:"Privileged"`
		CapAdd         []string `json:"CapAdd"`
		CapDrop        []string `json:"CapDrop"`
		Binds          []string `json:"Binds"`
		NetworkMode    string   `json:"NetworkMode"`
		PidMode        string   `json:"PidMode"`
		IpcMode        string   `json:"IpcMode"`
		UsernsMode     string   `json:"UsernsMode"`
		SecurityOpt    []string `json:"SecurityOpt"`
		ReadonlyRootfs bool     `json:"ReadonlyRootfs"`
		MaskedPaths    []string `json:"MaskedPaths"`
		RestartPolicy  struct {
			Name string `json:"Name"`
		} `json:"RestartPolicy"`
		Devices []struct {
			PathOnHost        string `json:"PathOnHost"`
			PathInContainer   string `json:"PathInContainer"`
			CgroupPermissions string `json:"CgroupPermissions"`
		} `json:"Devices"`
	} `json:"HostConfig"`
	Mounts []struct {
		Source      string `json:"Source"`
		Destination string `json:"Destination"`
		RW          bool   `json:"RW"`
	} `json:"Mounts"`
	NetworkSettings struct {
		Networks map[string]struct {
			IPAddress         string `json:"IPAddress"`
			GlobalIPv6Address string `json:"GlobalIPv6Address"`
		} `json:"Networks"`
	} `json:"NetworkSettings"`
}

// imageMeta is the per-image provenance, cached so N containers sharing an image
// cost a single API call.
type imageMeta struct {
	RepoDigest string
	Created    string
}

// dockerGetJSON performs one GET against the engine API with its own deadline.
func dockerGetJSON(ctx context.Context, cli *http.Client, endpoint string, timeout time.Duration, out any) error {
	rctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(rctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return err
	}
	resp, err := cli.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("docker api status %d", resp.StatusCode)
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

func scanDockerSocket(ctx context.Context, ep dockerEndpoint, vs *vulnScanner) ([]Container, error) {
	cli := dockerSocketClient(ep.path)
	var list []dockerListItem
	if err := dockerGetJSON(ctx, cli, apiBase+"/containers/json?all=1", requestTimeout, &list); err != nil {
		return nil, err
	}

	if len(list) > maxContainers {
		log.Printf("[containers] %s has %d containers, truncating to %d", ep.path, len(list), maxContainers)
		list = list[:maxContainers]
	}

	images := map[string]imageMeta{}
	out := make([]Container, 0, len(list))
	for _, li := range list {
		c := Container{
			ID:          shortID(li.ID),
			Name:        strings.TrimPrefix(firstOr(li.Names, ""), "/"),
			Image:       li.Image,
			ImageID:     shortID(li.ImageID),
			ImageDigest: li.ImageID,
			Command:     li.Command,
			State:       li.State,
			Status:      li.Status,
			Runtime:     ep.runtime,
			CreatedAt:   unixToRFC3339(li.Created),
		}
		for _, p := range li.Ports {
			if p.PublicPort > 0 {
				c.Ports = append(c.Ports, fmt.Sprintf("%s:%d->%d/%s", firstOr([]string{p.IP}, "0.0.0.0"), p.PublicPort, p.PrivatePort, p.Type))
			}
		}

		// Out of budget: keep the list-level row, flag it, skip the expensive part.
		if ctx.Err() != nil {
			c.Truncated = true
			out = append(out, c)
			continue
		}

		ins, ierr := dockerInspectOne(ctx, cli, li.ID)
		if ierr != nil {
			log.Printf("[containers] inspect %s failed: %v", c.ID, ierr)
			out = append(out, c)
			continue
		}
		applyInspect(&c, ins)

		// Runtime forensics — running containers only, best-effort.
		imageChecked := false
		if ins.State.Running {
			c.Changes, c.ChangesSummary = containerChanges(ctx, cli, li.ID)
			c.Processes = containerProcesses(ctx, cli, li.ID)
			if m, ok := containerImageMeta(ctx, cli, ins.Image, images); ok {
				c.ImageRepoDigest, c.ImageCreated, imageChecked = m.RepoDigest, m.Created, true
			}
		}

		c.SecretEnv = secretEnvNames(ins.Config.Env)
		c.ImageAgeDays = imageAgeDays(c.ImageCreated, time.Now())
		c.ImageVulns, c.ImageScanStatus = vs.scan(ctx, c.ImageDigest, imageScanRef(&c))
		c.Suspicious = containerRisks(&c, ins.HostConfig.SecurityOpt, imageChecked)
		out = append(out, c)
	}
	return out, nil
}

func dockerInspectOne(ctx context.Context, cli *http.Client, id string) (*dockerInspect, error) {
	var ins dockerInspect
	if err := dockerGetJSON(ctx, cli, apiBase+"/containers/"+id+"/json", requestTimeout, &ins); err != nil {
		return nil, err
	}
	return &ins, nil
}

// applyInspect copies the security- and forensics-relevant inspect fields onto
// the normalized container row.
func applyInspect(c *Container, ins *dockerInspect) {
	c.InspectOK = true
	if ins.Created != "" {
		c.CreatedAt = ins.Created
	}
	if ins.Image != "" {
		c.ImageDigest = ins.Image
		if c.ImageID == "" {
			c.ImageID = shortID(ins.Image)
		}
	}
	c.Pid = ins.State.Pid
	c.StateDetail = ContainerStateDetail{
		ExitCode:   ins.State.ExitCode,
		OOMKilled:  ins.State.OOMKilled,
		StartedAt:  ins.State.StartedAt,
		FinishedAt: ins.State.FinishedAt,
	}
	if c.State == "" {
		c.State = ins.State.Status
	}
	c.User = ins.Config.User
	c.Entrypoint = ins.Config.Entrypoint
	c.Cmd = ins.Config.Cmd
	c.Labels = filterLabels(ins.Config.Labels)
	c.LogPath = ins.LogPath
	c.UpperDir = ins.GraphDriver.Data.UpperDir

	c.Privileged = ins.HostConfig.Privileged
	c.NetworkMode = ins.HostConfig.NetworkMode
	c.HostNetwork = ins.HostConfig.NetworkMode == "host"
	c.HostPID = ins.HostConfig.PidMode == "host"
	c.HostIPC = ins.HostConfig.IpcMode == "host"
	c.CapAdd = ins.HostConfig.CapAdd
	c.CapDrop = ins.HostConfig.CapDrop
	c.UsernsMode = ins.HostConfig.UsernsMode
	c.ReadonlyRootfs = ins.HostConfig.ReadonlyRootfs
	c.RestartPolicy = ins.HostConfig.RestartPolicy.Name
	c.MaskedPathsCount = len(ins.HostConfig.MaskedPaths)
	// A privileged container legitimately has no masked paths; podman's compat
	// API may omit the field entirely, so only trust it for docker.
	c.MaskedPathsDisabled = c.Runtime == "docker" && !c.Privileged && c.MaskedPathsCount == 0

	seccomp, apparmorOpt := securityProfiles(ins.HostConfig.SecurityOpt)
	c.Seccomp = seccomp
	c.AppArmor = ins.AppArmorProfile
	if c.AppArmor == "" {
		c.AppArmor = apparmorOpt
	}

	for _, d := range ins.HostConfig.Devices {
		c.Devices = append(c.Devices, ContainerDevice{Host: d.PathOnHost, Container: d.PathInContainer, Perms: d.CgroupPermissions})
	}
	for _, m := range ins.Mounts {
		c.Mounts = append(c.Mounts, ContainerMount{Source: m.Source, Dest: m.Destination, RW: m.RW})
	}
	for name, n := range ins.NetworkSettings.Networks {
		c.Networks = append(c.Networks, name)
		if n.IPAddress != "" {
			c.IPs = append(c.IPs, n.IPAddress)
		}
		if n.GlobalIPv6Address != "" {
			c.IPs = append(c.IPs, n.GlobalIPv6Address)
		}
	}
	// Map iteration is random — sort so repeated scans diff cleanly.
	sort.Strings(c.Networks)
	sort.Strings(c.IPs)
}

// securityProfiles resolves the seccomp / apparmor profile names out of
// HostConfig.SecurityOpt. An inline JSON profile is reported as "custom".
func securityProfiles(opts []string) (seccomp, apparmor string) {
	for _, o := range opts {
		k, v, ok := strings.Cut(o, "=")
		if !ok {
			k, v, ok = strings.Cut(o, ":")
		}
		if !ok {
			if strings.EqualFold(o, "unconfined") {
				seccomp = "unconfined"
			}
			continue
		}
		if strings.HasPrefix(strings.TrimSpace(v), "{") {
			v = "custom"
		}
		switch strings.ToLower(strings.TrimSpace(k)) {
		case "seccomp":
			seccomp = truncStr(v, 128)
		case "apparmor":
			apparmor = truncStr(v, 128)
		}
	}
	if seccomp == "" {
		seccomp = "default"
	}
	return seccomp, apparmor
}

// keepLabelKeys are the labels that attribute a container to a compose project
// or a Kubernetes pod. Everything else is dropped so the payload stays small.
var keepLabelKeys = map[string]bool{
	"com.docker.compose.project":   true,
	"com.docker.compose.service":   true,
	"io.kubernetes.pod.name":       true,
	"io.kubernetes.pod.namespace":  true,
	"io.kubernetes.pod.uid":        true,
	"io.kubernetes.container.name": true,
}

func filterLabels(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := map[string]string{}
	for k, v := range in {
		lk := strings.ToLower(k)
		if keepLabelKeys[lk] || strings.HasPrefix(lk, "annotation.io.kubernetes.container.") {
			out[k] = truncStr(v, 256)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// ── runtime forensics (socket path, running containers only) ─────────────────

// containerChanges fetches the container filesystem diff (the `docker diff`
// API). A huge diff is normal for stateful apps, which is why entries are ranked
// by forensic interest (writes under /tmp, /etc, bin dirs, dropped scripts) and
// capped instead of dumped wholesale; the summary still counts the full set.
func containerChanges(ctx context.Context, cli *http.Client, id string) ([]ContainerChange, ContainerChangeSummary) {
	var raw []struct {
		Path string `json:"Path"`
		Kind int    `json:"Kind"`
	}
	if err := dockerGetJSON(ctx, cli, apiBase+"/containers/"+id+"/changes", enrichTimeout, &raw); err != nil {
		return nil, ContainerChangeSummary{}
	}
	all := make([]ContainerChange, 0, len(raw))
	var sum ContainerChangeSummary
	for _, r := range raw {
		ch := ContainerChange{Path: r.Path, Kind: changeKind(r.Kind)}
		switch ch.Kind {
		case "added":
			sum.Added++
		case "deleted":
			sum.Deleted++
		default:
			sum.Modified++
		}
		all = append(all, ch)
	}
	sum.Total = len(all)
	if len(all) > maxChanges {
		sort.SliceStable(all, func(i, j int) bool { return changeScore(all[i]) > changeScore(all[j]) })
		all = all[:maxChanges]
		sum.Truncated = true
	}
	return all, sum
}

func changeKind(k int) string {
	switch k {
	case 1:
		return "added"
	case 2:
		return "deleted"
	default:
		return "modified"
	}
}

// containerProcesses lists the processes inside the container. This fails on
// stopped/paused containers and on images without a usable ps — both expected,
// so the error is swallowed.
func containerProcesses(ctx context.Context, cli *http.Client, id string) []ContainerProcess {
	var doc struct {
		Titles    []string   `json:"Titles"`
		Processes [][]string `json:"Processes"`
	}
	q := url.Values{"ps_args": {"-eo pid,ppid,user,args"}}
	if err := dockerGetJSON(ctx, cli, apiBase+"/containers/"+id+"/top?"+q.Encode(), enrichTimeout, &doc); err != nil {
		// busybox/distroless images reject the custom ps args — retry with the default.
		if err := dockerGetJSON(ctx, cli, apiBase+"/containers/"+id+"/top", enrichTimeout, &doc); err != nil {
			return nil
		}
	}
	col := func(names ...string) int {
		for i, t := range doc.Titles {
			for _, n := range names {
				if strings.EqualFold(strings.TrimSpace(t), n) {
					return i
				}
			}
		}
		return -1
	}
	pidC, ppidC, userC, cmdC := col("PID"), col("PPID"), col("USER", "UID", "USERNAME"), col("ARGS", "COMMAND", "CMD")
	out := make([]ContainerProcess, 0, len(doc.Processes))
	for _, row := range doc.Processes {
		if len(out) >= maxProcesses {
			break
		}
		at := func(i int) string {
			if i >= 0 && i < len(row) {
				return strings.TrimSpace(row[i])
			}
			return ""
		}
		out = append(out, ContainerProcess{
			PID:  atoiSafe(at(pidC)),
			PPID: atoiSafe(at(ppidC)),
			User: at(userC),
			Cmd:  truncStr(at(cmdC), 512),
		})
	}
	return out
}

// containerImageMeta resolves image provenance, cached per image id.
func containerImageMeta(ctx context.Context, cli *http.Client, imageID string, cache map[string]imageMeta) (imageMeta, bool) {
	if imageID == "" {
		return imageMeta{}, false
	}
	if m, ok := cache[imageID]; ok {
		return m, true
	}
	var doc struct {
		RepoDigests []string `json:"RepoDigests"`
		Created     string   `json:"Created"`
	}
	if err := dockerGetJSON(ctx, cli, apiBase+"/images/"+imageID+"/json", enrichTimeout, &doc); err != nil {
		return imageMeta{}, false
	}
	m := imageMeta{RepoDigest: firstOr(doc.RepoDigests, ""), Created: doc.Created}
	cache[imageID] = m
	return m, true
}

// ── image vulnerability scan (opt-in, Trivy) ─────────────────────────────────

// vulnScanner runs the image scanner at most once per image and caps how many
// images a single run may pay for. It is off unless the caller asks for it or
// the endpoint sets CONTAINER_VULN_SCAN, because a vuln scan is orders of
// magnitude slower than the forensic collection around it.
type vulnScanner struct {
	enabled bool
	present bool // scanner binary found on PATH
	budget  int
	cache   map[string]*ImageVulnSummary
	status  map[string]string
}

func newVulnScanner(opt ContainerScanOptions) *vulnScanner {
	vs := &vulnScanner{
		enabled: opt.ScanImageVulns || vulnScanEnabledByEnv(),
		budget:  opt.MaxImageScans,
		cache:   map[string]*ImageVulnSummary{},
		status:  map[string]string{},
	}
	if vs.budget <= 0 {
		vs.budget = maxImageScans
	}
	if vs.enabled {
		if _, err := exec.LookPath(trivyName); err == nil {
			vs.present = true
		} else {
			log.Printf("[containers] image vuln scan requested but %s is not installed", trivyName)
		}
	}
	return vs
}

// scan returns the summary for an image plus the status that tells the UI why a
// nil summary is nil. key is the image id (so N containers on one image cost one
// scan); ref is what the scanner is pointed at.
func (vs *vulnScanner) scan(ctx context.Context, key, ref string) (*ImageVulnSummary, string) {
	switch {
	case !vs.enabled:
		return nil, imageScanOff
	case !vs.present:
		return nil, imageScanNoScanner
	case ref == "":
		return nil, imageScanFailed
	}
	if key == "" {
		key = ref
	}
	if st, ok := vs.status[key]; ok {
		return vs.cache[key], st
	}
	if vs.budget <= 0 || ctx.Err() != nil {
		return nil, imageScanCapped // not cached: the cap is per run, not per image
	}
	vs.budget--

	raw, err := runTrivy(ctx, ref)
	if err == nil {
		var sum *ImageVulnSummary
		if sum, err = parseTrivyReport(raw, time.Now()); err == nil {
			vs.cache[key], vs.status[key] = sum, imageScanOK
			return sum, imageScanOK
		}
	}
	log.Printf("[containers] %s scan of %s failed: %v", trivyName, ref, err)
	vs.status[key] = imageScanFailed
	return nil, imageScanFailed
}

// imageScanRef picks what to hand the scanner: the repo:tag the container was
// started from, falling back to the digest when the tag is gone (dangling image).
func imageScanRef(c *Container) string {
	if img := strings.TrimSpace(c.Image); img != "" && img != "<none>" && img != "<none>:<none>" {
		return img
	}
	return c.ImageDigest
}

func runTrivy(ctx context.Context, ref string) ([]byte, error) {
	tctx, cancel := context.WithTimeout(ctx, trivyTimeout)
	defer cancel()
	stdout := &boundedWriter{max: maxTrivyOutput}
	var stderr bytes.Buffer
	cmd := exec.CommandContext(tctx, trivyName, "image", "--quiet", "--format", "json",
		"--severity", "HIGH,CRITICAL", "--scanners", "vuln", ref)
	cmd.Stdout = stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("%v: %s", err, truncStr(collapseSpaces(stderr.String()), 200))
	}
	if stdout.overflow {
		return nil, fmt.Errorf("report exceeded %d bytes", maxTrivyOutput)
	}
	return stdout.buf.Bytes(), nil
}

// boundedWriter discards everything past a byte cap so a pathological scanner
// report cannot balloon the agent's memory.
type boundedWriter struct {
	buf      bytes.Buffer
	max      int
	overflow bool
}

func (w *boundedWriter) Write(p []byte) (int, error) {
	if room := w.max - w.buf.Len(); room < len(p) {
		w.overflow = true
		if room > 0 {
			w.buf.Write(p[:room])
		}
		return len(p), nil
	}
	return w.buf.Write(p)
}

// ── risk scoring ─────────────────────────────────────────────────────────────

// dangerCaps are the capabilities that turn a container into an escape primitive.
var dangerCaps = map[string]bool{
	"SYS_ADMIN": true, "SYS_PTRACE": true, "SYS_MODULE": true, "SYS_RAWIO": true,
	"SYS_BOOT": true, "DAC_READ_SEARCH": true, "DAC_OVERRIDE": true, "NET_ADMIN": true,
	"BPF": true, "PERFMON": true, "ALL": true,
}

// sensitiveHostPaths are host paths whose exposure into a container is an escape
// or credential-theft primitive. Matching is by subpath, so /etc/shadow and
// /root/.ssh are caught as well as /etc and /root.
var sensitiveHostPaths = []string{
	"/etc", "/root", "/proc", "/sys", "/boot", "/run", "/var/run",
	"/var/lib/docker", "/var/lib/containers", "/dev", "/home", "/var/log",
}

// benignMountPrefixes are runtime-managed paths (named volumes, image layers)
// that legitimately live under a sensitive prefix.
var benignMountPrefixes = []string{
	"/var/lib/docker/volumes/", "/var/lib/docker/overlay2/", "/var/lib/docker/containers/",
	"/var/lib/containers/storage/volumes/", "/var/lib/containers/storage/overlay/",
}

// benignDevNodes are the /dev entries compose files routinely map; on their own
// they are not an escape primitive.
var benignDevNodes = map[string]bool{
	"/dev/null": true, "/dev/zero": true, "/dev/random": true, "/dev/urandom": true,
	"/dev/shm": true, "/dev/fuse": true, "/dev/console": true, "/dev/tty": true, "/dev/log": true,
}

// sensitiveHostPath returns the sensitive prefix a mount source falls under, or
// "" when the mount is uninteresting.
func sensitiveHostPath(src string) string {
	if src == "" {
		return ""
	}
	if src == "/" {
		return "/"
	}
	if benignDevNodes[src] {
		return ""
	}
	for _, b := range benignMountPrefixes {
		if strings.HasPrefix(src, b) {
			return ""
		}
	}
	for _, p := range sensitiveHostPaths {
		if src == p || strings.HasPrefix(src, p+"/") {
			return p
		}
	}
	return ""
}

// containerRisks derives the misconfiguration flags that make a container a
// container-escape / lateral-movement / persistence risk. Ids are stable and
// machine-readable; escape-class risks are emitted first and the noisier
// low-severity signals (runs-as-root, secret-in-env) last, so a UI can rank by
// position. Risks are de-duplicated. It also fills c.EscapePaths, the subset of
// the escape preconditions the container actually meets.
func containerRisks(c *Container, securityOpt []string, imageChecked bool) []string {
	var s []string
	seen := map[string]bool{}
	add := func(id string) {
		if id == "" || seen[id] {
			return
		}
		seen[id] = true
		s = append(s, id)
	}

	// ── escape class ─────────────────────────────────────────────────────────
	if c.Privileged {
		add("privileged")
		// --privileged leaves CapAdd empty yet grants the full capability set,
		// so surface the effective-capability risk explicitly.
		add("cap:ALL")
	}
	if c.HostNetwork {
		add("host-network")
	}
	if c.HostPID {
		add("host-pid")
	}
	if c.HostIPC {
		add("host-ipc")
	}
	if !c.Privileged {
		// CapDrop=ALL removes the default set, so only explicitly added caps can
		// still be dangerous — a drop-all container that adds back only benign
		// caps (NET_BIND_SERVICE …) emits no capability risk at all.
		for _, cp := range c.CapAdd {
			if u := normCap(cp); dangerCaps[u] {
				add("cap:" + u)
			}
		}
	}
	for _, m := range c.Mounts {
		src := strings.ToLower(strings.TrimRight(m.Source, "/"))
		if src == "" {
			src = "/"
		}
		if isRuntimeSocketMount(src) {
			add("docker-socket-mounted")
			continue
		}
		if sensitiveHostPath(src) != "" {
			add("host-sensitive-mount:" + m.Source)
		}
	}
	for _, d := range c.Devices {
		hp := strings.ToLower(d.Host)
		if strings.HasPrefix(hp, "/dev/") && !benignDevNodes[hp] {
			add("device-passthrough")
		}
	}
	if strings.EqualFold(c.UsernsMode, "host") {
		add("userns-host")
	}
	if strings.HasPrefix(strings.ToLower(c.NetworkMode), "container:") {
		add("net-container-share")
	}
	if c.MaskedPathsDisabled {
		add("masked-paths-disabled")
	}
	for _, o := range securityOpt {
		lo := strings.ToLower(o)
		if strings.Contains(lo, "seccomp=unconfined") || strings.Contains(lo, "apparmor=unconfined") {
			add("unconfined")
		}
	}
	if strings.EqualFold(c.Seccomp, "unconfined") || strings.EqualFold(c.AppArmor, "unconfined") {
		add("unconfined")
	}

	// ── escape paths ─────────────────────────────────────────────────────────
	// The preconditions are also recorded on the container so the UI can render
	// the escape list without re-deriving it from the id strings.
	c.EscapePaths = escapePreconditions(c)
	for _, p := range c.EscapePaths {
		// A mounted runtime socket is already reported as docker-socket-mounted;
		// it stays an escape path but must not be flagged twice.
		if p == escapeDockerSock {
			continue
		}
		add(p)
	}
	for _, id := range escapeAttemptEvidence(c) {
		add(id)
	}

	// ── persistence / provenance ─────────────────────────────────────────────
	switch strings.ToLower(c.RestartPolicy) {
	case "always", "unless-stopped":
		add("restart-always")
	}
	if imageChecked && c.ImageRepoDigest == "" {
		add("image-no-repo-digest")
	}
	if c.ImageAgeDays > imageStaleDays {
		add("image-stale")
	}
	for _, ch := range c.Changes {
		if ch.Kind == "added" && suspiciousDrift(ch.Path) {
			add("drift-suspicious-write")
			break
		}
	}

	// ── low severity (common by default, kept for context) ───────────────────
	if c.User == "" || c.User == "root" || c.User == "0" || strings.HasPrefix(c.User, "0:") {
		add("runs-as-root")
	}
	if len(c.SecretEnv) > 0 {
		add("secret-in-env")
	}
	return s
}

// ── filesystem-drift ranking ─────────────────────────────────────────────────

// driftSensitiveDirs are the directories where a runtime write is worth an
// analyst's attention.
var driftSensitiveDirs = []string{
	"/tmp", "/var/tmp", "/dev/shm", "/etc", "/root", "/home",
	"/bin", "/sbin", "/usr/bin", "/usr/sbin", "/usr/local/bin", "/usr/local/sbin",
}

var scriptExts = map[string]bool{
	".sh": true, ".bash": true, ".py": true, ".pl": true, ".php": true,
	".rb": true, ".elf": true, ".so": true, ".bin": true,
}

// driftDirMatch reports whether a path is under a sensitive directory, and
// whether it *is* that directory (docker diff also lists parent dirs).
func driftDirMatch(p string) (hit, exact bool) {
	for _, d := range driftSensitiveDirs {
		if p == d {
			return true, true
		}
		if strings.HasPrefix(p, d+"/") {
			return true, false
		}
	}
	return false, false
}

// executableLooking reports whether a path looks like a dropped tool: a script
// or binary extension, or an extension-less file inside a bin directory.
func executableLooking(p string) bool {
	base := path.Base(p)
	ext := strings.ToLower(path.Ext(base))
	if scriptExts[ext] {
		return true
	}
	return ext == "" && (strings.Contains(p, "/bin/") || strings.Contains(p, "/sbin/"))
}

// suspiciousDrift marks an added path that looks like a dropped tool in a system
// or temp directory.
func suspiciousDrift(p string) bool {
	hit, exact := driftDirMatch(p)
	return hit && !exact && executableLooking(p)
}

// changeScore ranks a diff entry; higher scores survive the cap.
func changeScore(ch ContainerChange) int {
	hit, exact := driftDirMatch(ch.Path)
	if exact {
		return 0 // the directory itself, not its contents
	}
	exe := executableLooking(ch.Path)
	switch {
	case ch.Kind == "added" && hit && exe:
		return 4
	case ch.Kind == "added" && (hit || exe):
		return 3
	case ch.Kind == "modified" && hit:
		return 2
	case ch.Kind == "deleted" && hit:
		return 1
	}
	return 0
}

// ── CLI fallbacks (no socket access) ─────────────────────────────────────────

func scanDockerCLI(ctx context.Context) ([]Container, string, bool) {
	if _, err := exec.LookPath("docker"); err != nil {
		return nil, "", false
	}
	out, errOut, err := runShort(ctx, "docker", "ps", "-a", "--no-trunc", "--format", "{{json .}}")
	if err != nil {
		return nil, cliBlockedReason("docker", errOut, err), false
	}
	return parseCLIJSONLines(out, "docker"), "", true
}

func scanPodmanCLI(ctx context.Context) ([]Container, string, bool) {
	if _, err := exec.LookPath("podman"); err != nil {
		return nil, "", false
	}
	out, errOut, err := runShort(ctx, "podman", "ps", "-a", "--format", "{{json .}}")
	if err != nil {
		return nil, cliBlockedReason("podman", errOut, err), false
	}
	return parseCLIJSONLines(out, "podman"), "", true
}

// scanCrictlCLI covers Kubernetes nodes that run containerd/CRI-O without Docker.
func scanCrictlCLI(ctx context.Context) ([]Container, string, bool) {
	if _, err := exec.LookPath("crictl"); err != nil {
		return nil, "", false
	}
	out, errOut, err := runShort(ctx, "crictl", "ps", "-a", "-o", "json")
	if err != nil {
		return nil, cliBlockedReason("crictl", errOut, err), false
	}
	var doc struct {
		Containers []struct {
			ID           string `json:"id"`
			PodSandboxID string `json:"podSandboxId"`
			CreatedAt    string `json:"createdAt"`
			State        string `json:"state"`
			ImageRef     string `json:"imageRef"`
			Metadata     struct {
				Name string `json:"name"`
			} `json:"metadata"`
			Image struct {
				Image string `json:"image"`
			} `json:"image"`
			Labels      map[string]string `json:"labels"`
			Annotations map[string]string `json:"annotations"`
		} `json:"containers"`
	}
	if json.Unmarshal([]byte(out), &doc) != nil {
		return nil, "", false
	}
	res := make([]Container, 0, len(doc.Containers))
	for i, it := range doc.Containers {
		if i >= maxContainers {
			log.Printf("[containers] crictl returned %d containers, truncating to %d", len(doc.Containers), maxContainers)
			break
		}
		labels := filterLabels(it.Labels)
		if labels == nil {
			labels = filterLabels(it.Annotations)
		}
		res = append(res, Container{
			ID:          shortID(it.ID),
			Name:        it.Metadata.Name,
			Image:       it.Image.Image,
			ImageID:     shortID(it.ImageRef),
			ImageDigest: it.ImageRef,
			State:       strings.ToLower(strings.TrimPrefix(it.State, "CONTAINER_")),
			Status:      it.State,
			Runtime:     "containerd",
			CreatedAt:   it.CreatedAt,
			Labels:      labels,
			Networks:    splitNonEmpty(it.PodSandboxID, ","),
		})
	}
	return res, "", true
}

// cliBlockedReason returns a non-empty reason when a CLI failure means the
// runtime is present but unreachable (rather than simply absent).
func cliBlockedReason(tool, stderr string, err error) string {
	le := strings.ToLower(stderr + " " + err.Error())
	switch {
	case strings.Contains(le, "permission denied"),
		strings.Contains(le, "cannot connect to the docker daemon"),
		strings.Contains(le, "dial unix"),
		strings.Contains(le, "connect: connection refused"):
		return tool + ": " + truncStr(strings.TrimSpace(collapseSpaces(stderr)), 200)
	}
	return ""
}

// flexString decodes a value that may be a plain string (docker) or an array of
// strings (podman emits Names/Command as arrays).
type flexString string

func (f *flexString) UnmarshalJSON(b []byte) error {
	var s string
	if json.Unmarshal(b, &s) == nil {
		*f = flexString(s)
		return nil
	}
	var ss []string
	if json.Unmarshal(b, &ss) == nil {
		*f = flexString(strings.Join(ss, " "))
		return nil
	}
	*f = ""
	return nil // never fail the whole line over one odd field
}

// flexStrings decodes a comma-separated string or an array of strings.
type flexStrings []string

func (f *flexStrings) UnmarshalJSON(b []byte) error {
	var ss []string
	if json.Unmarshal(b, &ss) == nil {
		*f = ss
		return nil
	}
	var s string
	if json.Unmarshal(b, &s) == nil {
		*f = splitNonEmpty(s, ",")
		return nil
	}
	*f = nil
	return nil
}

// flexPorts decodes docker's "0.0.0.0:80->80/tcp" display string and podman's
// array-of-objects port form into one display list.
type flexPorts []string

func (f *flexPorts) UnmarshalJSON(b []byte) error {
	var s string
	if json.Unmarshal(b, &s) == nil {
		*f = splitNonEmpty(s, ",")
		return nil
	}
	var objs []struct {
		HostIP        string `json:"host_ip"`
		HostPort      any    `json:"host_port"`
		ContainerPort any    `json:"container_port"`
		Protocol      string `json:"protocol"`
	}
	if json.Unmarshal(b, &objs) == nil {
		var out []string
		for _, p := range objs {
			ip, proto := p.HostIP, p.Protocol
			if ip == "" {
				ip = "0.0.0.0"
			}
			if proto == "" {
				proto = "tcp"
			}
			out = append(out, fmt.Sprintf("%s:%s->%s/%s", ip, numToStr(p.HostPort), numToStr(p.ContainerPort), proto))
		}
		*f = out
		return nil
	}
	var ss []string
	if json.Unmarshal(b, &ss) == nil {
		*f = ss
		return nil
	}
	*f = nil
	return nil
}

// parseCLIJSONLines parses one-JSON-object-per-line output from docker/podman ps.
// The two runtimes disagree on the shape of several fields (podman emits Names,
// Command, Networks and Ports as arrays), hence the flex* decoders. Only basic
// fields are available without inspect, so InspectOK stays false and the
// security flags stay empty rather than reading as "clean".
func parseCLIJSONLines(out, runtime string) []Container {
	var res []Container
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var it struct {
			ID        string      `json:"ID"`
			Image     string      `json:"Image"`
			Names     flexStrings `json:"Names"`
			Command   flexString  `json:"Command"`
			State     flexString  `json:"State"`
			Status    flexString  `json:"Status"`
			CreatedAt flexString  `json:"CreatedAt"`
			Ports     flexPorts   `json:"Ports"`
			Networks  flexStrings `json:"Networks"`
		}
		if json.Unmarshal([]byte(line), &it) != nil {
			continue
		}
		if len(res) >= maxContainers {
			log.Printf("[containers] %s ps returned more than %d containers, truncating", runtime, maxContainers)
			break
		}
		res = append(res, Container{
			ID:        shortID(it.ID),
			Name:      strings.TrimPrefix(firstOr(it.Names, ""), "/"),
			Image:     it.Image,
			Command:   string(it.Command),
			State:     firstOr([]string{string(it.State)}, string(it.Status)),
			Status:    string(it.Status),
			Runtime:   runtime,
			CreatedAt: string(it.CreatedAt),
			Ports:     it.Ports,
			Networks:  it.Networks,
		})
	}
	return res
}

// ── helpers ──────────────────────────────────────────────────────────────────

// secretSubstrings match anywhere in an env var name.
var secretSubstrings = []string{
	"password", "passwd", "secret", "token", "apikey", "api_key", "access_key",
	"private_key", "credential", "jwt", "client_secret", "webhook",
	"database_url", "db_uri", "session_key", "signing",
}

// secretWords are short and FP-prone, so they must appear as a delimited word
// (AUTH_TOKEN yes, AUTHORITY no).
var secretWords = []string{"pwd", "auth", "dsn"}

// secretEnvSkip are names that trip the word matcher but never hold a secret.
var secretEnvSkip = map[string]bool{"pwd": true, "oldpwd": true}

// secretEnvNames returns the NAMES of env vars that look like they hold a
// credential. Values are never captured.
func secretEnvNames(env []string) []string {
	var names []string
	for _, e := range env {
		name := e
		if i := strings.IndexByte(e, '='); i >= 0 {
			name = e[:i]
		}
		ln := strings.ToLower(name)
		if ln == "" || secretEnvSkip[ln] {
			continue
		}
		hit := false
		for _, m := range secretSubstrings {
			if strings.Contains(ln, m) {
				hit = true
				break
			}
		}
		if !hit {
			for _, w := range secretWords {
				if containsWord(ln, w) {
					hit = true
					break
				}
			}
		}
		if hit {
			names = append(names, name) // NAME only — never the value
		}
	}
	return names
}

// containsWord reports whether w appears in s delimited by _, -, . or a boundary.
func containsWord(s, w string) bool {
	isBoundary := func(b byte) bool { return b == '_' || b == '-' || b == '.' }
	for i := 0; i+len(w) <= len(s); i++ {
		if s[i:i+len(w)] != w {
			continue
		}
		if i > 0 && !isBoundary(s[i-1]) {
			continue
		}
		if j := i + len(w); j < len(s) && !isBoundary(s[j]) {
			continue
		}
		return true
	}
	return false
}

// runShort runs a short-lived CLI and returns stdout and stderr separately;
// stderr is what tells us "permission denied" vs "no such runtime".
func runShort(ctx context.Context, name string, args ...string) (string, string, error) {
	ctx, cancel := context.WithTimeout(ctx, cliTimeout)
	defer cancel()
	var stdout, stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	return stdout.String(), stderr.String(), err
}

func shortID(id string) string {
	id = strings.TrimPrefix(id, "sha256:")
	if i := strings.Index(id, "@sha256:"); i >= 0 {
		id = id[i+len("@sha256:"):]
	}
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

func atoiSafe(s string) int {
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil {
		return 0
	}
	return n
}

func numToStr(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case float64:
		return strconv.FormatInt(int64(t), 10)
	}
	return ""
}

func unixToRFC3339(sec int64) string {
	if sec <= 0 {
		return ""
	}
	return time.Unix(sec, 0).UTC().Format(time.RFC3339)
}
