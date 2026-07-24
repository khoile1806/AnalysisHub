//go:build !linux

package parser

import "fmt"

// The container types mirror the Linux ones so the rest of the agent compiles on
// every platform; the scan itself is Linux-only for now.

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
type ContainerChange struct {
	Path string `json:"path"`
	Kind string `json:"kind"`
}

// ContainerChangeSummary counts the full diff even when stored entries are capped.
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

type Container struct {
	ID                  string                 `json:"id"`
	Name                string                 `json:"name"`
	Image               string                 `json:"image"`
	ImageID             string                 `json:"image_id"`
	ImageDigest         string                 `json:"image_digest"`
	ImageRepoDigest     string                 `json:"image_repo_digest"`
	ImageCreated        string                 `json:"image_created"`
	ImageAgeDays        int                    `json:"image_age_days"`
	ImageVulns          *ImageVulnSummary      `json:"image_vulns"`
	ImageScanStatus     string                 `json:"image_scan_status"`
	Command             string                 `json:"command"`
	Entrypoint          []string               `json:"entrypoint"`
	Cmd                 []string               `json:"cmd"`
	State               string                 `json:"state"`
	Status              string                 `json:"status"`
	Runtime             string                 `json:"runtime"`
	CreatedAt           string                 `json:"created_at"`
	Pid                 int                    `json:"pid"`
	Ports               []string               `json:"ports"`
	Networks            []string               `json:"networks"`
	IPs                 []string               `json:"ips"`
	NetworkMode         string                 `json:"network_mode"`
	Mounts              []ContainerMount       `json:"mounts"`
	Devices             []ContainerDevice      `json:"devices"`
	Labels              map[string]string      `json:"labels"`
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
	UpperDir            string                 `json:"upper_dir"`
	StateDetail         ContainerStateDetail   `json:"state_detail"`
	Changes             []ContainerChange      `json:"changes"`
	ChangesSummary      ContainerChangeSummary `json:"changes_summary"`
	Processes           []ContainerProcess     `json:"processes"`
	SecretEnv           []string               `json:"secret_env"`
	Suspicious          []string               `json:"suspicious"`
	EscapePaths         []string               `json:"escape_paths"`
	InspectOK           bool                   `json:"inspect_ok"`
	Truncated           bool                   `json:"truncated"`
}

// ScanContainers is Linux-only (Docker/containerd/podman). On other platforms it
// reports that clearly rather than returning misleading empty data.
func ScanContainers() ([]Container, error) {
	return ScanContainersWithOptions(ContainerScanOptions{})
}

// ScanContainersWithOptions mirrors the Linux entry point.
func ScanContainersWithOptions(ContainerScanOptions) ([]Container, error) {
	return nil, fmt.Errorf("container forensics is only supported on Linux agents")
}
