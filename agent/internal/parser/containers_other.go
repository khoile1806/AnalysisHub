//go:build !linux

package parser

import "fmt"

// ContainerMount / Container mirror the Linux types so the rest of the agent
// compiles on every platform; the scan itself is Linux-only for now.
type ContainerMount struct {
	Source string `json:"source"`
	Dest   string `json:"dest"`
	RW     bool   `json:"rw"`
}

type Container struct {
	ID          string           `json:"id"`
	Name        string           `json:"name"`
	Image       string           `json:"image"`
	ImageID     string           `json:"image_id"`
	Command     string           `json:"command"`
	State       string           `json:"state"`
	Status      string           `json:"status"`
	Runtime     string           `json:"runtime"`
	CreatedAt   string           `json:"created_at"`
	Pid         int              `json:"pid"`
	Ports       []string         `json:"ports"`
	Networks    []string         `json:"networks"`
	Mounts      []ContainerMount `json:"mounts"`
	Privileged  bool             `json:"privileged"`
	HostPID     bool             `json:"host_pid"`
	HostNetwork bool             `json:"host_network"`
	HostIPC     bool             `json:"host_ipc"`
	CapAdd      []string         `json:"cap_add"`
	User        string           `json:"user"`
	SecretEnv   []string         `json:"secret_env"`
	Suspicious  []string         `json:"suspicious"`
}

// ScanContainers is Linux-only (Docker/containerd/podman). On other platforms it
// reports that clearly rather than returning misleading empty data.
func ScanContainers() ([]Container, error) {
	return nil, fmt.Errorf("container forensics is only supported on Linux agents")
}
