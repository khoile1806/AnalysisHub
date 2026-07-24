package parser

import (
	"strings"
	"testing"
	"time"
)

// hardened is the baseline the precondition tests mutate: a normal application
// container that must never produce an escape id.
func hardened() *Container {
	return &Container{
		ID:        "abc123",
		Name:      "web",
		InspectOK: true,
		User:      "1000",
		CapDrop:   []string{"ALL"},
		CapAdd:    []string{"NET_BIND_SERVICE"},
		Mounts: []ContainerMount{
			{Source: "/var/lib/docker/volumes/app-data/_data", Dest: "/data", RW: true},
			{Source: "/etc/app/config.yml", Dest: "/etc/app/config.yml", RW: false},
		},
		Devices: []ContainerDevice{{Host: "/dev/null", Container: "/dev/null", Perms: "rwm"}},
	}
}

func hasID(ids []string, want string) bool {
	for _, id := range ids {
		if id == want {
			return true
		}
	}
	return false
}

func TestEscapePreconditionsHardened(t *testing.T) {
	if got := escapePreconditions(hardened()); len(got) != 0 {
		t.Fatalf("hardened container produced escape paths: %v", got)
	}
	// A container that could not be inspected has no config to judge.
	c := hardened()
	c.InspectOK = false
	c.Privileged = true
	if got := escapePreconditions(c); len(got) != 0 {
		t.Fatalf("uninspected container produced escape paths: %v", got)
	}
}

func TestEscapePreconditions(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*Container)
		want    []string
		notWant []string
	}{
		{
			name: "docker socket mount",
			mutate: func(c *Container) {
				c.Mounts = append(c.Mounts, ContainerMount{Source: "/var/run/docker.sock", Dest: "/var/run/docker.sock", RW: true})
			},
			want: []string{escapeDockerSock},
		},
		{
			name: "cgroup rw plus sys_admin",
			mutate: func(c *Container) {
				c.CapAdd = []string{"SYS_ADMIN"}
				c.Mounts = append(c.Mounts, ContainerMount{Source: "/sys/fs/cgroup", Dest: "/sys/fs/cgroup", RW: true})
			},
			want: []string{escapeCgroupRelease},
		},
		{
			name: "cgroup rw without sys_admin",
			mutate: func(c *Container) {
				c.Mounts = append(c.Mounts, ContainerMount{Source: "/sys/fs/cgroup", Dest: "/sys/fs/cgroup", RW: true})
			},
			notWant: []string{escapeCgroupRelease},
		},
		{
			name: "cgroup read-only with sys_admin",
			mutate: func(c *Container) {
				c.CapAdd = []string{"CAP_SYS_ADMIN"}
				c.Mounts = append(c.Mounts, ContainerMount{Source: "/sys/fs/cgroup", Dest: "/sys/fs/cgroup", RW: false})
			},
			notWant: []string{escapeCgroupRelease},
		},
		{
			name: "privileged plus cgroup v1 subsystem",
			mutate: func(c *Container) {
				c.Privileged = true
				c.Mounts = append(c.Mounts, ContainerMount{Source: "/sys/fs/cgroup/rdma", Dest: "/sys/fs/cgroup/rdma", RW: true})
			},
			want: []string{escapeCgroupRelease},
		},
		{
			name: "host root mounted rw",
			mutate: func(c *Container) {
				c.Mounts = append(c.Mounts, ContainerMount{Source: "/", Dest: "/host", RW: true})
			},
			want: []string{escapeHostRootMount, escapeCorePattern},
		},
		{
			name: "host root mounted ro",
			mutate: func(c *Container) {
				c.Mounts = append(c.Mounts, ContainerMount{Source: "/", Dest: "/host", RW: false})
			},
			notWant: []string{escapeHostRootMount, escapeCorePattern},
		},
		{
			name: "proc sys writable",
			mutate: func(c *Container) {
				c.Mounts = append(c.Mounts, ContainerMount{Source: "/proc/sys", Dest: "/proc/sys", RW: true})
			},
			want:    []string{escapeProcWritable, escapeCorePattern},
			notWant: []string{escapeHostRootMount},
		},
		{
			name: "proc mounted read-only",
			mutate: func(c *Container) {
				c.Mounts = append(c.Mounts, ContainerMount{Source: "/proc", Dest: "/host/proc", RW: false})
			},
			notWant: []string{escapeProcWritable, escapeCorePattern},
		},
		{
			name:   "sys_module added",
			mutate: func(c *Container) { c.CapAdd = []string{"SYS_MODULE"} },
			want:   []string{escapeKernelModule},
		},
		{
			name: "sys_module added then dropped",
			mutate: func(c *Container) {
				c.CapAdd = []string{"SYS_MODULE"}
				c.CapDrop = []string{"SYS_MODULE"}
			},
			notWant: []string{escapeKernelModule},
		},
		{
			name:    "ptrace without host pid",
			mutate:  func(c *Container) { c.CapAdd = []string{"SYS_PTRACE"} },
			notWant: []string{escapePtrace},
		},
		{
			name:    "host pid without ptrace",
			mutate:  func(c *Container) { c.HostPID = true },
			notWant: []string{escapePtrace},
		},
		{
			name: "ptrace with host pid",
			mutate: func(c *Container) {
				c.HostPID = true
				c.CapAdd = []string{"SYS_PTRACE"}
			},
			want: []string{escapePtrace},
		},
		{
			name:   "dac_read_search added",
			mutate: func(c *Container) { c.CapAdd = []string{"DAC_READ_SEARCH"} },
			want:   []string{escapeDacReadSearch},
		},
		{
			name:    "dac_override only",
			mutate:  func(c *Container) { c.CapAdd = []string{"DAC_OVERRIDE"} },
			notWant: []string{escapeDacReadSearch},
		},
		{
			name: "host disk device",
			mutate: func(c *Container) {
				c.Devices = append(c.Devices, ContainerDevice{Host: "/dev/sda1", Container: "/dev/sda1", Perms: "rwm"})
			},
			want: []string{escapeHostDisk},
		},
		{
			name: "device mapper device",
			mutate: func(c *Container) {
				c.Devices = append(c.Devices, ContainerDevice{Host: "/dev/mapper/vg0-root", Container: "/dev/xvda", Perms: "r"})
			},
			want: []string{escapeHostDisk},
		},
		{
			name: "benign device passthrough",
			mutate: func(c *Container) {
				c.Devices = append(c.Devices,
					ContainerDevice{Host: "/dev/fuse", Container: "/dev/fuse", Perms: "rwm"},
					ContainerDevice{Host: "/dev/snd", Container: "/dev/snd", Perms: "rwm"})
			},
			notWant: []string{escapeHostDisk},
		},
		{
			name: "privileged expands to the full capability set",
			mutate: func(c *Container) {
				c.Privileged = true
				c.CapAdd = nil
			},
			want:    []string{escapeKernelModule, escapeDacReadSearch},
			notWant: []string{escapePtrace, escapeHostRootMount},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := hardened()
			tt.mutate(c)
			got := escapePreconditions(c)
			for _, w := range tt.want {
				if !hasID(got, w) {
					t.Errorf("missing %s in %v", w, got)
				}
			}
			for _, n := range tt.notWant {
				if hasID(got, n) {
					t.Errorf("unexpected %s in %v", n, got)
				}
			}
		})
	}
}

func TestEscapeAttemptEvidence(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*Container)
		want    []string
		notWant []string
	}{
		{
			name: "escape tooling dropped in tmp",
			mutate: func(c *Container) {
				c.Changes = []ContainerChange{
					{Path: "/tmp", Kind: "modified"},
					{Path: "/tmp/linpeas.sh", Kind: "added"},
				}
			},
			want: []string{escapeSuspiciousTool},
		},
		{
			name: "arch suffixed tooling",
			mutate: func(c *Container) {
				c.Changes = []ContainerChange{{Path: "/root/pspy64", Kind: "added"}}
			},
			want: []string{escapeSuspiciousTool},
		},
		{
			name: "tooling only modified, not dropped",
			mutate: func(c *Container) {
				c.Changes = []ContainerChange{{Path: "/usr/bin/nsenter", Kind: "modified"}}
			},
			notWant: []string{escapeSuspiciousTool},
		},
		{
			name: "aws cdk from an npm install",
			mutate: func(c *Container) {
				c.Changes = []ContainerChange{{Path: "/app/node_modules/.bin/cdk", Kind: "added"}}
			},
			notWant: []string{escapeSuspiciousTool},
		},
		{
			name: "ordinary script write",
			mutate: func(c *Container) {
				c.Changes = []ContainerChange{
					{Path: "/tmp/entrypoint.sh", Kind: "added"},
					{Path: "/var/log/nsenterprise.log", Kind: "added"},
				}
			},
			notWant: []string{escapeSuspiciousTool},
		},
		{
			name: "nsenter into the host namespaces",
			mutate: func(c *Container) {
				c.Processes = []ContainerProcess{{PID: 12, Cmd: "nsenter -t 1 -m -u -i -n -p -- /bin/bash"}}
			},
			want: []string{escapeHostNSTool},
		},
		{
			name: "docker client inside the container",
			mutate: func(c *Container) {
				c.Processes = []ContainerProcess{{PID: 20, Cmd: "/usr/bin/docker run -v /:/host alpine"}}
			},
			want: []string{escapeHostNSTool},
		},
		{
			name: "dockerd is not a docker client",
			mutate: func(c *Container) {
				c.Processes = []ContainerProcess{
					{PID: 1, Cmd: "/usr/bin/dockerd --host=unix:///var/run/docker.sock"},
					{PID: 2, Cmd: "/usr/bin/docker-proxy -proto tcp -host-port 80"},
					{PID: 3, Cmd: "tail -f /var/log/docker.log"},
				}
			},
			notWant: []string{escapeHostNSTool},
		},
		{
			name: "unshare mount namespace",
			mutate: func(c *Container) {
				c.Processes = []ContainerProcess{{PID: 30, Cmd: "unshare --mount --fork /bin/sh"}}
			},
			want: []string{escapeHostNSTool},
		},
		{
			name: "unshare without the mount namespace",
			mutate: func(c *Container) {
				c.Processes = []ContainerProcess{{PID: 31, Cmd: "unshare --user --pid /bin/sh"}}
			},
			notWant: []string{escapeHostNSTool},
		},
		{
			name: "chroot into the mounted host",
			mutate: func(c *Container) {
				c.Processes = []ContainerProcess{{PID: 40, Cmd: "chroot /host /bin/bash"}}
			},
			want: []string{escapeHostNSTool},
		},
		{
			name: "ordinary chroot",
			mutate: func(c *Container) {
				c.Processes = []ContainerProcess{{PID: 41, Cmd: "chroot /srv/jail /bin/sh"}}
			},
			notWant: []string{escapeHostNSTool},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := hardened()
			tt.mutate(c)
			got := escapeAttemptEvidence(c)
			for _, w := range tt.want {
				if !hasID(got, w) {
					t.Errorf("missing %s in %v", w, got)
				}
			}
			for _, n := range tt.notWant {
				if hasID(got, n) {
					t.Errorf("unexpected %s in %v", n, got)
				}
			}
		})
	}
	if got := escapeAttemptEvidence(hardened()); len(got) != 0 {
		t.Fatalf("hardened container produced attempt evidence: %v", got)
	}
}

func TestImageAgeDays(t *testing.T) {
	now := time.Date(2026, 7, 24, 12, 0, 0, 0, time.UTC)
	tests := []struct {
		created string
		want    int
	}{
		{"", 0},
		{"not-a-date", 0},
		{"2026-07-24T00:00:00Z", 0},
		{"2026-07-14T12:00:00Z", 10},
		{"2024-07-24T12:00:00Z", 730},
		{"2027-01-01T00:00:00Z", 0}, // future timestamps read as unknown
	}
	for _, tt := range tests {
		if got := imageAgeDays(tt.created, now); got != tt.want {
			t.Errorf("imageAgeDays(%q) = %d, want %d", tt.created, got, tt.want)
		}
	}
	if imageAgeDays("2024-07-24T12:00:00Z", now) <= imageStaleDays {
		t.Errorf("a two-year-old image should be past the stale threshold")
	}
}

func TestParseTrivyReport(t *testing.T) {
	raw := []byte(`{"Results":[
		{"Target":"alpine:3.10 (alpine 3.10.0)","Vulnerabilities":[
			{"VulnerabilityID":"CVE-2021-1111","PkgName":"openssl","InstalledVersion":"1.1.1","FixedVersion":"1.1.1k","Severity":"HIGH","Title":"openssl:  buffer   overflow"},
			{"VulnerabilityID":"CVE-2021-2222","PkgName":"musl","InstalledVersion":"1.1.22","FixedVersion":"","Severity":"CRITICAL","Title":"musl: rce"},
			{"VulnerabilityID":"CVE-2021-2222","PkgName":"musl","InstalledVersion":"1.1.22","FixedVersion":"","Severity":"CRITICAL","Title":"musl: rce"}
		]},
		{"Target":"app/package-lock.json","Vulnerabilities":null}
	]}`)
	sum, err := parseTrivyReport(raw, time.Date(2026, 7, 24, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if sum.Critical != 2 || sum.High != 1 || sum.Total != 3 {
		t.Errorf("counts = %d critical / %d high / %d total", sum.Critical, sum.High, sum.Total)
	}
	if len(sum.Top) != 2 {
		t.Fatalf("top = %d entries, want 2 (duplicate cve+pkg collapsed)", len(sum.Top))
	}
	if sum.Top[0].Severity != "CRITICAL" {
		t.Errorf("top entry = %q, want the critical one first", sum.Top[0].Severity)
	}
	if sum.Top[1].Title != "openssl: buffer overflow" {
		t.Errorf("title = %q, want whitespace collapsed", sum.Top[1].Title)
	}
	if sum.Scanner != trivyName || sum.ScannedAt != "2026-07-24T12:00:00Z" {
		t.Errorf("scanner metadata = %q / %q", sum.Scanner, sum.ScannedAt)
	}
	if _, err := parseTrivyReport([]byte("not json"), time.Now()); err == nil {
		t.Errorf("malformed report should error rather than read as clean")
	}
}

func TestParseTrivyReportCapsTopList(t *testing.T) {
	var b strings.Builder
	b.WriteString(`{"Results":[{"Vulnerabilities":[`)
	for i := 0; i < maxTopVulns+10; i++ {
		if i > 0 {
			b.WriteString(",")
		}
		b.WriteString(`{"VulnerabilityID":"CVE-2020-` + string(rune('a'+i%26)) + string(rune('a'+i/26)) +
			`","PkgName":"pkg","Severity":"HIGH"}`)
	}
	b.WriteString(`]}]}`)
	sum, err := parseTrivyReport([]byte(b.String()), time.Now())
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(sum.Top) != maxTopVulns {
		t.Errorf("top = %d entries, want the %d cap", len(sum.Top), maxTopVulns)
	}
	if sum.Total != maxTopVulns+10 {
		t.Errorf("total = %d, want the full count %d", sum.Total, maxTopVulns+10)
	}
}
