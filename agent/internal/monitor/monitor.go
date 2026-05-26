package monitor

import (
	"encoding/json"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
)

// ProcessInfo represents a running process.
type ProcessInfo struct {
	PID     int    `json:"pid"`
	PPID    int    `json:"ppid"`
	Name    string `json:"name"`
	MemKB   int    `json:"mem_kb"`
	Cmdline string `json:"cmdline"`
}

// NetConn represents a network connection.
type NetConn struct {
	Proto  string `json:"proto"`
	Local  string `json:"local"`
	Remote string `json:"remote"`
	State  string `json:"state"`
}

// DiskInfo represents a single disk/partition.
type DiskInfo struct {
	Name    string  `json:"name"`
	TotalGB float64 `json:"total_gb"`
	FreeGB  float64 `json:"free_gb"`
}

// SysInfo holds hardware information about the endpoint.
type SysInfo struct {
	CPUModel   string     `json:"cpu_model"`
	CPUCores   int        `json:"cpu_cores"`
	RAMTotalMB int64      `json:"ram_total_mb"`
	RAMFreeMB  int64      `json:"ram_free_mb"`
	Disks      []DiskInfo `json:"disks"`
}

// CollectProcesses returns a JSON-encoded list of running processes.
func CollectProcesses() (string, error) {
	var procs []ProcessInfo
	if runtime.GOOS == "windows" {
		procs = collectProcessesWindows()
	} else {
		procs = collectProcessesLinux()
	}
	b, err := json.Marshal(procs)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// CollectNetstat returns a JSON-encoded list of network connections.
func CollectNetstat() (string, error) {
	var conns []NetConn
	if runtime.GOOS == "windows" {
		conns = collectNetstatWindows()
	} else {
		conns = collectNetstatLinux()
	}
	b, err := json.Marshal(conns)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// CollectSysInfo returns a JSON-encoded SysInfo struct.
func CollectSysInfo() (string, error) {
	var info SysInfo
	if runtime.GOOS == "windows" {
		info = collectSysInfoWindows()
	} else {
		info = collectSysInfoLinux()
	}
	b, err := json.Marshal(info)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// ── Processes ─────────────────────────────────────────────────────────────── //

func collectProcessesWindows() []ProcessInfo {
	out, err := exec.Command("wmic", "process", "get",
		"CommandLine,Name,ParentProcessId,ProcessId,WorkingSetSize",
		"/format:csv").Output()
	if err != nil {
		return nil
	}

	lines := strings.Split(strings.ReplaceAll(string(out), "\r\n", "\n"), "\n")
	colIdx := map[string]int{}
	headerFound := false
	var procs []ProcessInfo

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if !headerFound {
			if strings.HasPrefix(line, "Node,") {
				for i, f := range parseCSVLine(line) {
					colIdx[strings.TrimSpace(f)] = i
				}
				headerFound = true
			}
			continue
		}
		fields := parseCSVLine(line)
		get := func(name string) string {
			if i, ok := colIdx[name]; ok && i < len(fields) {
				return strings.TrimSpace(fields[i])
			}
			return ""
		}
		pid, _ := strconv.Atoi(get("ProcessId"))
		ppid, _ := strconv.Atoi(get("ParentProcessId"))
		memBytes, _ := strconv.ParseInt(get("WorkingSetSize"), 10, 64)
		if pid == 0 {
			continue
		}
		procs = append(procs, ProcessInfo{
			PID:     pid,
			PPID:    ppid,
			Name:    get("Name"),
			MemKB:   int(memBytes / 1024),
			Cmdline: get("CommandLine"),
		})
	}
	return procs
}

func collectProcessesLinux() []ProcessInfo {
	// pid, ppid, comm (name), rss (mem in KB), args (full cmdline)
	out, err := exec.Command("ps", "-eo", "pid,ppid,comm,rss,args", "--no-headers").Output()
	if err != nil {
		return nil
	}
	var procs []ProcessInfo
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		pid, _ := strconv.Atoi(fields[0])
		ppid, _ := strconv.Atoi(fields[1])
		mem, _ := strconv.Atoi(fields[3])
		cmdline := ""
		if len(fields) > 4 {
			cmdline = strings.Join(fields[4:], " ")
		}
		procs = append(procs, ProcessInfo{
			PID:     pid,
			PPID:    ppid,
			Name:    fields[2],
			MemKB:   mem,
			Cmdline: cmdline,
		})
	}
	return procs
}

// ── Network ───────────────────────────────────────────────────────────────── //

func collectNetstatWindows() []NetConn {
	out, err := exec.Command("netstat", "-an").Output()
	if err != nil {
		return nil
	}
	return parseNetstatOutput(string(out))
}

func collectNetstatLinux() []NetConn {
	out, err := exec.Command("ss", "-tun").Output()
	if err != nil {
		out, err = exec.Command("netstat", "-tun").Output()
		if err != nil {
			return nil
		}
	}
	return parseNetstatOutput(string(out))
}

func parseNetstatOutput(raw string) []NetConn {
	var conns []NetConn
	for _, line := range strings.Split(raw, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		proto := strings.ToLower(fields[0])
		if !strings.HasPrefix(proto, "tcp") && !strings.HasPrefix(proto, "udp") {
			continue
		}
		local := fields[1]
		remote := fields[2]
		state := ""
		if len(fields) >= 4 {
			state = fields[3]
		}
		if local == "Local" || local == "Local Address" {
			continue
		}
		conns = append(conns, NetConn{
			Proto:  strings.ToUpper(proto[:3]),
			Local:  local,
			Remote: remote,
			State:  state,
		})
	}
	return conns
}

// ── SysInfo ───────────────────────────────────────────────────────────────── //

func collectSysInfoWindows() SysInfo {
	info := SysInfo{CPUCores: runtime.NumCPU()}

	// CPU model
	if out, err := exec.Command("wmic", "cpu", "get", "Name", "/format:csv").Output(); err == nil {
		for _, line := range strings.Split(strings.ReplaceAll(string(out), "\r\n", "\n"), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "Node") {
				continue
			}
			parts := strings.SplitN(line, ",", 2)
			if len(parts) == 2 {
				info.CPUModel = strings.TrimSpace(parts[1])
				break
			}
		}
	}

	// RAM (values in KB)
	if out, err := exec.Command("wmic", "os", "get",
		"TotalVisibleMemorySize,FreePhysicalMemory", "/format:csv").Output(); err == nil {
		lines := strings.Split(strings.ReplaceAll(string(out), "\r\n", "\n"), "\n")
		colIdx := map[string]int{}
		headerFound := false
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			if !headerFound {
				if strings.HasPrefix(line, "Node,") {
					for i, f := range parseCSVLine(line) {
						colIdx[strings.TrimSpace(f)] = i
					}
					headerFound = true
				}
				continue
			}
			fields := parseCSVLine(line)
			get := func(name string) int64 {
				if i, ok := colIdx[name]; ok && i < len(fields) {
					v, _ := strconv.ParseInt(strings.TrimSpace(fields[i]), 10, 64)
					return v
				}
				return 0
			}
			info.RAMTotalMB = get("TotalVisibleMemorySize") / 1024
			info.RAMFreeMB = get("FreePhysicalMemory") / 1024
			break
		}
	}

	// Disks (values in bytes)
	if out, err := exec.Command("wmic", "logicaldisk",
		"where", "DriveType=3",
		"get", "DeviceID,Size,FreeSpace",
		"/format:csv").Output(); err == nil {
		lines := strings.Split(strings.ReplaceAll(string(out), "\r\n", "\n"), "\n")
		colIdx := map[string]int{}
		headerFound := false
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			if !headerFound {
				if strings.HasPrefix(line, "Node,") {
					for i, f := range parseCSVLine(line) {
						colIdx[strings.TrimSpace(f)] = i
					}
					headerFound = true
				}
				continue
			}
			fields := parseCSVLine(line)
			get := func(name string) string {
				if i, ok := colIdx[name]; ok && i < len(fields) {
					return strings.TrimSpace(fields[i])
				}
				return ""
			}
			name := get("DeviceID")
			sizeBytes, _ := strconv.ParseInt(get("Size"), 10, 64)
			freeBytes, _ := strconv.ParseInt(get("FreeSpace"), 10, 64)
			if name == "" || sizeBytes == 0 {
				continue
			}
			info.Disks = append(info.Disks, DiskInfo{
				Name:    name,
				TotalGB: float64(sizeBytes) / 1e9,
				FreeGB:  float64(freeBytes) / 1e9,
			})
		}
	}

	return info
}

func collectSysInfoLinux() SysInfo {
	info := SysInfo{CPUCores: runtime.NumCPU()}

	// CPU model from /proc/cpuinfo
	if out, err := exec.Command("sh", "-c",
		`grep "model name" /proc/cpuinfo | head -1 | cut -d: -f2`).Output(); err == nil {
		info.CPUModel = strings.TrimSpace(string(out))
	}

	// RAM from /proc/meminfo
	if out, err := exec.Command("sh", "-c",
		`grep -E "^MemTotal:|^MemAvailable:" /proc/meminfo`).Output(); err == nil {
		for _, line := range strings.Split(string(out), "\n") {
			fields := strings.Fields(line)
			if len(fields) < 2 {
				continue
			}
			val, _ := strconv.ParseInt(fields[1], 10, 64)
			switch {
			case strings.HasPrefix(line, "MemTotal:"):
				info.RAMTotalMB = val / 1024
			case strings.HasPrefix(line, "MemAvailable:"):
				info.RAMFreeMB = val / 1024
			}
		}
	}

	// Disks via df (skip tmpfs/devtmpfs/overlay)
	if out, err := exec.Command("df", "-k", "--output=source,size,avail",
		"--exclude-type=tmpfs",
		"--exclude-type=devtmpfs",
		"--exclude-type=overlay").Output(); err == nil {
		for i, line := range strings.Split(string(out), "\n") {
			if i == 0 || strings.TrimSpace(line) == "" {
				continue
			}
			fields := strings.Fields(line)
			if len(fields) < 3 {
				continue
			}
			totalKB, _ := strconv.ParseInt(fields[1], 10, 64)
			freeKB, _ := strconv.ParseInt(fields[2], 10, 64)
			info.Disks = append(info.Disks, DiskInfo{
				Name:    fields[0],
				TotalGB: float64(totalKB) / (1024 * 1024),
				FreeGB:  float64(freeKB) / (1024 * 1024),
			})
		}
	}

	return info
}

// ── CSV helper ────────────────────────────────────────────────────────────── //

func parseCSVLine(line string) []string {
	var fields []string
	var cur strings.Builder
	inQuote := false
	for _, ch := range line {
		switch {
		case ch == '"':
			inQuote = !inQuote
		case ch == ',' && !inQuote:
			fields = append(fields, cur.String())
			cur.Reset()
		default:
			cur.WriteRune(ch)
		}
	}
	fields = append(fields, cur.String())
	return fields
}
