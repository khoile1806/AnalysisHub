//go:build linux

package monitor

import (
	"os"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

func sampleResource() Resource {
	var r Resource

	// Memory from /proc/meminfo (values in kB).
	if data, err := os.ReadFile("/proc/meminfo"); err == nil {
		var total, avail int64
		for _, line := range strings.Split(string(data), "\n") {
			f := strings.Fields(line)
			if len(f) < 2 {
				continue
			}
			v, _ := strconv.ParseInt(f[1], 10, 64)
			switch f[0] {
			case "MemTotal:":
				total = v
			case "MemAvailable:":
				avail = v
			}
		}
		r.MemTotalMB = total / 1024
		r.MemUsedMB = (total - avail) / 1024
	}

	// Root filesystem usage.
	var st unix.Statfs_t
	if unix.Statfs("/", &st) == nil && st.Blocks > 0 {
		bs := uint64(st.Bsize)
		const gb = 1024 * 1024 * 1024
		total := st.Blocks * bs
		free := st.Bavail * bs
		r.DiskTotalGB = float64(total) / gb
		r.DiskUsedGB = float64(total-free) / gb
	}

	r.CPUPercent = cpuPercentLinux()
	return r
}

// cpuPercentLinux samples /proc/stat twice over a short window and returns the
// busy percentage.
func cpuPercentLinux() float64 {
	idle0, total0, ok := procStat()
	if !ok {
		return 0
	}
	time.Sleep(250 * time.Millisecond)
	idle1, total1, ok := procStat()
	if !ok {
		return 0
	}
	dt := total1 - total0
	di := idle1 - idle0
	if dt == 0 || di > dt {
		return 0
	}
	return float64(dt-di) / float64(dt) * 100
}

// procStat returns the aggregate idle and total CPU jiffies from the "cpu" line.
func procStat() (idle, total uint64, ok bool) {
	data, err := os.ReadFile("/proc/stat")
	if err != nil {
		return 0, 0, false
	}
	for _, line := range strings.Split(string(data), "\n") {
		if !strings.HasPrefix(line, "cpu ") {
			continue
		}
		fields := strings.Fields(line)[1:]
		for i, v := range fields {
			n, _ := strconv.ParseUint(v, 10, 64)
			total += n
			if i == 3 { // idle is the 4th field
				idle = n
			}
		}
		return idle, total, true
	}
	return 0, 0, false
}
