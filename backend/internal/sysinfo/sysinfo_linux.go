//go:build linux

package sysinfo

import (
	"bufio"
	"os"
	"runtime"
	"strconv"
	"strings"
	"syscall"
)

// CPUSample holds a snapshot of cumulative CPU ticks from /proc/stat.
// Two samples are needed to calculate a meaningful CPU %.
type CPUSample struct {
	Total uint64
	Idle  uint64
}

// ReadCPUSample reads the aggregate CPU line from /proc/stat.
func ReadCPUSample() (CPUSample, bool) {
	f, err := os.Open("/proc/stat")
	if err != nil {
		return CPUSample{}, false
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, "cpu ") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 5 {
			return CPUSample{}, false
		}
		var v [10]uint64
		for i := 1; i < len(fields) && i <= 10; i++ {
			v[i-1], _ = strconv.ParseUint(fields[i], 10, 64)
		}
		// user=0 nice=1 system=2 idle=3 iowait=4 irq=5 softirq=6 steal=7
		total := v[0] + v[1] + v[2] + v[3] + v[4] + v[5] + v[6] + v[7]
		idle := v[3] + v[4]
		return CPUSample{Total: total, Idle: idle}, true
	}
	return CPUSample{}, false
}

// CalcCPUPercent computes CPU usage % between two consecutive samples.
func CalcCPUPercent(prev, curr CPUSample) float64 {
	dt := float64(curr.Total - prev.Total)
	di := float64(curr.Idle - prev.Idle)
	if dt <= 0 {
		return 0
	}
	v := (1 - di/dt) * 100
	if v < 0 {
		return 0
	}
	if v > 100 {
		return 100
	}
	return v
}

// ReadMemInfo reads /proc/meminfo and returns (totalMB, usedMB, usedPercent).
func ReadMemInfo() (totalMB, usedMB uint64, percent float64) {
	f, err := os.Open("/proc/meminfo")
	if err != nil {
		return
	}
	defer f.Close()

	var total, available uint64
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 2 {
			continue
		}
		val, _ := strconv.ParseUint(fields[1], 10, 64)
		switch fields[0] {
		case "MemTotal:":
			total = val
		case "MemAvailable:":
			available = val
		}
	}
	if total == 0 {
		return
	}
	used := total - available
	totalMB = total / 1024
	usedMB = used / 1024
	percent = float64(used) / float64(total) * 100
	return
}

// ReadDiskInfo returns (usedGB, totalGB, usedPercent) for the filesystem
// containing path, using Bavail (space available to unprivileged users).
func ReadDiskInfo(path string) (usedGB, totalGB, percent float64) {
	var stat syscall.Statfs_t
	if err := syscall.Statfs(path, &stat); err != nil {
		return
	}
	totalBytes := stat.Blocks * uint64(stat.Bsize)
	availBytes := stat.Bavail * uint64(stat.Bsize)
	usedBytes := totalBytes - availBytes
	totalGB = float64(totalBytes) / 1e9
	usedGB = float64(usedBytes) / 1e9
	if totalBytes > 0 {
		percent = float64(usedBytes) / float64(totalBytes) * 100
	}
	return
}

// CPUCount returns the number of logical CPUs.
func CPUCount() int {
	return runtime.NumCPU()
}
