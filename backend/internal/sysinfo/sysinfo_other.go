//go:build !linux

package sysinfo

import "runtime"

// CPUSample is a no-op stub on non-Linux platforms.
type CPUSample struct {
	Total uint64
	Idle  uint64
}

func ReadCPUSample() (CPUSample, bool)           { return CPUSample{}, false }
func CalcCPUPercent(_, _ CPUSample) float64      { return 0 }
func ReadMemInfo() (uint64, uint64, float64)     { return 0, 0, 0 }
func ReadDiskInfo(_ string) (float64, float64, float64) { return 0, 0, 0 }
func CPUCount() int                              { return runtime.NumCPU() }
