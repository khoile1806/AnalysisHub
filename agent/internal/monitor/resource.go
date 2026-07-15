package monitor

// Resource is a point-in-time snapshot of agent host utilization. It is sent to
// the server as a "resource_report" so the fleet / system-health view shows live
// CPU / RAM / disk for each online agent.
type Resource struct {
	CPUPercent  float64
	MemUsedMB   int64
	MemTotalMB  int64
	DiskUsedGB  float64
	DiskTotalGB float64
}

// SampleResource returns the current host resource utilization. The CPU figure
// is sampled over a short window, so this call blocks briefly. Implementation is
// platform-specific (see resource_windows.go / resource_linux.go).
func SampleResource() Resource { return sampleResource() }
