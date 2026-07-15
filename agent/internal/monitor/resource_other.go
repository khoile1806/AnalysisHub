//go:build !windows && !linux

package monitor

// sampleResource is a no-op fallback on platforms without a native sampler; the
// agent still runs, it just reports zero utilization.
func sampleResource() Resource { return Resource{} }
