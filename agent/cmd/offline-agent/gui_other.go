//go:build !windows

package main

// openNativeWindow has no native-window implementation off Windows; the caller
// falls back to lorca (Linux/macOS with a display) or the system browser.
func openNativeWindow(_, _ string) bool { return false }
