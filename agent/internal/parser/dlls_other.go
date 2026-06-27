//go:build !windows

package parser

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// ScanLoadedDLLs enumerates loaded shared objects (.so) across all processes via
// /proc/<pid>/maps — the Linux equivalent of the ListDLLs view. Deduped by path
// with loader counts. Returns an empty set where /proc is unavailable (macOS).
func ScanLoadedDLLs() ([]DllRec, error) {
	procs, err := os.ReadDir("/proc")
	if err != nil {
		return []DllRec{}, nil
	}

	type agg struct {
		loaders map[string]bool
		susp    []string
	}
	byPath := map[string]*agg{}

	for _, p := range procs {
		if _, perr := strconv.Atoi(p.Name()); perr != nil {
			continue
		}
		b, rerr := os.ReadFile(filepath.Join("/proc", p.Name(), "maps"))
		if rerr != nil {
			continue
		}
		loader := strings.TrimSpace(string(mustRead(filepath.Join("/proc", p.Name(), "comm")))) + " (" + p.Name() + ")"

		localSeen := map[string]bool{}
		for _, line := range strings.Split(string(b), "\n") {
			// addr perms offset dev inode pathname
			fields := strings.Fields(line)
			if len(fields) < 6 {
				continue
			}
			path := strings.Join(fields[5:], " ")
			if !strings.HasPrefix(path, "/") || !isSharedObject(path) {
				continue
			}
			if localSeen[path] {
				continue
			}
			localSeen[path] = true

			a := byPath[path]
			if a == nil {
				a = &agg{loaders: map[string]bool{}, susp: flagModule(path)}
				byPath[path] = a
			}
			a.loaders[loader] = true
		}
	}

	out := make([]DllRec, 0, len(byPath))
	for path, a := range byPath {
		loaders := make([]string, 0, len(a.loaders))
		for l := range a.loaders {
			loaders = append(loaders, l)
			if len(loaders) >= 5 { // sample only
				break
			}
		}
		out = append(out, DllRec{
			Name:         filepath.Base(path),
			Path:         path,
			ProcessCount: len(a.loaders),
			Processes:    loaders,
			Suspicious:   a.susp,
		})
	}
	return out, nil
}

// isSharedObject reports whether a mapped path looks like a shared library.
func isSharedObject(path string) bool {
	base := filepath.Base(path)
	return strings.HasSuffix(base, ".so") || strings.Contains(base, ".so.")
}

func flagModule(path string) []string {
	var f []string
	low := strings.ToLower(path)
	if strings.Contains(low, "(deleted)") {
		f = append(f, "deleted-module")
	}
	for _, d := range []string{"/tmp/", "/dev/shm/", "/var/tmp/", "/home/"} {
		if strings.HasPrefix(low, d) {
			f = append(f, "module-from-unusual-path")
			break
		}
	}
	return f
}
