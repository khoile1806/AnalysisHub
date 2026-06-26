//go:build windows

package parser

import (
	"os"
	"sort"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Native loaded-module enumeration — the equivalent of Sysinternals ListDLLs.
// Walks every process's module list (Toolhelp), aggregates by unique DLL path,
// hashes + signature-checks each module and flags the classic DLL-hijack /
// injection tells (unsigned module in a user-writable dir, untrusted signature,
// module backing file missing on disk). Runs in the elevated context so it can
// read other processes' modules.

const dllMaxModules = 6000 // safety cap on distinct modules tracked

type dllAgg struct {
	name     string
	path     string
	procs    []string
	procSeen map[string]bool
}

// ScanLoadedDLLs enumerates loaded modules across all processes.
func ScanLoadedDLLs() ([]DllRec, error) {
	procMap := processNameMap()
	agg := make(map[string]*dllAgg) // lower(path) -> agg

	for pid, pname := range procMap {
		if pid == 0 || pid == 4 {
			continue
		}
		snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPMODULE|windows.TH32CS_SNAPMODULE32, pid)
		if err != nil {
			continue // protected / WOW64 mismatch — skip
		}
		var me windows.ModuleEntry32
		me.Size = uint32(unsafe.Sizeof(me))
		if err := windows.Module32First(snap, &me); err != nil {
			windows.CloseHandle(snap)
			continue
		}
		first := true
		for {
			path := windows.UTF16ToString(me.ExePath[:])
			lp := strings.ToLower(path)
			// The first module is the process image itself (.exe) — skip it; we
			// only want loaded libraries.
			if !first && strings.HasSuffix(lp, ".dll") {
				a := agg[lp]
				if a == nil {
					if len(agg) >= dllMaxModules {
						// stop tracking new modules but keep counting known ones
					} else {
						a = &dllAgg{name: windows.UTF16ToString(me.Module[:]), path: path, procSeen: map[string]bool{}}
						agg[lp] = a
					}
				}
				if a != nil {
					label := pname
					if label == "" {
						label = "pid"
					}
					key := label
					if !a.procSeen[key] {
						a.procSeen[key] = true
						if len(a.procs) < 12 {
							a.procs = append(a.procs, label)
						}
					}
				}
			}
			first = false
			if err := windows.Module32Next(snap, &me); err != nil {
				break
			}
		}
		windows.CloseHandle(snap)
	}

	// Enrich: hash + signature (cached + budgeted) + suspicion flags.
	hashCache := make(map[string][2]string)
	sigCache := make(map[string]string)
	budget := mftMaxTotalHashBytes

	recs := make([]DllRec, 0, len(agg))
	for lp, a := range agg {
		rec := DllRec{
			Name: a.name, Path: a.path,
			ProcessCount: len(a.procSeen),
			Processes:    a.procs,
		}
		if st, serr := os.Stat(a.path); serr == nil && !st.IsDir() && st.Size() > 0 {
			fi := st.Size()
			if h, ok := hashCache[lp]; ok {
				rec.MD5, rec.SHA256, rec.Hashed = h[0], h[1], h[1] != ""
			} else if fi <= mftMaxHashBytes && budget > 0 {
				if md5h, _, sha256h, herr := hashFile(a.path); herr == nil {
					rec.MD5, rec.SHA256, rec.Hashed = md5h, sha256h, true
					budget -= fi
					hashCache[lp] = [2]string{md5h, sha256h}
				}
			}
			if s, ok := sigCache[lp]; ok {
				rec.Signature = s
			} else {
				s = fileSignatureStatus(a.path)
				sigCache[lp] = s
				rec.Signature = s
			}
		} else {
			rec.Suspicious = append(rec.Suspicious, "backing file missing on disk")
		}
		rec.Suspicious = append(rec.Suspicious, flagDLL(a.path, rec.Signature)...)
		recs = append(recs, rec)
	}

	// Suspicious first, then most-loaded, then name.
	sort.Slice(recs, func(i, j int) bool {
		si, sj := len(recs[i].Suspicious), len(recs[j].Suspicious)
		if (si > 0) != (sj > 0) {
			return si > 0
		}
		if recs[i].ProcessCount != recs[j].ProcessCount {
			return recs[i].ProcessCount > recs[j].ProcessCount
		}
		return strings.ToLower(recs[i].Name) < strings.ToLower(recs[j].Name)
	})
	return recs, nil
}

// flagDLL returns DLL-hijack / injection suspicion reasons.
func flagDLL(path, signature string) []string {
	var reasons []string
	lp := strings.ToLower(path)
	if signature == "Untrusted" {
		reasons = append(reasons, "untrusted signature")
	}
	inSystem := strings.Contains(lp, `\windows\system32\`) || strings.Contains(lp, `\windows\winsxs\`) ||
		strings.Contains(lp, `\windows\syswow64\`)
	risky := false
	for _, frag := range suspiciousDirs {
		if strings.Contains(lp, frag) {
			risky = true
			break
		}
	}
	if signature == "Unsigned" && risky {
		reasons = append(reasons, "unsigned DLL in user-writable dir")
	} else if signature == "Unsigned" && !inSystem && strings.HasPrefix(lp, `c:\windows\`) {
		reasons = append(reasons, "unsigned DLL under Windows but outside System32")
	}
	return reasons
}
