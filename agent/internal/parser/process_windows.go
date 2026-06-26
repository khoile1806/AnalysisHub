//go:build windows

package parser

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
)

// ProcessRec is a richly-detailed running-process record captured for forensic
// triage: full lineage (parent), owning user, image path + command line, the
// content hash of the executable (for IOC / VirusTotal pivoting) and heuristic
// suspicion flags.
type ProcessRec struct {
	PID        int      `json:"pid"`
	PPID       int      `json:"ppid"`
	Name       string   `json:"name"`
	ParentName string   `json:"parent_name"`
	Path       string   `json:"path"`
	Cmdline    string   `json:"cmdline"`
	User       string   `json:"user"`
	MemKB      int      `json:"mem_kb"`
	Created    string   `json:"created"`
	MD5        string   `json:"md5,omitempty"`
	SHA256     string   `json:"sha256,omitempty"`
	Hashed     bool     `json:"hashed"`
	Signature  string   `json:"signature,omitempty"` // Signed | Unsigned | Untrusted
	Suspicious []string `json:"suspicious,omitempty"`
}

// psProc mirrors the JSON emitted by the collection script.
type psProc struct {
	PID     int    `json:"pid"`
	PPID    int    `json:"ppid"`
	Name    string `json:"name"`
	Path    string `json:"path"`
	Cmdline string `json:"cmdline"`
	User    string `json:"user"`
	MemKB   int    `json:"mem_kb"`
	Created string `json:"created"`
}

// psProcessScript enumerates every process with owner, image path, command line
// and start time via CIM, emitting compact JSON.
const psProcessScript = `$ErrorActionPreference='SilentlyContinue';
$ps = Get-CimInstance Win32_Process;
$out = foreach ($p in $ps) {
  $u='';
  try { $o = Invoke-CimMethod -InputObject $p -MethodName GetOwner; if ($o -and $o.User) { $u = "$($o.Domain)\$($o.User)" } } catch {}
  $c='';
  try { if ($p.CreationDate) { $c = $p.CreationDate.ToString('o') } } catch {}
  [pscustomobject]@{ pid=[int]$p.ProcessId; ppid=[int]$p.ParentProcessId; name=$p.Name; path=$p.ExecutablePath; cmdline=$p.CommandLine; user=$u; mem_kb=[int]($p.WorkingSetSize/1024); created=$c }
};
$out | ConvertTo-Json -Compress -Depth 3`

// procHashBudget bounds total bytes hashed while resolving executable hashes.
const procHashBudget int64 = 1 << 30 // ~1 GB

// criticalSystemProcs are protected OS images that should only ever run from
// System32 — anywhere else is a classic masquerade.
var criticalSystemProcs = map[string]bool{
	"svchost.exe": true, "lsass.exe": true, "services.exe": true,
	"csrss.exe": true, "winlogon.exe": true, "smss.exe": true,
	"wininit.exe": true, "spoolsv.exe": true, "taskhostw.exe": true,
}

var lolbins = []string{
	"powershell.exe", "pwsh.exe", "cmd.exe", "rundll32.exe", "regsvr32.exe",
	"mshta.exe", "certutil.exe", "wmic.exe", "bitsadmin.exe", "wscript.exe",
	"cscript.exe", "msbuild.exe", "installutil.exe", "regasm.exe",
}

// ScanProcesses enumerates running processes with full detail and hashes the
// backing executables. Runs in the UAC-elevated child so it can read other
// users' command lines / owners.
func ScanProcesses() ([]ProcessRec, error) {
	cmd := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", psProcessScript)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("process enumeration failed: %v", err)
	}

	raws, perr := parsePsProcs(out)
	if perr != nil {
		return nil, perr
	}

	nameByPID := make(map[int]string, len(raws))
	for _, r := range raws {
		nameByPID[r.PID] = r.Name
	}

	hashCache := make(map[string][2]string) // lower(path) -> {md5, sha256}
	sigCache := make(map[string]string)     // lower(path) -> signature status
	budget := procHashBudget

	recs := make([]ProcessRec, 0, len(raws))
	for _, r := range raws {
		rec := ProcessRec{
			PID: r.PID, PPID: r.PPID, Name: r.Name, ParentName: nameByPID[r.PPID],
			Path: r.Path, Cmdline: r.Cmdline, User: r.User, MemKB: r.MemKB, Created: r.Created,
		}
		if r.Path != "" {
			key := strings.ToLower(r.Path)
			if h, ok := hashCache[key]; ok {
				rec.MD5, rec.SHA256, rec.Hashed = h[0], h[1], h[1] != ""
			} else if fi, serr := os.Stat(r.Path); serr == nil && !fi.IsDir() && fi.Size() > 0 && fi.Size() <= mftMaxHashBytes && budget > 0 {
				if md5h, _, sha256h, herr := hashFile(r.Path); herr == nil {
					rec.MD5, rec.SHA256, rec.Hashed = md5h, sha256h, true
					budget -= fi.Size()
					hashCache[key] = [2]string{md5h, sha256h}
				} else {
					hashCache[key] = [2]string{"", ""}
				}
			} else {
				hashCache[key] = [2]string{"", ""}
			}
			// Authenticode status (embedded + catalog), cached per image path.
			if s, ok := sigCache[key]; ok {
				rec.Signature = s
			} else {
				s = fileSignatureStatus(r.Path)
				sigCache[key] = s
				rec.Signature = s
			}
		}
		rec.Suspicious = flagProcess(r.Name, r.Path, r.Cmdline)
		// An unsigned/untrusted image outside the System dirs is worth flagging.
		if rec.Signature == "Untrusted" {
			rec.Suspicious = append(rec.Suspicious, "untrusted signature")
		}
		recs = append(recs, rec)
	}
	return recs, nil
}

// parsePsProcs decodes the script output, tolerating the single-object form
// PowerShell emits when only one process is returned.
func parsePsProcs(out []byte) ([]psProc, error) {
	trimmed := bytes.TrimSpace(out)
	if len(trimmed) == 0 {
		return nil, fmt.Errorf("empty process output")
	}
	if trimmed[0] == '{' {
		var one psProc
		if err := json.Unmarshal(trimmed, &one); err != nil {
			return nil, fmt.Errorf("decode process json: %v", err)
		}
		return []psProc{one}, nil
	}
	var many []psProc
	if err := json.Unmarshal(trimmed, &many); err != nil {
		return nil, fmt.Errorf("decode process json: %v", err)
	}
	return many, nil
}

// flagProcess returns human-readable suspicion reasons for a process.
func flagProcess(name, path, cmdline string) []string {
	var reasons []string
	ln := strings.ToLower(name)
	lp := strings.ToLower(path)
	lc := strings.ToLower(cmdline)

	// Image runs from a user-writable / staging directory.
	if path != "" {
		for _, frag := range suspiciousDirs {
			if strings.Contains(lp, frag) {
				reasons = append(reasons, "image in "+strings.Trim(frag, `\`))
				break
			}
		}
	}

	// LOLBin invoked with offensive arguments.
	for _, b := range lolbins {
		if ln == b {
			if strings.Contains(lc, "-enc") || strings.Contains(lc, "encodedcommand") ||
				strings.Contains(lc, "downloadstring") || strings.Contains(lc, "frombase64") ||
				strings.Contains(lc, "-w hidden") || strings.Contains(lc, "-windowstyle hidden") ||
				strings.Contains(lc, "bypass") || strings.Contains(lc, "iex") ||
				strings.Contains(lc, "http://") || strings.Contains(lc, "https://") {
				reasons = append(reasons, "LOLBin with suspicious arguments")
			}
			break
		}
	}

	// Critical system-process name running from outside System32 (masquerade).
	if criticalSystemProcs[ln] && path != "" &&
		!strings.Contains(lp, `\windows\system32`) && !strings.Contains(lp, `\windows\syswow64`) {
		reasons = append(reasons, "system-process name outside System32 (masquerade?)")
	}

	// Executable extension with no resolvable image path but a command line — odd.
	return reasons
}
