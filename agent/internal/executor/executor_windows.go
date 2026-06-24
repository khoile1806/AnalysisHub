//go:build windows

package executor

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// runToolProcess launches execPath in a new console window on Windows.
// A PowerShell wrapper uses Tee-Object to write output both to the visible
// window and to a temp log file; this goroutine tails that log file and
// streams lines to outputCh so the dashboard receives real-time output.
func runToolProcess(ctx context.Context, execPath string, args []string, req JobRequest, toolDir string, outputCh chan<- string) error {
	// Automatically append -AcceptEula for known Sysinternals tools to prevent GUI hangs.
	baseName := strings.ToLower(filepath.Base(execPath))
	if isSysinternals(baseName) {
		hasEula := false
		for _, a := range args {
			if strings.ToLower(a) == "-accepteula" || strings.ToLower(a) == "/accepteula" {
				hasEula = true
				break
			}
		}
		if !hasEula {
			args = append(args, "-AcceptEula")
		}
	}

	// Automatically append /Q for DumpIt to prevent the Y/N prompt
	if strings.HasPrefix(baseName, "dumpit") {
		hasQuiet := false
		for _, a := range args {
			if strings.ToLower(a) == "/q" || strings.ToLower(a) == "-q" || strings.ToLower(a) == "/quiet" {
				hasQuiet = true
				break
			}
		}
		if !hasQuiet {
			args = append(args, "/Q")
		}
	}

	tmp := os.TempDir()
	logFile := filepath.Join(tmp, fmt.Sprintf("fhub_run_%s.log", req.JobID))
	ps1File := filepath.Join(tmp, fmt.Sprintf("fhub_run_%s.ps1", req.JobID))
	batFile := filepath.Join(tmp, fmt.Sprintf("fhub_run_%s.bat", req.JobID))

	defer func() {
		os.Remove(logFile)
		os.Remove(ps1File)
		os.Remove(batFile)
	}()

	// Pre-create log so the tail goroutine can open it immediately.
	if f, err := os.Create(logFile); err == nil {
		f.Close()
	}

	// Build the PowerShell invocation line based on file extension.
	ext := strings.ToLower(filepath.Ext(execPath))
	var toolLine string
	switch ext {
	case ".ps1":
		toolLine = fmt.Sprintf("& %s %s | Out-String -Stream", psSingleQuote(execPath), buildPSArgs(args))
	case ".bat", ".cmd":
		toolLine = fmt.Sprintf("cmd.exe /c %s %s", psSingleQuote(execPath), strings.Join(args, " "))
	default:
		toolLine = fmt.Sprintf("& %s %s | Out-String -Stream", psSingleQuote(execPath), buildPSArgs(args))
	}

	// PS1 wrapper: run tool, tee output to log file so both the window and
	// the dashboard can see it simultaneously.

	softLimitSnippet := ""
	if strings.ToLower(req.Priority) == "idle" {
		softLimitSnippet = "[System.Diagnostics.Process]::GetCurrentProcess().PriorityClass = 'Idle'\r\n"
	}

	ps1 := fmt.Sprintf(
		"param([switch]$Elevated)\r\n"+
			"# ForensicHub: %s [%s]\r\n"+
			"$ErrorActionPreference = 'Continue'\r\n"+
			"if ($Elevated) {\r\n"+
			"    %s%s 2>&1 | Tee-Object -FilePath %s -Append\r\n"+
			"    exit\r\n"+
			"}\r\n"+
			"try {\r\n"+
			"    %s%s 2>&1 | Tee-Object -FilePath %s\r\n"+
			"} catch {\r\n"+
			"    $msg = $_.Exception.Message\r\n"+
			"    if ($msg -match 'elevation' -or $msg -match 'supported') {\r\n"+
			"        Write-Output '[Agent] Tool requires elevation. Prompting UAC...' | Out-File -FilePath %s -Append -Encoding UTF8\r\n"+
			"        $argList = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-WindowStyle', 'Normal', '-File', $PSCommandPath, '-Elevated')\r\n"+
			"        Start-Process powershell -ArgumentList $argList -WorkingDirectory $pwd.Path -Verb RunAs -Wait\r\n"+
			"    } else {\r\n"+
			"        throw\r\n"+
			"    }\r\n"+
			"}\r\n",
		req.ToolName, req.JobID,
		softLimitSnippet, toolLine, psSingleQuote(logFile), // Elevated
		softLimitSnippet, toolLine, psSingleQuote(logFile), // Try
		psSingleQuote(logFile),                             // Catch
	)
	if err := os.WriteFile(ps1File, []byte(ps1), 0o600); err != nil {
		return fmt.Errorf("executor: write PS1 wrapper: %w", err)
	}

	// Batch launcher: open a new titled window and wait for it to exit.
	// This works identically to before, while the ps1File handles dynamic elevation.
	safeTitle := strings.ReplaceAll(req.ToolName, `"`, `'`)
	bat := fmt.Sprintf(
		"@echo off\r\nstart \"%s [%s]\" /wait powershell.exe -NoProfile -ExecutionPolicy Bypass -File \"%s\"\r\n",
		safeTitle, req.JobID, ps1File,
	)
	if err := os.WriteFile(batFile, []byte(bat), 0o600); err != nil {
		return fmt.Errorf("executor: write batch launcher: %w", err)
	}

	cmd := exec.CommandContext(ctx, "cmd.exe", "/c", batFile)
	cmd.Dir = toolDir

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("executor: start tool window: %w", err)
	}

	if err := applyHardLimitsWindows(cmd.Process.Pid, req.CPULimit, req.RAMLimit); err != nil {
		// Log the error but don't fail the execution if limit application fails
		fmt.Printf("[job:%s] warning: failed to apply hard limits: %v\n", req.JobID, err)
	}

	tailDone := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		tailFile(ctx, logFile, outputCh, tailDone)
	}()

	waitErr := cmd.Wait()
	close(tailDone)
	wg.Wait()

	if waitErr != nil {
		if ctx.Err() != nil {
			return fmt.Errorf("executor: tool stopped by operator")
		}
		return fmt.Errorf("executor: tool exited with error: %w", waitErr)
	}
	return nil
}

// psSingleQuote wraps s in PowerShell single quotes, doubling any embedded single quotes.
func psSingleQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "''") + "'"
}

// buildPSArgs single-quotes each argument and joins them with spaces.
func buildPSArgs(args []string) string {
	if len(args) == 0 {
		return ""
	}
	quoted := make([]string, len(args))
	for i, a := range args {
		quoted[i] = psSingleQuote(a)
	}
	return strings.Join(quoted, " ")
}

// tailFile reads a growing log file and forwards each new line to outputCh.
// It returns after done is closed and no further lines remain.
func tailFile(ctx context.Context, path string, outputCh chan<- string, done <-chan struct{}) {
	// Wait up to 2s for the file to become available.
	var f *os.File
	deadline := time.Now().Add(2 * time.Second)
	for {
		var err error
		f, err = os.Open(path)
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	buf := make([]byte, 64*1024)
	scanner.Buffer(buf, 1024*1024)

	tick := time.NewTicker(100 * time.Millisecond)
	defer tick.Stop()

	for {
		for scanner.Scan() {
			select {
			case outputCh <- scanner.Text():
			case <-ctx.Done():
				return
			}
		}

		select {
		case <-done:
			// Final drain after process exit.
			for scanner.Scan() {
				select {
				case outputCh <- scanner.Text():
				case <-ctx.Done():
					return
				}
			}
			return
		case <-ctx.Done():
			return
		case <-tick.C:
			// Re-scan for new lines written since last poll.
		}
	}
}

// isSysinternals checks if the filename belongs to a known Sysinternals tool that requires EULA.
func isSysinternals(filename string) bool {
	known := []string{
		"tcpview", "tcpvcon", "procdump", "pslist", "pskill", "psloggedon",
		"psexec", "psgetsid", "psinfo", "psping", "psservice", "pssuspend",
		"autoruns", "autorunsc", "procmon", "handle", "listdlls", "accesschk",
		"accessenum", "adexplorer", "bginfo", "contig", "coreinfo", "du",
		"efsinfo", "logonsessions", "ntfsinfo", "pendmoves", "pipelist",
		"portmon", "rammap", "sdelete", "shareenum", "shellrunas", "sigcheck",
		"streams", "strings", "sync", "vmmap", "volumeid", "whois",
	}
	for _, k := range known {
		if strings.HasPrefix(filename, k) {
			return true
		}
	}
	return false
}
