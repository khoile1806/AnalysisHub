//go:build windows

package executor

import (
	"bufio"
	"context"
	"debug/pe"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/windows"
)

// peSubsystemWindowsGUI is the PE OptionalHeader.Subsystem value for a GUI app
// (IMAGE_SUBSYSTEM_WINDOWS_GUI). Console apps are 3 (CUI).
const peSubsystemWindowsGUI = 2

// isGUIExecutable reports whether the .exe is a Windows GUI-subsystem program
// (e.g. Process Explorer, TCPView GUI, mbar) rather than a console tool. GUI
// tools must be launched with their own window — capturing their stdout in a
// pipeline (as we do for CLI tools) leaves the window invisible.
func isGUIExecutable(path string) bool {
	if !strings.EqualFold(filepath.Ext(path), ".exe") {
		return false
	}
	f, err := pe.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	switch oh := f.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		return oh.Subsystem == peSubsystemWindowsGUI
	case *pe.OptionalHeader64:
		return oh.Subsystem == peSubsystemWindowsGUI
	}
	return false
}

// isForcedConsoleTool reports whether a tool that LOOKS like a GUI app (GUI PE
// subsystem) is actually a headless CLI collector that must run on the console
// path — captured, waited-on and with its quiet flag — rather than being opened
// as an interactive window. Memory-acquisition tools are the common case.
func isForcedConsoleTool(baseName string) bool {
	for _, p := range []string{"dumpit", "winpmem", "magnetrance", "magnetramcapture", "ramcapture", "fdpro"} {
		if strings.HasPrefix(baseName, p) {
			return true
		}
	}
	return false
}

// launchGUITool opens a GUI tool in its own interactive window via Start-Process
// (ShellExecute), so it appears on the operator's desktop and — for tools whose
// manifest requests Administrator — triggers a single UAC instead of failing.
// It does NOT capture stdout or wait for the window to close, so a batch run
// isn't blocked by an interactive tool.
func launchGUITool(execPath string, args []string, toolDir string, outputCh chan<- string) error {
	send := func(s string) {
		select {
		case outputCh <- s:
		default:
		}
	}
	send("[Agent] GUI tool detected: " + filepath.Base(execPath))
	send("[Agent] Opening its window — interact with it directly, then close it when finished.")

	cmdStr := "Start-Process -FilePath " + psSingleQuote(execPath)
	if len(args) > 0 {
		quoted := make([]string, len(args))
		for i, a := range args {
			quoted[i] = psSingleQuote(a)
		}
		cmdStr += " -ArgumentList " + strings.Join(quoted, ",")
	}
	cmdStr += " -WorkingDirectory " + psSingleQuote(toolDir)

	cmd := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", cmdStr)
	cmd.Dir = toolDir
	out, err := cmd.CombinedOutput()
	if err != nil {
		send("[Agent] Failed to launch GUI tool: " + strings.TrimSpace(string(out)))
		return fmt.Errorf("executor: launch GUI tool: %w", err)
	}
	send("[Agent] GUI launched. This job is complete; the tool runs in its own window — close it when done.")
	return nil
}

// runToolProcess launches execPath in a new console window on Windows.
// A PowerShell wrapper uses Tee-Object to write output both to the visible
// window and to a temp log file; this goroutine tails that log file and
// streams lines to outputCh so the dashboard receives real-time output.
func runToolProcess(ctx context.Context, execPath string, args []string, req JobRequest, toolDir string, outputCh chan<- string) error {
	baseName := strings.ToLower(filepath.Base(execPath))

	// GUI tools (Process Explorer, TCPView/Autoruns GUI, mbar, …) must open their
	// own window. Detect by PE subsystem and launch detached FIRST — before any
	// CLI-oriented arg injection (-AcceptEula / /Q), which some GUI tools (e.g.
	// Autoruns) mistake for an input file and respond to with a usage dialog.
	//
	// EXCEPTION: some collectors ship as GUI-subsystem PEs but are really headless
	// (DumpIt does memory acquisition with /Q and writes a dump file — no window
	// needed). Route those down the console path (exactly like Loki) so /Q is
	// added, output is captured and we WAIT for completion; otherwise they take
	// the GUI path, pop their own interactive window and never finish.
	if !isForcedConsoleTool(baseName) && isGUIExecutable(execPath) {
		return launchGUITool(execPath, args, toolDir, outputCh)
	}

	// Automatically append -AcceptEula for known Sysinternals tools to prevent GUI hangs.
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
			"# AnalysisHub: %s [%s]\r\n"+
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
		psSingleQuote(logFile), // Catch
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

	// Launch the cmd.exe launcher SUSPENDED so we can drop it into a job object
	// BEFORE it spawns the powershell window and the real tool. Job membership and
	// the CPU/RAM caps are inherited by every descendant, so the whole
	// cmd -> powershell -> tool tree is governed — fixing the previous bug where
	// the limit (and a "stop") only reached the transient cmd.exe launcher.
	//
	// We deliberately do NOT use exec.CommandContext here: its ctx-cancel only
	// kills cmd.exe and would orphan powershell/the tool. Instead we kill the
	// entire tree via TerminateJobObject below.
	cmd := exec.Command("cmd.exe", "/c", batFile)
	// Run from the executable's OWN directory, not the tool root. Multi-file tools
	// (Comae/DumpIt, Redline's RunRedlineAudit.bat, KAPE, …) live in a subfolder
	// with driver/collector files they reference relatively; running from the tool
	// root makes them fail instantly. For single-file tools this is still toolDir.
	cmd.Dir = filepath.Dir(execPath)
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: windows.CREATE_SUSPENDED}

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("executor: start tool window: %w", err)
	}

	// A job is created even when no explicit limits are set, so we can always
	// terminate the whole tree atomically. job==0 means the (best-effort) setup
	// failed and we degrade to limiting/killing only the launcher.
	var job windows.Handle
	if j, err := createLimitedJob(req.CPULimit, req.RAMLimit); err != nil {
		fmt.Printf("[job:%s] warning: job object setup failed (limits/tree-kill disabled): %v\n", req.JobID, err)
	} else if err := assignProcessToJob(j, cmd.Process.Pid); err != nil {
		fmt.Printf("[job:%s] warning: assign to job failed (limits/tree-kill disabled): %v\n", req.JobID, err)
		windows.CloseHandle(j)
	} else {
		job = j
	}

	// Resume regardless of job outcome — a suspended process left unresumed hangs
	// forever. On resume failure we tear everything down and fail the job.
	if err := resumeProcess(cmd.Process.Pid); err != nil {
		if job != 0 {
			windows.TerminateJobObject(job, 1)
			windows.CloseHandle(job)
		}
		_ = cmd.Process.Kill()
		return fmt.Errorf("executor: resume tool process: %w", err)
	}

	// Operator "stop" (ctx cancel) → kill the whole tree, not just the launcher.
	doneWatch := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			if job != 0 {
				windows.TerminateJobObject(job, 1)
			} else {
				_ = cmd.Process.Kill()
			}
		case <-doneWatch:
		}
	}()

	tailDone := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		tailFile(ctx, logFile, outputCh, tailDone)
	}()

	waitErr := cmd.Wait()
	close(doneWatch)
	close(tailDone)
	wg.Wait()
	if job != 0 {
		windows.CloseHandle(job)
	}

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
