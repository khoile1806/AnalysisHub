//go:build !windows

package executor

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sync"
)

// runToolProcess runs execPath directly on Linux/macOS, streaming stdout and
// stderr to outputCh in real time via an io.Pipe.
func runToolProcess(ctx context.Context, execPath string, args []string, req JobRequest, toolDir string, outputCh chan<- string) error {
	if err := os.Chmod(execPath, 0o755); err != nil {
		return fmt.Errorf("executor: chmod %s: %w", execPath, err)
	}

	finalArgs := args
	finalExec := execPath

	// Soft limit: lowest scheduling priority for idle-priority jobs.
	if req.Priority == "idle" {
		finalArgs = append([]string{"-n", "19", execPath}, args...)
		finalExec = "nice"
	}

	// Hard limits: best-effort cgroup/rlimit wrapping that NEVER blocks execution
	// when a limiter is missing.
	finalExec, finalArgs, limitWarns := applyResourceLimitsUnix(finalExec, finalArgs, req)

	cmd := exec.CommandContext(ctx, finalExec, finalArgs...)
	cmd.Dir = toolDir
	for _, w := range limitWarns {
		select {
		case outputCh <- w:
		default:
		}
	}

	pr, pw := io.Pipe()
	cmd.Stdout = io.MultiWriter(os.Stdout, pw)
	cmd.Stderr = io.MultiWriter(os.Stderr, pw)

	if err := cmd.Start(); err != nil {
		pw.Close()
		return fmt.Errorf("executor: start %s: %w", execPath, err)
	}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer pr.Close()

		scanner := bufio.NewScanner(pr)
		buf := make([]byte, 64*1024)
		scanner.Buffer(buf, 1024*1024)

		dropped := 0
		for scanner.Scan() {
			line := scanner.Text()
			if dropped > 0 {
				select {
				case outputCh <- fmt.Sprintf("[Agent] ... %d lines dropped due to high volume ...", dropped):
					dropped = 0
				default:
				}
			}
			select {
			case outputCh <- line:
			case <-ctx.Done():
				return
			default:
				dropped++
			}
		}
		if dropped > 0 {
			select {
			case outputCh <- fmt.Sprintf("[Agent] ... %d lines dropped due to high volume ...", dropped):
			default:
			}
		}
	}()

	err := cmd.Wait()
	pw.Close()
	wg.Wait()
	pr.Close()

	if err != nil {
		if ctx.Err() != nil {
			return fmt.Errorf("executor: tool stopped by operator")
		}
		return fmt.Errorf("executor: tool exited with error: %w", err)
	}
	return nil
}

// applyResourceLimitsUnix wraps (execPath,args) with the best available hard-limit
// mechanism, in order of fidelity:
//
//	systemd-run  -> real cgroup CPU quota + memory max (preferred)
//	prlimit      -> address-space (RAM) ceiling only; CPU% not enforceable
//	none         -> run unwrapped
//
// It NEVER makes execution depend on a limiter being installed — if no limiter is
// present the tool still runs and a warning is returned for operator visibility,
// rather than failing the job outright (the previous behaviour hard-failed any
// limited job on hosts without systemd-run). Returned warnings are streamed to
// the job output by the caller.
func applyResourceLimitsUnix(execPath string, args []string, req JobRequest) (string, []string, []string) {
	if req.CPULimit <= 0 && req.RAMLimit <= 0 {
		return execPath, args, nil
	}
	var warns []string

	if _, err := exec.LookPath("systemd-run"); err == nil {
		// --collect reaps the transient scope on exit; --scope runs synchronously.
		sysArgs := []string{"--user", "--scope", "--collect", "-q"}
		if req.CPULimit > 0 {
			sysArgs = append(sysArgs, "-p", fmt.Sprintf("CPUQuota=%d%%", req.CPULimit))
		}
		if req.RAMLimit > 0 {
			sysArgs = append(sysArgs, "-p", fmt.Sprintf("MemoryMax=%dM", req.RAMLimit))
		}
		sysArgs = append(sysArgs, execPath)
		sysArgs = append(sysArgs, args...)
		return "systemd-run", sysArgs, warns
	}

	if req.RAMLimit > 0 {
		if _, err := exec.LookPath("prlimit"); err == nil {
			// prlimit sets the rlimit then execs; children inherit the cap.
			preArgs := []string{fmt.Sprintf("--as=%d", req.RAMLimit*1024*1024), execPath}
			preArgs = append(preArgs, args...)
			if req.CPULimit > 0 {
				warns = append(warns, fmt.Sprintf("[Agent] systemd-run unavailable: enforcing RAM cap %dMB via prlimit; CPU quota (%d%%) NOT enforced", req.RAMLimit, req.CPULimit))
			} else {
				warns = append(warns, fmt.Sprintf("[Agent] systemd-run unavailable: enforcing RAM cap %dMB via prlimit", req.RAMLimit))
			}
			return "prlimit", preArgs, warns
		}
	}

	warns = append(warns, "[Agent] No cgroup limiter (systemd-run/prlimit) available — CPU/RAM hard limits NOT enforced for this tool")
	return execPath, args, warns
}
