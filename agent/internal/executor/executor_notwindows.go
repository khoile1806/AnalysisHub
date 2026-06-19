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


	finalArgs := []string{}
	finalExec := execPath

	// Soft Limit
	if req.Priority == "idle" {
		finalArgs = append([]string{"-n", "19", execPath}, args...)
		finalExec = "nice"
	} else {
		finalArgs = args
	}

	// Hard Limit via systemd-run (if needed and applicable, simplified here to use prlimit or systemd-run)
	// For a robust implementation, one would check if systemd-run is available.
	// We'll wrap with systemd-run if limits are set.
	if req.CPULimit > 0 || req.RAMLimit > 0 {
		sysRunArgs := []string{"--user", "--scope", "-q"}
		if req.CPULimit > 0 {
			sysRunArgs = append(sysRunArgs, "-p", fmt.Sprintf("CPUQuota=%d%%", req.CPULimit))
		}
		if req.RAMLimit > 0 {
			sysRunArgs = append(sysRunArgs, "-p", fmt.Sprintf("MemoryMax=%dM", req.RAMLimit))
		}
		sysRunArgs = append(sysRunArgs, finalExec)
		finalArgs = append(sysRunArgs, finalArgs...)
		finalExec = "systemd-run"
	}

	cmd := exec.CommandContext(ctx, finalExec, finalArgs...)
	cmd.Dir = toolDir

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
