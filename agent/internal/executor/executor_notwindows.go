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

	cmd := exec.CommandContext(ctx, execPath, args...)
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
