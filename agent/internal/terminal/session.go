// Package terminal manages interactive PTY sessions spawned by the agent on
// behalf of admins connected through the ForensicHub web terminal.
package terminal

import (
	"context"
	"fmt"
	"runtime"
	"sync"

	"github.com/aymanbagabas/go-pty"
)

// Session wraps a single PTY and the shell process running inside it.
// Input is written via Write, output is delivered to the caller through the
// callback passed to Stream. Close terminates the shell and releases the PTY.
type Session struct {
	ID    string
	Shell string

	pty pty.Pty
	cmd *pty.Cmd

	closeOnce sync.Once
	closed    chan struct{}
}

// New opens a PTY and starts a shell. shell must be one of the values returned
// by SupportedShells() for the current OS; cols/rows set the initial window.
func New(id, shell string, cols, rows int) (*Session, error) {
	binary := shellBinary(shell)
	if binary == "" {
		return nil, fmt.Errorf("unsupported shell %q on %s", shell, runtime.GOOS)
	}

	p, err := pty.New()
	if err != nil {
		return nil, fmt.Errorf("open pty: %w", err)
	}

	if cols > 0 && rows > 0 {
		_ = p.Resize(cols, rows)
	}

	c := p.Command(binary)
	if err := c.Start(); err != nil {
		_ = p.Close()
		return nil, fmt.Errorf("start %s: %w", binary, err)
	}

	return &Session{
		ID:     id,
		Shell:  shell,
		pty:    p,
		cmd:    c,
		closed: make(chan struct{}),
	}, nil
}

// shellBinary maps a logical shell name to the concrete executable for the
// current OS. Returns empty string if the combination is not supported.
func shellBinary(shell string) string {
	switch shell {
	case "cmd":
		if runtime.GOOS == "windows" {
			return "cmd.exe"
		}
	case "powershell":
		if runtime.GOOS == "windows" {
			return "powershell.exe"
		}
	case "bash":
		if runtime.GOOS != "windows" {
			return "bash"
		}
	case "zsh":
		if runtime.GOOS != "windows" {
			return "zsh"
		}
	case "sh":
		if runtime.GOOS != "windows" {
			return "sh"
		}
	}
	return ""
}

// Write forwards stdin bytes to the shell.
func (s *Session) Write(data []byte) (int, error) {
	return s.pty.Write(data)
}

// Resize adjusts the PTY window dimensions.
func (s *Session) Resize(cols, rows int) error {
	return s.pty.Resize(cols, rows)
}

// Stream spawns two goroutines: one pumps PTY output to onData, the other waits
// for the shell to exit and then invokes onExit with the exit code.
// Cancelling ctx closes the session. Stream returns immediately.
func (s *Session) Stream(ctx context.Context, onData func([]byte), onExit func(exitCode int)) {
	readerDone := make(chan struct{})

	go func() {
		defer close(readerDone)
		buf := make([]byte, 4096)
		for {
			n, err := s.pty.Read(buf)
			if n > 0 {
				chunk := make([]byte, n)
				copy(chunk, buf[:n])
				onData(chunk)
			}
			if err != nil {
				return
			}
		}
	}()

	go func() {
		_ = s.cmd.Wait()
		code := 0
		if s.cmd.ProcessState != nil {
			code = s.cmd.ProcessState.ExitCode()
		}
		_ = s.Close() // Safely close PTY and signal closed
		<-readerDone
		onExit(code)
	}()

	go func() {
		select {
		case <-ctx.Done():
			_ = s.Close()
		case <-s.closed:
		}
	}()
}

// Close terminates the shell process and releases PTY resources. Safe to call
// multiple times.
func (s *Session) Close() error {
	var err error
	s.closeOnce.Do(func() {
		if s.cmd != nil && s.cmd.Process != nil {
			_ = s.cmd.Process.Kill()
		}
		err = s.pty.Close()
		close(s.closed)
	})
	return err
}
