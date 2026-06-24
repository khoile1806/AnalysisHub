package ws

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"
)

// Spooler handles offline queuing of outbound WebSocket messages.
type Spooler struct {
	mu      sync.Mutex
	dir     string
	curFile string
}

// NewSpooler creates a new Spooler that writes to workDir/spool.
func NewSpooler(workDir string) (*Spooler, error) {
	spoolDir := filepath.Join(workDir, "spool")
	if err := os.MkdirAll(spoolDir, 0o700); err != nil {
		return nil, fmt.Errorf("create spool dir: %w", err)
	}

	return &Spooler{
		dir:     spoolDir,
		curFile: filepath.Join(spoolDir, "spool.jsonl"),
	}, nil
}

// Enqueue appends a message to the local spool file.
func (s *Spooler) Enqueue(msg outboundMsg) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	data, err := json.Marshal(msg)
	if err != nil {
		return err
	}

	f, err := os.OpenFile(s.curFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()

	if _, err := f.Write(append(data, '\n')); err != nil {
		return err
	}

	return nil
}

// DequeueAll processes all spooled messages by sending them via sendFunc.
// If sendFunc returns an error, the remaining messages are kept in the spool.
func (s *Spooler) DequeueAll(sendFunc func(msg outboundMsg) error) {
	s.mu.Lock()
	
	// If the spool file doesn't exist or is empty, nothing to do.
	info, err := os.Stat(s.curFile)
	if err != nil || info.Size() == 0 {
		s.mu.Unlock()
		return
	}

	// Rename the current spool file to a processing file.
	// This allows new messages to be enqueued to a fresh spool.jsonl while we process.
	processingFile := filepath.Join(s.dir, "spool.jsonl.processing")
	
	// Remove any leftover processing file from a previous crash
	os.Remove(processingFile)
	
	if err := os.Rename(s.curFile, processingFile); err != nil {
		log.Printf("[spooler] error renaming spool file: %v", err)
		s.mu.Unlock()
		return
	}
	s.mu.Unlock() // unlock while we process network calls

	f, err := os.Open(processingFile)
	if err != nil {
		log.Printf("[spooler] error opening processing file: %v", err)
		return
	}

	scanner := bufio.NewScanner(f)
	var failedLines [][]byte
	
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}

		var msg outboundMsg
		if err := json.Unmarshal(line, &msg); err != nil {
			log.Printf("[spooler] error unmarshaling line: %v", err)
			continue
		}

		// Try to send
		if err := sendFunc(msg); err != nil {
			log.Printf("[spooler] error sending spooled message: %v", err)
			// Network failed again, save this line and the rest of the file
			failedLines = append(failedLines, append([]byte(nil), line...))
			break
		}
	}

	// If we broke out early due to network failure, read the rest of the file
	if len(failedLines) > 0 {
		for scanner.Scan() {
			failedLines = append(failedLines, append([]byte(nil), scanner.Bytes()...))
		}
	}

	f.Close()

	// If everything succeeded, remove the processing file.
	if len(failedLines) == 0 {
		os.Remove(processingFile)
		log.Printf("[spooler] successfully flushed all spooled messages")
		return
	}

	// Re-enqueue the failed lines so they aren't lost.
	s.mu.Lock()
	defer s.mu.Unlock()
	
	// Open the current spool file (which might have new messages)
	// We prepend the failed lines back to the start of a temp file, then append the new messages,
	// but a simpler approach is just to append them to the current spool file.
	// Note: appending puts older messages after newer messages, which breaks ordering.
	// For logging/output this might be acceptable, but strict ordering is better.
	
	// To preserve order:
	// 1. Create a new file with failedLines.
	// 2. Append contents of curFile (if any) to it.
	// 3. Rename new file to curFile.
	
	// Let's use os.ReadFile and WriteFile to be safe, files are small.
	var newContents []byte
	for _, fl := range failedLines {
		newContents = append(newContents, fl...)
		newContents = append(newContents, '\n')
	}
	if existing, err := os.ReadFile(s.curFile); err == nil {
		newContents = append(newContents, existing...)
	}
	os.WriteFile(s.curFile, newContents, 0o600)
	os.Remove(processingFile)
}
