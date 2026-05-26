// Package fs implements the filesystem browser handler for the agent. It
// serves list / read_file / read_folder / read_bundle operations requested by
// the backend over WebSocket. All results are streamed back as fs_response
// frames via the provided send callback.
package fs

import (
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/yeka/zip"
)

// maxPayloadBytes caps single-file and bundle raw content to 1 GiB.
const maxPayloadBytes int64 = 1 << 30 // 1 GiB

// maxListEntries caps the number of directory entries returned by handleList.
// Very large directories (e.g. C:\Windows\System32) can contain tens of
// thousands of entries; iterating d.Info() per entry on a slow FS can easily
// exceed the 30-second backend timeout. Cap at 5000 so the response is always
// fast and the agent stays responsive.
const maxListEntries = 5000

// chunkSize is the raw byte size per fs_response data frame. ~256 KiB raw
// becomes ~341 KiB base64 — well under the default 1 MiB WebSocket frame.
const chunkSize = 256 * 1024

// Entry mirrors the backend's FsEntry — kept local so agent and backend evolve
// independently.
type Entry struct {
	Name    string `json:"name"`
	Size    int64  `json:"size"`
	IsDir   bool   `json:"is_dir"`
	ModTime string `json:"mod_time"`
	Mode    string `json:"mode,omitempty"`
}

// Response is the payload emitted through the send callback. The client WS
// layer wraps it into an outbound fs_response message with the session ID.
type Response struct {
	Op        string  `json:"op"`
	Entries   []Entry `json:"entries,omitempty"`
	Truncated bool    `json:"truncated,omitempty"` // true when entry list was capped at maxListEntries
	Data      string  `json:"data,omitempty"`      // base64 chunk
	Size      int64   `json:"size,omitempty"`      // total size (first frame of read_file)
	Done      bool    `json:"done,omitempty"`
	Error     string  `json:"error,omitempty"`
}

// SendFunc is called once per fs_response frame the agent wishes to emit.
type SendFunc func(Response) error

// Request describes a single fs operation.
type Request struct {
	Op    string   // "list" | "read_file" | "read_folder" | "read_bundle"
	Path  string   // single path (list / read_file / read_folder)
	Paths []string // multi-path (read_bundle)
}

// Handle dispatches req to the appropriate operation. Errors are delivered
// through send as fs_response{error: ...}; the returned error is non-nil only
// when send itself fails (connection dead), so the caller can stop early.
func Handle(req Request, send SendFunc) error {
	switch req.Op {
	case "list":
		return handleList(req.Path, send)
	case "read_file":
		return handleReadFile(req.Path, send)
	case "read_folder":
		return handleReadFolder(req.Path, send)
	case "read_bundle":
		return handleReadBundle(req.Paths, send)
	default:
		return send(Response{Op: req.Op, Error: "unknown fs op: " + req.Op, Done: true})
	}
}

func cleanAbs(p string) (string, error) {
	if p == "" {
		return "", fmt.Errorf("empty path")
	}
	// Strip a surrounding quote a user may have pasted from a file-manager.
	p = strings.Trim(p, `"'`)
	// Go's Clean resolves "..", so any remaining "../" component after Clean
	// means the original was malformed (e.g. "/foo/../../bar").
	cleaned := filepath.Clean(filepath.FromSlash(p))
	// A literal ".." after clean only happens on relative paths going above cwd.
	if strings.HasPrefix(cleaned, "..") {
		return "", fmt.Errorf("path escapes its root")
	}
	return cleaned, nil
}

func handleList(raw string, send SendFunc) error {
	path, err := cleanAbs(raw)
	if err != nil {
		return send(Response{Op: "list", Error: err.Error(), Done: true})
	}
	// For root listings on Windows (e.g. "C:\\") we need the trailing separator
	// or os.ReadDir treats "C:" as the current dir on drive C.
	if len(path) == 2 && path[1] == ':' {
		path += string(filepath.Separator)
	}
	raws, err := os.ReadDir(path)
	if err != nil {
		return send(Response{Op: "list", Error: err.Error(), Done: true})
	}
	truncated := len(raws) > maxListEntries
	if truncated {
		raws = raws[:maxListEntries]
	}
	entries := make([]Entry, 0, len(raws))
	for _, d := range raws {
		info, err := d.Info()
		if err != nil {
			continue
		}
		entries = append(entries, Entry{
			Name:    d.Name(),
			Size:    info.Size(),
			IsDir:   d.IsDir(),
			ModTime: info.ModTime().UTC().Format(time.RFC3339),
			Mode:    info.Mode().String(),
		})
	}
	return send(Response{Op: "list", Entries: entries, Truncated: truncated, Done: true})
}

func handleReadFile(raw string, send SendFunc) error {
	path, err := cleanAbs(raw)
	if err != nil {
		return send(Response{Op: "read_file", Error: err.Error(), Done: true})
	}
	info, err := os.Stat(path)
	if err != nil {
		return send(Response{Op: "read_file", Error: err.Error(), Done: true})
	}
	if info.IsDir() {
		return send(Response{Op: "read_file", Error: "path is a directory", Done: true})
	}
	if info.Size() > maxPayloadBytes {
		return send(Response{Op: "read_file", Error: "file exceeds 1GB limit", Done: true})
	}
	f, err := os.Open(path)
	if err != nil {
		return send(Response{Op: "read_file", Error: err.Error(), Done: true})
	}
	defer f.Close()

	first := true
	buf := make([]byte, chunkSize)
	for {
		n, rerr := f.Read(buf)
		if n > 0 {
			resp := Response{Op: "read_file", Data: base64.StdEncoding.EncodeToString(buf[:n])}
			if first {
				resp.Size = info.Size()
				first = false
			}
			if err := send(resp); err != nil {
				return err
			}
		}
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			return send(Response{Op: "read_file", Error: rerr.Error(), Done: true})
		}
	}
	return send(Response{Op: "read_file", Done: true})
}

func handleReadFolder(raw string, send SendFunc) error {
	path, err := cleanAbs(raw)
	if err != nil {
		return send(Response{Op: "read_folder", Error: err.Error(), Done: true})
	}
	info, err := os.Stat(path)
	if err != nil {
		return send(Response{Op: "read_folder", Error: err.Error(), Done: true})
	}
	if !info.IsDir() {
		return send(Response{Op: "read_folder", Error: "path is not a directory", Done: true})
	}
	root := path
	rootName := filepath.Base(root)
	return streamZip("read_folder", send, func(zw *zip.Writer, counter *int64) error {
		return walkAndZip(zw, counter, root, rootName)
	})
}

func handleReadBundle(paths []string, send SendFunc) error {
	if len(paths) == 0 {
		return send(Response{Op: "read_bundle", Error: "no paths", Done: true})
	}
	cleaned := make([]string, 0, len(paths))
	for _, p := range paths {
		c, err := cleanAbs(p)
		if err != nil {
			return send(Response{Op: "read_bundle", Error: err.Error() + ": " + p, Done: true})
		}
		cleaned = append(cleaned, c)
	}
	return streamZip("read_bundle", send, func(zw *zip.Writer, counter *int64) error {
		for _, p := range cleaned {
			info, err := os.Stat(p)
			if err != nil {
				return err
			}
			base := filepath.Base(p)
			if info.IsDir() {
				if err := walkAndZip(zw, counter, p, base); err != nil {
					return err
				}
			} else {
				if err := zipSingleFile(zw, counter, p, base, info); err != nil {
					return err
				}
			}
		}
		return nil
	})
}

// streamZip builds a zip via a pipe and streams chunks as fs_response
// frames. writeFn contributes zip entries; it is free to return an error which
// will be surfaced as an fs_response{error:...}.
func streamZip(op string, send SendFunc, writeFn func(zw *zip.Writer, counter *int64) error) error {
	pr, pw := io.Pipe()
	var counter int64
	writeErrCh := make(chan error, 1)

	// Writer goroutine — produces the zip stream.
	go func() {
		zw := zip.NewWriter(pw)
		err := writeFn(zw, &counter)
		_ = zw.Close()
		if err != nil {
			_ = pw.CloseWithError(err)
			writeErrCh <- err
			return
		}
		_ = pw.Close()
		writeErrCh <- nil
	}()

	buf := make([]byte, chunkSize)
	for {
		n, rerr := pr.Read(buf)
		if n > 0 {
			resp := Response{Op: op, Data: base64.StdEncoding.EncodeToString(buf[:n])}
			if err := send(resp); err != nil {
				_ = pr.CloseWithError(err)
				return err
			}
		}
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			return send(Response{Op: op, Error: rerr.Error(), Done: true})
		}
	}
	if err := <-writeErrCh; err != nil {
		return send(Response{Op: op, Error: err.Error(), Done: true})
	}
	return send(Response{Op: op, Done: true})
}

// walkAndZip recursively adds root (directory) into zw, entries named relative
// to prefix so the extracted archive preserves folder structure. Symlinks are
// added as symlink entries (not followed) to avoid escaping root.
func walkAndZip(zw *zip.Writer, counter *int64, root, prefix string) error {
	return filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // skip unreadable entries rather than aborting the whole archive
		}
		rel, rerr := filepath.Rel(root, path)
		if rerr != nil {
			return nil
		}
		name := prefix
		if rel != "." {
			name = filepath.ToSlash(filepath.Join(prefix, rel))
		}
		return zipEntry(zw, counter, path, name, info)
	})
}

func zipSingleFile(zw *zip.Writer, counter *int64, path, name string, info os.FileInfo) error {
	return zipEntry(zw, counter, path, name, info)
}

func zipEntry(zw *zip.Writer, counter *int64, path, name string, info os.FileInfo) error {
	hdr, err := zip.FileInfoHeader(info)
	if err != nil {
		return nil
	}
	hdr.Name = name
	if info.IsDir() {
		hdr.Name = name + "/"
	}
	hdr.Method = zip.Deflate
	hdr.SetPassword("infected")
	hdr.SetEncryptionMethod(zip.StandardEncryption)

	writer, err := zw.CreateHeader(hdr)
	if err != nil {
		return err
	}

	if info.Mode()&os.ModeSymlink != 0 {
		if target, err := os.Readlink(path); err == nil {
			_, err = io.WriteString(writer, target)
			return err
		}
		return nil
	}

	if !info.Mode().IsRegular() {
		return nil
	}
	*counter += info.Size()
	if *counter > maxPayloadBytes {
		return fmt.Errorf("bundle exceeds 1GB limit")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	_, err = io.Copy(writer, f)
	return err
}
