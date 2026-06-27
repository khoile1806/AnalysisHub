//go:build !windows

package parser

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// ScanNetwork enumerates TCP/UDP connections from /proc/net (Linux), attributing
// each socket to its owning process via the inode → /proc/<pid>/fd map. Returns
// an empty result where /proc/net is unavailable (e.g. macOS). Linux has no
// uniform resolver cache, so DNS is left empty.
func ScanNetwork() (*NetworkResult, error) {
	res := &NetworkResult{Connections: []Connection{}, DNS: []DNSCacheEntry{}}
	if _, err := os.Stat("/proc/net/tcp"); err != nil {
		return res, nil
	}
	inodePID := socketInodeMap()
	for _, t := range []struct{ file, proto string }{
		{"/proc/net/tcp", "TCP"}, {"/proc/net/tcp6", "TCP6"},
		{"/proc/net/udp", "UDP"}, {"/proc/net/udp6", "UDP6"},
	} {
		res.Connections = append(res.Connections, parseProcNet(t.file, t.proto, inodePID)...)
	}
	return res, nil
}

// CollectConnectionsJSON returns the connection list as a JSON string (used by
// the realtime/netconn paths).
func CollectConnectionsJSON() (string, error) {
	r, err := ScanNetwork()
	if err != nil {
		return "[]", err
	}
	b, err := json.Marshal(r.Connections)
	if err != nil {
		return "[]", err
	}
	return string(b), nil
}

var tcpStates = map[string]string{
	"01": "ESTABLISHED", "02": "SYN_SENT", "03": "SYN_RECV", "04": "FIN_WAIT1",
	"05": "FIN_WAIT2", "06": "TIME_WAIT", "07": "CLOSE", "08": "CLOSE_WAIT",
	"09": "LAST_ACK", "0A": "LISTEN", "0B": "CLOSING",
}

// parseProcNet parses one /proc/net/{tcp,tcp6,udp,udp6} table.
func parseProcNet(path, proto string, inodePID map[string]procRef) []Connection {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	v6 := strings.HasSuffix(proto, "6")
	udp := strings.HasPrefix(proto, "UDP")
	var out []Connection
	lines := strings.Split(string(b), "\n")
	for i, line := range lines {
		if i == 0 { // header
			continue
		}
		f := strings.Fields(line)
		if len(f) < 10 {
			continue
		}
		lip, lport := parseHexEndpoint(f[1], v6)
		rip, rport := parseHexEndpoint(f[2], v6)
		state := tcpStates[strings.ToUpper(f[3])]
		if udp {
			state = ""
		}
		inode := f[9]
		ref := inodePID[inode]

		dir := "outbound"
		if state == "LISTEN" || (udp && rip == "0.0.0.0") || rport == 0 {
			dir = "listen"
		}
		if rip == "127.0.0.1" || rip == "::1" || lip == rip {
			dir = "local"
		}

		out = append(out, Connection{
			Proto: proto, LocalAddr: lip, LocalPort: lport,
			RemoteAddr: rip, RemotePort: rport, State: state,
			PID: ref.pid, Process: ref.name, ImagePath: ref.exe, Direction: dir,
		})
	}
	return out
}

// parseHexEndpoint decodes a "HEXADDR:HEXPORT" field from /proc/net.
func parseHexEndpoint(s string, v6 bool) (string, int) {
	parts := strings.SplitN(s, ":", 2)
	if len(parts) != 2 {
		return "", 0
	}
	port, _ := strconv.ParseInt(parts[1], 16, 32)
	if v6 {
		return hexToIPv6(parts[0]), int(port)
	}
	return hexToIPv4(parts[0]), int(port)
}

func hexToIPv4(h string) string {
	b, err := hex.DecodeString(h)
	if err != nil || len(b) != 4 {
		return ""
	}
	return fmt.Sprintf("%d.%d.%d.%d", b[3], b[2], b[1], b[0]) // stored little-endian
}

func hexToIPv6(h string) string {
	b, err := hex.DecodeString(h)
	if err != nil || len(b) != 16 {
		return ""
	}
	ip := make(net.IP, 16)
	for i := 0; i < 16; i += 4 { // each 4-byte word is little-endian
		ip[i], ip[i+1], ip[i+2], ip[i+3] = b[i+3], b[i+2], b[i+1], b[i]
	}
	return ip.String()
}

type procRef struct {
	pid  int
	name string
	exe  string
}

// socketInodeMap builds socket-inode → owning process by scanning every
// /proc/<pid>/fd symlink for "socket:[inode]" targets.
func socketInodeMap() map[string]procRef {
	m := map[string]procRef{}
	procs, err := os.ReadDir("/proc")
	if err != nil {
		return m
	}
	for _, p := range procs {
		pid, perr := strconv.Atoi(p.Name())
		if perr != nil {
			continue
		}
		fdDir := filepath.Join("/proc", p.Name(), "fd")
		fds, derr := os.ReadDir(fdDir)
		if derr != nil {
			continue
		}
		var ref *procRef
		for _, fd := range fds {
			target, lerr := os.Readlink(filepath.Join(fdDir, fd.Name()))
			if lerr != nil || !strings.HasPrefix(target, "socket:[") {
				continue
			}
			inode := strings.TrimSuffix(strings.TrimPrefix(target, "socket:["), "]")
			if ref == nil {
				name := strings.TrimSpace(string(mustRead(filepath.Join("/proc", p.Name(), "comm"))))
				exe, _ := os.Readlink(filepath.Join("/proc", p.Name(), "exe"))
				ref = &procRef{pid: pid, name: name, exe: exe}
			}
			m[inode] = *ref
		}
	}
	return m
}

func mustRead(path string) []byte {
	b, _ := os.ReadFile(path)
	return b
}
