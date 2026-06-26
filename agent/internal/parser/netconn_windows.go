//go:build windows

package parser

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Native network-connection enumeration — the equivalent of Sysinternals
// TCPView / NetworkMiner's host & session views, built directly on the Windows
// IP Helper API (GetExtendedTcpTable / GetExtendedUdpTable). Runs WITHOUT
// elevation for the local machine's own sockets, so it is safe to stream live.

var (
	iphlpapi                = windows.NewLazySystemDLL("iphlpapi.dll")
	procGetExtendedTcpTable = iphlpapi.NewProc("GetExtendedTcpTable")
	procGetExtendedUdpTable = iphlpapi.NewProc("GetExtendedUdpTable")
)

const (
	afInet  = 2
	afInet6 = 23

	tcpTableOwnerPidAll = 5 // TCP_TABLE_OWNER_PID_ALL
	udpTableOwnerPid    = 1 // UDP_TABLE_OWNER_PID

	procQueryLimitedInfo = 0x1000 // PROCESS_QUERY_LIMITED_INFORMATION
)

// MIB_TCP_STATE → human-readable.
var tcpStates = map[uint32]string{
	1: "CLOSED", 2: "LISTENING", 3: "SYN_SENT", 4: "SYN_RCVD", 5: "ESTABLISHED",
	6: "FIN_WAIT1", 7: "FIN_WAIT2", 8: "CLOSE_WAIT", 9: "CLOSING", 10: "LAST_ACK",
	11: "TIME_WAIT", 12: "DELETE_TCB",
}

// ── Reverse-DNS cache (shared, async so live ticks never block on DNS) ──────── //

var (
	dnsCacheMu sync.Mutex
	dnsCache   = map[string]string{}
	dnsPending = map[string]bool{}
)

// cachedReverse returns a cached PTR for ip, kicking off a background lookup on
// the first miss. The live collector uses this so a tick never blocks on DNS.
func cachedReverse(ip string) string {
	dnsCacheMu.Lock()
	if h, ok := dnsCache[ip]; ok {
		dnsCacheMu.Unlock()
		return h
	}
	if dnsPending[ip] {
		dnsCacheMu.Unlock()
		return ""
	}
	dnsPending[ip] = true
	dnsCacheMu.Unlock()

	go func() {
		host := resolveHost(ip)
		dnsCacheMu.Lock()
		dnsCache[ip] = host // cache even empty results to avoid lookup storms
		delete(dnsPending, ip)
		dnsCacheMu.Unlock()
	}()
	return ""
}

func resolveHost(ip string) string {
	ctx, cancel := context.WithTimeout(context.Background(), 800*time.Millisecond)
	defer cancel()
	names, err := net.DefaultResolver.LookupAddr(ctx, ip)
	if err != nil || len(names) == 0 {
		return ""
	}
	return strings.TrimSuffix(names[0], ".")
}

// isRoutable reports whether ip is a public address worth reverse-resolving.
func isRoutable(ip net.IP) bool {
	if ip == nil || ip.IsUnspecified() || ip.IsLoopback() ||
		ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsMulticast() || ip.IsPrivate() {
		return false
	}
	return true
}

// ── Public API ──────────────────────────────────────────────────────────────── //

// ScanNetwork returns a full, enriched snapshot: connections with owning
// process + image path + reverse DNS, plus the DNS resolver cache. Used by the
// one-shot "Scan" button.
func ScanNetwork() (*NetworkResult, error) {
	conns := collectConnections(true)
	return &NetworkResult{Connections: conns, DNS: collectDNSCache()}, nil
}

// CollectConnectionsJSON returns a lightweight connection list (process name +
// cached reverse DNS only, no image-path resolution) as JSON — cheap enough to
// stream every couple of seconds for the live view.
func CollectConnectionsJSON() (string, error) {
	b, err := json.Marshal(collectConnections(false))
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// ── Collection ──────────────────────────────────────────────────────────────── //

func collectConnections(details bool) []Connection {
	procMap := processNameMap()
	pathCache := map[uint32]string{}

	var out []Connection
	out = append(out, readTCP(afInet, procMap)...)
	out = append(out, readTCP(afInet6, procMap)...)
	out = append(out, readUDP(afInet, procMap)...)
	out = append(out, readUDP(afInet6, procMap)...)

	for i := range out {
		c := &out[i]
		// Reverse DNS for routable remotes (cached / async).
		if c.RemoteAddr != "" {
			if ip := net.ParseIP(c.RemoteAddr); isRoutable(ip) {
				c.RemoteHost = cachedReverse(c.RemoteAddr)
			}
		}
		// Image path only in the heavy one-shot scan.
		if details && c.PID > 0 {
			if p, ok := pathCache[uint32(c.PID)]; ok {
				c.ImagePath = p
			} else {
				p = imagePath(uint32(c.PID))
				pathCache[uint32(c.PID)] = p
				c.ImagePath = p
			}
		}
	}

	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Process != out[j].Process {
			return strings.ToLower(out[i].Process) < strings.ToLower(out[j].Process)
		}
		return out[i].RemoteAddr < out[j].RemoteAddr
	})
	return out
}

func getExtendedTable(proc *windows.LazyProc, af, class int) []byte {
	var size uint32
	// First call with a nil buffer returns the required size.
	proc.Call(0, uintptr(unsafe.Pointer(&size)), 0, uintptr(af), uintptr(class), 0)
	if size == 0 {
		return nil
	}
	buf := make([]byte, size)
	r, _, _ := proc.Call(uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)), 0, uintptr(af), uintptr(class), 0)
	if r != 0 {
		return nil
	}
	return buf
}

// portBE decodes a port stored as a network-order WORD in the low bytes of a
// DWORD field (the IP Helper table layout).
func portBE(b []byte) int {
	if len(b) < 2 {
		return 0
	}
	return int(b[0])<<8 | int(b[1])
}

func readTCP(af int, procMap map[uint32]string) []Connection {
	buf := getExtendedTable(procGetExtendedTcpTable, af, tcpTableOwnerPidAll)
	if len(buf) < 4 {
		return nil
	}
	n := binary.LittleEndian.Uint32(buf[0:4])
	rows := buf[4:]
	var out []Connection
	if af == afInet {
		const rowSize = 24 // state, local addr, local port, remote addr, remote port, pid
		for i := 0; i < int(n); i++ {
			off := i * rowSize
			if off+rowSize > len(rows) {
				break
			}
			r := rows[off : off+rowSize]
			state := binary.LittleEndian.Uint32(r[0:4])
			pid := binary.LittleEndian.Uint32(r[20:24])
			lAddr := net.IP(append([]byte(nil), r[4:8]...)).String()
			lPort := portBE(r[8:10])
			rAddr := net.IP(append([]byte(nil), r[12:16]...)).String()
			rPort := portBE(r[16:18])
			out = append(out, mkTCP("TCP", state, lAddr, lPort, rAddr, rPort, pid, procMap))
		}
	} else {
		const rowSize = 56
		for i := 0; i < int(n); i++ {
			off := i * rowSize
			if off+rowSize > len(rows) {
				break
			}
			r := rows[off : off+rowSize]
			lAddr := net.IP(append([]byte(nil), r[0:16]...)).String()
			lPort := portBE(r[20:22])
			rAddr := net.IP(append([]byte(nil), r[24:40]...)).String()
			rPort := portBE(r[44:46])
			state := binary.LittleEndian.Uint32(r[48:52])
			pid := binary.LittleEndian.Uint32(r[52:56])
			out = append(out, mkTCP("TCP6", state, lAddr, lPort, rAddr, rPort, pid, procMap))
		}
	}
	return out
}

func readUDP(af int, procMap map[uint32]string) []Connection {
	buf := getExtendedTable(procGetExtendedUdpTable, af, udpTableOwnerPid)
	if len(buf) < 4 {
		return nil
	}
	n := binary.LittleEndian.Uint32(buf[0:4])
	rows := buf[4:]
	var out []Connection
	if af == afInet {
		const rowSize = 12 // local addr, local port, pid
		for i := 0; i < int(n); i++ {
			off := i * rowSize
			if off+rowSize > len(rows) {
				break
			}
			r := rows[off : off+rowSize]
			lAddr := net.IP(append([]byte(nil), r[0:4]...)).String()
			lPort := portBE(r[4:6])
			pid := binary.LittleEndian.Uint32(r[8:12])
			out = append(out, mkUDP("UDP", lAddr, lPort, pid, procMap))
		}
	} else {
		const rowSize = 28 // local addr[16], scope, local port, pid
		for i := 0; i < int(n); i++ {
			off := i * rowSize
			if off+rowSize > len(rows) {
				break
			}
			r := rows[off : off+rowSize]
			lAddr := net.IP(append([]byte(nil), r[0:16]...)).String()
			lPort := portBE(r[20:22])
			pid := binary.LittleEndian.Uint32(r[24:28])
			out = append(out, mkUDP("UDP6", lAddr, lPort, pid, procMap))
		}
	}
	return out
}

func mkTCP(proto string, state uint32, lAddr string, lPort int, rAddr string, rPort int, pid uint32, procMap map[uint32]string) Connection {
	st := tcpStates[state]
	if st == "" {
		st = fmt.Sprintf("STATE_%d", state)
	}
	dir := "outbound"
	if st == "LISTENING" {
		dir = "listen"
		rAddr, rPort = "", 0
	}
	return Connection{
		Proto: proto, LocalAddr: lAddr, LocalPort: lPort,
		RemoteAddr: rAddr, RemotePort: rPort, State: st,
		PID: int(pid), Process: procMap[pid], Direction: dir,
	}
}

func mkUDP(proto, lAddr string, lPort int, pid uint32, procMap map[uint32]string) Connection {
	return Connection{
		Proto: proto, LocalAddr: lAddr, LocalPort: lPort,
		State: "", PID: int(pid), Process: procMap[pid], Direction: "listen",
	}
}

// ── Process name / image path ───────────────────────────────────────────────── //

func processNameMap() map[uint32]string {
	m := map[uint32]string{0: "System Idle", 4: "System"}
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return m
	}
	defer windows.CloseHandle(snap)
	var pe windows.ProcessEntry32
	pe.Size = uint32(unsafe.Sizeof(pe))
	if err := windows.Process32First(snap, &pe); err != nil {
		return m
	}
	for {
		m[pe.ProcessID] = windows.UTF16ToString(pe.ExeFile[:])
		if err := windows.Process32Next(snap, &pe); err != nil {
			break
		}
	}
	return m
}

func imagePath(pid uint32) string {
	if pid == 0 {
		return ""
	}
	h, err := windows.OpenProcess(procQueryLimitedInfo, false, pid)
	if err != nil {
		return ""
	}
	defer windows.CloseHandle(h)
	buf := make([]uint16, 1024)
	size := uint32(len(buf))
	if err := windows.QueryFullProcessImageName(h, 0, &buf[0], &size); err != nil {
		return ""
	}
	return windows.UTF16ToString(buf[:size])
}

// ── DNS resolver cache (ipconfig /displaydns) ───────────────────────────────── //

func collectDNSCache() []DNSCacheEntry {
	out, err := exec.Command("ipconfig", "/displaydns").Output()
	if err != nil {
		return nil
	}
	var entries []DNSCacheEntry
	var cur DNSCacheEntry
	flush := func() {
		if cur.Name != "" && cur.Data != "" {
			entries = append(entries, cur)
		}
		cur = DNSCacheEntry{}
	}
	for _, raw := range strings.Split(strings.ReplaceAll(string(out), "\r\n", "\n"), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "---") {
			continue
		}
		idx := strings.Index(line, ":")
		if idx < 0 {
			continue
		}
		key := strings.TrimSpace(strings.ReplaceAll(line[:idx], ".", ""))
		val := strings.TrimSpace(line[idx+1:])
		switch {
		case strings.EqualFold(key, "Record Name"):
			flush()
			cur.Name = val
		case strings.EqualFold(key, "Record Type"):
			cur.Type = dnsTypeName(val)
		case strings.HasSuffix(key, "Record"):
			// e.g. "A (Host) Record", "CNAME Record", "AAAA Record", "PTR Record"
			if val != "" {
				cur.Data = val
			}
		}
	}
	flush()
	return entries
}

func dnsTypeName(code string) string {
	switch strings.TrimSpace(code) {
	case "1":
		return "A"
	case "2":
		return "NS"
	case "5":
		return "CNAME"
	case "12":
		return "PTR"
	case "15":
		return "MX"
	case "16":
		return "TXT"
	case "28":
		return "AAAA"
	case "33":
		return "SRV"
	default:
		if _, err := strconv.Atoi(code); err == nil {
			return "TYPE" + code
		}
		return code
	}
}
