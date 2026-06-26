package parser

// Network-forensics data model (platform-neutral). The Windows collector lives
// in netconn_windows.go; other platforms get a stub in netconn_other.go.

// Connection is one TCP/UDP endpoint pair with its owning process — the native
// equivalent of Sysinternals TCPView / NetworkMiner's "Sessions" view.
type Connection struct {
	Proto      string `json:"proto"` // TCP, TCP6, UDP, UDP6
	LocalAddr  string `json:"local_addr"`
	LocalPort  int    `json:"local_port"`
	RemoteAddr string `json:"remote_addr"`
	RemotePort int    `json:"remote_port"`
	State      string `json:"state"`
	PID        int    `json:"pid"`
	Process    string `json:"process"`
	ImagePath  string `json:"image_path,omitempty"`
	RemoteHost string `json:"remote_host,omitempty"` // reverse DNS (cached, best-effort)
	Direction  string `json:"direction"`             // listen | outbound | local
}

// DNSCacheEntry is one record from the endpoint's DNS resolver cache
// (ipconfig /displaydns) — NetworkMiner's "DNS" view.
type DNSCacheEntry struct {
	Name string `json:"name"`
	Type string `json:"type"`
	Data string `json:"data"`
}

// NetworkResult is a full network-forensics snapshot.
type NetworkResult struct {
	Connections []Connection    `json:"connections"`
	DNS         []DNSCacheEntry `json:"dns"`
}
