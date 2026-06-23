package osint

import "testing"

func TestInferOSUnit(t *testing.T) {
	// Banner disclosing distro
	r1 := []portResult{{port: 22, banner: "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5", product: "OpenSSH", version: "8.2"}}
	if f, ok := inferOS(r1); !ok || f.Value == "" {
		t.Fatal("expected Ubuntu banner OS")
	} else { t.Logf("banner: %s", f.Value) }
	// Windows port profile
	r2 := []portResult{{port: 3389, service: "RDP"}, {port: 445, service: "SMB"}, {port: 135, service: "MSRPC"}}
	if f, ok := inferOS(r2); !ok { t.Fatal("expected Windows from ports") } else { t.Logf("ports: %s", f.Value) }
	// Linux port profile
	r3 := []portResult{{port: 22, service: "SSH"}, {port: 80, service: "HTTP"}}
	if f, ok := inferOS(r3); !ok { t.Fatal("expected Linux from ports") } else { t.Logf("ports: %s", f.Value) }
}
