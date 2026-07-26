package forge

import (
	"strings"
	"testing"
)

// runOne is a helper to run a single operation and return the final output.
func runOne(t *testing.T, op string, args Args, input string) Result {
	t.Helper()
	res, err := Run(input, []RecipeStep{{Op: op, Args: args}})
	if err != nil {
		t.Fatalf("%s: %v", op, err)
	}
	return res
}

// Every encode op must round-trip with its decode counterpart.
func TestRoundTrips(t *testing.T) {
	const msg = "The quick brown fox — 0xDEADBEEF"
	pairs := []struct{ enc, dec string }{
		{"To Base64", "From Base64"},
		{"To Base32", "From Base32"},
		{"To Base58", "From Base58"},
		{"To Hex", "From Hex"},
		{"To Binary", "From Binary"},
		{"To Decimal", "From Decimal"},
		{"To Charcode", "From Charcode"},
		{"Gzip", "Gunzip"},
		{"Zlib Deflate", "Zlib Inflate"},
	}
	for _, p := range pairs {
		res, err := Run(msg, []RecipeStep{{Op: p.enc}, {Op: p.dec}})
		if err != nil {
			t.Errorf("%s→%s: %v", p.enc, p.dec, err)
			continue
		}
		if res.Output != msg {
			t.Errorf("%s→%s round-trip: got %q want %q", p.enc, p.dec, res.Output, msg)
		}
	}
}

// Symmetric ciphers must decode themselves.
func TestSymmetricCiphers(t *testing.T) {
	const msg = "attack at dawn"
	cases := []struct {
		op   string
		args Args
	}{
		{"ROT13", nil},
		{"ROT47", nil},
		{"Atbash", nil},
		{"XOR", Args{"key": "s3cr3t", "format": "utf8"}},
		{"RC4", Args{"key": "hunter2", "format": "utf8"}},
	}
	for _, c := range cases {
		res, err := Run(msg, []RecipeStep{{Op: c.op, Args: c.args}, {Op: c.op, Args: c.args}})
		if err != nil {
			t.Errorf("%s: %v", c.op, err)
			continue
		}
		if res.Output != msg {
			t.Errorf("%s self-inverse: got %q want %q", c.op, res.Output, msg)
		}
	}
}

func TestFromBase64_Auto(t *testing.T) {
	// url-safe, unpadded → auto must still decode it.
	res := runOne(t, "From Base64", Args{"alphabet": "auto"}, "SGVsbG8td29ybGQ")
	if res.Output != "Hello-world" {
		t.Errorf("auto base64: got %q", res.Output)
	}
}

func TestPowerShellDecode(t *testing.T) {
	// base64(UTF-16LE("whoami")) as PowerShell -enc would carry it.
	enc := runOne(t, "To Base64", nil, string(toWide("whoami")))
	res := runOne(t, "PowerShell Decode", nil, enc.Output)
	if res.Output != "whoami" {
		t.Errorf("powershell decode: got %q", res.Output)
	}
}

func toWide(s string) []byte {
	out := make([]byte, 0, len(s)*2)
	for _, r := range s {
		out = append(out, byte(r), byte(r>>8))
	}
	return out
}

func TestAESGCMRoundTrip(t *testing.T) {
	key := "00112233445566778899aabbccddeeff" // 16 bytes hex
	nonce := "000000000000000000000000"        // 12 bytes hex
	enc := runOne(t, "AES Encrypt", Args{"key": key, "keyfmt": "hex", "mode": "GCM", "iv": nonce, "ivfmt": "hex"}, "secret message")
	// Encrypt output is binary → hex-dumped; instead run the full recipe in bytes.
	res, err := Run("secret message", []RecipeStep{
		{Op: "AES Encrypt", Args: Args{"key": key, "keyfmt": "hex", "mode": "GCM", "iv": nonce, "ivfmt": "hex"}},
		{Op: "To Hex"},
		{Op: "AES Decrypt", Args: Args{"key": key, "keyfmt": "hex", "mode": "GCM", "input": "hex"}},
	})
	if err != nil {
		t.Fatalf("gcm recipe: %v", err)
	}
	if res.Output != "secret message" {
		t.Errorf("aes-gcm round-trip: got %q", res.Output)
	}
	_ = enc
}

func TestAESCBCRoundTrip(t *testing.T) {
	key := "00112233445566778899aabbccddeeff"
	iv := "0102030405060708090a0b0c0d0e0f10"
	res, err := Run("padded plaintext block test", []RecipeStep{
		{Op: "AES Encrypt", Args: Args{"key": key, "keyfmt": "hex", "mode": "CBC", "iv": iv, "ivfmt": "hex"}},
		{Op: "To Hex"},
		{Op: "AES Decrypt", Args: Args{"key": key, "keyfmt": "hex", "mode": "CBC", "iv": iv, "ivfmt": "hex", "input": "hex"}},
	})
	if err != nil {
		t.Fatalf("cbc recipe: %v", err)
	}
	if res.Output != "padded plaintext block test" {
		t.Errorf("aes-cbc round-trip: got %q", res.Output)
	}
}

func TestChainedRecipe(t *testing.T) {
	// A realistic peel: hex(base64("payload")) decoded back.
	res, err := Run("payload", []RecipeStep{
		{Op: "To Base64"},
		{Op: "To Hex"},
		{Op: "From Hex"},
		{Op: "From Base64"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Output != "payload" {
		t.Errorf("chained: got %q", res.Output)
	}
	if len(res.Steps) != 4 {
		t.Errorf("expected 4 step traces, got %d", len(res.Steps))
	}
}

func TestMorse(t *testing.T) {
	res, err := Run("SOS HELP", []RecipeStep{{Op: "To Morse"}, {Op: "From Morse"}})
	if err != nil {
		t.Fatal(err)
	}
	if res.Output != "SOS HELP" {
		t.Errorf("morse round-trip: got %q", res.Output)
	}
}

func TestUnknownOp(t *testing.T) {
	_, err := Run("x", []RecipeStep{{Op: "Nonexistent Op"}})
	if err == nil {
		t.Error("expected error for unknown op")
	}
}

func TestOperationsRegistered(t *testing.T) {
	ops := Operations()
	if len(ops) < 30 {
		t.Errorf("expected a rich operation set, got %d", len(ops))
	}
	// Spot-check categories are present.
	cats := map[string]bool{}
	for _, o := range ops {
		cats[o.Category] = true
	}
	for _, want := range []string{"Encoding", "Cipher", "Compression", "Hashing", "Parsing", "IOC", "Analysis", "Text"} {
		if !cats[want] {
			t.Errorf("missing category %q", want)
		}
	}
}

func TestEntropy(t *testing.T) {
	res := runOne(t, "Entropy", nil, strings.Repeat("A", 100))
	if !strings.Contains(res.Output, "0.0000") {
		t.Errorf("entropy of constant data should be 0, got %q", res.Output)
	}
}
