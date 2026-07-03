package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/analysishub/agent/internal/offline"
	"github.com/zserge/lorca"
)

func main() {
	log.SetFlags(log.LstdFlags | log.Lmsgprefix)
	log.SetPrefix("[offline-agent] ")

	// Parse CLI flags.
	mode := detectMode()
	for _, arg := range os.Args[1:] {
		switch strings.ToLower(arg) {
		case "--http", "--gui":
			mode = "gui"
		case "--cli":
			mode = "cli"
		case "--info":
			mode = "info"
		case "--help", "-h":
			printUsage()
			return
		}
	}

	// Single self-contained .exe: unpack the bundle (bundle.json + tools/) that
	// was appended to this binary into a temp working dir, then load from there.
	// A loose binary (no appended payload) keeps the legacy on-disk behaviour.
	if dir, ok, xerr := offline.ExtractEmbeddedBundle(); xerr != nil {
		fmt.Fprintf(os.Stderr, "\n[!] Failed to unpack embedded bundle: %v\n\n", xerr)
		os.Exit(1)
	} else if ok {
		offline.SetBundleDir(dir)
	}

	// Load bundle manifest from bundle.json (same directory as binary).
	manifest, err := offline.LoadManifest()
	if err != nil {
		fmt.Fprintf(os.Stderr, "\n[!] Cannot load bundle: %v\n", err)
		fmt.Fprintf(os.Stderr, "    Make sure bundle.json and the tools/ directory are present\n")
		fmt.Fprintf(os.Stderr, "    next to this binary.\n\n")
		os.Exit(1)
	}

	runner := offline.NewRunner()

	switch mode {
	case "info":
		printManifest(manifest)
	case "gui":
		runGUIMode(manifest, runner)
	default:
		runCLIMode(manifest, runner)
	}
}

// printManifest prints the loaded bundle (name, case, tools) and exits. Useful
// to inspect a self-contained .exe without launching the UI.
func printManifest(m *offline.BundleManifest) {
	embedded := "no (loose files next to binary)"
	if offline.HasEmbeddedBundle() {
		embedded = "yes (single self-contained .exe)"
	}
	fmt.Printf("Bundle      : %s\n", m.Name)
	if m.CaseName != "" {
		fmt.Printf("Case        : %s\n", m.CaseName)
	}
	fmt.Printf("Platform    : %s\n", m.Platform)
	fmt.Printf("Self-contained: %s\n", embedded)
	fmt.Printf("Tools (%d):\n", len(m.Tools))
	for i, t := range m.Tools {
		fmt.Printf("  %d. %s [%s]\n", i+1, t.Name, t.Category)
	}
}

// runGUIMode starts the embedded HTTP server and opens the Lorca Desktop UI.
func runGUIMode(manifest *offline.BundleManifest, runner *offline.Runner) {
	port := offline.PickPort()
	url := fmt.Sprintf("http://localhost:%d", port)

	fmt.Printf("\n")
	fmt.Printf("  AnalysisHub Offline Agent\n")
	fmt.Printf("  Bundle : %s\n", manifest.Name)
	fmt.Printf("  UI     : %s\n", url)
	fmt.Printf("\n")

	// Start HTTP server in a background goroutine
	go func() {
		srv := offline.NewHTTPServer(manifest, runner, port)
		if err := srv.Start(); err != nil {
			log.Fatalf("HTTP server error: %v", err)
		}
	}()
	waitForServer(url)

	title := "AnalysisHub Offline Agent — " + manifest.Name

	// 1. Preferred: a REAL native application window (Edge WebView2 on Windows).
	//    Not a browser tab - its own window, title bar, icon and taskbar entry.
	fmt.Println("  Opening native application window…")
	if openNativeWindow(url, title) {
		fmt.Println("  Window closed, shutting down agent.")
		os.Exit(0)
	}

	// 2. Fallback: lorca (drives an installed Chrome/Edge in app mode).
	hasDisplay := runtime.GOOS == "windows" ||
		os.Getenv("DISPLAY") != "" || os.Getenv("WAYLAND_DISPLAY") != ""
	if hasDisplay {
		fmt.Println("  WebView2 unavailable — falling back to app-mode browser window…")
		if ui, err := lorca.New(url, "", 1100, 760); err == nil {
			defer ui.Close()
			<-ui.Done()
			fmt.Println("  Window closed, shutting down agent.")
			os.Exit(0)
		} else {
			fmt.Printf("  [Warning] app-mode window failed: %v\n", err)
			fmt.Println("  Falling back to default browser…")
			go openBrowser(url)
			select {}
		}
	}

	// 3. Headless (SSH): print the tunnel instructions and keep serving.
	fmt.Println("  SSH tunnel (run on your machine):")
	fmt.Printf("    ssh -L %d:localhost:%d user@<victim-ip>\n", port, port)
	fmt.Printf("  Then open: %s\n", url)
	select {}
}

// waitForServer briefly polls the local UI server so the window doesn't open
// before the first response is ready.
func waitForServer(url string) {
	for i := 0; i < 50; i++ {
		if resp, err := http.Get(url); err == nil {
			resp.Body.Close()
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// runCLIMode runs the interactive terminal interface.
func runCLIMode(manifest *offline.BundleManifest, runner *offline.Runner) {
	offline.RunCLI(manifest, runner)
}

// detectMode returns "gui" or "cli" based on the environment.
func detectMode() string {
	if runtime.GOOS == "windows" {
		return "gui"
	}
	// Desktop Linux/macOS: use GUI server.
	if os.Getenv("DISPLAY") != "" || os.Getenv("WAYLAND_DISPLAY") != "" {
		return "gui"
	}
	if runtime.GOOS == "darwin" {
		return "gui"
	}
	// Headless Linux (SSH): default to CLI.
	return "cli"
}

// openBrowser launches the system browser pointing to url.
func openBrowser(url string) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("cmd", "/c", "start", url)
	case "darwin":
		cmd = exec.Command("open", url)
	default:
		// Try common Linux openers in order.
		for _, opener := range []string{"xdg-open", "sensible-browser", "firefox", "chromium"} {
			if _, err := exec.LookPath(opener); err == nil {
				cmd = exec.Command(opener, url)
				break
			}
		}
	}
	if cmd != nil {
		cmd.Start() //nolint:errcheck
	}
}

func printUsage() {
	fmt.Println(`AnalysisHub Offline Agent

Usage:
  agent-offline [--gui] [--cli] [--info]

Flags:
  --gui    Force Desktop GUI mode (native application window)
  --cli    Force interactive CLI mode (best for SSH/headless)
  --info   Print the bundled tool list and exit (no UI)

Auto-detection:
  Windows         → native window (Edge WebView2; app-mode browser fallback)
  Linux + DISPLAY → GUI mode
  Linux headless  → CLI mode (SSH-friendly)

Packaging:
  The Windows build is a SINGLE self-contained .exe — the bundle (manifest +
  tools) is appended to the binary and unpacked to a temp folder at startup.
  Just double-click it; no install, no loose files. Reports are written next to
  the .exe. (Loose-file bundles with bundle.json + tools/ next to the binary are
  still supported for the Linux ZIP.)
`)
}

