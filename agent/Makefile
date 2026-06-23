# ── Online agent ────────────────────────────────────────────────────────────
build-windows:
	GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -o forensichub-agent.exe ./cmd/agent

build-linux:
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -ldflags="-s -w" -o forensichub-agent-linux ./cmd/agent

build-darwin-amd64:
	GOOS=darwin GOARCH=amd64 go build -ldflags="-s -w" -o forensichub-agent-darwin-amd64 ./cmd/agent

build-darwin-arm64:
	GOOS=darwin GOARCH=arm64 go build -ldflags="-s -w" -o forensichub-agent-darwin-arm64 ./cmd/agent

build-darwin: build-darwin-amd64 build-darwin-arm64

build-all: build-windows build-linux build-darwin

build-local:
	go build -o forensichub-agent ./cmd/agent

# ── Offline agent ────────────────────────────────────────────────────────────
build-offline-windows:
	# -H windowsgui → no console window flashes when the user double-clicks the
	# single .exe; it opens straight into the native WebView2 application window.
	GOOS=windows GOARCH=amd64 go build -ldflags="-s -w -H windowsgui" -o agent-offline.exe ./cmd/offline-agent

build-offline-linux:
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -ldflags="-s -w" -o agent-offline-linux ./cmd/offline-agent

build-offline-darwin-amd64:
	GOOS=darwin GOARCH=amd64 go build -ldflags="-s -w" -o agent-offline-darwin-amd64 ./cmd/offline-agent

build-offline-darwin-arm64:
	GOOS=darwin GOARCH=arm64 go build -ldflags="-s -w" -o agent-offline-darwin-arm64 ./cmd/offline-agent

build-offline-all: build-offline-windows build-offline-linux build-offline-darwin-amd64 build-offline-darwin-arm64

# Build both online and offline agents for all platforms
build-everything: build-all build-offline-all
