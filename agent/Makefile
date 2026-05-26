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
