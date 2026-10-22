.PHONY: build test audit install

build:
	go build -trimpath -o cfkey .

test:
	go test -race ./...

# Everything a reviewer should run before trusting a change.
audit: test
	go vet ./...
	go run honnef.co/go/tools/cmd/staticcheck@latest ./...
	go run golang.org/x/vuln/cmd/govulncheck@latest ./...

# Installs into a root-owned directory so agents (running as you) cannot
# replace the binary you type your master token into.
install: build
	sudo install -o root -m 0755 cfkey /usr/local/bin/cfkey
