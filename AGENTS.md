# AGENTS.md

Go 1.23+ CLI for a pure-Go GlobalProtect-to-SOCKS5 MVP.

## Commands

- `go test ./...` - run tests.
- `go test -race -shuffle=on -count=1 ./...` - verification test gate.
- `go build -trimpath -o bin/gp-socks ./cmd/gp-socks` - build the binary.

## Architecture

- `cmd/gp-socks/` - entrypoint only.
- `internal/app/` - CLI command dispatch and output shaping.
- `internal/gp/` - GlobalProtect auth artifacts, prelogin parsing, and HTTP client.
- `internal/socks5/` - minimal SOCKS5 TCP `CONNECT` server.

## Conventions

- No cgo unless explicitly approved.
- Do not bypass SSO/MFA or read browser cookie stores.
- Keep bearer tokens out of logs/stdout.
- `context.Context` first for cancellable I/O.
- Errors wrap with `%w`.
- Keep Go files under 250 pure LOC.
