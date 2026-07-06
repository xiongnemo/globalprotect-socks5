# globalprotect-socks5

Pure-Go MVP for a local SOCKS5 front-end to GlobalProtect-compatible authentication and pre-tunnel scaffolding.

This repository intentionally starts with the safe pieces that can be tested without bypassing SSO/MFA:

- parse GlobalProtect SSO callback/cookie artifacts without printing bearer secrets;
- probe a GlobalProtect portal prelogin endpoint and print the SSO URL when returned;
- run a local SOCKS5 TCP `CONNECT` listener over an injectable dialer seam.

The current `serve` command is a SOCKS5 scaffold with a direct TCP dialer; it is not VPN-backed egress until a GlobalProtect tunnel dialer is added.

It does not read browser cookie databases, bypass MFA, call an external `openconnect` binary, use Docker as runtime, or use cgo.

## Commands

```bash
go test ./...
go build -o bin/gp-socks ./cmd/gp-socks

./bin/gp-socks probe --portal https://vpn.monashuniversity.cn --host-id test-host
./bin/gp-socks parse-auth 'globalprotectcallback:...'
./bin/gp-socks serve --listen 127.0.0.1:1080
```

`probe` may print an SSO URL. Completing that SSO flow requires the user's browser presence.
