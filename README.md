# globalprotect-socks5

Pure-Go MVP for a local SOCKS5 front-end to GlobalProtect-compatible authentication and pre-tunnel scaffolding.

This repository intentionally starts with the safe pieces that can be tested without bypassing SSO/MFA:

- parse GlobalProtect SSO callback/cookie artifacts without printing bearer secrets;
- probe a GlobalProtect portal prelogin endpoint and print the SSO URL when returned;
- complete user-present SSO in system Chrome or Edge and capture the ACS response artifact through CDP;
- run a local SOCKS5 TCP `CONNECT` listener over an injectable dialer seam.

The current `serve` command is a SOCKS5 scaffold with a direct TCP dialer; it is not VPN-backed egress until a GlobalProtect tunnel dialer is added.

It does not read browser cookie databases, bypass MFA, call an external `openconnect` binary, use Docker as runtime, or use cgo.

## Commands

```bash
go test ./...
go build -o bin/gp-socks ./cmd/gp-socks

./bin/gp-socks probe --portal https://vpn.monashuniversity.cn --host-id test-host
./bin/gp-socks auth --portal https://vpn.monashuniversity.cn --host-id test-host --browser auto
./bin/gp-socks parse-auth 'globalprotectcallback:...'
./bin/gp-socks serve --listen 127.0.0.1:1080
```

`probe` may print an SSO URL. Completing that SSO flow requires the user's browser presence.

`auth` runs the same prelogin probe, opens the returned SAML request in a temporary Chrome/Edge profile, listens for the GlobalProtect ACS response through Chrome DevTools Protocol, and prints only a redacted artifact summary such as `prelogin_cookie_present=true`. It never reads an existing browser profile or cookie database. Use `--browser chrome`, `--browser edge`, or `--browser-path <path>` when auto-discovery is not enough.
