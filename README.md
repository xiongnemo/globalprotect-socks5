# globalprotect-socks5

Pure-Go MVP for a local SOCKS5 front-end to GlobalProtect-compatible authentication and SSL tunnel egress.

This repository intentionally starts with the safe pieces that can be tested without bypassing SSO/MFA:

- parse GlobalProtect SSO callback/cookie artifacts without printing bearer secrets;
- probe a GlobalProtect portal prelogin endpoint and print the SSO URL when returned;
- complete user-present SSO in system Chrome or Edge and capture the ACS response artifact through CDP;
- run a local SOCKS5 TCP `CONNECT` listener directly or through a GlobalProtect SSL packet tunnel.

Without `--portal`, `serve` uses a direct TCP dialer. With `--portal`, it performs one user-present portal SAML capture, exchanges that artifact for portal policy and a portal user-auth cookie, uses the portal cookie to log in to the selected gateway, opens the GlobalProtect SSL packet tunnel, and routes SOCKS5 `CONNECT` traffic through a userspace TCP/IP stack. If that gateway login is explicitly rejected with HTTP 512, `serve` performs gateway SAML prelogin and a second browser capture before retrying; other gateway failures do not trigger fallback. IPv6 and in-tunnel DNS are not supported yet; hostname targets are resolved before dialing through the tunnel.

It does not read browser cookie databases, bypass MFA, call an external `openconnect` binary, use Docker as runtime, or use cgo.

## Commands

```bash
go test ./...
go build -o bin/gp-socks ./cmd/gp-socks

./bin/gp-socks probe --portal https://vpn.monashuniversity.cn --host-id test-host
./bin/gp-socks auth --portal https://vpn.monashuniversity.cn --host-id test-host --browser auto
./bin/gp-socks parse-auth 'globalprotectcallback:...'
./bin/gp-socks serve --listen 127.0.0.1:1080
./bin/gp-socks serve --listen 127.0.0.1:1080 --portal https://vpn.monashuniversity.cn --host-id test-host --browser auto
./bin/gp-socks serve --listen 127.0.0.1:1080 --portal https://vpn.monashuniversity.cn --host-id test-host --browser auto --browser-profile-dir .gp-browser-profile
./bin/gp-socks serve --listen 127.0.0.1:1080 --portal https://vpn.monashuniversity.cn --host-id test-host --browser auto --debug-log gp-debug.jsonl
```

`probe` may print an SSO URL. Completing that SSO flow requires the user's browser presence.

`auth` runs the same prelogin probe, opens the returned SAML request in a temporary Chrome/Edge profile, listens for the GlobalProtect ACS response through Chrome DevTools Protocol, and prints only a redacted artifact summary such as `prelogin_cookie_present=true`. It never reads an existing browser profile or cookie database. Use `--browser chrome`, `--browser edge`, or `--browser-path <path>` when auto-discovery is not enough.

Use `--browser-profile-dir <path>` with `auth` or portal-backed `serve` to opt in to a dedicated persistent browser profile for the SSO window. This may retain local IdP/browser session state and reduce repeated credential or MFA prompts, including during gateway SAML fallback, but it is not GlobalProtect auth-cookie caching and it still does not read your default browser profile or cookie stores. The identity provider and gateway remain free to require fresh authentication.

`serve --portal ...` uses the same browser-present auth flow, obtains portal config, selects the first usable external gateway, then starts the SOCKS5 listener. Use `--gateway <url>` to override the selected gateway while still obtaining portal auth material first. The command keeps bearer cookies out of stdout and logs; only the local listen address is printed.

Use `--debug-log <path>` with `probe`, `auth`, or `serve` when troubleshooting portal or gateway compatibility. It writes local JSONL events for GlobalProtect control-plane HTTP calls, including stage, path, status, request form field names, and redacted failure snippets. It does not write raw SAML payloads, cookies, auth cookies, bearer tokens, assertions, passwords, or Authorization values.

Keep `--listen` on a loopback address unless you intentionally want other machines to use the proxy. The SOCKS5 listener has no authentication, so binding it to `0.0.0.0` can expose VPN-backed egress to the local network.

Use `https://` portal and gateway URLs. `http://` is accepted only for local tests and will send GlobalProtect auth material without TLS.

## Prereleases

Each push to `master` runs tests on Linux, Windows, and macOS, cross-compiles 18 pure-Go binaries, and publishes an idempotent prerelease with a `SHA256SUMS` manifest. The first release is `v0.0.1`; each commit after the latest `v0.0.N` tag increments the patch component by one.

Verify a downloaded binary before running it:

```bash
sha256sum -c SHA256SUMS --ignore-missing
```
