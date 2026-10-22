# globalprotect-socks5

Pure-Go MVP for a local SOCKS5 front-end to GlobalProtect-compatible authentication and SSL tunnel egress.

This repository intentionally starts with the safe pieces that can be tested without bypassing SSO/MFA:

- parse GlobalProtect SSO callback/cookie artifacts without printing bearer secrets;
- probe a GlobalProtect portal prelogin endpoint and print the SSO URL when returned;
- complete user-present SSO in system Chrome or Edge and capture the ACS response artifact through CDP;
- run a local SOCKS5 TCP `CONNECT` listener directly or through a GlobalProtect SSL packet tunnel.

Without `--portal`, `serve` uses a direct TCP dialer. With `--portal`, it performs a user-present portal SAML capture, exchanges that artifact for portal policy and both portal auth-cookie variants, then calls the selected gateway prelogin and retains its response before trying those portal credentials at the gateway. If the gateway accepts them, no gateway SAML exchange is needed. If the cookies are absent or explicitly rejected with HTTP 512, `serve` completes the retained gateway SAML request in the same live, isolated Chromium session and retries with the newly issued gateway prelogin cookie; the existing IdP session can make this second protocol exchange silent, although the IdP may still require fresh interaction. Other gateway failures do not trigger SAML fallback. IPv6 is not supported yet. In portal-backed mode, hostname targets can be resolved through DNS inside the VPN tunnel.

It does not read browser cookie databases, bypass MFA, call an external `openconnect` binary, use Docker as runtime, or use cgo.

## Commands

The command grammar is:

```text
gp-socks [--config FILE | --no-config] [--log-level LEVEL] <auth|parse-auth|probe|serve> [options]
```

`--config`, `--no-config`, and `--log-level` are root flags and must precede the command. Command-specific flags follow the command. `--config` and `--no-config` are mutually exclusive.

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
./bin/gp-socks serve --listen 127.0.0.1:1080 --socks-username proxy-user --socks-password 'replace-with-a-strong-password'
./bin/gp-socks serve --portal https://vpn.example.edu --dns-mode vpn --dns-servers 10.0.0.53,10.0.0.54
```

Linux and macOS shell:

```bash
cp config.yaml.template config.yaml
./bin/gp-socks --log-level info serve
./bin/gp-socks --config ./another.yaml serve
```

Windows PowerShell:

```powershell
Copy-Item .\config.yaml.template .\config.yaml
.\bin\gp-socks.exe --log-level info serve
.\bin\gp-socks.exe --config .\another.yaml serve
```

`probe` may print an SSO URL. Completing that SSO flow requires the user's browser presence.

`auth` runs the same prelogin probe, opens the returned SAML request in a temporary Chrome/Edge profile, listens for the GlobalProtect ACS response through Chrome DevTools Protocol, and prints only a redacted artifact summary such as `prelogin_cookie_present=true`. It never reads an existing browser profile or cookie database. Use `--browser chrome`, `--browser edge`, or `--browser-path <path>` when auto-discovery is not enough.

By default, portal-backed `serve` keeps one isolated temporary profile and one live Chromium runtime across the portal capture and any gateway SAML fallback, then deletes that profile when authentication finishes. Use `--browser-profile-dir <path>` with `auth` or `serve` to opt in to a dedicated profile that persists across commands. This may retain local IdP/browser state and reduce repeated credential or MFA prompts, but it is not GlobalProtect auth-cookie caching and it never reads your default browser profile or cookie stores. The identity provider and gateway remain free to require fresh authentication.

`serve --portal ...` obtains portal config, selects the first usable external gateway, performs gateway prelogin, and prefers the portal-issued user/prelogon auth cookies before falling back to gateway SAML. Use `--gateway <url>` to override the selected gateway while still obtaining portal auth material first. The command keeps bearer cookies out of stdout and logs; only the local listen address is printed.

Use `--debug-log <path>` with `probe`, `auth`, or `serve` when troubleshooting portal or gateway compatibility. It writes local JSONL events for GlobalProtect control-plane HTTP calls, including stage, path, status, request form field names, and redacted failure snippets. It does not write raw SAML payloads, cookies, auth cookies, bearer tokens, assertions, passwords, or Authorization values.

### SOCKS5 authentication and connection controls

Set both `--socks-username` and `--socks-password` to require SOCKS5 username/password authentication (RFC 1929). When credentials are configured, the server accepts only that method and does not fall back to unauthenticated SOCKS5. Each value must contain 1–255 UTF-8 bytes; leaving both blank disables authentication, while setting only one is invalid.

RFC 1929 does not encrypt the username, password, or proxied traffic. Keep the listener on loopback whenever possible. A non-loopback listen address is rejected unless the invocation includes the CLI-only `--allow-non-loopback` flag **and** valid SOCKS5 credentials. Even then, expose it only on a trusted network or behind an encrypted transport; do not publish it directly to the Internet.

Passwords may be written directly in YAML, supplied through `GP_SOCKS_PASSWORD`, or passed with `--socks-password`. They are not written to normal output, application logs, or the redacted debug log, but each storage mechanism has its own exposure risk: protect the YAML file with appropriate filesystem permissions, limit access to the process environment, and remember that CLI arguments can be retained in shell history or visible in process listings. Use placeholders rather than real credentials in shared scripts and documentation.

The listener defaults to a `10s` SOCKS handshake deadline, a `30s` target connection timeout, and at most `256` concurrent client connections. Configure these with `--handshake-timeout`, `--connect-timeout`, and `--max-connections` (valid range `1`–`65535`). The handshake deadline covers greeting, optional authentication, and the `CONNECT` request. These settings do not impose an idle timeout on an established proxied stream. Connections accepted after the concurrency limit is reached are closed immediately.

Equivalent environment configuration, using example-only credentials, is:

```bash
export GP_SOCKS_USERNAME='proxy-user'
export GP_SOCKS_PASSWORD='replace-with-a-strong-password'
export GP_SOCKS_HANDSHAKE_TIMEOUT='10s'
export GP_SOCKS_CONNECT_TIMEOUT='30s'
export GP_SOCKS_MAX_CONNECTIONS='256'
./bin/gp-socks serve
```

### VPN DNS and hostname resolution

Portal-backed `serve` defaults to `dns_mode: "vpn"`. It uses the IPv4 DNS servers and search suffixes delivered by the selected gateway, and sends those DNS queries through the VPN tunnel. Supplying `dns_servers` replaces the gateway-provided server list; entries must be IPv4 address literals. The resolver tries UDP first and can retry truncated replies over TCP, all through the tunnel.

Set `dns_mode: "system"` (or `--dns-mode system`) only to opt out explicitly and use the host's normal resolver. System mode can leak target names outside the VPN and cannot be combined with custom `dns_servers`. Custom DNS servers require portal-backed mode. In VPN mode, if neither the gateway nor the user supplies a DNS server, domain-name connections fail rather than silently falling back to system DNS; IPv4-literal targets still work.

The SOCKS client must send the hostname to the proxy for this remote resolution to apply. For example, use `curl --socks5-hostname 127.0.0.1:1080 https://example.com/` or a `socks5h://127.0.0.1:1080` proxy URL. A client configured for plain `socks5://` may resolve names locally before contacting the proxy, bypassing VPN DNS regardless of server settings.

Example-only environment and CLI overrides are:

```bash
export GP_SOCKS_DNS_MODE='vpn'
export GP_SOCKS_DNS_SERVERS='10.0.0.53,10.0.0.54'
./bin/gp-socks serve --portal https://vpn.example.edu

./bin/gp-socks serve --portal https://vpn.example.edu \
  --dns-mode vpn --dns-servers 10.0.0.53,10.0.0.54
```

### Tunnel liveness and reconnection

The GPST data channel sends dead-peer detection probes after receive inactivity and treats a missing response as a dead tunnel. It also observes the gateway-provided tunnel timeout and initiates a planned reconnect before rekey becomes due. Reconnection opens a new packet tunnel with the already-established gateway session; it does not bypass SSO/MFA or read browser cookie stores.

Each loss or planned rekey gets up to five reconnect attempts: the first is immediate, followed by exponential delays of `1s`, `2s`, `4s`, and `8s`; each attempt has a `30s` connection deadline. New SOCKS `CONNECT` requests wait while recovery is in progress and resume on the replacement tunnel. Connections carried by the old packet tunnel are interrupted and must be retried by the client. If all attempts fail, `serve` closes the SOCKS listener and exits with an error.

Use `https://` portal and gateway URLs. `http://` is accepted only for local tests and will send GlobalProtect auth material without TLS.

## Configuration

The production CLI automatically looks for exactly `./config.yaml` in the process working directory. A missing automatic file is ignored; an existing file that cannot be read or parsed fails the command. `--config FILE` selects only that explicit YAML file and suppresses automatic discovery. `--no-config` disables the file layer entirely, which is useful for automation running in an untrusted working directory. `GP_SOCKS_CONFIG` is not supported.

The repository and release include `config.yaml.template`. Copy it to `config.yaml` before editing it; the template itself is never loaded automatically. Root `log_level` and the `probe`, `auth`, and `serve` sections are optional. Only the section for the selected command is applied; `parse-auth` has no command section.

A complete file that spells out every supported field is:

```yaml
log_level: "error"

probe:
  portal: ""
  host_id: "gp-socks"
  sso_file: ""
  debug_log: ""

auth:
  portal: ""
  host_id: "gp-socks"
  browser: "auto"
  browser_path: ""
  browser_profile_dir: ""
  timeout: "5m"
  debug_log: ""

serve:
  listen: "127.0.0.1:1080"
  socks_username: ""
  socks_password: ""
  handshake_timeout: "10s"
  connect_timeout: "30s"
  max_connections: "256"
  portal: ""
  gateway: ""
  dns_mode: "vpn"
  dns_servers: ""
  host_id: "gp-socks"
  browser: "auto"
  browser_path: ""
  browser_profile_dir: ""
  timeout: "5m"
  debug_log: ""
```

Parsing is strict, limited to one YAML document, and capped at 1 MiB. The selected path must resolve to a regular file. Keys must use the exact lowercase snake_case names shown above. Unknown, duplicate, case-variant, or non-string keys are rejected. Sections must be mappings, and every leaf value must resolve to a YAML string; quote empty values and values such as booleans, numbers, or dates when a literal string is intended. `null`, wrong types, multiple documents, anchors, aliases, merge keys, and custom tags are rejected.

Each field is resolved independently with this exact precedence:

```text
defaults < one selected YAML file < applicable GP_SOCKS_* environment < explicit command/root CLI flags
```

As a general rule, a present empty environment or CLI value still overrides lower-precedence sources and is validated as the final value. One narrow exception applies to `serve.portal`: a blank environment or CLI value that would clear a lower-precedence nonblank portal is rejected as a configuration error rather than silently switching `serve` to direct mode. If no lower-precedence portal is nonblank, a blank `serve.portal` remains valid and `serve` runs in direct mode. Environment variables apply only to the selected command as follows:

| Environment variable | Applies to | Field |
| --- | --- | --- |
| `GP_SOCKS_LOG_LEVEL` | all commands | root `log_level` |
| `GP_SOCKS_PORTAL` | `probe`, `auth`, `serve` | `portal` |
| `GP_SOCKS_HOST_ID` | `probe`, `auth`, `serve` | `host_id` |
| `GP_SOCKS_SSO_FILE` | `probe` | `sso_file` |
| `GP_SOCKS_DEBUG_LOG` | `probe`, `auth`, `serve` | `debug_log` |
| `GP_SOCKS_BROWSER` | `auth`, `serve` | `browser` |
| `GP_SOCKS_BROWSER_PATH` | `auth`, `serve` | `browser_path` |
| `GP_SOCKS_BROWSER_PROFILE_DIR` | `auth`, `serve` | `browser_profile_dir` |
| `GP_SOCKS_TIMEOUT` | `auth`, `serve` | `timeout` |
| `GP_SOCKS_LISTEN` | `serve` | `listen` |
| `GP_SOCKS_USERNAME` | `serve` | `socks_username` |
| `GP_SOCKS_PASSWORD` | `serve` | `socks_password` |
| `GP_SOCKS_HANDSHAKE_TIMEOUT` | `serve` | `handshake_timeout` |
| `GP_SOCKS_CONNECT_TIMEOUT` | `serve` | `connect_timeout` |
| `GP_SOCKS_MAX_CONNECTIONS` | `serve` | `max_connections` |
| `GP_SOCKS_GATEWAY` | `serve` | `gateway` |
| `GP_SOCKS_DNS_MODE` | `serve` | `dns_mode` |
| `GP_SOCKS_DNS_SERVERS` | `serve` | `dns_servers` |

The defaults are:

| Scope | Defaults |
| --- | --- |
| root | `log_level`: `error` |
| `probe` | `portal`: `""`; `host_id`: `gp-socks`; `sso_file`, `debug_log`: `""` |
| `auth` | `portal`: `""`; `host_id`: `gp-socks`; `browser`: `auto`; `browser_path`, `browser_profile_dir`, `debug_log`: `""`; `timeout`: `5m` |
| `serve` | `listen`: `127.0.0.1:1080`; `socks_username`, `socks_password`: `""`; `handshake_timeout`: `10s`; `connect_timeout`: `30s`; `max_connections`: `256`; `portal`, `gateway`, `dns_servers`: `""`; `dns_mode`: `vpn`; `host_id`: `gp-socks`; `browser`: `auto`; `browser_path`, `browser_profile_dir`, `debug_log`: `""`; `timeout`: `5m` |

The automatic `config.yaml`, relative `--config` paths, and all other explicit relative paths are resolved from the process working directory, not from the config file's directory.

The final resolved `serve.listen` must not be blank or whitespace-only. SOCKS credentials, durations, the connection limit, DNS mode, and custom DNS servers are also validated before any debug-log file, browser, authentication, tunnel, or listener activity. `--allow-non-loopback` is intentionally CLI-only and is not persisted in YAML or accepted through an environment variable.

When used as a library, `app.NewRunner` is environment- and filesystem-neutral: it does not read the process environment unless `app.IO.LookupEnv` is supplied, and it does not discover `config.yaml` unless `app.IO.AutoConfig` is true. The production CLI explicitly enables both behaviors; embedders can opt into either independently.

## Application logging

Application log levels are `error`, `warn`, `info`, and `debug`; the default is `error`. Ordinary application logs are JSON records written to stderr. The selected level controls only fixed operational records such as command start, command completion, gateway fallback, and command failure. User-facing command output on stdout or stderr is independent of the application log level, so documented values such as usernames, SSO URLs, and listen addresses may still appear there.

`--debug-log` is independent of application logging and `--log-level`. It writes optional redacted GlobalProtect HTTP JSONL; `--log-level` neither enables nor disables it nor changes its content. When a debug log is configured, failure to open, write, or close its file may fail the command.

Configuration-failure and ordinary application JSON records never include auth artifacts, SAML, cookies, bearer tokens, callback bodies or headers, usernames, host IDs, URLs, paths, or targets as log attributes. Their attributes are limited to fixed operational fields. This restriction applies to application logs, not user-facing command output: documented values such as a username, SSO URL, or listen address may still be printed.

Application JSON uses fixed `stage`/`code` classifications for sensitive setup failures: `config`/`config_open`, `config`/`log_level_invalid`, and `listener`/`listen_failed`. These records contain neither underlying causes nor configured values.

## Prereleases

Each push to `master` runs tests on Linux, Windows, and macOS, cross-compiles 18 pure-Go binaries, and publishes an idempotent prerelease containing those binaries, `config.yaml.template`, and a `SHA256SUMS` manifest. The first release is `v0.0.1`; each commit after the latest `v0.0.N` tag increments the patch component by one.

Verify a downloaded binary before running it:

```bash
sha256sum -c SHA256SUMS --ignore-missing
```

The Linux binaries for `386`, `amd64`, `arm` (v7), `arm64`, `loong64`, `ppc64le`, `riscv64` and `s390x` are also packaged as `.deb`, `.rpm` and `.apk`, which install `gp-socks` to `/usr/bin` and `config.yaml.template` to `/usr/share/gp-socks/`. They are installed and started on Debian, Ubuntu, Fedora, Rocky Linux and Alpine before a prerelease is published, and can be installed from [package.anzupop.com](https://package.anzupop.com):

```bash
sudo curl -fsSLo /usr/share/keyrings/nemo.gpg https://package.anzupop.com/keys/nemo-packages.gpg
echo "deb [signed-by=/usr/share/keyrings/nemo.gpg] https://package.anzupop.com/apt nightly main" | sudo tee /etc/apt/sources.list.d/nemo.list
sudo apt update && sudo apt install gp-socks
```
