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

Use `--browser-profile-dir <path>` with `auth` or portal-backed `serve` to opt in to a dedicated persistent browser profile for the SSO window. This may retain local IdP/browser session state and reduce repeated credential or MFA prompts, including during gateway SAML fallback, but it is not GlobalProtect auth-cookie caching and it still does not read your default browser profile or cookie stores. The identity provider and gateway remain free to require fresh authentication.

`serve --portal ...` uses the same browser-present auth flow, obtains portal config, selects the first usable external gateway, then starts the SOCKS5 listener. Use `--gateway <url>` to override the selected gateway while still obtaining portal auth material first. The command keeps bearer cookies out of stdout and logs; only the local listen address is printed.

Use `--debug-log <path>` with `probe`, `auth`, or `serve` when troubleshooting portal or gateway compatibility. It writes local JSONL events for GlobalProtect control-plane HTTP calls, including stage, path, status, request form field names, and redacted failure snippets. It does not write raw SAML payloads, cookies, auth cookies, bearer tokens, assertions, passwords, or Authorization values.

Keep `--listen` on a loopback address unless you intentionally want other machines to use the proxy. The SOCKS5 listener has no authentication, so binding it to `0.0.0.0` can expose VPN-backed egress to the local network.

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
  portal: ""
  gateway: ""
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
| `GP_SOCKS_GATEWAY` | `serve` | `gateway` |

The defaults are:

| Scope | Defaults |
| --- | --- |
| root | `log_level`: `error` |
| `probe` | `portal`: `""`; `host_id`: `gp-socks`; `sso_file`, `debug_log`: `""` |
| `auth` | `portal`: `""`; `host_id`: `gp-socks`; `browser`: `auto`; `browser_path`, `browser_profile_dir`, `debug_log`: `""`; `timeout`: `5m` |
| `serve` | `listen`: `127.0.0.1:1080`; `portal`, `gateway`: `""`; `host_id`: `gp-socks`; `browser`: `auto`; `browser_path`, `browser_profile_dir`, `debug_log`: `""`; `timeout`: `5m` |

The automatic `config.yaml`, relative `--config` paths, and all other explicit relative paths are resolved from the process working directory, not from the config file's directory.

The final resolved `serve.listen` must not be blank or whitespace-only. An invalid value is rejected before any debug-log file, browser, authentication, tunnel, or listener activity.

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
