# secretd — Implementation Specification

This document specifies `secretd`, a local secrets-release daemon, and its companion tools. It is written for an AI agent to implement. Where a decision is not stated, choose the simplest option that satisfies the security requirements and record the choice in `docs/DECISIONS.md`.

## 1. Overview

`secretd` holds an encrypted store of named secrets. A local process (the *client*) asks `secretd` for a secret by name over a Unix domain socket. `secretd` identifies the caller with `SO_PEERCRED`, checks a per-secret ACL, then sends a push notification to the *owner* (the human who administers the server). The owner approves the request and supplies the decryption key through an authenticated HTTPS endpoint. Only then does `secretd` decrypt the secret and return it to the waiting client. Every release is one-shot.

Secrets at rest are always encrypted. The decryption key is never stored on disk by `secretd` and is held in memory only for the duration of one release.

### Components (Cargo workspace)

| Crate | Kind | Purpose |
|---|---|---|
| `secretd` | bin | The daemon |
| `secretctl` | bin | Admin CLI: manage the store, and (optionally) approve/deny from a terminal |
| `secret` | bin | Client CLI: `get` and `inject` |
| `secret-client` | lib | Reusable Rust client for the JSON-RPC protocol |
| `secret-proto` | lib | Shared types: JSON-RPC messages, error codes, framing |

Language: Rust (stable, edition 2021 or later). Targets: Linux (`SO_PEERCRED`, `/proc`) and macOS (`LOCAL_PEERCRED`/`LOCAL_PEERPID`, libproc); see §22.

## 2. Threat model

In scope:
- A local unprivileged user or process attempting to obtain secrets it is not entitled to.
- A compromised client process that was legitimately allowed to request secrets (limited by one-shot release and owner approval of each request).
- Disk theft or backup leakage of the store file.
- Notification channel eavesdropping (the push message must not contain secrets or keys).
- Notification spam / request flooding from a local user.

Out of scope: root on the host, kernel compromise, physical memory attacks, a compromised owner device.

## 3. Unix socket protocol

### 3.1 Transport
- Socket path default: `/run/secretd/secretd.sock`. Configurable.
- Type: `SOCK_STREAM`. Permissions are `0660` or `0666`, set by config; real access control is the ACL, not the filesystem mode. The parent directory is `0755` and owned by the `secretd` user.
- Support systemd socket activation (`LISTEN_FDS`/`LISTEN_PID`). If activated, use fd 3 instead of binding.
- Framing: newline-delimited JSON (one JSON-RPC 2.0 message per line, UTF-8, max line length 64 KiB; reject larger and close).
- One request may be in flight per connection at a time. Requests that wait for approval keep the connection open. The server must not block other connections while waiting (use async I/O, e.g. `tokio`).

### 3.2 Caller identity
On every accepted connection, read `SO_PEERCRED` (`getsockopt`, `struct ucred`: pid, uid, gid) immediately. Use it, never any value the client supplies. Then:
- Resolve `/proc/<pid>/exe` (readlink) and read `/proc/<pid>/cmdline` (truncate to 256 bytes, sanitize control characters). Capture these once at connect time.
- Record the process start time from `/proc/<pid>/stat`. Before releasing a secret, re-read it and confirm the pid still has the same exe and start time. If not, abort with `CALLER_CHANGED`. This mitigates pid reuse and exec-after-connect.
- If `/proc` resolution fails (the process exited), treat the request as denied.

### 3.3 JSON-RPC methods

All messages follow JSON-RPC 2.0.

**`secret.get`**
- params: `{ "name": string, "reason"?: string, "timeout_secs"?: integer }`
- `reason` is free text (max 200 chars) shown to the owner. It is untrusted; sanitize it and label it as client-supplied.
- `timeout_secs` is the max time the client will wait, clamped to the server max (default 300s).
- result on success: `{ "name": string, "value": string, "encoding": "utf8" | "base64" }`. Binary secrets use `base64`.
- Blocks until approved, denied, or timed out.

**`secret.list`**
- params: `{}`
- result: `{ "names": [string] }`: only names this caller passes the ACL for. Values are never listed.

**`server.ping`**
- result: `{ "version": string, "sealed": true }`, where `sealed` is always true in this design (no standing unsealed state).

### 3.4 Error codes
Use JSON-RPC error objects with these `code` values in the application range, and a stable string in `data.kind`:

| code | `data.kind` | Meaning |
|---|---|---|
| -32001 | `NOT_FOUND` | No such secret, **or** caller not permitted by ACL (indistinguishable to prevent name probing) |
| -32002 | `DENIED` | Owner denied the request |
| -32003 | `TIMEOUT` | No owner response in time |
| -32004 | `RATE_LIMITED` | Per-uid pending cap or rate limit hit |
| -32005 | `CALLER_CHANGED` | Peer identity verification failed at release time |
| -32006 | `DECRYPT_FAILED` | Owner-supplied key was wrong (owner may retry; the request stays pending until the retry limit, see §5) |
| -32007 | `INTERNAL` | Anything else; never leak details |

Standard JSON-RPC errors (-32700, -32600, -32601, -32602) apply for malformed input.

## 4. Secret store

- The store is a single [age](https://age-encryption.org) file, default `/var/lib/secretd/store.age`, mode `0600`, owned by `secretd`. It is encrypted to a **single passphrase** using age's scrypt recipient (use the Rust `age` crate; no custom crypto). The plaintext is a serialized map of `name -> {encoding, value}` (e.g., JSON or CBOR).
- One passphrase per store. There are no per-secret keys.
- **Unseal-per-request:** `secretd` is always sealed. For each approved request it decrypts the store in memory with the owner-supplied passphrase, extracts only the one requested secret, then immediately zeroizes the passphrase, the decrypted map, and all other secrets. Nothing is cached between requests, and a second request needs a fresh passphrase entry.
- Names and ACLs are kept in the config file (`/etc/secretd/config.toml`), not the store, so ACLs can be evaluated while sealed. `secretd` should warn if the config and store disagree about which names exist, but must not need the passphrase to start.
- Writes (done only by `secretctl`) are atomic: write temp, `fsync`, rename.
- scrypt work factor: use age's default or higher for new stores. Because age uses one scrypt derivation per decrypt, expect roughly 0.5–1s per approval; this is acceptable.
- In-memory handling: use `zeroize` / `secrecy`; call `mlock` on passphrase and plaintext buffers where possible; disable core dumps (`prctl(PR_SET_DUMPABLE, 0)`, `RLIMIT_CORE=0`). Decryption must run on a blocking thread so it does not stall the async runtime.

## 5. Approval flow

1. Client sends `secret.get`.
2. `secretd` checks: ACL (§6), rate limits (§8). If it fails, return the error immediately and audit it. No notification is sent for ACL failures.
3. `secretd` creates a **pending request** with a random 128-bit `request_id` and a separate random 256-bit `approval_token` (both from the OS CSPRNG). It stores caller identity, secret name, reason, created and expiry times.
4. `secretd` sends a push notification (§7) containing: request id, secret name, caller uid/username, pid, exe path, sanitized cmdline, client-supplied reason (labelled), expiry time, and an approval URL containing the token. **Never** include the secret or any key.
5. The owner opens the approval URL (§7.2) and signs in with Google OIDC. Only after passing that gate (and the allowlist check) does the page show the request details and the Approve (passphrase field) and Deny controls.
6. On approve, `secretd` re-verifies the caller (§3.2), unseals the store with the passphrase, extracts the one secret, zeroizes the passphrase and everything else decrypted (§4), and returns the value to the waiting client.
7. On wrong passphrase, return an inline error to the owner and allow up to 3 attempts; after that, the request is denied and audited (`DECRYPT_FAILED` is sent to the client only on final failure).
8. On deny, timeout, or client disconnect, the pending request is removed. Client disconnect before approval cancels the request, and the approval URL then returns 410 Gone.
9. Approval tokens are single-use and expire with the request.

### Release policy
One-shot only. Every `secret.get` requires a fresh approval. There is no grant caching, no standing unsealed state, and no TTL window.

## 6. Authorization (ACLs)

Defined per secret in the config file:

```toml
[[secret]]
name = "db-password"
description = "Primary DB password"          # shown to owner
allow_uids = [1000]                          # numeric or names resolved at startup
allow_gids = [100]                           # optional
allow_exes = ["/usr/bin/psql", "/opt/app/bin/app"]  # absolute, canonical paths
```

Rules:
- A caller is allowed iff (uid ∈ `allow_uids` OR gid ∈ `allow_gids`) AND (`allow_exes` is non-empty AND the resolved `/proc/<pid>/exe` exactly equals one entry). If `allow_exes` is omitted, the config loader must emit a warning and treat the secret as exe-unrestricted only if `allow_any_exe = true` is set explicitly. Otherwise refuse to start.
- Exact path match on the canonicalized path. If the exe path ends in ` (deleted)`, deny.
- Deny by default. A secret with no ACL entries is unreachable.
- Config file must be owned by root or `secretd` and not group/world writable; refuse to start otherwise.
- Reload config on `SIGHUP`.

Note: exe matching is a defense-in-depth measure, not a sandbox boundary. A process running as an allowed uid can still exec an allowed binary with attacker-controlled input, so owner approval of each request remains the real gate.

## 7. Notifications and the approval endpoint

### 7.1 Push notification
- Provider: ntfy-compatible HTTP POST (`POST <topic URL>` with headers `Title`, `Priority`, `Tags`, `Click`, optional `Authorization`), plus a generic webhook mode (JSON POST to a configurable URL with optional HMAC-SHA256 signature header).
- Config: `[notify] kind = "ntfy" | "webhook"`, `url`, auth token (read from a file path, not inline), timeout, retry (3 attempts with backoff).
- `Click` is set to the approval URL.
- If the notification fails after retries, fail the request with `INTERNAL`, audit it, and drop the pending request.
- The message body is plain text. Sanitize all caller-controlled strings (strip control and bidi characters, truncate).

### 7.2 Approval HTTPS endpoint
`secretd` runs an HTTP server (separate listener from the Unix socket) for the owner.

- `secretd` does **not** terminate TLS and needs no certificate or key. It serves plain HTTP and must be reachable only via loopback or through a reverse proxy that handles TLS.
  - Default listen address is `127.0.0.1:8443`. If the configured address is not loopback, refuse to start unless `allow_non_loopback = true` is set (for a proxy on another host or a container network), and log a warning.
  - `external_url` (an `https://` URL) is mandatory. It is used to build approval links and the OIDC `redirect_url`, and the cookie `Secure` flag is always set based on it, never on the incoming scheme.
  - Reverse proxy: `trusted_proxies` lists the proxy IPs/CIDRs (default `127.0.0.1/32`, `::1/128`). Use `X-Forwarded-For` for source-IP rate limiting and audit only when the TCP peer is in `trusted_proxies`; otherwise ignore it and use the peer address. Reject requests whose `Host` header does not match `external_url`'s host.
  - Document an example proxy config (nginx or Caddy) in the README that forwards only `/approve/`, `/auth/` and `/healthz`, and sets `X-Forwarded-For`.
- Routes:
  - `GET /approve/<request_id>?t=<approval_token>`: if there is no valid owner session, redirect into the OIDC login flow (below) and return here afterwards. Once authenticated, render request details with **Approve** (passphrase field) and **Deny** buttons. Constant-time token compare. Response headers: `Cache-Control: no-store`, `Referrer-Policy: no-referrer`, a strict CSP, `X-Frame-Options: DENY`.
  - `POST /approve/<request_id>`: form fields `t`, `action` (`approve`|`deny`), `passphrase` (for approve), `csrf`. CSRF token is bound to the request id and session and issued by the GET.
  - `GET /auth/login`, `GET /auth/callback`: OIDC authorization-code flow (below).
  - `GET /healthz`: unauthenticated, returns `ok` only.
- **Owner authentication is Google OIDC only.** There are no local passwords, bearer tokens, or basic-auth credentials.
  - Flow: authorization code with PKCE, plus `state` and `nonce`. Use the `openidconnect` crate against `https://accounts.google.com` (discovery document). Request scopes `openid email`.
  - Validate the ID token fully: signature against Google's JWKS, `iss`, `aud` equal to the configured client id, `exp`, `nonce`, `email_verified == true`. Match on the `email` claim (case-insensitive, exact) against `owner_emails`, a configured allowlist. Not on the `hd` claim alone. Anything not on the list gets a generic 403 and an audit event.
  - **OIDC is a session gate, not a per-request step.** Once the owner has signed in, the session is reused across requests until it expires. Do not force re-authentication (no `prompt=login` / `max_age`). The per-request control is the passphrase, which must be entered for every approval.
  - **Passkeys:** not required or enforced by `secretd`. Sign-in method is Google's concern; the owner may use a passkey if their Google account offers it. If an `amr` claim is present, record it in the audit log but do not rely on it.
  - After login, issue a server-side session (default 1 hour via `session_ttl_secs`, absolute expiry, `HttpOnly`, `Secure`, `SameSite=Lax`). The session identifies the owner only. It authorizes viewing and acting on pending requests, but never releases a secret without the passphrase. Sessions are in-memory only and lost on restart.
  - `secretd` stores no Google tokens beyond validating the ID token. Discard the access and refresh tokens (do not request offline access).
- Approval therefore needs three things: the unguessable per-request token (delivered via push), a valid Google-authenticated session for an allowlisted email, and the store passphrase (entered every time), which is the actual decryption key.
- Rate-limit failed attempts per source IP (e.g., 5 per minute, then 429).
- Never log tokens, passphrases, ID tokens, or secret values. Never put the passphrase in a URL.

### 7.3 Terminal fallback
`secretctl pending` lists pending requests and `secretctl approve|deny <id>` lets the owner act locally. These talk to a second Unix socket (`/run/secretd/admin.sock`, mode `0600`, owner `root`, peer uid must be 0 per `SO_PEERCRED`). The passphrase is read with echo disabled and sent over the admin socket. This path is for use over SSH when the HTTPS endpoint is not reachable.

## 8. Rate limiting and caps

Configurable, with defaults:
- Max pending requests per uid: 3.
- Max pending requests total: 32.
- Max `secret.get` attempts per uid: 10 per minute.
- Max concurrent connections per uid: 8; total: 128.
- Idle connection timeout (no request in flight): 30s.
- Request timeout (pending approval): 300s default, configurable max.
- Duplicate suppression: if the same uid+exe already has a pending request for the same secret, return `RATE_LIMITED` rather than sending a second notification.

## 9. Audit log

- Append-only JSON Lines at `/var/log/secretd/audit.jsonl`, mode `0640`.
- One event per state change: `request_received`, `acl_denied`, `rate_limited`, `notified`, `notify_failed`, `approved`, `denied`, `timeout`, `client_disconnected`, `decrypt_failed`, `released`, `caller_changed`, `admin_action`.
- Fields: `ts` (RFC 3339 UTC), `event`, `request_id`, `secret_name`, `uid`, `gid`, `pid`, `exe`, `outcome`, `source_ip` (for HTTP events). **Never** include values, passphrases, tokens, or reasons that were rejected.
- Failure to write the audit log must fail the request closed.

## 10. Client tools

### 10.1 `secret-client` library
- `Client::connect(path)`, `client.get(name, GetOptions) -> Result<SecretValue>`, `client.list()`.
- `SecretValue` wraps bytes with zeroize-on-drop and a `Debug` impl that does not print contents.
- Sync API is fine; an async API behind a feature flag is optional.

### 10.2 `secret` CLI
- `secret get <name> [--reason TEXT] [--timeout SECS] [--socket PATH]`: prints the value to stdout with no trailing newline unless stdout is a TTY. Exit codes: 0 ok; 1 generic; 2 not found/ACL; 3 denied; 4 timeout; 5 rate limited. Progress ("waiting for owner approval…") goes to stderr.
- `secret list`
- `secret inject`: template substitution modelled on `op inject`.
  - `secret inject [-i FILE] [-o FILE] [--reason TEXT] [--timeout SECS] [--force]`. Reads stdin when `-i` is omitted; writes stdout when `-o` is omitted.
  - Token syntax: `{{ secret:NAME }}`, with optional whitespace inside the braces. `NAME` matches `[A-Za-z0-9._/-]+`. Escape a literal token with `\{{ secret:NAME }}`.
  - Each distinct name is requested once per invocation (requests are issued sequentially or in parallel; either is fine, but must respect the per-uid pending cap, so default to sequential) and substituted at every occurrence.
  - If any secret fails (denied, timeout, not found), exit non-zero and write **nothing** to the output (buffer output; write atomically at the end). When `-o` is used the file is created with mode `0600` and refuses to overwrite without `--force`.
  - Must work as a streaming-tolerant filter: tokens may be split across read-chunk boundaries, so parse on a buffer, not per-chunk.
  - Binary-safe for non-token bytes; secrets with `encoding: base64` are decoded before substitution.
  - `secret run -- CMD ARGS...` with `--env NAME=secret:NAME` is optional and out of scope for v1.

## 11. Admin CLI (`secretctl`)

All commands talk to the admin socket or operate on the store file directly (when the daemon is stopped, with the passphrase prompt).
- `secretctl init`: create an empty store and set the passphrase.
- `secretctl add <name>`: reads the value from stdin or a no-echo prompt; prompts for the passphrase; encrypts and writes. `--file PATH` for binary input.
- `secretctl remove <name>`
- `secretctl list`: names plus ACL summary from config. Never values.
- `secretctl rotate-passphrase`: decrypt every secret with the old passphrase and re-encrypt with a new one, atomically.
- `secretctl pending | approve <id> | deny <id>` (see §7.3)
- `secretctl check-config` (validates config, ACLs, OIDC settings, listen address, file permissions)

Secrets are never accepted as command-line arguments (they would leak via `/proc/*/cmdline` and shell history).

## 12. Configuration

TOML at `/etc/secretd/config.toml`. Example skeleton:

```toml
[daemon]
user = "secretd"
socket = "/run/secretd/secretd.sock"
admin_socket = "/run/secretd/admin.sock"
store = "/var/lib/secretd/store.age"
audit_log = "/var/log/secretd/audit.jsonl"
request_timeout_secs = 300

[limits]
max_pending_per_uid = 3
max_pending_total = 32

[notify]
kind = "ntfy"
url = "https://ntfy.example.com/secretd-alerts"
auth_token_file = "/etc/secretd/ntfy.token"

[approval]
listen = "127.0.0.1:8443"            # plain HTTP; TLS is the reverse proxy's job
external_url = "https://secretd.example.com"
trusted_proxies = ["127.0.0.1/32", "::1/128"]

[approval.oidc]
issuer = "https://accounts.google.com"
client_id = "xxxxxxxx.apps.googleusercontent.com"
client_secret_file = "/etc/secretd/oidc-client-secret"
redirect_url = "https://secretd.example.com/auth/callback"
owner_emails = ["owner@example.com"]
session_ttl_secs = 3600

[[secret]]
name = "db-password"
allow_uids = [1000]
allow_exes = ["/usr/bin/psql"]
```

`secretd` starts as root only if needed to bind privileged resources, then drops to the configured user. Prefer socket activation so it never needs root.

## 13. Packaging and deployment

- `packaging/secretd.service` and `packaging/secretd.socket`: systemd units with hardening (`NoNewPrivileges`, `ProtectSystem=strict`, `ProtectHome`, `PrivateTmp`, `PrivateDevices`, `RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6`, `MemoryDenyWriteExecute`, `LockPersonality`, `CapabilityBoundingSet=` empty, `ReadWritePaths` limited to the state and log dirs, `SystemCallFilter=@system-service`). Note: reading other processes' `/proc/<pid>/exe` needs `ptrace` access mode `PTRACE_MODE_READ_FSCREDS`; confirm it works under the unit's hardening for processes of other uids, and if it requires `CAP_SYS_PTRACE` or `hidepid` adjustments, document the minimal setting needed.
- `packaging/config.example.toml`.
- `README.md` with a quickstart.

## 14. Testing requirements

- Unit tests: framing, JSON-RPC parsing/errors, token parsing for `inject` (including chunk-boundary splits and escapes), ACL evaluation, age store encrypt/decrypt round trip, wrong-passphrase and tamper detection, and a check that unseal returns only the requested secret and the passphrase buffer is zeroized.
- OIDC tests use a mock OIDC provider (local issuer with a test JWKS): reject bad signature, wrong `aud`/`iss`, expired token, wrong `nonce`, `email_verified=false`, an email not on the allowlist, and an expired or missing session.
- Integration tests (spawn the daemon on a temp socket, using a mock ntfy HTTP server and driving the approval endpoint over HTTP):
  - approve flow returns the secret; deny returns `DENIED`; timeout returns `TIMEOUT`;
  - ACL miss is indistinguishable from an unknown name;
  - wrong passphrase retry limit;
  - client disconnect cancels the pending request and invalidates the URL;
  - a reused approval token and an expired token are rejected;
  - per-uid pending cap and duplicate suppression;
  - audit log contains expected events and never contains the secret value or passphrase;
  - `secret inject` writes nothing when any lookup fails.
- Tests that require multiple uids may be gated behind an env var (they need root); otherwise cover uid logic with an injectable peer-credential provider trait.
- `cargo clippy -- -D warnings` and `cargo fmt --check` must pass. Use `cargo deny` or `cargo audit` in CI if available.

## 15. Suggested crates

`tokio`, `serde`/`serde_json`, `nix` or `rustix` (`getsockopt` `SO_PEERCRED`, `prctl`, `mlock`), `axum` (approval server, plain HTTP), `reqwest` (with rustls) for outbound notifications and the Google OIDC calls, `age` (scrypt passphrase recipient), `openidconnect`, `tower-sessions` or similar, `zeroize`, `secrecy`, `rand`/`getrandom`, `subtle` (constant-time compare), `toml`, `clap`, `tracing`, `thiserror`/`anyhow`, `tempfile` for tests.

## 16. Milestones

1. `secret-proto` + store format + `secretctl init/add/list`, with tests.
2. `secretd` Unix socket server with `SO_PEERCRED`, ACLs, `secret.get` returning a decrypted value through a stub approver (test-only).
3. Notification + HTTPS approval endpoint + admin socket fallback.
4. Rate limits, audit log, caller re-verification.
5. `secret` CLI (`get`, `list`, `inject`) and `secret-client` library.
6. systemd units, packaging, docs, hardening review.

## 17. Non-goals (v1)

Network-reachable secret access (Unix socket only), platforms other than Linux and macOS (§22), grant caching or TTL leases, secret versioning/history, multi-owner or quorum approval, HSM/TPM integration, `secret run`. (Home Assistant and FIFO support are v1.1 extensions in §19-§20.)

## 18. Decisions and open questions

Resolved:
1. One passphrase per age-encrypted store. It unseals the store for a single request, then everything is discarded (§4).
2. Owner authentication is Google OIDC only, restricted to an email allowlist, with a reusable session (§7.2). The owner supplies the passphrase on every approval. The earlier `owner_auth_token_file` design is removed.
3. `secretd` has no TLS code and needs no cert or key. It listens on loopback (or behind a TLS-terminating reverse proxy) and trusts forwarded headers only from configured proxies (§7.2).

Passkeys are not required; whatever sign-in methods Google offers (including passkeys) are sufficient (§7.2).

Note: Google OIDC needs an HTTPS redirect URI on a real hostname (or `localhost`), so the reverse proxy must front a real domain with a valid certificate.

## 19. Home Assistant channel (v1.1 extension)

Adds Home Assistant (HA) as an additional notification and approval channel. The existing web/OIDC path (§7.2) and admin socket (§7.3) remain; which channels are enabled is a per-deployment choice.

### 19.1 Channels
- Introduce a channel abstraction: each enabled channel can (a) announce a pending request and (b) deliver an approve/deny decision plus the passphrase. Channels are `web` (§7.2), `admin` (§7.3) and `homeassistant`.
- `[channels] enabled = ["web", "admin", "homeassistant"]`; at least one approval channel must be enabled, and `check-config` refuses to start otherwise.
- A request may be resolved through any enabled channel. The first valid resolution wins; the others are told the request is closed (HA notification cleared, web URL gives 410).
- A request fails with `INTERNAL` only if **every** enabled notification channel fails to announce it. A single channel failing is audited but not fatal.
- If HA is the only channel, no HTTP listener or OIDC configuration is required.

### 19.2 Connection to HA
- Config:
  ```toml
  [homeassistant]
  url = "http://homeassistant.local:8123"
  token_file = "/etc/secretd/ha.token"          # long-lived access token, secretd-only (0400)
  notify_service = "notify.mobile_app_owner_phone"
  passphrase_entity = "input_text.secretd_passphrase"
  owner_user_ids = ["<ha-user-id>"]             # allowlist, see 19.4
  allow_insecure_http = false
  ```
- Use HA's WebSocket API (`/api/websocket`) for events and service calls, authenticated with the token. Reconnect with exponential backoff (1s up to 60s). While disconnected the channel is unavailable, which counts as a notification failure for new requests and is audited.
- The token is sent over the network, so require an `https://` URL unless the host is loopback or `allow_insecure_http = true` is set explicitly (warn at startup, since a LAN-only HA is common). Never log the token.
- Pin HA's CA/cert via an optional `ca_file`.

### 19.3 Flow
1. On a new pending request, call `notify_service` with the same details as §5 step 4 (secret name, uid/user, pid, exe, sanitized cmdline, labelled client reason, expiry, request id) and `data.tag = <request_id>`. Add two actions: `SECRETD_APPROVE_<request_id>_<approval_token>` and `SECRETD_DENY_<request_id>_<approval_token>`. The approval token is the same 256-bit per-request token as §5 and is **not** shown in the notification text.
2. The owner types the passphrase into `passphrase_entity` (an `input_text` helper with `mode: password`, `max: 255`), then taps **Approve**. Passphrases longer than 255 characters are not supported on this channel; `check-config` documents this.
3. On the `mobile_app_notification_action` event, secretd validates the action id (constant-time token compare, request still pending, event origin passes 19.4).
   - **Deny:** resolve as denied, clear the notification.
   - **Approve:** read the current state of `passphrase_entity`, then **immediately** call `input_text.set_value` with an empty string, whether or not decryption succeeds. If the entity was empty, do not attempt unseal. Re-notify "enter the passphrase first, then tap Approve" and keep the request pending. This does not count as a failed attempt.
4. Run the normal approve path (§5 steps 6-7, including caller re-verification and the 3-attempt limit). On a wrong passphrase, send a follow-up notification with the attempts left, using the same tag.
5. On success, failure or timeout, clear the notification (`message: clear_notification`, same tag).
- Only one approval is processed at a time on this channel, since all requests share one entity. If a second Approve arrives while one is being processed, answer it with a "busy, try again" notification.

### 19.4 Authorization of HA events
- HA event context carries `user_id` for events caused by an authenticated user. Accept an action event only if `context.user_id` is present and in `owner_user_ids`. Events with a missing or non-listed user are ignored and audited (`ha_event_rejected`, with the user id if present, never the action id).
- **Verify during implementation** that the Companion app's `mobile_app_notification_action` event reliably carries `context.user_id`. If it does not, document the weaker model (anyone who can fire events on the HA bus can still not approve without the per-request token, which only the notification contains) and add `ha_require_user_id = false` as an explicit opt-out. Record the finding in `docs/DECISIONS.md`.
- The passphrase entity is read only in response to a valid Approve action for a pending request. Never read it on state changes.

### 19.5 Security considerations
- The passphrase transits HA: it is in the entity's state, the HA event bus and WebSocket, and may be written by the **recorder/history/logbook**. Anyone with admin access to HA can read it while it is set. This weakens the "owner device only" model and must be documented prominently in the README.
- Required documentation: exclude `passphrase_entity` from `recorder`, `history` and `logbook` (give the YAML), use `mode: password`, keep HA behind its own strong auth/MFA, and use HTTPS to HA.
- secretd must clear the entity immediately after reading it (step 3) and on request timeout/deny/disconnect. If clearing fails, retry and audit `ha_clear_failed`; do not release the secret until the clear has been attempted.
- At startup, query the entity's current state. If it is non-empty, clear it and audit (a stale passphrase must not linger).
- Notification text contains no passphrase and no approval token.
- Audit events add a `channel` field (`web`, `admin`, `homeassistant`) to every approval-related event; new events: `ha_connected`, `ha_disconnected`, `ha_event_rejected`, `ha_clear_failed`.

### 19.6 Tests
- Mock HA WebSocket server: auth, reconnect with backoff, service calls recorded, event injection.
- Approve with entity filled, approve with entity empty (re-prompt, no attempt consumed), deny, wrong passphrase then right, timeout clears notification.
- Entity cleared after every read (verify via mock), including on wrong passphrase and on decrypt failure.
- Event from a user not in `owner_user_ids`, a missing user id, a wrong token, an already-resolved request, and a second concurrent Approve (busy).
- First-resolution-wins across channels (HA approve while web page is open → web gives 410).
- Startup clears a stale non-empty entity.

## 20. Named-pipe (FIFO) secrets (v1.1 extension)

Lets a legacy program read a secret by opening a named pipe. A process opening the FIFO for reading triggers the same notification and approval flow as `secret.get`, and on approval the secret is written to the pipe.

### 20.1 Config
```toml
[[fifo]]
path = "/run/secretd/pipes/db-password"
secret = "db-password"        # must exist in [[secret]]
owner = "app"                 # user that may read; also the pipe's owner
group = "app"
mode = "0440"                 # default 0440; 0640/0660 only for owner/group use
enforce_acl = false           # see 20.3
```

- `secretd` creates the FIFO at startup (`mkfifo`, then `fchown`/`chmod` to the configured values, ignoring umask) in a directory that is owned by the daemon user and not writable by others. If the path already exists it must be a FIFO owned by the daemon user, not a symlink (`lstat`); otherwise refuse to start. `O_NOFOLLOW` where available. Remove the FIFO on clean shutdown.
- Access control is the FIFO's owner/group/mode. Permission to open the pipe is the first gate. The daemon user needs no extra privilege to create it.
- Multiple `[[fifo]]` entries may map to the same secret.

### 20.2 Detecting a reader
- Keep the FIFO armed by repeatedly attempting `open(O_WRONLY | O_NONBLOCK)`: it fails with `ENXIO` until a reader exists and succeeds as soon as one opens. Poll (e.g. every 100-250 ms) or use `inotify` `IN_OPEN` to avoid busy polling. The wait must be cancellable at shutdown or SIGHUP reload. Do not use a blocking `open` that cannot be interrupted.
- Ignore `SIGPIPE` process-wide; handle `EPIPE` on write as "reader went away".
- When a reader is detected, start a pending request exactly as for `secret.get`, with the channel list from §19.1, with these differences:
  - There is no `SO_PEERCRED` for pipes. Identify readers by scanning `/proc/*/fd/*` for entries resolving to the FIFO's `(st_dev, st_ino)`, excluding secretd itself, and keeping those whose `/proc/<pid>/fdinfo/<fd>` flags show read access. Capture pid, uid, gid, exe, sanitized cmdline and start time for each (same as §3.2). This needs the same `/proc` access as §3.2.
  - The notification and audit entry say `via FIFO <path>` and mark the identities **best-effort** (a process may not be found because of a race or because it closed the fd).
  - `reason` is `"read of <fifo path>"`.
- The reader's open or read blocks while the owner approves. That is expected. Document that readers must tolerate blocking (up to the request timeout).

### 20.3 Policy and verification
- Per-request limits (§8) apply, keyed on the FIFO path: at most 1 pending request per FIFO, plus a per-FIFO attempt limit (default 10 per minute) and the global caps. After a denial or timeout, wait a cool-down (default 5 s) before re-arming to avoid notification spam from a program that retries in a loop. A new request is not started while one is pending for the same FIFO.
- **Ambiguity rule:** if more than one distinct reader process holds the FIFO open for reading at request creation or at release, deny with audit `fifo_ambiguous`. A single write goes to one reader nondeterministically.
- **Identity rule:** if `enforce_acl = true`, the single identified reader must satisfy the secret's ACL (§6: uid/gid and exe). If no reader can be identified, deny with audit `fifo_reader_unknown`. If `enforce_acl = false` (default), identification is informational for the owner and the FIFO's file permissions are the gate.
- **Re-verification at release:** just before writing, re-scan; if the reader set differs from the snapshot (a different pid, exe or start time, or no readers left), abort with audit `caller_changed` and write nothing.
- The same single-use approval rules apply: one approval releases the secret to exactly one open of the FIFO.

### 20.4 Delivery
- On approval, unseal and obtain the one secret (§4, `unseal_one`). Write the **raw** value (base64 secrets are decoded first) with no added newline, using a non-blocking write loop with a deadline (default 5 s) so a stuck reader cannot hold the secret in memory indefinitely. Then close the write end so the reader sees EOF, zeroize the value, and re-arm after the cool-down.
- Handle `EPIPE`/`EAGAIN` timeouts: audit `aborted`, never retry the write on a later open.
- Audit `released` only after the full value was written; if only part was written, audit `aborted` with the byte count (never the data).
- A secret larger than the pipe buffer (64 KiB default) is supported through the loop; it is not required to be atomic.

### 20.5 Security notes (document in README/HARDENING)
- Any process allowed by file permissions can trigger a notification and, if approved, receives the secret. Without `enforce_acl` there is no exe pinning. Use a dedicated user/group, `0440`, and a private directory.
- Reader identification by `/proc` scan is racy and best-effort. The owner's approval is still the real gate.
- Same-uid readers can race to open the FIFO between the identified reader and the write, which the re-verification step narrows but cannot eliminate. A reader that is not the one the owner saw may get the secret if it opens the pipe at the right moment; the ambiguity check covers readers already present at release time.
- The FIFO directory must not be reachable by untrusted users, and the daemon's systemd unit needs `ReadWritePaths` for it.

### 20.6 Tests
- Reader detection: open for read triggers a notification; no reader means no request; shutdown cancels the wait.
- Approve → reader receives the exact bytes and then EOF; deny/timeout → EOF with no data; reader exits before approval → abort, nothing written, audited.
- Identity capture (pid/uid/exe) in the notification; `enforce_acl` allow and deny; unknown-reader and two-readers (ambiguous) denial; reader-set change between request and release.
- FIFO setup: refuses a symlink, a non-FIFO, wrong owner; sets owner/group/mode regardless of umask; cleans up on shutdown.
- Cool-down and per-FIFO limits; binary secrets are written raw; large secret is written in full; stuck reader hits the write deadline.
- Audit never contains the secret.

## 21. Milestones for the extensions

7. Channel abstraction: refactor notification and approval into channels without changing behavior (existing tests must still pass).
8. Home Assistant channel (§19) with the mock HA server and docs on recorder exclusion.
9. FIFO secrets (§20) with `[[fifo]]` config, `secretctl check-config` support, packaging (`ReadWritePaths`, tmpfiles) and docs.
10. Security review of both extensions.

## 22. Platform support (Linux and macOS)

`secretd` builds, tests and runs on Linux and on macOS (Apple silicon and Intel). The OS-specific parts sit behind small traits or `cfg(target_os)` modules; behaviour on Linux is the reference and is unchanged by the macOS port. Other Unixes are not supported.

### 22.1 Mechanisms per OS

| Concern | Linux | macOS |
|---|---|---|
| Peer uid/gid | `SO_PEERCRED` (tokio `peer_cred`) | `LOCAL_PEERCRED` credentials via `getpeereid` (tokio `peer_cred`) |
| Peer pid | `SO_PEERCRED` | `LOCAL_PEERPID` (`getsockopt(SOL_LOCAL)`), read by `secretd` itself: tokio would report `LOCAL_PEEREPID`, the effective pid, which differs for delegated sockets |
| Pid-reuse handle | `SO_PEERPIDFD` pidfd where the kernel has it (liveness re-checked at release) | none; start time only |
| Process identity (`ProcInfoReader`) | `/proc/<pid>/exe`, `cmdline` (256 bytes, sanitised), `stat` field 22 | `proc_pidpath` (exe), `sysctl(KERN_PROCARGS2)` argv only, environment never kept (best effort, same sanitising and 256-byte limit), `proc_pidinfo(PROC_PIDTBSDINFO)` `pbi_start_tvsec/tvusec` for the start time, `sysctl(KERN_PROC_PID)` `p_starttime` when `proc_pidinfo` is refused |
| Process gone | `/proc/<pid>` missing | libproc/sysctl report `ESRCH` (mapped to `NotFound`) |
| Deleted executable | ` (deleted)` suffix is always denied | no such concept: a binary whose vnode path cannot be resolved makes `proc_pidpath` fail, which is "unresolvable" and denied |
| Core dumps / inspection | `RLIMIT_CORE=0`, `prctl(PR_SET_DUMPABLE, 0)` | `RLIMIT_CORE=0`, `ptrace(PT_DENY_ATTACH)` (best effort; a failure is only a warning) |
| `mlock` | as before | as before (best effort) |
| FIFO reader scan (§20.2) | `/proc/*/fd` and `fdinfo` flags | `proc_listpids`, `proc_pidinfo(PROC_PIDLISTFDS)`, `proc_pidfdinfo(PROC_PIDFDVNODEPATHINFO)`: match the file's device and inode, `FREAD` in the open flags means "reader" |
| Socket activation | systemd `LISTEN_FDS`/`LISTEN_PID`/`LISTEN_FDNAMES` | none by default (plain bind); opt-in launchd activation of `Sockets` entries named `secretd` and `admin` through `launch_activate_socket` |
| Default socket paths | `/run/secretd/secretd.sock`, `/run/secretd/admin.sock` | `/var/run/secretd/secretd.sock`, `/var/run/secretd/admin.sock` |
| Default store | `/var/lib/secretd/store.age` | `/var/db/secretd/store.age` |
| Service manager | `packaging/secretd.service`, `.socket`, `sysusers.d`, `tmpfiles.d` | `packaging/launchd/` (LaunchDaemon plist, example `[daemon]` section, `dscl` steps) |

Explicit configuration works the same on both; only the defaults differ (`secret_proto::DEFAULT_RUN_DIR`, `DEFAULT_SOCKET`, `DEFAULT_ADMIN_SOCKET`, `DEFAULT_STORE`, also the default of the `secret` CLI).

`start_time` in `ProcInfo` is OS-specific (clock ticks since boot on Linux, microseconds since the epoch on macOS) and is only ever compared for equality between two reads. The re-verification semantics of §3.2 are identical: a changed executable or start time gives `CALLER_CHANGED`; an unresolvable process is denied.

### 22.2 Inspecting other users' processes

A caller that cannot be resolved is denied (`proc_unavailable`, audited): that is the only failure mode, ACLs are never weakened. What the daemon may inspect decides which callers can work:

* Linux: other uids need `CAP_SYS_PTRACE` (granted by the unit, see `docs/HARDENING.md`).
* macOS: the same uid is always inspectable. For other uids the daemon needs root for descriptor tables (`PROC_PIDLISTFDS`, hence FIFO reader detection) and `KERN_PROCARGS2` (hence the command line, which is only context). `proc_pidpath` and the start time are expected to be available without root (`proc_pidpath` and `sysctl(KERN_PROC_PID)` are not restricted to the same user in XNU), but this is an observation about XNU, not an Apple-documented guarantee, so `secretd` checks it empirically at start-up.

Start-up check (macOS only, after privileges were dropped): `secretd` reads the identity of pid 1 (`launchd`, owned by root). If that fails, then a secret whose ACL pins an executable (`allow_exes`) for anyone other than the daemon's own uid (any `allow_gids` entry counts) is a configuration error and the daemon **refuses to start**, naming the secret; `allow_any_exe` secrets for other users only produce a warning (their requests will be denied with `proc_unavailable`). The remedy is `daemon.user = "root"` (no privilege drop) or restricting the ACL to the daemon's own uid. FIFO readers of other users are unidentified when the daemon is not root: with `enforce_acl = true` they are refused (`fifo_reader_unknown`), without it the request shows an unidentified reader.

### 22.3 Privileges and users

Neither sysusers nor tmpfiles is assumed. On macOS the job is started by launchd as root, binds its sockets (creating `/var/run/secretd`, which macOS clears at boot), gives the client socket to the daemon user and group, drops to `daemon.user` (`_secretd`) and verifies root cannot be regained; this is the existing root-start path of §13, not a new one. The service account and groups are created with `dscl` (README in `packaging/launchd/`). FIFOs on macOS use a directory owned by the daemon user (`/var/db/secretd-pipes`), because `/var/run/secretd` is owned by root.

### 22.4 FIFO semantics on macOS

`open(O_WRONLY|O_NONBLOCK)` on a FIFO without a reader fails with `ENXIO` on both systems, and a reader still blocked in its own `open(O_RDONLY)` counts as a reader on both. The polling reader detection of §20.2 and the re-arm pause are unchanged. A vanished reader is detected through `poll(POLLOUT)` on the write end (`POLLERR` on Linux, `POLLHUP` expected on macOS; both are accepted) and, independently, as `EPIPE` on write. tokio waits with kqueue instead of epoll.

### 22.5 Not supported or different

* No `SO_PEERPIDFD`/pidfd on macOS: pid reuse is caught by the start time only.
* No systemd-style sandbox on macOS (`ProtectSystem`, syscall filter, capability bounding, `MemoryDenyWriteExecute`): `PT_DENY_ATTACH`, `RLIMIT_CORE=0` and the dedicated account are the available hardening. Hardened-runtime/notarization entitlements are not used.
* launchd socket activation is opt-in and not covered by automated tests.
* Unix socket paths are limited to 104 bytes on macOS (108 on Linux).
* Exe pinning is by path on both systems (not inode).

### 22.6 Tests and CI

Linux-only tests are gated with `#[cfg(target_os = "linux")]` (the `setpriv` multi-uid test, pidfd tests, the `/proc/<pid>/fdinfo` helpers). Pure parsers (`KERN_PROCARGS2`, `/proc/<pid>/stat`) are tested on every OS; macOS-only unit tests for the libproc/sysctl wrappers and `LOCAL_PEERPID` run on macOS. CI runs `cargo fmt --check`, `cargo clippy --workspace --all-targets -- -D warnings` and `cargo test --workspace` on `ubuntu-latest` and `macos-latest`.
