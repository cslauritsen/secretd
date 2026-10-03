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

Language: Rust (stable, edition 2021 or later). Target: Linux only (`SO_PEERCRED`, `/proc`).

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

- Single file, default `/var/lib/secretd/store.enc`, mode `0600`, owned by `secretd`.
- Format: a versioned header plus an encrypted blob.
  - KDF: Argon2id (params stored in the header; defaults m=64 MiB, t=3, p=1) deriving a key from the owner's passphrase.
  - AEAD: XChaCha20-Poly1305 (or AES-256-GCM). Each secret is encrypted individually so one approval decrypts only the requested secret. Use a per-secret random nonce and bind the secret name and store version as AAD.
  - Metadata that must be readable before decryption (secret names, ACLs) is stored in a plaintext-but-integrity-protected section (an HMAC under a key derived from the passphrase is acceptable; alternatively place the ACLs in the config file instead). **Decision for the implementer:** keep names and ACLs in the config file (`/etc/secretd/config.toml`) and keep only ciphertexts in the store. This avoids needing the key to evaluate ACLs.
- Writes are atomic (write temp, `fsync`, rename).
- In-memory handling: use `zeroize` / `secrecy`; call `mlock` on key and plaintext buffers where possible; disable core dumps (`prctl(PR_SET_DUMPABLE, 0)`, `RLIMIT_CORE=0`).
- Passphrase-derived key is derived on demand per approval and dropped immediately after decrypting the one requested secret.

## 5. Approval flow

1. Client sends `secret.get`.
2. `secretd` checks: ACL (§6), rate limits (§8). If it fails, return the error immediately and audit it. No notification is sent for ACL failures.
3. `secretd` creates a **pending request** with a random 128-bit `request_id` and a separate random 256-bit `approval_token` (both from the OS CSPRNG). It stores caller identity, secret name, reason, created and expiry times.
4. `secretd` sends a push notification (§7) containing: request id, secret name, caller uid/username, pid, exe path, sanitized cmdline, client-supplied reason (labelled), expiry time, and an approval URL containing the token. **Never** include the secret or any key.
5. The owner opens the approval URL (§7.2), reviews the details, and either denies, or approves by entering the passphrase.
6. On approve, `secretd` re-verifies the caller (§3.2), derives the key, decrypts the one secret, zeroizes the key, and returns the value to the waiting client.
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

- Must use TLS. Config: cert and key paths, listen address. Provide `secretctl gen-cert` to create a self-signed cert, and print its SHA-256 fingerprint for pinning. Plain HTTP is only allowed when bound to a loopback address (for use behind a reverse proxy) with an explicit config flag.
- Routes:
  - `GET /approve/<request_id>?t=<approval_token>`: HTML page showing request details with **Approve** (passphrase field) and **Deny** buttons. Constant-time token compare. Response headers: `Cache-Control: no-store`, `Referrer-Policy: no-referrer`, a strict CSP, `X-Frame-Options: DENY`.
  - `POST /approve/<request_id>`: form fields `t`, `action` (`approve`|`deny`), `passphrase` (for approve), `csrf`. CSRF token is bound to the request id and issued by the GET.
  - `GET /healthz`: unauthenticated, returns `ok` only.
- Authentication is **two factors**: possession of the unguessable per-request token (delivered via push) **and** the passphrase, which is the actual decryption key. In addition, require an HTTP basic-auth or bearer credential, configured as `owner_auth_token_file`, **if** `require_owner_auth = true` (default true). The push notification URL does not contain this credential; the owner's browser or phone stores it. This keeps a leaked push message insufficient to approve.
- Rate-limit failed attempts per source IP (e.g., 5 per minute, then 429).
- Never log tokens, passphrases, or secret values. Never put the passphrase in a URL.
- JSON API equivalent for tooling (optional, same auth): `POST /api/v1/requests/<id>/approve`.

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
- `secretctl gen-cert`, `secretctl check-config` (validates config, ACLs, file permissions)

Secrets are never accepted as command-line arguments (they would leak via `/proc/*/cmdline` and shell history).

## 12. Configuration

TOML at `/etc/secretd/config.toml`. Example skeleton:

```toml
[daemon]
user = "secretd"
socket = "/run/secretd/secretd.sock"
admin_socket = "/run/secretd/admin.sock"
store = "/var/lib/secretd/store.enc"
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
listen = "0.0.0.0:8443"
external_url = "https://secretd.example.com:8443"
tls_cert = "/etc/secretd/tls.crt"
tls_key = "/etc/secretd/tls.key"
require_owner_auth = true
owner_auth_token_file = "/etc/secretd/owner.token"

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

- Unit tests: framing, JSON-RPC parsing/errors, token parsing for `inject` (including chunk-boundary splits and escapes), ACL evaluation, store encrypt/decrypt round trip, tamper detection, and KDF parameter handling.
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

`tokio`, `serde`/`serde_json`, `nix` or `rustix` (`getsockopt` `SO_PEERCRED`, `prctl`, `mlock`), `axum` + `rustls` (approval server), `reqwest` (with rustls) for notifications, `argon2`, `chacha20poly1305`, `zeroize`, `secrecy`, `rand`/`getrandom`, `subtle` (constant-time compare), `toml`, `clap`, `tracing`, `thiserror`/`anyhow`, `tempfile` for tests.

## 16. Milestones

1. `secret-proto` + store format + `secretctl init/add/list`, with tests.
2. `secretd` Unix socket server with `SO_PEERCRED`, ACLs, `secret.get` returning a decrypted value through a stub approver (test-only).
3. Notification + HTTPS approval endpoint + admin socket fallback.
4. Rate limits, audit log, caller re-verification.
5. `secret` CLI (`get`, `list`, `inject`) and `secret-client` library.
6. systemd units, packaging, docs, hardening review.

## 17. Non-goals (v1)

Network-reachable secret access (Unix socket only), non-Linux platforms, grant caching or TTL leases, secret versioning/history, multi-owner or quorum approval, HSM/TPM integration, `secret run`.

## 18. Open questions for the owner

Defaults assumed above; confirm or change:
1. The passphrase typed into the approval page is the store's master passphrase (one KDF for all secrets), not a per-secret key. Should individual secrets support separate passphrases?
2. Is a self-signed certificate with fingerprint pinning acceptable, or should the spec assume a reverse proxy with a real certificate?
3. Is the extra `owner_auth_token_file` credential on the HTTPS endpoint acceptable (it makes phone approval need one-time browser setup), or should the unguessable URL plus passphrase be sufficient?
