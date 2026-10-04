# secretd

`secretd` is a local secrets-release daemon for Linux and macOS. It keeps an
[age](https://age-encryption.org)-encrypted store of named secrets and releases one only
after **you** approve that exact request, from your phone, with a passphrase you type each
time.

```
 client process ──Unix socket──▶ secretd ──push (ntfy/webhook)──▶ owner's phone
   (secret get)    SO_PEERCRED     │  ACL check, rate limits          │ tap link
                                   │                                  ▼
                                   │◀── HTTPS via reverse proxy ── approval page
                                   │      Google sign-in (OIDC) + store passphrase
                                   ▼
                       decrypt ONE secret in memory, zeroize, return it (one shot)
```

* Always sealed: the passphrase is never stored; every release needs a fresh approval.
* The caller is identified by the kernel (`SO_PEERCRED`, plus `SO_PEERPIDFD` where available; on
  macOS `LOCAL_PEERCRED`/`LOCAL_PEERPID`) and `/proc/<pid>/exe` (macOS: `proc_pidpath`), snapshotted at accept, re-checked when each request arrives and again at
  release time (pid reuse / exec-after-connect gives `CALLER_CHANGED`). **Executable pinning is
  defence in depth, not a boundary:** a process running as an allowed uid can run an allowed binary
  (or win a connect/fork/exec race) and pass the ACL. The owner's per-request approval and passphrase
  are the real gate, so give secrets to dedicated uids and read the caller details on the approval page.
* Per-secret ACLs (uid / gid / executable path), per-uid rate limits, an append-only audit log.
* Owner authentication is Google OIDC restricted to an email allowlist; `secretd` itself speaks
  plain HTTP on loopback and sits behind a TLS-terminating reverse proxy.
* Approval channels are selectable (`web`, `admin`, `homeassistant`), and a secret can also be
  released through a named pipe for legacy programs (see "Channels", "Home Assistant channel" and
  "Named-pipe (FIFO) secrets" below).

| Crate | Purpose |
|---|---|
| `secretd` | the daemon |
| `secretctl` | admin CLI: init/add/remove/list, rotate-passphrase, check-config, terminal approve/deny |
| `secret` | client CLI: `get`, `list`, `inject` |
| `secret-client` | Rust client library |
| `secret-proto` | shared protocol types, store format, config model |

See [`docs/DECISIONS.md`](docs/DECISIONS.md) for choices the spec left open and
[`docs/HARDENING.md`](docs/HARDENING.md) for the security review.

## Build and install

```sh
cargo build --release          # stable Rust (developed on 1.97); Linux and macOS
sudo install -m0755 target/release/{secretd,secretctl,secret} /usr/bin/
sudo install -m0644 packaging/secretd.service packaging/secretd.socket \
     packaging/secretd-admin.socket /etc/systemd/system/
sudo install -m0644 packaging/tmpfiles.d/secretd.conf /etc/tmpfiles.d/
sudo install -m0644 packaging/sysusers.d/secretd.conf /etc/sysusers.d/
sudo systemd-sysusers && sudo systemd-tmpfiles --create
# Who may ask for secrets: members of the dedicated socket group (NOT the `secretd` group).
sudo usermod -aG secretd-clients alice
```

### macOS

The same workspace builds on macOS (Apple silicon and Intel) with `cargo build --release`. Install
the binaries, create the `_secretd` account and the `_secretd-clients` group with `dscl`, create the
directories and load the LaunchDaemon as described in
[`packaging/launchd/README.md`](packaging/launchd/README.md) (plist, example `[daemon]` section,
`launchctl` commands). Differences you will notice:

* default paths are `/var/run/secretd/secretd.sock` (client socket; the `secret` CLI default too),
  `/var/run/secretd/admin.sock`, `/var/db/secretd/store.age`; explicit config works as on Linux;
* the job starts as root, binds the sockets, then drops to `_secretd` (`daemon.user`); there is no
  `LISTEN_FDS` socket activation (plain bind; launchd activation is opt-in and untested);
* identifying a caller of **another user** needs root for some information. `secretd` checks this
  at start-up and **refuses to start** if an ACL pins an executable for such callers and they cannot
  be inspected; use `daemon.user = "root"` or restrict the ACL to the daemon's uid. Requests whose
  caller cannot be identified are denied and audited, never allowed with a weaker ACL. FIFO reader
  detection of other users' processes also needs root;
* no pidfd (pid reuse is caught by the start time), no systemd-style sandbox; `PT_DENY_ATTACH` and
  `RLIMIT_CORE=0` replace `PR_SET_DUMPABLE`.

See [`docs/HARDENING.md`](docs/HARDENING.md#macos) and spec section 22.

The client socket belongs to `secretd-clients`, a group created by `sysusers.d` that is separate
from the `secretd` group which can read `/etc/secretd`: being allowed to connect never implies read
access to the daemon's files. (The ACLs in the config still decide what each caller may request.)

## Quickstart

1. **Google OIDC client.** In Google Cloud Console create an OAuth client (type *Web
   application*) with the authorized redirect URI `https://secretd.example.com/auth/callback`.
   Save the client secret to `/etc/secretd/oidc-client-secret`
   (`chown secretd:secretd`, `chmod 0400`; credential files must be readable by the daemon user only). Google requires a real hostname with a valid
   certificate, hence the reverse proxy below.
2. **Push channel.** Pick an [ntfy](https://ntfy.sh) topic (use a long random name or an
   access-controlled topic) and install the ntfy app on your phone. Put an access token, if any,
   in `/etc/secretd/ntfy.token` (`secretd:secretd`, `0400`).
3. **Config.** `sudo install -m0640 -o root -g secretd packaging/config.example.toml
   /etc/secretd/config.toml`, then set `external_url`, `oidc.client_id`, `owner_emails`,
   `notify.url` and your `[[secret]]` ACLs. Validate it:
   ```sh
   sudo secretctl check-config
   ```
4. **Create the store and add secrets** (stop the daemon first; `secretctl` edits the file
   directly and prompts for the passphrase with echo disabled). **Run these as the `secretd`
   user** (`sudo -u secretd`), so the store is owned by the account the daemon runs as. If run as
   root, `secretctl` chowns the store to the daemon user (`daemon.user`) afterwards and warns, but
   the supported way is `sudo -u secretd`. Only the terminal approval commands (`pending`, `approve`,
   `deny`) need root, because the admin socket accepts uid 0 only. `--passphrase-file` is for
   automation and tests, not for real stores.
   ```sh
   sudo -u secretd secretctl init
   echo -n 's3cret' | sudo -u secretd secretctl add db-password   # or no-echo prompt
   sudo -u secretd secretctl add tls-key --file ./key.pem          # binary-safe
   sudo -u secretd secretctl list                                  # names + ACLs, never values
   ```
   Secrets are never accepted as command-line arguments. `secretctl rotate-passphrase`
   re-encrypts everything under a new passphrase atomically.
5. **Reverse proxy.** Use [`packaging/nginx.conf.example`](packaging/nginx.conf.example) or
   [`packaging/Caddyfile.example`](packaging/Caddyfile.example) (both below).
6. **Start.**
   ```sh
   sudo systemctl enable --now secretd.socket secretd-admin.socket secretd.service
   sudo systemctl reload secretd      # re-read ACLs/limits (SIGHUP)
   ```
7. **Use it** as a permitted user, from a permitted executable:
   ```sh
   secret get db-password --reason "nightly backup"      # blocks until you approve
   psql "host=db password=$(secret get db-password)"
   secret list
   secret inject -i app.conf.tpl -o app.conf             # {{ secret:db-password }} tokens
   ```
   Your phone buzzes; tap the notification, sign in with Google, check the caller (uid, exe,
   command line; the reason text is client-supplied and marked as such), enter the store
   passphrase and press **Approve** (or **Deny**). Over SSH you can instead run
   `sudo secretctl pending` and `sudo secretctl approve <id>` / `deny <id>` (admin socket,
   root only, passphrase prompt with echo disabled).

   Keep the client connection open while waiting: a client that half-closes its write side after
   sending the request (`shutdown(SHUT_WR)`) is treated as gone and the request is cancelled.

`secret` exit codes: `0` ok, `1` generic, `2` not found / not permitted, `3` denied, `4` timeout,
`5` rate limited. `secret inject` writes nothing and exits non-zero if any lookup fails; with
`-o` the file is created `0600` and an existing file is only replaced with `--force`.

### Template syntax

`{{ secret:NAME }}` (spaces optional, `NAME` is `[A-Za-z0-9._/-]+`). Escape with
`\{{ secret:NAME }}` to emit the token literally. Each name is requested once per run and
substituted everywhere; binary (base64-stored) secrets are decoded first.

## Example reverse proxy (nginx)

`secretd` serves **plain HTTP** on `127.0.0.1:8443` and never touches certificates. Forward only
`/approve/`, `/auth/` and `/healthz`, pass the original `Host` (it must equal the host in
`external_url`) and set `X-Forwarded-For`:

```nginx
server {
    listen 443 ssl;
    http2 on;
    server_name secretd.example.com;
    ssl_certificate     /etc/letsencrypt/live/secretd.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/secretd.example.com/privkey.pem;
    ssl_protocols       TLSv1.2 TLSv1.3;
    client_max_body_size 16k;

    location ~ ^/(approve/|auth/|healthz$) {
        proxy_pass http://127.0.0.1:8443;
        proxy_set_header Host              $host;
        proxy_set_header X-Forwarded-For   $remote_addr;   # replace, don't append
        proxy_set_header X-Forwarded-Proto https;
    }
    location / { return 404; }
}
```

Caddy equivalent:

```caddyfile
secretd.example.com {
	@secretd path /approve/* /auth/* /healthz
	handle @secretd {
		reverse_proxy 127.0.0.1:8443 {
			header_up X-Forwarded-For {remote_host}
		}
	}
	handle {
		respond 404
	}
}
```

`X-Forwarded-For` is only honoured when the TCP peer is in `approval.trusted_proxies`
(default loopback); keep the proxy on the same host, or list its address and set
`allow_non_loopback = true` if `secretd` must listen elsewhere.

## Channels

The owner can be reached, and can approve, through any enabled *channel*:

```toml
[channels]
enabled = ["web", "admin"]      # default; "homeassistant" is the third (see below)
```

* `web`: push notification (ntfy/webhook) plus the Google-OIDC approval page. Needs `[notify]`,
  `[approval]` and `[approval.oidc]`.
* `admin`: the root-only admin socket (`secretctl pending|approve|deny`). Pull based, announces nothing.
* `homeassistant`: see the Home Assistant section. With `web` off, no HTTP listener, `[notify]`,
  `[approval]` or OIDC settings are needed.

At least one must be enabled (`secretctl check-config` and the daemon refuse to start otherwise).
A request may be resolved through any enabled channel; the first valid resolution wins and the
others are told the request is closed (web URL: 410, Home Assistant notification cleared). A
request fails with `INTERNAL` only if **every** enabled notification channel (`web`,
`homeassistant`) failed to announce it; a single failing channel is audited (`notify_failed`
with its `channel`) but not fatal. Every approval-related audit event carries a `channel` field.
Which channels are enabled (and their settings) needs a restart to change (SIGHUP does not re-wire channels).

## Home Assistant channel

Instead of (or besides) the web page, the owner can approve from a **Home Assistant** (HA)
actionable notification: `secretd` sends it through your `notify.mobile_app_*` service, you type the
store passphrase into an `input_text` helper in HA, and tap **Approve** (or **Deny**).

```toml
[channels]
enabled = ["homeassistant", "admin"]          # no [notify]/[approval]/OIDC needed without "web"

[homeassistant]
url = "https://homeassistant.example.com:8123"
token_file = "/etc/secretd/ha.token"          # long-lived access token, secretd:secretd 0400
notify_service = "notify.mobile_app_owner_phone"
passphrase_entity = "input_text.secretd_passphrase"
owner_user_ids = ["0123456789abcdef0123456789abcdef"]   # HA user id(s) allowed to approve
# allow_insecure_http = false                 # http:// to a non-loopback host needs this (warns)
# ca_file = "/etc/secretd/ha-ca.pem"          # pin the CA/certificate for https
# ha_require_user_id = true                   # see "Who may approve" below
```

`secretd` keeps one WebSocket connection to `/api/websocket` (token authenticated, reconnecting with
exponential backoff from 1 s up to 60 s). While it is down the channel counts as failed for new
requests (audited as `notify_failed`; the request fails only if no other channel announced it).
The URL must be `https://` unless the host is loopback or `allow_insecure_http = true` (a LAN-only
HA is common; this logs a warning: the token and the passphrase then cross the LAN unencrypted).

**Flow.** The notification carries the same details as the other channels (secret, request id,
caller uid/user, pid, exe, command line, the labelled client reason, expiry) and two actions,
`SECRETD_APPROVE_<request id>_<token>` and `SECRETD_DENY_<request id>_<token>`; the 256-bit
per-request token is only inside the action ids, never in the text. You type the passphrase into
`passphrase_entity`, then tap Approve. `secretd` reads the entity **only** in response to a valid
Approve for a pending request and clears it *immediately*, whatever happens next (wrong
passphrase, store error, deny, timeout, client disconnect). An Approve with an empty entity
re-prompts ("enter the passphrase first") and does not count as an attempt; a wrong passphrase
re-sends the notification with the attempts left. Only one approval is processed at a time (the
entity is shared); a second Approve meanwhile gets a "busy, try again" notification. At start-up
(and on reconnect while nothing is pending) a non-empty entity is treated as stale and cleared
(audited `ha_entity_cleared`). Passphrases longer than 255 characters cannot be entered this way
(`input_text` maximum); `secretctl check-config` reminds you.

**HA setup (required).** Create the helper and keep it out of the recorder, history and logbook:

```yaml
# configuration.yaml
input_text:
  secretd_passphrase:
    name: secretd passphrase
    mode: password        # masks the field in the UI
    min: 0
    max: 255
    initial: ""           # do not restore an old value after a restart

recorder:
  exclude:
    entities:
      - input_text.secretd_passphrase    # keeps it out of the database and therefore history

logbook:
  exclude:
    entities:
      - input_text.secretd_passphrase

# history: has no filter of its own in current Home Assistant (it reads the recorder
# database); on older versions with `history: exclude:` add the entity there as well.
```

Also: put HA behind its own strong authentication/MFA, use HTTPS to HA, and give `secretd` a
**dedicated, non-administrator HA user** for its long-lived token.

> **Risk: the passphrase transits Home Assistant.** While you are typing it, it is the state of an
> entity, and when you tap Approve it sits in the HA state machine, travels over the HA event bus
> and WebSocket to `secretd`, and (unless excluded as above) can be written by the recorder, history
> and logbook. Anyone with administrator access to HA (or to a process that can read its state
> machine or WebSocket) can read it while it is set, and a compromised HA host can capture it. This
> weakens the "your phone is the only place the passphrase exists" property of the web channel. Use
> the web channel (or `secretctl approve` over SSH) if HA is not at least as trusted as the secrets.
> `secretd` itself never logs, audits or stores the passphrase, the token or the HA access token.

**Who may approve.** Home Assistant puts the id of the user who registered the phone in
`context.user_id` of the `mobile_app_notification_action` event (verified in HA's source: the
`mobile_app` webhook fires the event with `registration_context`, see `docs/DECISIONS.md`).
`secretd` accepts an action only if that user id is in `owner_user_ids` **and** the action carries the
right per-request token; everything else is ignored and audited as `ha_event_rejected` (with the user
id if present, never the action id). To find your user id: Developer tools > Events > listen to
`mobile_app_notification_action`, tap any notification action on the phone and read
`context.user_id`. `ha_require_user_id = false` is an explicit opt-out for setups whose events carry
no user id (then only the token protects against other HA users, and `secretd` warns at start-up).
The app event name is `mobile_app_notification_action` for the Android and current iOS Companion apps.

## Named-pipe (FIFO) secrets

For legacy programs that can only read a file: a pipe that behaves like `secret get`. The program
opens the pipe for reading; `secretd` notices, starts the same pending request (push notification,
owner approval with the passphrase), and on approval writes the **raw** value (base64 secrets are
decoded, no newline is added) into the pipe and closes it, so the reader sees the bytes and then EOF.

```toml
[[fifo]]
path = "/run/secretd/pipes/db-password"
secret = "db-password"      # must exist in [[secret]]; several pipes may share one secret
group = "app"               # the readers' group (the daemon user must be a member of it)
mode = "0640"               # owner rw, group r (default); at most 0660, never any `other` access
enforce_acl = false         # true: the one identified reader must also satisfy the secret's ACL
# owner = "secretd"         # default: the daemon user
# attempts_per_min = 10     # reader detections per minute before further ones are refused
# cooldown_secs = 5         # pause before the pipe is armed again after a request
# write_deadline_secs = 5   # time allowed to push the value into the pipe
```

`mode` is an octal string. **The daemon must be able to open the pipe for writing**, so it is the
owner (default) with the owner write bit, or a member of `group` with the group write bit; readers
get access through `group`. (An unprivileged daemon can only chown to itself and chgrp to groups it
belongs to; `secretd` refuses to start, and `secretctl check-config` reports it, if the combination
cannot work.) The pipe is created at start-up in a directory owned by the daemon user that nobody
else can write to (`/run/secretd/pipes`, created by the packaged `tmpfiles.d`; the unit has
`ReadWritePaths` for it), with owner/group/mode set explicitly (the umask plays no role), and removed
on clean shutdown. An existing path must be a FIFO owned by the daemon user (a leftover is replaced);
a symlink or any other file makes `secretd` refuse to start. Reload (`SIGHUP`) re-arms the pipes if
their configuration changed.

What the owner sees: the notification and approval page say `via FIFO <path>` and show the reader's
pid, uid, executable and command line, found by scanning `/proc/*/fd` for processes that hold the pipe
open for reading, marked **best effort** (a process can be missed by a race or because the daemon may
not look into it). Rules: if more than one distinct process has the pipe open for reading, the request
is denied (`fifo_ambiguous`); with `enforce_acl = true` the single identified reader must pass the
secret's ACL, and an unidentifiable reader is denied (`fifo_reader_unknown`); just before writing, the
reader set is checked again and a different process (or none) aborts the release with
`caller_changed` and writes nothing. A deny, a timeout or a reader that left gives EOF without data.
After every request the pipe stays closed for `cooldown_secs` (at least 250 ms) and at most
`attempts_per_min` readers per minute are considered, so a program that retries in a loop cannot
flood you.

**Readers must tolerate blocking:** their `open` or `read` waits for the owner's approval, up to
`daemon.request_timeout_secs` (default 300 s), and then sees EOF with no data if nobody approved.

**Security notes.** Any process the file permissions let open the pipe can trigger a notification and,
if you approve, receives the secret: without `enforce_acl` nothing pins the executable. Use a
dedicated user/group, a private directory, and the tightest mode that works. Reader identification is
racy; a same-uid process can race to open the pipe between the identified reader and the write (the
re-check narrows but cannot close that window, and a reader that opens after the check at the right
moment can receive the value). Your approval remains the real gate. The packaged unit has not been run
under real systemd in the development environment (see `docs/HARDENING.md`).

## Audit log and limits

`/var/log/secretd/audit.jsonl` (mode `0640`, JSON lines, every event has an `outcome`) is reopened
on `SIGHUP`: rotate with `mv audit.jsonl audit.jsonl.1 && systemctl reload secretd`. Repeated
rejections (`rate_limited`, `acl_denied`, `caller_changed`, HTTP limiter hits) are written once per
60 s window per uid/IP followed by a summary line with a count; real approvals are logged
individually and fail closed if the log cannot be written. The unit bounds descriptors, memory
(`MemoryMax=1G`: one scrypt derivation needs about 256 MiB at the default work factor, and stores
above work factor 2^22 are refused) and tasks; raise `LimitNOFILE` if you raise the connection limits.

## Approval model

An approval needs three things: the unguessable per-request link (delivered by push), a valid
Google sign-in for an allow-listed verified email (a session is reused for `session_ttl_secs`),
and the store passphrase, typed every time and used as the actual decryption key. Three wrong
passphrases deny the request. Approval links are single-use and die with the request (timeout,
denial, client disconnect: HTTP 410).

## Development

```sh
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
SECRETD_TEST_MULTIUID=1 cargo test --workspace                    # Linux only: needs root + setpriv
```

CI (`.github/workflows/ci.yml`) runs fmt, clippy and the test suite on Linux and on macOS. The macOS
job is the only place the libproc, `LOCAL_PEERPID` and `PT_DENY_ATTACH` code runs; on Linux you can
type-check it with `rustup target add aarch64-apple-darwin` and
`cargo check --workspace --all-targets --target aarch64-apple-darwin` (the `ring` C build script
needs a macOS C toolchain, or a stub compiler via `CC_aarch64_apple_darwin`, for that to succeed).

The integration tests run the daemon in-process with an injectable peer-credential provider,
process-table reader (`/proc` or libproc) and notifier, a mock ntfy server and a mock OIDC provider (test JWKS under
`crates/secretd/tests/common/keys/`; these keys protect nothing). `crates/secretd/tests/binary.rs`
also drives the real `secretd` binary end to end.

## Status and limits

Linux and macOS (see the macOS notes above for what differs). Network-reachable secret access, grant caching/leases, secret history, multi-owner
approval, HSM/TPM support and `secret run` are non-goals for v1. Known gaps are listed in
[`docs/HARDENING.md`](docs/HARDENING.md#known-gaps).

MIT licensed.
