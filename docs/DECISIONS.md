# Implementation decisions

Choices the specification left open, recorded as simply as possible.

## Workspace layout

- `secret-proto` holds the wire types (JSON-RPC, error codes, framing, sanitising)
  unconditionally. The server-only pieces (age store, configuration model, ACL
  evaluation, mlock helpers) live in the same crate behind the `server` feature so
  the client library does not pull in `age`, `toml` or `nix`. `secretd` and
  `secretctl` enable that feature.
- `age` 0.11 (stable API) is used for the store; `openidconnect` 4 for OIDC.

## Store (milestone 1)

- Plaintext format is JSON: `{"version":1,"secrets":{NAME:{"encoding":"utf8|base64","value":"..."}}}`.
  Values are held in `Zeroizing<String>`; the decrypted buffer is a `Zeroizing<Vec<u8>>`
  allocated with enough capacity that reading never reallocates (a realloc would leave
  an unzeroized copy behind).
- Text that is valid UTF-8 is stored as `utf8`, anything else as `base64`.
- Wrong passphrase (age header stanza fails) maps to `WrongPassphrase`; a payload that
  fails authentication, or any malformed plaintext, maps to `Corrupt`.
- New stores use age's default scrypt work factor (benchmarked to ~1s). `secretctl
  --work-factor N` overrides it (used by tests to stay fast).
- `unseal_one` takes `&mut Passphrase` and zeroizes it in place on every path, so the
  caller can verify zeroization. The passphrase and plaintext are `mlock`ed best effort.
- The daemon cannot compare config names against store contents at start-up because
  the names live inside the encrypted file and it must not need the passphrase. Instead
  `secretctl add` warns when a name has no `[[secret]]` entry, `secretctl list
  --check-store` compares both sides, and the daemon warns (logs) when an approved
  request names a secret absent from the store.
- Passphrase input for `secretctl`: no-echo prompt by default, or `--passphrase-file`
  (first line) for automation and tests. Secrets are never accepted as arguments.
  Values come from stdin (one trailing newline stripped) or `--file` (bytes verbatim).

## Configuration

- `socket_mode` is an integer written as a TOML octal literal (`0o660` or `0o666`).
- `allow_exes` entries must be absolute; if they exist they are canonicalised at load
  (so a symlinked `/usr/bin/foo` matches the resolved `/proc/<pid>/exe`), otherwise they
  are used verbatim with a warning.
- Giving both `allow_exes` and `allow_any_exe = true` is a configuration error.
- `approval.oidc.redirect_url` is optional and defaults to `<external_url>/auth/callback`.
- Config ownership check: owner must be root, the invoking user (euid) or the daemon user named
  by `daemon.user` in the file itself (not a hard-coded `secretd`), and the file must not be
  group/world writable. The file is opened once and the checks use that descriptor. Trusting the
  user named inside the file is circular by nature: the path must be one only the administrator can
  write (`/etc/secretd`); the check catches misconfigured ownership, it does not defend against a
  hostile `--config` path.
- Limits that make no sense at zero (`max_pending_*`, `max_conns_*`, `max_gets_per_uid_per_min`,
  `max_rejections_per_conn`, `admin_idle_timeout_secs`, the approval connection limits and timeouts)
  are rejected at load.
- `approval.oidc.issuer` must be `https://`. Plain `http://` is tolerated only for loopback hosts
  (the mock provider in the tests, local development) and then logs a warning.
- `daemon.socket_group` (optional) names the group that owns the client socket when `secretd` binds
  it itself; under socket activation the unit's `SocketGroup=` decides. Default in the packaging:
  the dedicated `secretd-clients`.
- Secret names are `[A-Za-z0-9._/-]+`, at most 256 bytes.

## Daemon core (milestone 2)

- Peer credentials: `PeerCredProvider` trait. The real provider uses tokio's
  `UnixStream::peer_cred`, which is a `getsockopt(SO_PEERCRED)` on Linux. Tests inject
  `StaticPeerCred`. `/proc` access is behind a `ProcReader` trait (real and in-memory
  implementations) so caller re-verification can be tested without real processes.
- Everything the daemon does is in the `secretd` library (`Core` + `server` + `runtime`);
  `main.rs` only wires it up. Integration tests run the library in-process on a temp
  socket instead of spawning the binary.
- A connection whose `/proc` lookup failed stays open (so `server.ping` works) but every
  `secret.get` is answered `NOT_FOUND` and `secret.list` is empty ("treated as denied").
- `secret.get` with a syntactically invalid name returns `INVALID_PARAMS`; valid-looking
  but unknown/forbidden names return `NOT_FOUND` with an identical error object.
- The per-uid attempt rate limit is checked before the ACL and applies to every name so
  a `RATE_LIMITED` reply never reveals ACL state. Pending caps / duplicate suppression are
  checked after the ACL (they can only be hit by callers that passed it, apart from the
  global cap, which is a documented minor side channel).
- `timeout_secs` is clamped to `[1, daemon.request_timeout_secs]`; absent means the maximum.
- `secret.list` and `secret.get` re-read `/proc/<pid>` when they arrive and compare exe and start
  time with the accept-time snapshot (see "Identity capture" below).
- The release response line is serialised straight into a pre-sized `Zeroizing<Vec<u8>>`
  so the value is not copied into ordinary heap buffers by the server.
- Notifications (no `id`) are ignored without a reply. One request per connection is in
  flight at a time; bytes pipelined while a request waits stay buffered for the next one.
  While waiting, the connection task watches the socket for EOF to cancel the request. EOF includes a half-close: a client that sends its request and then
  `shutdown(SHUT_WR)` (as one-shot netcat-style clients do) is indistinguishable from one that went away
  and the request is cancelled (approval URL: 410). Clients must keep the write half open until the
  answer arrives; `secret-client` does.
- Audit events, in the order they occur for a release: `request_received`, `notified`,
  `approve_attempt` (every passphrase submission, written *before* the passphrase is used, so it
  does not claim an approval that has not happened), `decrypt_failed` (wrong passphrase),
  `approved` (the passphrase opened the store), `released`. Further events: `denied`, `timeout`,
  `client_disconnected`, `notify_failed`, `caller_changed`, `acl_denied`, `rate_limited`,
  `aborted` (see below), `admin_action`. **Every** event carries an `outcome` (a per-event default
  from `audit::default_outcome`, overridden where more specific).
- `request_received` is only written for requests that passed the caller re-check, the attempt
  limiter and the ACL, i.e. requests that can reach the owner. Rejections anyone local can cause at
  will (`rate_limited`, `acl_denied`, `caller_changed`, and the HTTP failure/login limiters) go
  through a coalescer: the first event per (event, outcome, uid or ip) in a 60 s window is written
  in full, further ones only bump a counter that is written as one `summary: N further event(s)`
  line per window (flushed every 30 s and at shutdown). A write failure fails the request closed
  only for lines actually written. This caps the audit volume of a local flooder (previously ~5 MB/s
  of log). On top of that a client connection is closed after `limits.max_rejections_per_conn`
  (default 8) rejections that never reached the owner.
- `released` is audited by the request handler that is waiting for the client, after it received the
  value and before it is written to the socket; the approver is told "released" only after that
  audit succeeded (an ack channel). If the audit write fails the value is dropped and the client gets
  `INTERNAL`. If the client gave up first (timeout, disconnect, half-close), the approver's delivery
  fails: nothing is released, the audit shows `aborted` (`outcome: client_gone`) and the owner page /
  admin reply say "not released". The window between approve and delivery is the **whole unseal**
  (about a second of scrypt), not an instant, so this is a normal path rather than an edge case.
  A remaining, unavoidable edge: the value reached the handler and the `released` line was written,
  but the write to the client socket then fails (client died in that microsecond).
- How approve decides who wins against deny/timeout/disconnect: `approve` takes the request's reply
  sender out of the registry (the entry stays, marked busy, so caps and duplicate suppression keep
  counting it) for the whole unseal. `deny` of a busy request is refused (`Busy`, "approval in
  progress") instead of silently losing to the release. The waiting handler closes its end of the
  channel when its timeout or the disconnect fires, then checks once more for an already-sent
  outcome; whichever happens first wins, atomically. A wrong passphrase puts the sender back and
  clears busy; a request cancelled meanwhile is reported as gone. Concurrent approvals of the same
  request: the second gets `Busy`.
- Unsealing is serialised by a one-permit gate: one scrypt derivation needs 128 MiB x 2^(logN-17)
  (about 256 MiB at age's default), and `MemoryMax` in the unit is sized for one at a time.
  Maximum accepted work factor is 2^22 (`secret_proto::store::MAX_WORK_FACTOR`; it was 26 = 64 GiB),
  and `secretctl` refuses to write a store above it. Stores needing more than ~2^19 also need a
  larger `MemoryMax`.
- Audit-write failure policy, by action: anything that starts or advances an approval fails closed
  (`request_received`, `notified`, `approve_attempt`, `approved`, `released`, a recorded
  `decrypt_failed`: a wrong guess whose record cannot be written is not given a retry; `admin.approve`
  and `admin.pending` are refused with `INTERNAL`). Actions in the fail-safe direction proceed and
  report the gap: `denied` (the request is denied; the admin reply carries `warning`, the HTTP page
  says "not logged"), `caller_changed`, the acl re-check at release and `timeout` /
  `client_disconnected` (the request ends anyway; the failure is logged to stderr by `Core::audit`).
- The audit file is opened `O_APPEND|O_NOFOLLOW` with mode 0640 and `fchmod`ed to 0640 after every
  open, because `UMask=0077` in the unit would otherwise create it 0600 (and an existing file keeps
  whatever mode it had). Each event is serialised to one buffer and written with a single `write_all`.
  SIGHUP reopens the file (log rotation: rename, then `systemctl reload secretd`); if the reopen fails
  the old handle stays in use.
- Identity capture: the accept loop reads `SO_PEERCRED` and `/proc/<pid>/{exe,cmdline,stat}` inline,
  as the first thing it does with a new connection, before the handler task is spawned, before the
  connection caps are consulted and before any NSS user-name lookup (that is deferred into the task).
  When `secret.get`/`secret.list` arrives `/proc/<pid>` is re-read; a different exe or start time, or
  a vanished process, is answered with `CALLER_CHANGED` (`secret.list`: empty list) and audited
  (`caller_changed`, outcome `at_request`). With `SO_PEERPIDFD` (Linux 6.5+) the daemon also keeps a
  pidfd per connection and checks it still refers to a live process, which closes pid reuse beyond the
  start-time comparison; the pidfd is ignored if `/proc/self/fdinfo` shows a different pid than
  `SO_PEERCRED` (pid namespaces), and on older kernels the code falls back to `/proc` only.
  **This does not make exe pinning a boundary:** a same-uid process can `connect()`, `fork()` and
  have the parent `exec` an allowed binary before the daemon reads `/proc`; the snapshot then shows the
  allowed exe while the child holds the socket. Owner approval of each request is the real gate.
- The approval listener has its own accept loop (hyper-util on top of the axum `Router`): a
  connection semaphore (`approval.max_connections`, default 64; extra connections are closed at accept),
  hyper's header-read timeout (`header_read_timeout_secs`, 10; also bounds idle keep-alive), a
  per-request timeout around the whole handler stack including body reads (`request_timeout_secs`, 30,
  answers 408; it must exceed one unseal, because a timeout cancels an approval that is in flight and
  the request then ends as an error rather than a release) and a connection lifetime cap of 10x that.
  The tower-http `TimeoutLayer` was not added as a dependency: a `tokio::time::timeout` in the existing
  middleware does the same.
- `/auth/login`: each start is counted per source IP (`approval.max_login_starts_per_min`, 10) before
  the upstream discovery call. Login state is bounded globally (1000) and per IP (5); at a bound the
  oldest entry (per IP, then overall) is evicted instead of answering 503, so a flooder can only expire
  its own and the globally oldest pending logins.
- `Host` matching compares canonical forms: lower case, IPv6 literals parsed and re-rendered (any
  zero-compression or case matches), trailing dot and the default port 443 dropped. Anything that does
  not parse is a 400.
- Admin socket: idle timeout is `limits.admin_idle_timeout_secs` (default 600) instead of a fixed
  120 s, because `secretctl approve` keeps the connection open while the operator types a passphrase.
- `sanitize::clean` replaces everything in the Unicode general categories Cc, Cf, Cn, Co, Cs, Zl, Zp and
  Zs (except the ASCII space), using the `unicode-general-category` crate, plus code points that render
  blank or change rendering although they are not in those categories: tag characters U+E0000-E007F,
  variation selectors (U+FE00-FE0F, U+E0100-E01EF), U+180B-180F (includes U+180E), U+FFF9-FFFB, U+2800,
  U+3164, U+FFA0, U+115F/1160, U+17B4/17B5, U+034F. Characters unassigned in the crate's Unicode version
  are replaced too (safe direction). Zero-width-joiner emoji sequences are therefore flattened.
- `secretctl` run as root writes the store as root; it then chowns the file to `daemon.user` (and says
  so) so the unprivileged daemon can read it, or warns if the config/user cannot be resolved. The
  supported way is `sudo -u secretd secretctl ...`; the admin commands (`pending|approve|deny`) need
  uid 0 because of the admin socket.
- `--passphrase-file` (secretctl) is for automation and tests only: it leaves the passphrase in a file.
  Interactive use should rely on the no-echo prompt.
- Process start: sockets are bound (or inherited via `LISTEN_FDS`, matched by
  `LISTEN_FDNAMES` `secretd`/`admin`, else fd 3 is the client socket) while privileged, then
  root is dropped to `daemon.user`, then the audit log is opened. Config reload (SIGHUP)
  swaps ACLs, limits and timeouts; listen addresses, notifier and OIDC settings need a restart.

## Notification, approval endpoint, admin socket (milestone 3)

- ntfy: `POST <url>` with `Title` (ASCII-only), `Priority` (config, default `high`),
  `Tags: lock`, `Click` (approval URL) and optional `Authorization: Bearer <token from
  auth_token_file>`. The plain-text body lists secret, request id, caller, exe, cmdline, the
  client reason (labelled untrusted), expiry and the approval URL. Retries: `attempts` (default
  3) with exponential backoff starting at `backoff_ms` (default 500 ms). Non-2xx counts as failure.
  Errors are logged with `without_url()` so topic URLs do not reach logs.
- Webhook: JSON body (same fields, `reason_source` marks the reason as untrusted) with
  `X-Secretd-Signature: sha256=<hex HMAC-SHA256>` when `hmac_secret_file` is configured.
- Approval server: axum 0.8 on plain HTTP; `Host` must equal the host (and port, if any) of
  `external_url` for every route except `/healthz`. Cookies use the `__Host-` prefix, always
  `Secure; HttpOnly; SameSite=Lax; Path=/`, independent of the incoming scheme.
- Source IP: `X-Forwarded-For` is honoured only when the TCP peer is in `trusted_proxies`; the
  header is walked from the right skipping trusted proxies, so leading (spoofable) entries are
  ignored.
- Failed-attempt limiter: 5 per minute per source IP (configurable via
  `approval.max_failed_attempts_per_min`) then 429 + `Retry-After`. Counted failures: unknown
  or expired request id, bad approval token, bad CSRF, wrong passphrase, failed/forbidden OIDC
  callbacks.
- Unknown, expired, cancelled and already-resolved request URLs all return 410 Gone (so they are
  indistinguishable); a wrong token for a live request returns a generic 403.
- Token handling: the approval token lives only in memory and in the push message; it is not in
  the audit log. It is compared in constant time (`subtle`) before the OIDC redirect, so the
  login flow is only started for URLs that carry a valid token. It travels through the login
  redirect as a validated `next` parameter (strict `/approve/<32 hex>?t=<token chars>` format; any
  other value is rejected, so there is no open redirect).
- CSRF token: `HMAC-SHA256(per-process random key, "csrf|<session id>|<request id>")`, issued by
  the GET and verified on POST; stateless.
- OIDC: discovery and JWKS are fetched lazily on first login, cached for 1 h and refreshed once
  (at most every 30 s) after a failed verification to survive key rotation. Login state
  (PKCE verifier, nonce, `next`) is server-side, single-use, 10 min TTL, bound to the browser by a
  login cookie equal to `state`. Access/refresh tokens are dropped immediately after the ID token
  is extracted. `amr`, if present, is written to the audit log (`detail`) and never trusted.
- Auth outcomes are audited as `admin_action` with `outcome` `oidc_login` / `oidc_rejected` /
  `bad_approval_token` / `bad_csrf` (the spec's event list has no dedicated auth events).
- The passphrase arrives in a form body; the HTTP stack makes short-lived copies that are not
  zeroized (the copy handed to the store is). This is a known gap.
- Admin socket: JSON-RPC (`admin.pending`, `admin.approve`, `admin.deny`); each call is audited as
  `admin_action`. `secretctl approve` re-prompts on wrong passphrase when interactive, and
  makes a single attempt with `--passphrase-file`.
- Tests use RSA key pairs committed under `crates/secretd/tests/common/keys/` that exist only for
  the mock OIDC provider; they protect nothing.

## Limits, audit, re-verification (milestone 4)

- Rate-limit windows use a sliding 60 s window of attempt timestamps per uid (tokio `Instant`,
  so tests can use paused time). Every `secret.get` that reaches the limiter counts, including
  ones that later fail the ACL.
- Connection caps are enforced after the identity snapshot (which is taken first, see below): an
  over-cap connection receives one `RATE_LIMITED` error line (id `null`) and is closed. The idle timeout only applies while no
  request is in flight, so a request waiting for approval is not dropped.
- Caller re-verification at release compares `/proc/<pid>/exe` and the stat start time with the
  values captured at connect, then re-checks the ACL against the *current* config (so a SIGHUP
  that removes access also stops requests that are already pending; the client sees `NOT_FOUND`).
- Audit writes are synchronous with a per-write flush (no fsync per event, to keep approvals
  quick); a write error fails the request closed with `INTERNAL` (see the policy below).
- Besides the in-process tests, `tests/binary.rs` starts the real `secretd` binary (real sockets,
  real `SO_PEERCRED` and `/proc`) with `daemon.user = "root"`, which makes the privilege drop a
  no-op so the test also works as an unprivileged user.

## Client library and CLI (milestone 5)

- `secret-client` is synchronous. Responses are read into zeroizing buffers (no `BufReader`
  copy) and the value is parsed straight into a `Zeroizing<String>`; `SecretValue` zeroizes on
  drop and its `Debug` prints only the length. An async API was not added (optional in the spec).
- `secret` socket path: `--socket`, else `$SECRETD_SOCKET`, else `/run/secretd/secretd.sock`.
- `secret get` always prints "waiting for owner approval..." to stderr; a trailing newline is
  added only when stdout is a terminal. Exit codes follow the spec; `CALLER_CHANGED`,
  `DECRYPT_FAILED`, `INTERNAL` and connection errors all exit 1.
- `inject` tokens: whitespace inside the braces is spaces and tabs only. A single backslash
  immediately before a well-formed token escapes it (`\\{{ secret:A }}` therefore yields a
  literal backslash followed by the literal token, because
  only the last backslash escapes). Malformed tokens pass through unchanged.
- `inject` reads the whole template into memory (limit 64 MiB), requests each distinct name once
  and sequentially over one connection, buffers the output, and writes it only after every lookup
  succeeded. A template without tokens never contacts the daemon. Default `--reason` is
  `secret inject`.
- `-o FILE`: checked for existence *before* any approval is requested; created with mode 0600 via
  `create_new`; with `--force` it is written to a 0600 temp file in the same directory and renamed.
- The `secret` crate's integration tests run the real binary against the in-process daemon core
  with the real `SO_PEERCRED`/`/proc` providers (ACL pins the binary's own path and uid).

## Packaging and hardening (milestone 6)

- Two socket units: `secretd.socket` (client socket, `FileDescriptorName=secretd`, 0660
  `secretd:secretd-clients`; the dedicated group is created by `sysusers.d`, the `secretd` user is not a
  member and the `secretd` group, which can read `/etc/secretd`, is deliberately not used) and `secretd-admin.socket` (`FileDescriptorName=admin`, 0600 root). The
  service lists both in `Sockets=`; `secretd` maps inherited descriptors by `LISTEN_FDNAMES`.
  `tmpfiles.d` creates `/run/secretd` (0755, `secretd:secretd`), `sysusers.d` the user.
- `CapabilityBoundingSet=CAP_SYS_PTRACE` + `AmbientCapabilities=CAP_SYS_PTRACE` instead of the
  spec's empty bounding set: reading another uid's `/proc/<pid>/exe` needs it (verified
  experimentally; details in `docs/HARDENING.md`).
- Under systemd the service starts as `User=secretd`, so the daemon's own privilege drop is a no-op;
  when started as root outside systemd it binds sockets, then drops to `daemon.user`.
- `rust-version` is not declared (unverified MSRV); the code is developed and tested on stable 1.97.
- CI (`.github/workflows/ci.yml`) runs fmt, clippy, tests, the gated multi-uid test as root, and
  `cargo audit` via `rustsec/audit-check`. `cargo deny` is not configured.
- The multi-uid `SO_PEERCRED` test is gated behind `SECRETD_TEST_MULTIUID=1` (needs root and
  `setpriv`); everything else covers uid logic through the injectable peer-credential provider.
- The unit adds `LimitNOFILE=1024` (two descriptors per client connection: socket and pidfd, plus the
  approval connections; the daemon warns at start if the limit is below `2*max_conns_total +
  approval.max_connections + 64`), `LimitMEMLOCK=32M`, `MemoryMax=1G`, `MemorySwapMax=0`,
  `TasksMax=64` (the runtime is built with 4 workers and at most 8 blocking threads) and the explicit
  `SystemCallFilter=~ptrace process_vm_readv process_vm_writev pidfd_getfd`.
- Credential files (`oidc-client-secret`, ntfy token, webhook key) are `secretd:secretd 0400`, not
  `root:secretd 0640`: the socket group is a different group, but the daemon's own group can read
  `/etc/secretd`, so nothing but the daemon user should be able to read secrets there. systemd
  `LoadCredential=` is an alternative. `secretctl check-config` warns when a credential file is
  readable by the client socket group.

## Channels (milestone 7)

- `[channels] enabled` defaults to `["web", "admin"]` when the table is absent, so existing configs
  behave as before. `web` needs `[notify]`, `[approval]` and `[approval.oidc]` (both are now optional
  in the config model: `Config.notify` / `Config.approval` are `Option`, `Some` exactly when `web` is
  enabled). Tables present while `web` is off are ignored with a warning. Duplicates, unknown names
  and an empty list are config errors, which `secretctl check-config` reports (it loads the config
  with the same validator as the daemon).
- `Channel` trait (`secretd::channel`): `announce` (push to the owner), `announces()` (false for the
  pull-based admin channel) and `closed` (the request left the pending state). The *decision* half of
  a channel is a call to `Core::approve` / `Core::deny` with a `Source` (`Http(ip)`, `Admin`,
  `HomeAssistant`), so first-resolution-wins stays a single mechanism: the pending registry and the
  reply-channel handoff that already decided approve vs deny vs timeout.
- `Core::new(cfg, audit, notifier, procs)` is kept (web + admin around one `Notifier`) so the in-process
  test harness and the CLI tests are unchanged; `Core::with_channels` takes an explicit set.
- Announcing: every announcing channel is called concurrently. The request becomes answerable as soon
  as the first one succeeded *and its `notified` event was written* (audit order stays
  `request_received`, `notified`, ...); slower channels keep going and are audited when they finish.
  If all announcing channels failed, the request fails `INTERNAL`. If there is none (admin only), the
  request is answerable immediately and no `notified` event exists. A failing audit write on
  `notified` still fails closed.
- `closed` is called once per request on every channel, detached (a slow channel never delays the
  client's reply), with `Released | Denied | Timeout | Cancelled | Failed`. The web channel needs
  nothing (unknown request ids already answer 410).
- Audit `channel` is set on events that have a channel: `notified` / `notify_failed` (the announcing
  channel), `approve_attempt`, `approved`, `denied`, `decrypt_failed`, `released`, `aborted` (the
  resolving channel), the web endpoint's `admin_action` / `rate_limited` lines (`web`) and the admin
  socket's `admin_action` (`admin`). Events that belong to no channel (`request_received`, `timeout`,
  `client_disconnected`, `acl_denied`, `rate_limited` for socket clients) have none.
- `Notification` gained `approval_token` (channels other than web build their action ids from it) and
  its `approval_url` is empty without the web channel. Its `Debug` output redacts both, so a stray
  `{:?}` cannot log a token.

## Home Assistant channel (milestone 8)

- **Does the Companion app event carry `context.user_id`?** Checked in Home Assistant core
  (`homeassistant/components/mobile_app/webhook.py`, `dev` branch, October 2026): the app delivers
  notification actions through the `fire_event` webhook command, which does
  `hass.bus.async_fire(event_type, data, EventOrigin.remote, context=registration_context(config_entry.data))`,
  and `registration_context()` in `helpers.py` is `Context(user_id=registration[CONF_USER_ID])`.
  So `mobile_app_notification_action` events carry the id of the HA user who registered the device
  (not the user currently logged in to the HA frontend, and not necessarily the person holding the
  phone). It was verified by reading the source; it was **not** tested against a live Companion app
  (none is available here). Caveats: a registration without a user id yields `user_id: null`; events
  fired from automations/scripts inherit the context of whatever triggered them; and anyone who can
  fire events as the owner's user (their long-lived token) is indistinguishable from the owner.
  Hence the allowlist (`owner_user_ids`) is mandatory by default and `ha_require_user_id = false`
  exists as the opt-out the spec asks for: with it, events *without* a user id are accepted
  (events with a user id must still be in `owner_user_ids` when that list is non-empty), and the
  daemon warns at start-up. Even then the per-request token (only inside the notification) must match.
- Event name: only `mobile_app_notification_action` is subscribed (Android and current iOS
  Companion). Legacy iOS builds that fire `ios.notification_action_fired` are not supported.
- Library: `tokio-tungstenite` 0.30 with rustls (`ring`), no new async runtime. TLS roots: the
  system store, or only `ca_file` when set (a pin: nothing else is trusted). `wss://` handshakes
  use the `ring` provider explicitly, so the process-wide default provider is never needed.
- Protocol: one connection; command ids are assigned by the connection task; every call has a
  10 s timeout; an application-level `ping` every 30 s and a dead-connection cut-off after 75 s without
  traffic. Reconnect delay doubles from `backoff_min_ms` (1000) to `backoff_max_ms` (60000) and
  resets after a connection that authenticated; both are configurable only so the tests can use
  small values. An `auth_invalid` reply is treated like any other connection failure (same backoff).
- Reading the entity uses the WebSocket `get_states` command and picks the one entity out of the
  answer (HA has no per-entity read command on the WebSocket API; REST would need a second
  connection and client). It transfers all states of the HA instance for each Approve; the state
  list is dropped immediately and only the entity value is kept in a zeroizing buffer. A
  `render_template` subscription would be leaner but is event based and stays subscribed.
  `unknown` and `unavailable` count as empty.
- Clearing: `input_text.set_value` with `value: ""` right after the read (before the unseal, so
  also on every failure path), 3 attempts 200 ms apart; if all fail, `ha_clear_failed` is audited and
  the approval still proceeds ("the clear has been attempted"). The clear is skipped when the entity
  was empty. When a request ends for any reason other than a release, its `closed` hook clears the
  notification and the entity again (so a passphrase typed and never submitted does not linger).
  Consequence: a timeout of request A can clear a passphrase the owner is typing for request B;
  B's Approve then re-prompts. At connect (and on reconnect while no request announced on HA is
  pending) the entity is read once and cleared if non-empty, audited as `ha_entity_cleared`
  (outcome `stale`); this is an extra event beside the four in the spec.
- Authorization order of an action event: prefix check (other apps' actions are ignored silently),
  user id (`user_missing` / `user_not_allowed`), id/token syntax (`malformed_action`), request still
  pending (`unknown_request`), constant-time token compare (`bad_token`). Each rejection is audited
  as `ha_event_rejected` through the coalescer (one line per outcome and user per minute plus a
  summary) with the user id in `detail` and the request id when it parsed, **never** the action id
  or token. At most 16 action events are handled concurrently; extra ones are dropped (warning).
- Busy: a channel-wide flag taken by the first Approve; a concurrent Approve is answered with a
  "Busy, try again" notification and does not read the entity. A Deny of a request that is being
  unsealed answers "approval in progress" (core refuses it as busy).
- The notification is sent with `data.tag = <request id>`, `ttl: 0`, `priority: high`; re-prompts
  (empty entity, wrong passphrase with attempts left, busy) reuse the tag and carry the two actions
  again, because a notification replaced by a plain message would leave no Approve button. The token
  is kept in memory in the channel to rebuild them.
- Config: `homeassistant.url` must be http(s); plain http to a non-loopback host is an error without
  `allow_insecure_http = true` (warning with). `notify_service` must look like `notify.<name>`,
  `passphrase_entity` like `input_text.<name>`. `owner_user_ids` may be empty only with
  `ha_require_user_id = false`.
- The passphrase read from HA passes through the WebSocket message buffer and `serde_json::Value`
  before it reaches the zeroizing buffer; like the HTTP form path, those transient copies are not
  zeroized (see HARDENING known gaps). The same is true of the access token in the auth message.
- Tests use `tests/common/ha.rs`, a mock HA WebSocket server (auth, subscription, `call_service`,
  `get_states`, event injection, connection drops, rejected connections, failing services).
