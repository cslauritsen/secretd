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
- Config ownership check: owner must be root, the daemon user, or (for `secretctl`) the
  invoking user, and the file must not be group/world writable.
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
- The release response line is serialised straight into a pre-sized `Zeroizing<Vec<u8>>`
  so the value is not copied into ordinary heap buffers by the server.
- Notifications (no `id`) are ignored without a reply. One request per connection is in
  flight at a time; bytes pipelined while a request waits stay buffered for the next one.
  While waiting, the connection task watches the socket for EOF to cancel the request.
- Audit events: `request_received` is written for every syntactically valid `secret.get`
  before any other check. `released` is written before the value is handed to the client; if
  it cannot be written the request fails with `INTERNAL`. Residual edge: if the client's
  timeout fires in the instant between `released` being audited and delivery, the audit shows
  `released` although the client saw `TIMEOUT`.
- Process start: sockets are bound (or inherited via `LISTEN_FDS`, matched by
  `LISTEN_FDNAMES` `secretd`/`admin`, else fd 3 is the client socket) while privileged, then
  root is dropped to `daemon.user`, then the audit log is opened. Config reload (SIGHUP)
  swaps ACLs, limits and timeouts; listen addresses, notifier and OIDC settings need a restart.
