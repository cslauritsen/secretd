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
