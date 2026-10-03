# secretd

`secretd` is a local secrets-release daemon for Linux. It keeps an
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
* The caller is identified by the kernel (`SO_PEERCRED`, plus `SO_PEERPIDFD` where available)
  and `/proc/<pid>/exe`, snapshotted at accept, re-checked when each request arrives and again at
  release time (pid reuse / exec-after-connect gives `CALLER_CHANGED`). **Executable pinning is
  defence in depth, not a boundary:** a process running as an allowed uid can run an allowed binary
  (or win a connect/fork/exec race) and pass the ACL. The owner's per-request approval and passphrase
  are the real gate, so give secrets to dedicated uids and read the caller details on the approval page.
* Per-secret ACLs (uid / gid / executable path), per-uid rate limits, an append-only audit log.
* Owner authentication is Google OIDC restricted to an email allowlist; `secretd` itself speaks
  plain HTTP on loopback and sits behind a TLS-terminating reverse proxy.

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
cargo build --release          # stable Rust (developed on 1.97), Linux only
sudo install -m0755 target/release/{secretd,secretctl,secret} /usr/bin/
sudo install -m0644 packaging/secretd.service packaging/secretd.socket \
     packaging/secretd-admin.socket /etc/systemd/system/
sudo install -m0644 packaging/tmpfiles.d/secretd.conf /etc/tmpfiles.d/
sudo install -m0644 packaging/sysusers.d/secretd.conf /etc/sysusers.d/
sudo systemd-sysusers && sudo systemd-tmpfiles --create
# Who may ask for secrets: members of the dedicated socket group (NOT the `secretd` group).
sudo usermod -aG secretd-clients alice
```

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
SECRETD_TEST_MULTIUID=1 cargo test --workspace                    # needs root + setpriv
```

The integration tests run the daemon in-process with an injectable peer-credential provider,
`/proc` reader and notifier, a mock ntfy server and a mock OIDC provider (test JWKS under
`crates/secretd/tests/common/keys/`; these keys protect nothing). `crates/secretd/tests/binary.rs`
also drives the real `secretd` binary end to end.

## Status and limits

Linux only. Network-reachable secret access, grant caching/leases, secret history, multi-owner
approval, HSM/TPM support and `secret run` are non-goals for v1. Known gaps are listed in
[`docs/HARDENING.md`](docs/HARDENING.md#known-gaps).

MIT licensed.
