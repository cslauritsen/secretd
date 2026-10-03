# Hardening review

## Reading other users' `/proc/<pid>/exe` (spec section 13 question)

`secretd` identifies callers with `SO_PEERCRED` (always works) and describes/verifies them via
`/proc/<pid>/{exe,cmdline,stat}`. Findings on a Linux kernel, checked with `setpriv`:

| Reader | `readlink /proc/<pid>/exe` of another uid's process | `/proc/<pid>/cmdline`, `/stat` |
|---|---|---|
| unprivileged other uid, no capabilities | **EACCES** | readable |
| same unprivileged uid, plus `CAP_SYS_PTRACE` | works | readable |
| root | works | readable |

Reading `exe` needs `PTRACE_MODE_READ_FSCREDS`, which for a different uid means
`CAP_SYS_PTRACE` (Yama's `ptrace_scope` only restricts attach, not this read). A `secretd` without
the capability can therefore only resolve callers of its own uid, and every other caller fails
closed ("treated as denied", as the spec requires), which is safe but makes the daemon useless.

**Minimal setting:** run the service as the unprivileged `secretd` user and keep exactly one
capability:

```
CapabilityBoundingSet=CAP_SYS_PTRACE
AmbientCapabilities=CAP_SYS_PTRACE
```

(shipped in `packaging/secretd.service`). `CapabilityBoundingSet=` empty, as the spec's generic
hardening list suggests, is incompatible with callers of other uids. Also do **not** set
`PrivateUsers=` (other uids would be remapped) or `ProtectProc=invisible`, and do not mount
`/proc` with `hidepid=2` unless `secretd`'s group is exempted with `gid=`: they hide other users'
processes and every request then fails closed. `PrivateTmp`,
`PrivateDevices`, `ProtectSystem=strict`, `MemoryDenyWriteExecute`, `SystemCallFilter` and
`RestrictAddressFamilies` do not interfere. `tests/packaging.rs` asserts these settings, and
`SECRETD_TEST_MULTIUID=1 cargo test -p secret --test cli multiuid` exercises real
`SO_PEERCRED` with two different uids (as root, where `/proc` is readable). I could not run the
unit under real systemd in this environment, so the unit file itself has been reviewed but not
executed.

Where the process can only hold a weaker identity (for example `exe` of a setuid or
non-dumpable process without the capability) the result is the same failure mode: denial.

## Controls in place

| Threat (spec section 2) | Control |
|---|---|
| Local user asks for secrets it must not get | `SO_PEERCRED` identity, per-secret uid/gid/exe ACL, deny by default, `(deleted)` exe denied, ACL miss indistinguishable from unknown name |
| Compromised permitted client | one-shot release, per-request owner approval and passphrase, caller re-verified at release (exe + start time), ACL re-checked against the current config |
| Store theft / backup leak | single age file, scrypt passphrase recipient, 0600, atomic writes; passphrase never stored |
| Notification eavesdropping | message carries identifiers and an approval link only: no secret, no key; link is useless without a Google session for an allow-listed email and the passphrase |
| Notification/request flooding | per-uid pending cap, total cap, per-minute attempt limit, connection caps, duplicate suppression, 64 KiB line cap, idle timeout, per-IP failed-attempt limiter on HTTP |
| Approval endpoint abuse | Host pinning, `Secure; HttpOnly; SameSite=Lax; __Host-` cookies, CSRF bound to session and request, strict CSP with per-response nonce, `no-store`, `no-referrer`, `X-Frame-Options: DENY`, constant-time token compare, single-use state/nonce/PKCE, open-redirect-proof `next` |
| Log leakage | audit log and tracing never contain values, passphrases, tokens or client reasons (asserted in tests) |

Process hardening: `RLIMIT_CORE=0` and `PR_SET_DUMPABLE=0` at start, `mlock` (best effort) on the
passphrase and plaintext buffers, `zeroize` on every secret-bearing buffer, decryption on a
blocking thread, root dropped after binding sockets (or never held under socket activation),
systemd sandboxing as shipped.

## Known gaps

* **Transient copies.** The passphrase passes through the HTTP stack (request body, form
  parser) and, on the admin socket, through `serde_json::Value` before it reaches the zeroizing
  buffer; those short-lived copies are freed but not zeroized. The same applies to the
  `secret-client` request path for names (not secret) and to the `age` crate's internal key
  schedule. Out of scope per the threat model (physical memory attacks, root).
* **`mlock` is best effort** and subject to `RLIMIT_MEMLOCK`; failures are silent. Consider
  `LimitMEMLOCK=` or encrypted swap.
* **Audit/release race.** `released` is audited before the value is written to the client; if
  the client's own timeout fires in that instant the log says released while the client saw
  `TIMEOUT`. The value is single-use either way.
* **Global pending cap side channel.** When `max_pending_total` is exhausted, callers that pass
  the ACL see `RATE_LIMITED` while others still see `NOT_FOUND`.
* **Store/config mismatches** cannot be detected at start-up without the passphrase (see
  `DECISIONS.md`); `secretctl list --check-store` and runtime warnings cover it.
* **Process identity is defence in depth.** An allowed uid can exec an allowed binary with
  hostile input; the owner's per-request approval remains the real gate. `cmdline` can be
  rewritten by a process after start and is shown to the owner only as context.
* **OIDC availability.** Login depends on Google being reachable; discovery is retried on the
  next login and the last good metadata is reused. The terminal fallback (`secretctl approve`)
  works without Google.
* **Reload scope.** SIGHUP re-reads ACLs, limits and timeouts only; sockets, notifier and OIDC
  settings need a restart.
* **Dependency audit.** CI runs `cargo audit`; `cargo build` currently prints a
  future-incompatibility notice for a transitive proc-macro crate.

## Operational advice

* Give `/etc/secretd/*` to `root:secretd` mode `0640`; run `secretctl check-config` after edits.
* Use a high-entropy store passphrase kept in a password manager: it is the decryption key, and
  scrypt cost is about 1 second per guess on this machine class.
* Treat the ntfy topic as semi-secret; prefer an access-controlled topic.
* Back up `/var/lib/secretd/store.age` freely (it is encrypted) but not the config's token files.
* Review `/var/log/secretd/audit.jsonl` for `acl_denied`, `rate_limited`, `caller_changed` and
  `admin_action` events with `oidc_rejected`.
