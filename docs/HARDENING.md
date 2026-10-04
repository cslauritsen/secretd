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

### Why `CAP_SYS_PTRACE`, and what it costs

The capability is needed for exactly one thing: `readlink(/proc/<pid>/exe)` for clients of another
uid (above). It is not needed for anything else, and it is **not harmless**. A `secretd` that has been
compromised (code execution inside the daemon) and holds `CAP_SYS_PTRACE` can read the memory of other
processes, including a client that has just received a secret, by opening `/proc/<pid>/mem` (a plain
file read, not a syscall the seccomp filter can see) or by attaching with `ptrace`. The kernel's
checks for that are `PTRACE_MODE_ATTACH`, which the capability satisfies for every process in the
same user namespace, root's included unless a security module or `kernel.yama.ptrace_scope=3` forbids
it. Mitigations that are in place: the explicit `SystemCallFilter=~ptrace process_vm_readv
process_vm_writev pidfd_getfd` removes the syscall routes (it does *not* stop `/proc/<pid>/mem`),
`MemoryDenyWriteExecute`, `NoNewPrivileges`, an unprivileged user, a minimal syscall set and address
families, `ProtectSystem=strict`. Residual risk: a daemon exploit becomes a memory-reading primitive
against every process on the host. If that is unacceptable, run with no capability and accept that
only callers of the daemon's own uid can be identified (or set `kernel.yama.ptrace_scope=3` and keep
only same-uid clients), or split the `/proc` lookup into a tiny privileged helper. This is a deliberate
trade-off, recorded in `docs/DECISIONS.md`.

### Executable pinning does not stop a same-uid attacker

`allow_exes` is defence in depth, not a boundary:

* A process with an allowed uid can run an allowed binary (with hostile arguments, environment,
  `LD_PRELOAD`-free input, a debugger-less plugin directory...) and talk to the socket from it.
* A process can `connect()`, `fork()` and `exec` an allowed binary in the parent *before* the daemon
  reads `/proc`: the snapshot then shows the allowed exe while the child that holds the descriptor is
  attacker code. The daemon narrows the window (the snapshot is the first thing done after `accept`,
  inline, before any cap check or name lookup; `/proc/<pid>` is re-read when each `secret.get` arrives
  and a changed exe or start time, or an exited process, gives `CALLER_CHANGED`; with `SO_PEERPIDFD`
  the pid cannot silently refer to a different process) but cannot close it: if the exec wins the race
  nothing changes afterwards to detect.
* Matching is by path, not inode: a binary replaced at an allowed path by someone with write access to
  it, hard links, or the same path in a different mount namespace all match. (Documented limit; not
  fixed.)

The real gate is the owner: every release needs a fresh approval *and* the passphrase, and the
approval page shows the caller's pid, exe and command line. Do not treat `allow_exes` as a way to make
a shared-uid host safe; give secrets to dedicated uids.

## Controls in place

| Threat (spec section 2) | Control |
|---|---|
| Local user asks for secrets it must not get | `SO_PEERCRED` identity, per-secret uid/gid/exe ACL, deny by default, `(deleted)` exe denied, ACL miss indistinguishable from unknown name |
| Compromised permitted client | one-shot release, per-request owner approval and passphrase, caller re-verified at release (exe + start time), ACL re-checked against the current config |
| Store theft / backup leak | single age file, scrypt passphrase recipient, 0600, atomic writes; passphrase never stored |
| Notification eavesdropping | message carries identifiers and an approval link only: no secret, no key; link is useless without a Google session for an allow-listed email and the passphrase |
| Notification/request flooding | per-uid pending cap, total cap, per-minute attempt limit, connection caps, duplicate suppression, 64 KiB line cap, idle timeout, a per-connection rejection budget (the connection is closed after 8 rejections that never reached the owner), per-IP failed-attempt and login-start limiters on HTTP |
| Audit-log flooding / disk fill | `rate_limited`, `acl_denied`, `caller_changed` and the HTTP limiter events are coalesced per (event, outcome, uid/ip) per 60 s window: one full line, then one summary line with a count. Real approvals are still logged one by one and still fail closed |
| Resource exhaustion of the daemon | approval listener: connection semaphore (64), header-read timeout (10 s), request timeout (30 s), connection lifetime cap; unit: `LimitNOFILE`, `LimitMEMLOCK`, `MemoryMax`, `MemorySwapMax=0`, `TasksMax`; one unseal at a time; maximum scrypt work factor 2^22 |
| Race between approval and deny/timeout/disconnect | the approver holds the reply channel for the whole unseal; deny of a busy request is refused; a client that gave up makes delivery fail and the owner is told "not released" (audit `aborted`); `released` is only written once the value reached the waiting handler |
| Approval endpoint abuse | Host pinning, `Secure; HttpOnly; SameSite=Lax; __Host-` cookies, CSRF bound to session and request, strict CSP with per-response nonce, `no-store`, `no-referrer`, `X-Frame-Options: DENY`, constant-time token compare, single-use state/nonce/PKCE, open-redirect-proof `next` |
| Log leakage | audit log and tracing never contain values, passphrases, tokens or client reasons (asserted in tests) |
| Socket access implies file access | the client socket belongs to the dedicated group `secretd-clients`; credential files are `secretd:secretd 0400`, not readable by that group (`secretctl check-config` warns otherwise) |
| Audit log permissions | the file is `fchmod`ed to 0640 after every open (the unit's `UMask=0077` would otherwise make it 0600) and reopened on SIGHUP for rotation |

Process hardening: `RLIMIT_CORE=0` and `PR_SET_DUMPABLE=0` at start, `mlock` (best effort) on the
passphrase and plaintext buffers, `zeroize` on every secret-bearing buffer, decryption on a
blocking thread, root dropped after binding sockets (or never held under socket activation),
systemd sandboxing as shipped.

## Home Assistant channel

| Threat | Control |
|---|---|
| Passphrase lingers in HA | entity read only on a valid Approve (and once at connect), cleared immediately after the read on every path, cleared again when a request ends without a release, stale value cleared at start-up; `ha_clear_failed` audited after 3 failed attempts |
| Forged action events on the HA bus | `context.user_id` must be in `owner_user_ids`, request must be pending, per-request token compared in constant time; rejections audited (`ha_event_rejected`, coalesced) without the action id |
| Token or passphrase in notification text/logs/audit | text carries neither (token only inside action ids); `Notification` redacts url/token in `Debug`; tests assert audit and daemon log never contain the passphrase, the HA token or the action token |
| HA token on the wire | `https://` required (loopback or `allow_insecure_http = true` excepted, with a warning); optional `ca_file` pin |
| Flood of events | at most 16 action events handled at once, rejections coalesced in the audit log, one approval at a time |

Residual risks, also in the README: the passphrase **does transit Home Assistant** (entity state,
event bus, WebSocket, possibly recorder/history/logbook if not excluded) and is readable by HA
administrators while it is set; a compromised HA host or long-lived token holder acting as the owner
user can approve (still needing the per-request token, which only the notification contains).
`get_states` is used to read the entity, so each Approve pulls the full state list of HA into
`secretd`'s memory (dropped at once). Passphrases over 255 characters are not supported on this channel.
Transient copies of the passphrase and of the access token in WebSocket/JSON buffers are not
zeroized (same class as the HTTP form path).

## Known gaps

* **Transient copies (not fixed).** The passphrase passes through the HTTP stack (request body, form
  parser) and, on the admin socket, through `serde_json::Value` before it reaches the zeroizing
  buffer; those short-lived copies are freed but not zeroized. Remaining zeroization gaps in the HTTP
  and admin parsing are accepted. The same applies to the
  `secret-client` request path for names (not secret) and to the `age` crate's internal key
  schedule. Out of scope per the threat model (physical memory attacks, root).
* **`mlock` is best effort** and subject to `RLIMIT_MEMLOCK` (the unit sets `LimitMEMLOCK=32M`);
  failures are silent. The unit also sets `MemorySwapMax=0`; encrypted swap is still advisable for the
  rest of the host.
* **Approve vs deny/timeout/disconnect window.** The window is the *whole unseal* (an scrypt
  derivation, about a second at the default work factor), not an instant. Inside it the outcome is
  decided atomically and reported truthfully: the owner sees "released" only if the waiting handler
  received the value and wrote the `released` audit line; otherwise "not released" (`aborted`). Deny
  of a request that is being approved is refused as busy. One edge remains: the value reached the
  handler and was audited as released, and then the write to the client socket fails.
* **Audit failure policy.** Starting or advancing an approval fails closed when the log cannot be
  written (including refusing `admin.approve`/`admin.pending` and not granting a retry for a
  `decrypt_failed` that could not be recorded). Denials, caller changes and timeouts proceed because
  they are the safe direction; the gap is reported (admin reply `warning`, HTTP page, stderr).
* **Half-close cancels the request.** The daemon treats read-EOF on the client socket as "client
  gone". A client that sends its request and then `shutdown(SHUT_WR)` cancels it (approval URL: 410).
  Clients must keep the connection fully open until the answer arrives.
* **`X-Forwarded-For` can be spoofed by local users.** Loopback is in `trusted_proxies` by default, so
  any local user can connect to `127.0.0.1:8443` and send a forged `X-Forwarded-For`, evading the
  per-IP limiters or pinning their failures on another address, and misattributing `source_ip` in the
  audit log. Not fixed: keep the HTTP port reachable only by the proxy (put the proxy and secretd in
  separate network namespaces/containers, or listen on a Unix socket behind the proxy) if local users
  are untrusted.
* **Cancelled approvals.** A request timeout on the HTTP side (default 30 s) cancels an approval that
  is still unsealing. The request then ends with an error instead of a release (nothing is released);
  keep `request_timeout_secs` well above the unseal time of your work factor.
* **`secretctl --passphrase-file`** exists for automation and the test suite. It leaves the store
  passphrase in a file; use the no-echo prompt for real stores.
* **Global pending cap side channel.** When `max_pending_total` is exhausted, callers that pass
  the ACL see `RATE_LIMITED` while others still see `NOT_FOUND`.
* **Store/config mismatches** cannot be detected at start-up without the passphrase (see
  `DECISIONS.md`); `secretctl list --check-store` and runtime warnings cover it.
* **Process identity is defence in depth.** An allowed uid can exec an allowed binary with
  hostile input, or win the connect/fork/exec race described above; the owner's per-request approval
  remains the real gate. Exe matching is by path, not inode (not fixed). `cmdline` can be rewritten by
  a process after start and is shown to the owner only as context.
* **OIDC availability.** Login depends on Google being reachable; discovery is retried on the
  next login and the last good metadata is reused. The terminal fallback (`secretctl approve`)
  works without Google.
* **Reload scope.** SIGHUP re-reads ACLs, limits and timeouts and reopens the audit log; sockets,
  the approval listener's limits, notifier and OIDC settings need a restart.
* **Dependency audit.** CI runs `cargo audit`; `cargo build` currently prints a
  future-incompatibility notice for a transitive proc-macro crate.

## Operational advice

* Config file: `root:secretd` mode `0640`. Credential files (OIDC client secret, ntfy token, webhook
  key): owned by `secretd`, mode `0400` (or use systemd `LoadCredential=`); they must not be readable
  by `secretd-clients`. Run `secretctl check-config` after edits.
* Only members of the dedicated `secretd-clients` group can connect to the client socket
  (`usermod -aG secretd-clients alice`); the `secretd` user is not a member.
* Run `secretctl init|add|remove|rotate-passphrase` as the daemon user (`sudo -u secretd ...`); the
  terminal approval commands need root (admin socket). A root run of the store commands chowns the file
  to the daemon user and says so.
* Rotate the audit log with `mv audit.jsonl audit.jsonl.1 && systemctl reload secretd`; SIGHUP reopens
  the file (mode 0640).
* Use a high-entropy store passphrase kept in a password manager: it is the decryption key, and
  scrypt cost is about 1 second per guess on this machine class.
* Treat the ntfy topic as semi-secret; prefer an access-controlled topic.
* Back up `/var/lib/secretd/store.age` freely (it is encrypted) but not the config's token files.
* Review `/var/log/secretd/audit.jsonl` for `acl_denied`, `rate_limited`, `caller_changed` and
  `admin_action` events with `oidc_rejected`.
