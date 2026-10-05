# secretd on macOS (LaunchDaemon)

Files here:

| File | Purpose |
|---|---|
| `org.secretd.secretd.plist` | LaunchDaemon: `KeepAlive`, log path, descriptor limit, umask |
| `config.macos.example.toml` | the `[daemon]` section with macOS paths; use it in place of the one in `../config.example.toml` |

How the daemon is run: launchd starts it as **root** (no `UserName` key); secretd creates
`/var/run/secretd` (macOS clears `/var/run` at every boot, and only root can recreate it), binds its
sockets, gives the client socket to `_secretd` and the `_secretd-clients` group, then **drops to the
`daemon.user` account (`_secretd`)** and checks that root cannot be regained. This is the same
start-as-root-then-drop path as on Linux without socket activation. With `user = "root"` in the
config it simply stays root.

**Read this before choosing the user.** secretd identifies callers by process (executable path and
start time). On macOS reading another user's process needs privileges: `proc_pidpath` and the start
time generally work for any process, but open descriptors (`proc_pidinfo(PROC_PIDLISTFDS)`, used for
named pipes) and the command line need root or the same uid. secretd probes this at startup and
**refuses to start** if an ACL pins an executable for callers other than the daemon's own uid and
those callers cannot be inspected; it never falls back to a weaker ACL. If you hit that refusal, run
with `user = "root"`. Details: [`docs/HARDENING.md`](../../docs/HARDENING.md#macos).

## Install

Build and install the binaries (adjust the prefix and the path in the plist to match):

```sh
cargo build --release
sudo install -m0755 target/release/{secretd,secretctl,secret} /usr/local/bin/
```

Create the service account and groups. Service accounts live below uid 500 and are hidden from
the login window; pick ids that are free on your machine (check with
`dscl . -list /Users UniqueID | sort -k2 -n | tail`):

```sh
UID_SECRETD=301      # free id < 500 on this Mac
sudo dscl . -create /Groups/_secretd
sudo dscl . -create /Groups/_secretd PrimaryGroupID "$UID_SECRETD"
sudo dscl . -create /Groups/_secretd RealName "secretd daemon"

sudo dscl . -create /Users/_secretd
sudo dscl . -create /Users/_secretd UniqueID "$UID_SECRETD"
sudo dscl . -create /Users/_secretd PrimaryGroupID "$UID_SECRETD"
sudo dscl . -create /Users/_secretd UserShell /usr/bin/false
sudo dscl . -create /Users/_secretd RealName "secretd daemon"
sudo dscl . -create /Users/_secretd NFSHomeDirectory /var/empty
sudo dscl . -create /Users/_secretd IsHidden 1

# The dedicated client group: members may connect to the socket. Not the `_secretd` group,
# which can read /etc/secretd: being allowed to connect must not imply access to its files.
sudo dscl . -create /Groups/_secretd-clients
sudo dscl . -create /Groups/_secretd-clients PrimaryGroupID "$((UID_SECRETD + 1))"
sudo dscl . -create /Groups/_secretd-clients RealName "secretd clients"
sudo dseditgroup -o edit -a "$USER" -t user _secretd-clients
# Only if you use [[fifo]] with group = "_secretd-clients": the daemon must belong to that group.
# sudo dseditgroup -o edit -a _secretd -t user _secretd-clients
```

Directories and configuration:

```sh
sudo install -d -o root -g wheel -m 0755 /etc/secretd
sudo install -d -o _secretd -g _secretd -m 0700 /var/db/secretd          # the store
sudo install -d -o _secretd -g _secretd -m 0750 /var/log/secretd         # audit + daemon log
sudo install -d -o _secretd -g _secretd -m 0711 /var/db/secretd-pipes    # only for [[fifo]]
# /var/run/secretd is created by the daemon itself (0755, root) at every start.

# Start from ../config.example.toml, replace its [daemon] section with config.macos.example.toml,
# then:
sudo install -o root -g _secretd -m 0640 config.toml /etc/secretd/config.toml
sudo secretctl check-config
```

Create the store and secrets with `secretctl` as described in the top-level README, preferably as
`sudo -u _secretd secretctl init` (the store lives
at `/var/db/secretd/store.age` and must end up owned by `_secretd`; `secretctl` also chowns it when run
as root).

Install and start the job (launchd refuses a plist that is not `root:wheel` and not writable by
others):

```sh
sudo install -o root -g wheel -m 0644 packaging/launchd/org.secretd.secretd.plist \
     /Library/LaunchDaemons/org.secretd.secretd.plist
sudo launchctl bootstrap system /Library/LaunchDaemons/org.secretd.secretd.plist
sudo launchctl kickstart -k system/org.secretd.secretd     # (re)start now
```

Day to day:

```sh
sudo launchctl print system/org.secretd.secretd             # state, last exit status
sudo launchctl kill HUP system/org.secretd.secretd          # reload ACLs/limits, reopen the audit log
sudo launchctl bootout system/org.secretd.secretd           # stop and unload
tail -f /var/log/secretd/secretd.log
sudo tail -f /var/log/secretd/audit.jsonl
```

Then, as a member of `_secretd-clients` (log out and in, or `newgrp`, so the group applies):

```sh
secret list                      # default socket: /var/run/secretd/secretd.sock
```

Not supported or different on macOS: no `LISTEN_FDS` socket activation (launchd activation is an
opt-in, untested alternative: see the commented `Sockets` block in the plist), no pidfd (a recycled
pid is caught by the start time only), no `(deleted)` executable marker, no `CAP_SYS_PTRACE`
(root is the equivalent), the sandbox of the systemd unit has no counterpart here (see
`docs/HARDENING.md`). Unix socket paths are limited to 104 bytes on macOS.
