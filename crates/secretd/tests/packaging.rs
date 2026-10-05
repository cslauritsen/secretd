//! Sanity checks that the shipped systemd units carry the hardening required
//! by the specification (section 13).

use std::path::PathBuf;

fn read(name: &str) -> String {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../packaging")
        .join(name);
    std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("{}: {e}", p.display()))
}

fn has_line(text: &str, line: &str) -> bool {
    text.lines().any(|l| l.trim() == line)
}

#[test]
fn service_unit_is_hardened() {
    let s = read("secretd.service");
    for want in [
        "NoNewPrivileges=yes",
        "ProtectSystem=strict",
        "ProtectHome=yes",
        "PrivateTmp=yes",
        "PrivateDevices=yes",
        "RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6",
        "MemoryDenyWriteExecute=yes",
        "LockPersonality=yes",
        "SystemCallFilter=@system-service",
        "ReadWritePaths=/var/lib/secretd /var/log/secretd -/run/secretd/pipes",
        "User=secretd",
        "Sockets=secretd.socket secretd-admin.socket",
    ] {
        assert!(has_line(&s, want), "service unit lacks {want}");
    }
    // The bounding set is limited to the one capability needed to read other
    // users' /proc/<pid>/exe; nothing else may be granted.
    assert!(has_line(&s, "CapabilityBoundingSet=CAP_SYS_PTRACE"));
    assert!(has_line(&s, "AmbientCapabilities=CAP_SYS_PTRACE"));
    // Same-uid memory/descriptor access is blocked even though the daemon keeps
    // CAP_SYS_PTRACE, and the unit bounds descriptors, memory and tasks.
    assert!(has_line(
        &s,
        "SystemCallFilter=~ptrace process_vm_readv process_vm_writev pidfd_getfd"
    ));
    let limit = |key: &str| -> String {
        s.lines()
            .find_map(|l| l.trim().strip_prefix(key))
            .unwrap_or_else(|| panic!("service unit lacks {key}"))
            .to_string()
    };
    // Default config: 2 fds per connection (socket + pidfd) for 128 connections,
    // 64 approval connections, 64 headroom.
    let nofile: u64 = limit("LimitNOFILE=").parse().unwrap();
    assert!(
        nofile >= 2 * 128 + 64 + 64,
        "LimitNOFILE={nofile} has no headroom"
    );
    assert!(!limit("LimitMEMLOCK=").is_empty());
    assert!(!limit("MemoryMax=").is_empty());
    assert!(!limit("TasksMax=").is_empty());
    for forbidden in [
        "PrivateUsers=yes",
        "ProtectProc=invisible",
        "PrivateNetwork=yes",
    ] {
        assert!(!has_line(&s, forbidden), "{forbidden} would break secretd");
    }
}

#[test]
fn socket_units() {
    let c = read("secretd.socket");
    assert!(has_line(&c, "ListenStream=/run/secretd/secretd.sock"));
    assert!(has_line(&c, "FileDescriptorName=secretd"));
    assert!(has_line(&c, "SocketMode=0660"));
    // A dedicated group, distinct from the daemon's own group (which can read
    // /etc/secretd).
    assert!(has_line(&c, "SocketGroup=secretd-clients"));
    assert!(!has_line(&c, "SocketGroup=secretd"));
    let a = read("secretd-admin.socket");
    assert!(has_line(&a, "ListenStream=/run/secretd/admin.sock"));
    assert!(has_line(&a, "FileDescriptorName=admin"));
    assert!(has_line(&a, "SocketMode=0600"));
    assert!(has_line(&a, "SocketUser=root"));
}

#[test]
fn proxy_examples_forward_only_the_documented_paths() {
    let n = read("nginx.conf.example");
    assert!(n.contains("approve/|auth/|healthz$"));
    assert!(n.contains("proxy_set_header X-Forwarded-For   $remote_addr;"));
    assert!(n.contains("return 404;"));
    let c = read("Caddyfile.example");
    assert!(c.contains("/approve/* /auth/* /healthz"));
}

#[test]
fn clients_group_is_dedicated() {
    let su = read("sysusers.d/secretd.conf");
    assert!(su.lines().any(|l| l.trim() == "g secretd-clients -"));
    // The daemon user must not be a member of the clients group.
    assert!(!su
        .lines()
        .any(|l| l.starts_with("m secretd secretd-clients")));
    let cfg = read("config.example.toml");
    assert!(cfg.contains("socket_group = \"secretd-clients\""));
    // Credential files are for the daemon user only.
    assert!(cfg.contains("secretd:secretd 0400") || cfg.contains("mode 0400"));
    assert!(
        !cfg.contains("root:secretd 0640 ("),
        "credential files must not be group-readable"
    );
}

#[test]
fn pipe_directory_is_provisioned() {
    // The named pipes need a daemon-owned directory that nobody else can write
    // to, and the unit must be allowed to write there.
    let t = read("tmpfiles.d/secretd.conf");
    assert!(has_line(&t, "d /run/secretd/pipes 0711 secretd secretd -"));
    let s = read("secretd.service");
    assert!(s
        .lines()
        .any(|l| l.trim().starts_with("ReadWritePaths=") && l.contains("-/run/secretd/pipes")));
    // Pipes need mknod: the syscall filter must stay on a group that has it.
    assert!(has_line(&s, "SystemCallFilter=@system-service"));
    // The example config documents the pipe and the Home Assistant channel.
    let c = read("config.example.toml");
    assert!(c.contains("[[fifo]]") && c.contains("[homeassistant]"));
}

// ------------------------------------------------------------------ macOS
// These read static files, so they run on every OS (the systemd tests above
// do too; only checks that need Linux itself are gated elsewhere).

fn read_launchd(name: &str) -> String {
    read(&format!("launchd/{name}"))
}

/// The plist with XML comments removed.
fn uncommented(text: &str) -> String {
    let mut out = String::new();
    let mut rest = text;
    while let Some((before, after)) = rest.split_once("<!--") {
        out.push_str(before);
        rest = after.split_once("-->").map_or("", |x| x.1);
    }
    out.push_str(rest);
    out
}

#[test]
fn launchd_plist_runs_the_daemon_restarts_it_and_logs() {
    let p = uncommented(&read_launchd("org.secretd.secretd.plist"));
    assert!(p.contains("<string>org.secretd.secretd</string>"));
    assert!(p.contains("<string>/usr/local/bin/secretd</string>"));
    assert!(p.contains("<string>--config</string>"));
    assert!(p.contains("<string>/etc/secretd/config.toml</string>"));
    for key in [
        "<key>KeepAlive</key>",
        "<key>RunAtLoad</key>",
        "<key>ThrottleInterval</key>",
        "<key>StandardErrorPath</key>",
        "<key>StandardOutPath</key>",
        "<key>SoftResourceLimits</key>",
        "<key>Umask</key>",
    ] {
        assert!(p.contains(key), "missing {key}");
    }
    assert!(p.contains("/var/log/secretd/secretd.log"));
    // The job starts as root and the daemon drops to `_secretd` itself (the
    // socket directory under /var/run must be recreated at every boot).
    assert!(!p.contains("<key>UserName</key>"));
    // The optional launchd socket activation block stays commented out.
    assert!(!p.contains("<key>Sockets</key>"));
}

#[test]
fn launchd_example_config_uses_macos_paths_and_dedicated_groups() {
    let c = read_launchd("config.macos.example.toml");
    assert!(has_line(&c, "user = \"_secretd\""));
    assert!(has_line(&c, "socket = \"/var/run/secretd/secretd.sock\""));
    assert!(has_line(
        &c,
        "admin_socket = \"/var/run/secretd/admin.sock\""
    ));
    assert!(has_line(&c, "store = \"/var/db/secretd/store.age\""));
    assert!(has_line(&c, "socket_group = \"_secretd-clients\""));
    assert!(!c.lines().any(|l| l.contains("\"/run/secretd/")));
    assert!(!c.lines().any(|l| l.starts_with("store = \"/var/lib")));
}

#[test]
fn launchd_readme_documents_user_directories_and_install() {
    let r = read_launchd("README.md");
    for want in [
        "dscl . -create /Users/_secretd",
        "dscl . -create /Groups/_secretd-clients",
        "dseditgroup",
        "/Library/LaunchDaemons/org.secretd.secretd.plist",
        "launchctl bootstrap system",
        "install -d -o _secretd",
    ] {
        assert!(r.contains(want), "README misses {want}");
    }
}
