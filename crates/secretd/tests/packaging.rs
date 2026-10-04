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
