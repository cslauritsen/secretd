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
        "ReadWritePaths=/var/lib/secretd /var/log/secretd",
        "User=secretd",
        "Sockets=secretd.socket secretd-admin.socket",
    ] {
        assert!(has_line(&s, want), "service unit lacks {want}");
    }
    // The bounding set is limited to the one capability needed to read other
    // users' /proc/<pid>/exe; nothing else may be granted.
    assert!(has_line(&s, "CapabilityBoundingSet=CAP_SYS_PTRACE"));
    assert!(has_line(&s, "AmbientCapabilities=CAP_SYS_PTRACE"));
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
