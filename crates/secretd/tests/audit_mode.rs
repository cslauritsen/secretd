//! Audit file mode and reopen behaviour. This is its own test binary (own
//! process) because it changes the process umask.
use secretd::audit::{Audit, AuditEvent};
use std::os::unix::fs::PermissionsExt;

fn mode(p: &std::path::Path) -> u32 {
    std::fs::metadata(p).unwrap().permissions().mode() & 0o777
}

#[test]
fn audit_file_is_0640_even_under_umask_077() {
    // The systemd unit runs with UMask=0077; the file must still be 0640.
    // SAFETY: only test in this binary, no concurrent file creation.
    let old = unsafe { libc::umask(0o077) };
    let d = tempfile::tempdir().unwrap();
    let p = d.path().join("audit.jsonl");
    let a = Audit::open(&p).unwrap();
    a.log(&AuditEvent::new("request_received")).unwrap();
    assert_eq!(mode(&p), 0o640, "new file");

    // A pre-existing file with a different mode is corrected on open.
    let q = d.path().join("old.jsonl");
    std::fs::write(&q, b"").unwrap();
    std::fs::set_permissions(&q, std::fs::Permissions::from_mode(0o666)).unwrap();
    Audit::open(&q).unwrap();
    assert_eq!(mode(&q), 0o640, "existing file");

    // Reopening (SIGHUP after rotation) creates the new file with the same mode.
    std::fs::rename(&p, d.path().join("audit.jsonl.1")).unwrap();
    a.reopen().unwrap();
    a.log(&AuditEvent::new("timeout")).unwrap();
    assert_eq!(mode(&p), 0o640, "reopened file");
    unsafe { libc::umask(old) };
}

#[test]
fn reopen_follows_rotation_and_keeps_old_handle_on_failure() {
    let d = tempfile::tempdir().unwrap();
    let p = d.path().join("audit.jsonl");
    let a = Audit::open(&p).unwrap();
    a.log(&AuditEvent::new("request_received")).unwrap();
    let rotated = d.path().join("audit.jsonl.1");
    std::fs::rename(&p, &rotated).unwrap();
    // Before reopening, lines still go to the rotated file (same inode).
    a.log(&AuditEvent::new("notified")).unwrap();
    a.reopen().unwrap();
    a.log(&AuditEvent::new("timeout")).unwrap();
    let old = std::fs::read_to_string(&rotated).unwrap();
    let new = std::fs::read_to_string(&p).unwrap();
    assert_eq!(old.lines().count(), 2);
    assert_eq!(new.lines().count(), 1);
    assert!(new.contains("\"timeout\"") && new.contains("\"outcome\""));
    // A failing reopen (directory gone) leaves the working handle in place.
    let sub = d.path().join("sub");
    std::fs::create_dir(&sub).unwrap();
    let b = Audit::open(&sub.join("a.jsonl")).unwrap();
    std::fs::remove_file(sub.join("a.jsonl")).unwrap();
    std::fs::remove_dir(&sub).unwrap();
    assert!(b.reopen().is_err());
    assert!(b.log(&AuditEvent::new("timeout")).is_ok());
}

#[test]
fn symlinked_audit_path_is_refused() {
    let d = tempfile::tempdir().unwrap();
    let target = d.path().join("target");
    std::fs::write(&target, b"").unwrap();
    let link = d.path().join("audit.jsonl");
    std::os::unix::fs::symlink(&target, &link).unwrap();
    assert!(Audit::open(&link).is_err());
}
