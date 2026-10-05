//! Creating and verifying the pipe (spec 20.1): no symlinks, only FIFOs of ours,
//! owner/group/mode regardless of umask, directory rules, clean-up.
//! Every test takes the lock because one of them changes the process umask.

use secret_proto::config::FifoCfg;
use secretd::fifo::{remove, setup};
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

static LOCK: Mutex<()> = Mutex::new(());

fn euid() -> u32 {
    unsafe { libc::geteuid() }
}
fn egid() -> u32 {
    unsafe { libc::getegid() }
}

fn cfg(path: &Path) -> FifoCfg {
    FifoCfg {
        path: path.to_path_buf(),
        secret: "s".into(),
        owner: None,
        gid: egid(),
        mode: 0o640,
        enforce_acl: false,
        attempts_per_min: 10,
        cooldown_secs: 5,
        write_deadline_secs: 5,
    }
}

/// A private directory for pipes: owned by us, mode 0755.
fn pipes_dir(d: &tempfile::TempDir) -> PathBuf {
    let p = d.path().join("pipes");
    std::fs::create_dir(&p).unwrap();
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
    p
}

fn mkfifo(p: &Path) {
    let c = std::ffi::CString::new(p.to_str().unwrap()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
}

#[test]
fn sets_owner_group_and_mode_regardless_of_umask() {
    let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let d = tempfile::tempdir().unwrap();
    let dir = pipes_dir(&d);
    for mode in [0o640, 0o660, 0o600] {
        let p = dir.join(format!("m{mode:o}"));
        let mut c = cfg(&p);
        c.mode = mode;
        // A hostile umask would leave mkfifo(0600) at 0400.
        let old = unsafe { libc::umask(0o277) };
        let r = setup(&c, euid());
        unsafe { libc::umask(old) };
        let id = r.unwrap();
        let md = std::fs::symlink_metadata(&p).unwrap();
        assert!(md.file_type().is_fifo());
        assert_eq!(md.mode() & 0o7777, mode, "mode {mode:o}");
        assert_eq!((md.uid(), md.gid()), (euid(), egid()));
        assert_eq!((md.dev(), md.ino()), (id.dev, id.ino));
    }
}

#[test]
fn refuses_a_symlink_and_a_non_fifo() {
    let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let d = tempfile::tempdir().unwrap();
    let dir = pipes_dir(&d);
    // A symlink (even to a perfectly good FIFO) is refused and left alone.
    let target = d.path().join("target");
    mkfifo(&target);
    let link = dir.join("link");
    std::os::unix::fs::symlink(&target, &link).unwrap();
    let e = setup(&cfg(&link), euid()).unwrap_err().to_string();
    assert!(e.contains("symlink"), "{e}");
    assert!(std::fs::symlink_metadata(&link)
        .unwrap()
        .file_type()
        .is_symlink());
    assert_eq!(
        std::fs::metadata(&target).unwrap().mode() & 0o7777,
        0o600,
        "target untouched"
    );
    // A dangling symlink too.
    let dangling = dir.join("dangling");
    std::os::unix::fs::symlink(d.path().join("nowhere"), &dangling).unwrap();
    assert!(setup(&cfg(&dangling), euid())
        .unwrap_err()
        .to_string()
        .contains("symlink"));
    // A regular file, a directory, a socket.
    let file = dir.join("file");
    std::fs::write(&file, "data").unwrap();
    let e = setup(&cfg(&file), euid()).unwrap_err().to_string();
    assert!(e.contains("not a FIFO"), "{e}");
    assert_eq!(
        std::fs::read_to_string(&file).unwrap(),
        "data",
        "not clobbered"
    );
    let sub = dir.join("sub");
    std::fs::create_dir(&sub).unwrap();
    assert!(setup(&cfg(&sub), euid())
        .unwrap_err()
        .to_string()
        .contains("not a FIFO"));
    let sock = dir.join("sock");
    let _l = std::os::unix::net::UnixListener::bind(&sock).unwrap();
    assert!(setup(&cfg(&sock), euid())
        .unwrap_err()
        .to_string()
        .contains("not a FIFO"));
}

#[test]
fn leftover_fifo_of_ours_is_replaced_and_foreign_owner_refused() {
    let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let d = tempfile::tempdir().unwrap();
    let dir = pipes_dir(&d);
    let p = dir.join("left");
    mkfifo(&p);
    let before = std::fs::symlink_metadata(&p).unwrap().ino();
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o666)).unwrap();
    let id = setup(&cfg(&p), euid()).unwrap();
    let md = std::fs::symlink_metadata(&p).unwrap();
    assert_eq!(md.mode() & 0o7777, 0o640, "mode corrected");
    assert_eq!(md.ino(), id.ino);
    let _ = before;

    // A pipe owned by somebody else needs root to arrange.
    if euid() != 0 {
        eprintln!("not root; skipping the foreign-owner case");
        return;
    }
    let q = dir.join("foreign");
    mkfifo(&q);
    std::os::unix::fs::chown(&q, Some(54321), Some(54321)).unwrap();
    let e = setup(&cfg(&q), euid()).unwrap_err().to_string();
    assert!(e.contains("owned by uid 54321"), "{e}");
    // Unless that is the configured owner (a leftover of a run of ours).
    let mut c = cfg(&q);
    c.owner = Some(54321);
    setup(&c, euid()).unwrap();
    assert_eq!(std::fs::symlink_metadata(&q).unwrap().uid(), 54321);
}

#[test]
fn directory_rules() {
    let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let d = tempfile::tempdir().unwrap();
    // Missing: created with mode 0755.
    let fresh = d.path().join("a/b/pipe");
    setup(&cfg(&fresh), euid()).unwrap();
    assert_eq!(
        std::fs::metadata(fresh.parent().unwrap()).unwrap().mode() & 0o7777,
        0o755
    );
    // Writable by group or others: refused.
    let open = pipes_dir(&d).with_file_name("open");
    std::fs::create_dir(&open).unwrap();
    for bad in [0o775, 0o757] {
        std::fs::set_permissions(&open, std::fs::Permissions::from_mode(bad)).unwrap();
        let e = setup(&cfg(&open.join("p")), euid())
            .unwrap_err()
            .to_string();
        assert!(e.contains("writable by group or others"), "{e}");
    }
    // A symlink as the directory: refused.
    let real = d.path().join("real");
    std::fs::create_dir(&real).unwrap();
    let link = d.path().join("linkdir");
    std::os::unix::fs::symlink(&real, &link).unwrap();
    let e = setup(&cfg(&link.join("p")), euid())
        .unwrap_err()
        .to_string();
    assert!(e.contains("symlink"), "{e}");
    assert!(!real.join("p").exists());
    // Owned by someone other than the daemon user: refused.
    let keep = tempfile::tempdir().unwrap();
    let ours = pipes_dir(&keep);
    let e = setup(&cfg(&ours.join("p")), euid() + 1)
        .unwrap_err()
        .to_string();
    assert!(e.contains("not by the daemon user"), "{e}");
}

#[test]
fn daemon_must_be_able_to_write_the_pipe() {
    let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    if euid() == 0 {
        eprintln!("root can open anything; skipping");
        return;
    }
    let d = tempfile::tempdir().unwrap();
    let dir = pipes_dir(&d);
    let p = dir.join("ro");
    let mut c = cfg(&p);
    c.mode = 0o440; // owner may only read: the daemon could never write
    let e = setup(&c, euid()).unwrap_err().to_string();
    assert!(e.contains("cannot open it for writing"), "{e}");
    assert!(!p.exists(), "an unusable pipe is not left behind");
}

#[test]
fn remove_only_removes_the_inode_it_created() {
    let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let d = tempfile::tempdir().unwrap();
    let dir = pipes_dir(&d);
    let p = dir.join("r");
    let id = setup(&cfg(&p), euid()).unwrap();
    remove(&p, id);
    assert!(!p.exists());
    // Replaced by another pipe (someone else's): left alone.
    let id = setup(&cfg(&p), euid()).unwrap();
    // Keep the old inode allocated so the replacement cannot reuse its number.
    std::fs::hard_link(&p, dir.join("keep")).unwrap();
    std::fs::remove_file(&p).unwrap();
    mkfifo(&p);
    remove(&p, id);
    assert!(p.exists());
}

#[test]
fn directories_the_daemon_creates_are_0755_under_a_restrictive_umask() {
    // The packaged unit runs with UMask=0077: a plain mkdir would give 0700 and
    // lock the readers out of their pipe.
    let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let d = tempfile::tempdir().unwrap();
    let top = d.path().join("run");
    let dir = top.join("secretd").join("pipes");
    let p = dir.join("db");
    let old = unsafe { libc::umask(0o077) };
    let r = setup(&cfg(&p), euid());
    unsafe { libc::umask(old) };
    let id = r.unwrap();
    for created in [&top, &top.join("secretd"), &dir] {
        let mode = std::fs::metadata(created).unwrap().mode() & 0o7777;
        assert_eq!(mode, 0o755, "{} is {mode:o}", created.display());
    }
    // The pipe itself still has exactly the configured mode.
    assert_eq!(std::fs::metadata(&p).unwrap().mode() & 0o7777, 0o640);
    remove(&p, id);
}
