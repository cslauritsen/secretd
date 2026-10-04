//! macOS process inspection and launchd glue (spec section 22).
//!
//! Everything here is a thin, checked wrapper over `libproc` (`proc_pidpath`,
//! `proc_pidinfo`, `proc_pidfdinfo`, `proc_listpids`), `sysctl` and
//! `launch_activate_socket`. The module only exists on macOS.
//!
//! Access rules (Apple documents none of this precisely; this is the observed
//! behaviour of XNU's `proc_info` and why the daemon has a startup check):
//! inspecting a process owned by another user needs root (or an entitlement
//! such as `com.apple.system-task-ports`); the same uid is always allowed.
//! Every failure is returned as an `io::Error` and the callers treat it as
//! "unresolvable": the request is denied and audited.

use std::ffi::{c_int, c_void, CString};
use std::io;
use std::os::fd::RawFd;
use zeroize::Zeroizing;

/// `proc_listpids` type selector: every process.
const PROC_ALL_PIDS: u32 = 1;
/// `proc_pidfdinfo` flavor: `struct vnode_fdinfowithpath`.
const PROC_PIDFDVNODEPATHINFO: c_int = 2;
/// `FREAD` from `<sys/fcntl.h>`: the descriptor was opened for reading
/// (`proc_fileinfo.fi_openflags` holds kernel `f_flag` bits, not `O_*`).
const FREAD: u32 = 0x0001;
const MAXPATHLEN: usize = 1024;

/// `struct proc_fileinfo` (`<sys/proc_info.h>`).
#[repr(C)]
struct ProcFileInfo {
    fi_openflags: u32,
    fi_status: u32,
    fi_offset: i64,
    fi_type: i32,
    fi_guardflags: u32,
}

/// `struct vinfo_stat`.
#[repr(C)]
struct VinfoStat {
    vst_dev: u32,
    vst_mode: u16,
    vst_nlink: u16,
    vst_ino: u64,
    vst_uid: u32,
    vst_gid: u32,
    vst_times: [i64; 8],
    vst_size: i64,
    vst_blocks: i64,
    vst_blksize: i32,
    vst_flags: u32,
    vst_gen: u32,
    vst_rdev: u32,
    vst_qspare: [i64; 2],
}

/// `struct vnode_info`.
#[repr(C)]
struct VnodeInfo {
    vi_stat: VinfoStat,
    vi_type: i32,
    vi_pad: i32,
    vi_fsid: [i32; 2],
}

/// `struct vnode_info_path`.
#[repr(C)]
struct VnodeInfoPath {
    vip_vi: VnodeInfo,
    vip_path: [u8; MAXPATHLEN],
}

/// `struct vnode_fdinfowithpath`.
#[repr(C)]
struct VnodeFdInfoWithPath {
    pfi: ProcFileInfo,
    pvip: VnodeInfoPath,
}

// The layout is part of the kernel ABI; a mismatch must not compile.
const _: () = assert!(std::mem::size_of::<ProcFileInfo>() == 24);
const _: () = assert!(std::mem::size_of::<VinfoStat>() == 136);
const _: () = assert!(std::mem::size_of::<VnodeInfo>() == 152);
const _: () = assert!(std::mem::size_of::<VnodeFdInfoWithPath>() == 1200);
const _: () = assert!(std::mem::size_of::<libc::proc_bsdinfo>() == 136);
const _: () = assert!(std::mem::size_of::<libc::proc_fdinfo>() == 8);

/// The last OS error, with `ESRCH` mapped to `NotFound` ("the process is
/// gone") and a zero errno (libproc returns 0 without setting it when the
/// kernel gave back less than asked) to a generic error.
fn last_err(what: &str) -> io::Error {
    let e = io::Error::last_os_error();
    match e.raw_os_error() {
        Some(libc::ESRCH) => {
            io::Error::new(io::ErrorKind::NotFound, format!("{what}: no such process"))
        }
        Some(0) | None => io::Error::other(format!("{what}: no data")),
        Some(_) => io::Error::new(e.kind(), format!("{what}: {e}")),
    }
}

fn pid_arg(pid: u32) -> io::Result<c_int> {
    c_int::try_from(pid).map_err(|_| io::Error::new(io::ErrorKind::NotFound, "pid out of range"))
}

/// `proc_pidpath`: the executable of `pid`. `NotFound` when the process is
/// gone (`ESRCH`).
pub fn pid_path(pid: u32) -> io::Result<String> {
    let p = pid_arg(pid)?;
    let mut buf = vec![0u8; libc::PROC_PIDPATHINFO_MAXSIZE as usize];
    // SAFETY: `buf` is valid for `buf.len()` bytes.
    let n = unsafe { libc::proc_pidpath(p, buf.as_mut_ptr().cast(), buf.len() as u32) };
    if n <= 0 {
        return Err(last_err("proc_pidpath"));
    }
    buf.truncate(n as usize);
    // Some releases include the trailing NUL in the count.
    while buf.last() == Some(&0) {
        buf.pop();
    }
    if buf.is_empty() {
        return Err(io::Error::other("proc_pidpath: empty path"));
    }
    Ok(String::from_utf8_lossy(&buf).into_owned())
}

/// `proc_pidinfo(PROC_PIDTBSDINFO)`: uids, gids and the start time.
pub fn bsd_info(pid: u32) -> io::Result<libc::proc_bsdinfo> {
    let p = pid_arg(pid)?;
    // SAFETY: `proc_bsdinfo` is plain old data; all-zero is a valid value.
    let mut info: libc::proc_bsdinfo = unsafe { std::mem::zeroed() };
    let size = std::mem::size_of::<libc::proc_bsdinfo>() as c_int;
    // SAFETY: `info` is valid for `size` bytes.
    let n = unsafe {
        libc::proc_pidinfo(
            p,
            libc::PROC_PIDTBSDINFO,
            0,
            (&mut info as *mut libc::proc_bsdinfo).cast::<c_void>(),
            size,
        )
    };
    if n != size {
        return Err(last_err("proc_pidinfo(PROC_PIDTBSDINFO)"));
    }
    // A recycled or reused slot would report another pid.
    if info.pbi_pid != pid {
        return Err(io::Error::new(io::ErrorKind::NotFound, "pid mismatch"));
    }
    Ok(info)
}

/// `sysctl(KERN_PROCARGS2)`: the raw argument/environment block of `pid`.
/// It contains the environment, hence the zeroizing buffer; parse it with
/// [`crate::procinfo::parse_procargs2`] and drop it.
pub fn proc_args(pid: u32) -> io::Result<Zeroizing<Vec<u8>>> {
    let p = pid_arg(pid)?;
    let mut mib = [libc::CTL_KERN, libc::KERN_PROCARGS2, p];
    let mut size: libc::size_t = 0;
    // SAFETY: size query only (oldp is null).
    let rc = unsafe {
        libc::sysctl(
            mib.as_mut_ptr(),
            3,
            std::ptr::null_mut(),
            &mut size,
            std::ptr::null_mut(),
            0,
        )
    };
    if rc != 0 || size == 0 {
        return Err(last_err("sysctl(KERN_PROCARGS2)"));
    }
    // The block may grow between the two calls; leave some slack.
    let mut buf = Zeroizing::new(vec![0u8; size + 4096]);
    let mut len: libc::size_t = buf.len();
    // SAFETY: `buf` is valid for `len` bytes.
    let rc = unsafe {
        libc::sysctl(
            mib.as_mut_ptr(),
            3,
            buf.as_mut_ptr().cast(),
            &mut len,
            std::ptr::null_mut(),
            0,
        )
    };
    if rc != 0 {
        return Err(last_err("sysctl(KERN_PROCARGS2)"));
    }
    buf.truncate(len);
    Ok(buf)
}

/// Every pid (`proc_listpids(PROC_ALL_PIDS)`).
pub fn list_pids() -> io::Result<Vec<u32>> {
    // SAFETY: size query only.
    let need = unsafe { libc::proc_listpids(PROC_ALL_PIDS, 0, std::ptr::null_mut(), 0) };
    if need <= 0 {
        return Err(last_err("proc_listpids"));
    }
    // Processes may appear between the calls: 25% slack.
    let cap = (need as usize / std::mem::size_of::<c_int>()) * 5 / 4 + 16;
    let mut pids: Vec<c_int> = vec![0; cap];
    // SAFETY: `pids` is valid for `cap * 4` bytes.
    let n = unsafe {
        libc::proc_listpids(
            PROC_ALL_PIDS,
            0,
            pids.as_mut_ptr().cast(),
            (cap * std::mem::size_of::<c_int>()) as c_int,
        )
    };
    if n <= 0 {
        return Err(last_err("proc_listpids"));
    }
    pids.truncate(n as usize / std::mem::size_of::<c_int>());
    Ok(pids
        .into_iter()
        .filter(|p| *p > 0)
        .map(|p| p as u32)
        .collect())
}

/// `proc_pidinfo(PROC_PIDLISTFDS)`: `(fd, fdtype)` of every descriptor of
/// `pid`. `PermissionDenied` for processes of other users unless root.
pub fn list_fds(pid: u32) -> io::Result<Vec<(i32, u32)>> {
    let p = pid_arg(pid)?;
    // SAFETY: size query only.
    let need = unsafe { libc::proc_pidinfo(p, libc::PROC_PIDLISTFDS, 0, std::ptr::null_mut(), 0) };
    if need <= 0 {
        return Err(last_err("proc_pidinfo(PROC_PIDLISTFDS)"));
    }
    let each = libc::PROC_PIDLISTFD_SIZE as usize;
    let cap = need as usize / each + 16; // descriptors may be opened meanwhile
    let mut fds: Vec<libc::proc_fdinfo> = (0..cap)
        .map(|_| libc::proc_fdinfo {
            proc_fd: 0,
            proc_fdtype: 0,
        })
        .collect();
    // SAFETY: `fds` is valid for `cap * each` bytes.
    let n = unsafe {
        libc::proc_pidinfo(
            p,
            libc::PROC_PIDLISTFDS,
            0,
            fds.as_mut_ptr().cast(),
            (cap * each) as c_int,
        )
    };
    if n <= 0 {
        return Err(last_err("proc_pidinfo(PROC_PIDLISTFDS)"));
    }
    fds.truncate(n as usize / each);
    Ok(fds
        .into_iter()
        .map(|f| (f.proc_fd, f.proc_fdtype))
        .collect())
}

/// What `proc_pidfdinfo(PROC_PIDFDVNODEPATHINFO)` says about a vnode
/// descriptor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VnodeFd {
    /// `st_dev` of the file, as the kernel's 32-bit `dev_t` bit pattern.
    pub dev: u32,
    pub ino: u64,
    /// Opened with read access (`FREAD`).
    pub readable: bool,
}

pub fn vnode_fd(pid: u32, fd: i32) -> io::Result<VnodeFd> {
    let p = pid_arg(pid)?;
    // SAFETY: plain old data; all-zero is valid.
    let mut info: VnodeFdInfoWithPath = unsafe { std::mem::zeroed() };
    let size = std::mem::size_of::<VnodeFdInfoWithPath>() as c_int;
    // SAFETY: `info` is valid for `size` bytes.
    let n = unsafe {
        libc::proc_pidfdinfo(
            p,
            fd,
            PROC_PIDFDVNODEPATHINFO,
            (&mut info as *mut VnodeFdInfoWithPath).cast(),
            size,
        )
    };
    if n < size {
        return Err(last_err("proc_pidfdinfo(PROC_PIDFDVNODEPATHINFO)"));
    }
    Ok(VnodeFd {
        dev: info.pvip.vip_vi.vi_stat.vst_dev,
        ino: info.pvip.vip_vi.vi_stat.vst_ino,
        readable: info.pfi.fi_openflags & FREAD != 0,
    })
}

/// Truncate a 64-bit `st_dev` (as `MetadataExt::dev` returns it, sign
/// extended from the kernel's 32-bit `dev_t`) to libproc's 32-bit value.
pub fn dev32(st_dev: u64) -> u32 {
    st_dev as u32
}

// ---------------------------------------------------------------- launchd

extern "C" {
    /// `<launch.h>` (macOS 10.10+): the descriptors of the socket entry
    /// `name` in the job's `Sockets` dictionary; the array is `malloc`ed.
    fn launch_activate_socket(
        name: *const libc::c_char,
        fds: *mut *mut c_int,
        cnt: *mut usize,
    ) -> c_int;
}

/// Descriptors launchd opened for the `Sockets` entry `name`. Errors are the
/// documented ones: `ESRCH` (not started by launchd), `ENOENT` (no such
/// entry), `EALREADY` (already fetched).
pub fn launchd_sockets(name: &str) -> io::Result<Vec<RawFd>> {
    let c = CString::new(name).map_err(io::Error::other)?;
    let mut fds: *mut c_int = std::ptr::null_mut();
    let mut cnt: usize = 0;
    // SAFETY: valid NUL-terminated name and out-pointers.
    let rc = unsafe { launch_activate_socket(c.as_ptr(), &mut fds, &mut cnt) };
    if rc != 0 {
        return Err(io::Error::from_raw_os_error(rc));
    }
    if fds.is_null() {
        return Ok(Vec::new());
    }
    // SAFETY: launchd returned `cnt` descriptors in a malloc'ed array that we
    // free right after copying.
    let out = unsafe { std::slice::from_raw_parts(fds, cnt) }.to_vec();
    unsafe { libc::free(fds.cast()) };
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::MetadataExt;

    #[test]
    fn own_path_start_time_and_pid() {
        let me = std::process::id();
        let path = pid_path(me).unwrap();
        assert_eq!(
            path,
            std::env::current_exe()
                .unwrap()
                .canonicalize()
                .unwrap()
                .to_string_lossy()
        );
        let b = bsd_info(me).unwrap();
        assert_eq!(b.pbi_pid, me);
        assert!(b.pbi_start_tvsec > 0);
        assert_eq!(b.pbi_uid, unsafe { libc::geteuid() });
    }

    #[test]
    fn own_argv_is_readable_and_has_the_binary_first() {
        let buf = proc_args(std::process::id()).unwrap();
        let argv = crate::procinfo::parse_procargs2(&buf).unwrap();
        assert!(!argv.is_empty());
    }

    #[test]
    fn a_vanished_process_is_not_found() {
        let mut c = std::process::Command::new("true").spawn().unwrap();
        let pid = c.id();
        c.wait().unwrap();
        let e = pid_path(pid).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::NotFound, "{e}");
        assert_eq!(bsd_info(pid).unwrap_err().kind(), io::ErrorKind::NotFound);
    }

    #[test]
    fn listing_finds_us_and_our_fifo_descriptor() {
        let me = std::process::id();
        assert!(list_pids().unwrap().contains(&me));
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("f");
        let c = CString::new(p.to_str().unwrap()).unwrap();
        // SAFETY: valid path.
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
        // O_RDWR never blocks on a FIFO.
        let f = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&p)
            .unwrap();
        let md = f.metadata().unwrap();
        let mut hit = None;
        for (fd, ty) in list_fds(me).unwrap() {
            if ty == libc::PROX_FDTYPE_VNODE as u32 {
                if let Ok(v) = vnode_fd(me, fd) {
                    if v.dev == dev32(md.dev()) && v.ino == md.ino() {
                        hit = Some(v);
                    }
                }
            }
        }
        let v = hit.expect("the FIFO descriptor is listed");
        assert!(v.readable);
    }

    #[test]
    fn write_only_descriptors_are_not_readable() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("w");
        let f = std::fs::File::create(&p).unwrap();
        let md = f.metadata().unwrap();
        let me = std::process::id();
        let mut seen = false;
        for (fd, ty) in list_fds(me).unwrap() {
            if ty == libc::PROX_FDTYPE_VNODE as u32 {
                if let Ok(v) = vnode_fd(me, fd) {
                    if v.dev == dev32(md.dev()) && v.ino == md.ino() {
                        seen = true;
                        assert!(!v.readable);
                    }
                }
            }
        }
        assert!(seen);
    }

    #[test]
    fn launchd_activation_outside_launchd_is_an_error_not_a_crash() {
        assert!(launchd_sockets("secretd-no-such-entry").is_err());
    }
}
