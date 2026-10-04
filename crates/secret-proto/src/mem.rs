//! Best-effort memory hardening helpers (mlock / process hardening).

/// Lock a byte range into RAM so it is not swapped. Best effort: returns
/// whether the lock succeeded.  Never fails the caller.
pub fn lock(ptr: *const u8, len: usize) -> bool {
    if len == 0 {
        return true;
    }
    // SAFETY: mlock only reads the address range and does not dereference it.
    unsafe { libc::mlock(ptr.cast(), len) == 0 }
}

/// Undo [`lock`]. Call after the memory has been zeroized.
pub fn unlock(ptr: *const u8, len: usize) {
    if len == 0 {
        return;
    }
    // SAFETY: as for `lock`.
    unsafe {
        libc::munlock(ptr.cast(), len);
    }
}

/// Disable core dumps and debugger/ptrace-style memory inspection by other
/// processes. Best effort; the caller only warns when this returns false.
///
/// * every OS: `RLIMIT_CORE = 0`;
/// * Linux: `prctl(PR_SET_DUMPABLE, 0)` (also makes `/proc/<pid>/mem` and
///   ptrace by non-root peers fail);
/// * macOS: `ptrace(PT_DENY_ATTACH)`, which stops debuggers (lldb, dtrace) from
///   attaching and disables core dumps for the process. It is a hint to the
///   kernel, not a security boundary (root can still use task ports unless
///   SIP/hardened-runtime rules forbid it) and may fail, for example under a
///   debugger; startup never depends on it.
///
/// Returns true if every step that applies on this OS succeeded.
pub fn disable_core_dumps() -> bool {
    let lim = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: plain syscall with a valid argument.
    let a = unsafe { libc::setrlimit(libc::RLIMIT_CORE, &lim) } == 0;
    a & deny_inspection()
}

#[cfg(target_os = "linux")]
fn deny_inspection() -> bool {
    // SAFETY: plain syscall with constant arguments.
    unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) == 0 }
}

#[cfg(target_os = "macos")]
fn deny_inspection() -> bool {
    // SAFETY: PT_DENY_ATTACH ignores pid/addr/data; null/zero are the
    // documented values.
    unsafe { libc::ptrace(libc::PT_DENY_ATTACH, 0, std::ptr::null_mut(), 0) == 0 }
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn deny_inspection() -> bool {
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lock_and_unlock_do_not_panic() {
        let buf = [0u8; 64];
        let _ = lock(buf.as_ptr(), buf.len());
        unlock(buf.as_ptr(), buf.len());
        assert!(lock(buf.as_ptr(), 0));
    }
}
