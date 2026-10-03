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

/// Disable core dumps and ptrace-style memory inspection by non-root peers:
/// `RLIMIT_CORE=0` and `PR_SET_DUMPABLE=0`.  Returns true if both succeeded.
pub fn disable_core_dumps() -> bool {
    let lim = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: plain syscalls with valid arguments.
    unsafe {
        let a = libc::setrlimit(libc::RLIMIT_CORE, &lim) == 0;
        let b = libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) == 0;
        a && b
    }
}
