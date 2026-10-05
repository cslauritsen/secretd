//! Small OS-specific helpers that `nix` does not provide on every platform
//! (macOS lacks `initgroups` and `getgrouplist` in `nix` 0.29).

use std::ffi::CString;
use std::io;

#[cfg(any(target_os = "macos", target_os = "ios"))]
type BaseGid = libc::c_int;
#[cfg(not(any(target_os = "macos", target_os = "ios")))]
type BaseGid = libc::gid_t;

/// Supplementary groups of `user` (including `gid`), via `getgrouplist(3)`.
/// `None` when the lookup fails.
#[allow(clippy::unnecessary_cast)] // BaseGid is c_int on macOS, u32 on Linux
pub fn group_ids(user: &str, gid: u32) -> Option<Vec<u32>> {
    let name = CString::new(user).ok()?;
    let mut size: libc::c_int = 32;
    while size <= 65536 {
        // Group ids are `int` on macOS and `gid_t` elsewhere; both are 32 bits.
        let mut buf: Vec<BaseGid> = vec![0; size as usize];
        let mut count = size;
        // SAFETY: `buf` has room for `count` entries and `name` is NUL-terminated.
        let rc = unsafe {
            libc::getgrouplist(
                name.as_ptr(),
                gid as BaseGid,
                buf.as_mut_ptr().cast(),
                &mut count,
            )
        };
        if rc >= 0 {
            buf.truncate(count.max(0) as usize);
            return Some(buf.into_iter().map(|g| g as u32).collect());
        }
        // Too small: Linux reports the needed size, macOS may not.
        size = if count > size { count } else { size * 2 };
    }
    None
}

/// `initgroups(3)`: set the supplementary groups of the process to those of
/// `user` (plus `gid`). Needs root.
#[allow(clippy::unnecessary_cast)] // BaseGid is c_int on macOS, u32 on Linux
pub fn init_groups(user: &str, gid: u32) -> io::Result<()> {
    let name = CString::new(user).map_err(io::Error::other)?;
    // SAFETY: `name` is a valid NUL-terminated string.
    let rc = unsafe { libc::initgroups(name.as_ptr(), gid as BaseGid) };
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn root_is_in_its_own_group() {
        // gid 0 exists on Linux (root) and macOS (wheel); the user is `root`
        // on both.
        let g = group_ids("root", 0).expect("root resolves");
        assert!(g.contains(&0));
    }

    #[test]
    fn unknown_user_yields_at_most_the_base_group() {
        // getgrouplist does not fail for unknown names; it returns the base
        // group only.
        let g = group_ids("no-such-user-secretd", 4242).unwrap_or_default();
        assert!(g.iter().all(|x| *x == 4242));
    }
}
