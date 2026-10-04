//! Per-secret ACL evaluation (spec section 6).

use crate::config::SecretAcl;

/// Identity of a caller as established from the peer credentials
/// (`SO_PEERCRED` / `LOCAL_PEERCRED`) and the process table (`/proc` / libproc).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallerIds<'a> {
    pub uid: u32,
    pub gid: u32,
    pub exe: &'a str,
}

/// A caller is allowed iff (uid in `allow_uids` OR gid in `allow_gids`) AND
/// (`allow_exes` is non-empty and the exe matches exactly, OR `allow_exes` is
/// empty and `allow_any_exe = true`).  An exe path ending in ` (deleted)` is
/// always denied.  Everything else is denied.
pub fn is_allowed(acl: &SecretAcl, caller: &CallerIds<'_>) -> bool {
    if caller.exe.ends_with(" (deleted)") {
        return false;
    }
    let who = acl.uids.contains(&caller.uid) || acl.gids.contains(&caller.gid);
    if !who {
        return false;
    }
    if acl.exes.is_empty() {
        acl.allow_any_exe
    } else {
        acl.exes.iter().any(|e| e == caller.exe)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn acl(uids: &[u32], gids: &[u32], exes: &[&str], any: bool) -> SecretAcl {
        SecretAcl {
            name: "s".into(),
            description: None,
            uids: uids.to_vec(),
            gids: gids.to_vec(),
            exes: exes.iter().map(|s| s.to_string()).collect(),
            allow_any_exe: any,
        }
    }

    fn c(uid: u32, gid: u32, exe: &str) -> CallerIds<'_> {
        CallerIds { uid, gid, exe }
    }

    #[test]
    fn uid_and_exe_match() {
        let a = acl(&[1000], &[], &["/usr/bin/psql"], false);
        assert!(is_allowed(&a, &c(1000, 5, "/usr/bin/psql")));
        assert!(!is_allowed(&a, &c(1001, 5, "/usr/bin/psql")));
        assert!(!is_allowed(&a, &c(1000, 5, "/usr/bin/psq")));
        assert!(!is_allowed(&a, &c(1000, 5, "/usr/bin/psql/")));
        assert!(!is_allowed(&a, &c(1000, 5, "usr/bin/psql")));
    }

    #[test]
    fn gid_or_uid() {
        let a = acl(&[1], &[100], &["/x"], false);
        assert!(is_allowed(&a, &c(2, 100, "/x")));
        assert!(is_allowed(&a, &c(1, 7, "/x")));
        assert!(!is_allowed(&a, &c(2, 7, "/x")));
    }

    #[test]
    fn deleted_exe_denied_even_with_any_exe() {
        let a = acl(&[1], &[], &["/x"], false);
        assert!(!is_allowed(&a, &c(1, 1, "/x (deleted)")));
        let b = acl(&[1], &[], &[], true);
        assert!(!is_allowed(&b, &c(1, 1, "/x (deleted)")));
        let a2 = acl(&[1], &[], &["/x (deleted)"], false);
        assert!(!is_allowed(&a2, &c(1, 1, "/x (deleted)")));
    }

    #[test]
    fn any_exe_must_be_explicit() {
        let a = acl(&[1], &[], &[], false);
        assert!(!is_allowed(&a, &c(1, 1, "/anything")));
        let b = acl(&[1], &[], &[], true);
        assert!(is_allowed(&b, &c(1, 1, "/anything")));
        assert!(!is_allowed(&b, &c(2, 1, "/anything")));
    }

    #[test]
    fn empty_acl_is_unreachable() {
        let a = acl(&[], &[], &["/x"], false);
        assert!(!is_allowed(&a, &c(0, 0, "/x")));
        let b = acl(&[], &[], &[], true);
        assert!(!is_allowed(&b, &c(0, 0, "/x")));
    }
}
