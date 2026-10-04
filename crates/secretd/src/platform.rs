//! Per-OS startup checks (spec section 22).
//!
//! The daemon identifies a caller by its process (`ProcInfoReader`). On Linux
//! reading another user's `/proc/<pid>/exe` needs `CAP_SYS_PTRACE`; on macOS
//! `proc_pidinfo` and `proc_pidpath` of another user's process need root. A
//! daemon without that access cannot identify callers of other uids: every
//! request from them is denied (`proc_unavailable`) and audited. That is the
//! safe direction, but a configuration that pins an executable for such a
//! caller can never work, so on macOS the daemon refuses to start with it
//! rather than silently serving nobody (and never falls back to weaker ACLs).

use secret_proto::config::Config;
use std::io;

/// Outcome of [`check_process_inspection`].
#[derive(Debug, Default, PartialEq, Eq)]
pub struct InspectionReport {
    /// Reasons to refuse to start.
    pub errors: Vec<String>,
    /// Findings that are only logged.
    pub warnings: Vec<String>,
}

/// Judge the configuration against what the daemon can inspect.
///
/// `probe` is the result of reading a process owned by another user (pid 1);
/// `daemon_uid` is the uid the daemon runs as after dropping privileges. A
/// secret is *affected* when someone other than the daemon's own uid may
/// request it (any `gids` entry counts: group members cannot be mapped to
/// uids here). Affected secrets that pin an executable (`exes`) are errors;
/// affected `allow_any_exe` secrets are warnings, because every request still
/// needs the caller to be resolvable and will be denied.
pub fn check_process_inspection(
    cfg: &Config,
    daemon_uid: u32,
    probe: &io::Result<()>,
) -> InspectionReport {
    let mut rep = InspectionReport::default();
    let Err(e) = probe else {
        return rep;
    };
    for s in &cfg.secrets {
        let others = s.uids.iter().any(|u| *u != daemon_uid) || !s.gids.is_empty();
        if !others {
            continue;
        }
        if !s.exes.is_empty() {
            rep.errors.push(format!(
                "secret {:?} pins an executable for callers other than uid {daemon_uid}, but \
                 this daemon cannot inspect other users' processes ({e}); every such request \
                 would be denied. Run secretd as root (daemon.user = \"root\"), or restrict the \
                 ACL to the daemon's own uid. See docs/HARDENING.md, \"macOS\"",
                s.name
            ));
        } else {
            rep.warnings.push(format!(
                "secret {:?} is open to callers other than uid {daemon_uid}, but this daemon \
                 cannot inspect other users' processes ({e}); their requests will be denied \
                 with proc_unavailable",
                s.name
            ));
        }
    }
    rep
}

#[cfg(test)]
mod tests {
    use super::*;
    use secret_proto::config::SecretAcl;

    fn cfg_with(acls: Vec<SecretAcl>) -> Config {
        let mut c = Config::parse(
            "[channels]\nenabled = [\"admin\"]\n",
            &secret_proto::config::SystemResolver,
        )
        .expect("admin-only config loads");
        c.secrets = acls;
        c
    }

    fn acl(name: &str, uids: &[u32], gids: &[u32], exes: &[&str], any: bool) -> SecretAcl {
        SecretAcl {
            name: name.into(),
            description: None,
            uids: uids.to_vec(),
            gids: gids.to_vec(),
            exes: exes.iter().map(|s| s.to_string()).collect(),
            allow_any_exe: any,
        }
    }

    fn denied() -> io::Result<()> {
        Err(io::Error::new(io::ErrorKind::PermissionDenied, "EPERM"))
    }

    #[test]
    fn working_inspection_never_complains() {
        let c = cfg_with(vec![acl("a", &[501], &[], &["/usr/bin/psql"], false)]);
        assert_eq!(
            check_process_inspection(&c, 300, &Ok(())),
            InspectionReport::default()
        );
    }

    #[test]
    fn exe_pinned_acl_for_another_uid_is_refused_without_inspection() {
        let c = cfg_with(vec![acl("a", &[501], &[], &["/usr/bin/psql"], false)]);
        let r = check_process_inspection(&c, 300, &denied());
        assert_eq!(r.errors.len(), 1, "{r:?}");
        assert!(r.errors[0].contains("\"a\"") && r.errors[0].contains("EPERM"));
        assert!(r.warnings.is_empty());
    }

    #[test]
    fn group_acls_count_as_other_users() {
        let c = cfg_with(vec![acl("g", &[], &[20], &["/x"], false)]);
        assert_eq!(check_process_inspection(&c, 300, &denied()).errors.len(), 1);
    }

    #[test]
    fn the_daemons_own_uid_needs_no_special_access() {
        let c = cfg_with(vec![acl("own", &[300], &[], &["/x"], false)]);
        assert_eq!(
            check_process_inspection(&c, 300, &denied()),
            InspectionReport::default()
        );
    }

    #[test]
    fn any_exe_acls_only_warn() {
        let c = cfg_with(vec![acl("open", &[501], &[], &[], true)]);
        let r = check_process_inspection(&c, 300, &denied());
        assert!(r.errors.is_empty());
        assert_eq!(r.warnings.len(), 1);
    }
}
