//! What a SIGHUP reload applies and what it does not.
//!
//! `Core::set_config` swaps the whole configuration, and everything the core
//! reads per request (secrets and their ACLs, limits, the request timeout, the
//! store path) follows at once. Other parts were built from the configuration
//! at start-up and keep their copy: the sockets, the audit file path, the
//! approval endpoint and its OIDC client, the push notifier, the set of
//! channels, and the Home Assistant connection. [`restart_required`] names
//! those, so the daemon can say so instead of claiming everything was
//! reloaded. The one Home Assistant setting that must not wait for a restart,
//! the approver allowlist (revoking an id has to work), is applied live by
//! `HaChannel::apply_config`; `[[fifo]]` changes are re-armed by the daemon.

use secret_proto::config::{Config, HaCfg};

/// Sections of `new` that differ from `old` but only take effect after a
/// restart. Empty when the reload was complete (apart from pipes, which the
/// daemon re-arms itself, and the live Home Assistant allowlist).
pub fn restart_required(old: &Config, new: &Config) -> Vec<String> {
    let mut v = Vec::new();
    let (a, b) = (&old.daemon, &new.daemon);
    for (name, changed) in [
        ("daemon.user", a.user != b.user),
        ("daemon.socket", a.socket != b.socket),
        ("daemon.admin_socket", a.admin_socket != b.admin_socket),
        ("daemon.audit_log", a.audit_log != b.audit_log),
        ("daemon.socket_mode", a.socket_mode != b.socket_mode),
        ("daemon.socket_group", a.socket_group != b.socket_group),
    ] {
        if changed {
            v.push(name.to_string());
        }
    }
    if old.channels.enabled != new.channels.enabled {
        v.push("channels.enabled".into());
    }
    // These sections carry no secrets (file names only), so comparing their
    // debug renderings is exact and does not need a derive on every type.
    if format!("{:?}", old.notify) != format!("{:?}", new.notify) {
        v.push("notify".into());
    }
    if format!("{:?}", old.approval) != format!("{:?}", new.approval) {
        v.push("approval".into());
    }
    if ha_rest(old.homeassistant.as_ref()) != ha_rest(new.homeassistant.as_ref()) {
        v.push("homeassistant (everything except owner_user_ids and ha_require_user_id)".into());
    }
    v
}

/// The Home Assistant settings that need a restart, rendered for comparison.
fn ha_rest(h: Option<&HaCfg>) -> String {
    match h {
        None => "none".into(),
        Some(h) => {
            let mut h = h.clone();
            // Applied live.
            h.owner_user_ids.clear();
            h.require_user_id = true;
            format!("{h:?}")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use secret_proto::config::NameResolver;

    struct R;
    impl NameResolver for R {
        fn uid(&self, _: &str) -> Option<u32> {
            Some(1000)
        }
        fn gid(&self, _: &str) -> Option<u32> {
            Some(1000)
        }
    }

    const BASE: &str = "[daemon]\nstore = \"/s\"\nsocket = \"/run/a.sock\"\n\
                        admin_socket = \"/run/b.sock\"\naudit_log = \"/l\"\n\
                        [[secret]]\nname = \"x\"\nallow_uids = [1000]\nallow_any_exe = true\n";

    fn cfg(daemon_extra: &str, ha_extra: &str, owners: &str, secret_extra: &str) -> Config {
        let text = format!(
            "{}\n[channels]\nenabled = [\"homeassistant\", \"admin\"]\n[homeassistant]\n\
             url = \"https://ha\"\ntoken_file = \"/t\"\n\
             notify_service = \"notify.mobile_app_x\"\npassphrase_entity = \"input_text.p\"\n\
             owner_user_ids = {owners}\n{ha_extra}\n",
            BASE.replace("[[secret]]", &format!("{daemon_extra}\n[[secret]]"))
                .replace(
                    "allow_any_exe = true\n",
                    &format!("allow_any_exe = true\n{secret_extra}")
                )
        );
        Config::parse(&text, &R).unwrap_or_else(|e| panic!("{e}\n{text}"))
    }

    #[test]
    fn live_settings_need_no_restart() {
        let a = cfg("", "", "[\"u1\"]", "");
        // Allowlist, secrets and limits are applied on reload.
        let b = cfg("", "ha_require_user_id = true", "[\"u2\", \"u3\"]", "");
        assert_eq!(restart_required(&a, &b), Vec::<String>::new());
    }

    #[test]
    fn startup_only_settings_are_named() {
        let a = cfg("", "", "[\"u1\"]", "");
        let b = cfg(
            "",
            "allow_insecure_http = false\nca_file = \"/ca\"",
            "[\"u1\"]",
            "",
        );
        let r = restart_required(&a, &b);
        assert_eq!(r.len(), 1, "{r:?}");
        assert!(r[0].starts_with("homeassistant"), "{r:?}");
        // The allowlist changing alongside does not hide it, nor add to it.
        let c = cfg("", "ca_file = \"/ca\"", "[\"other\"]", "");
        assert_eq!(restart_required(&a, &c).len(), 1);
        // Daemon paths and the channel set.
        let mut d = a.clone();
        d.daemon.socket = "/run/other.sock".into();
        d.daemon.audit_log = "/other".into();
        let r = restart_required(&a, &d);
        assert!(r.contains(&"daemon.socket".to_string()));
        assert!(r.contains(&"daemon.audit_log".to_string()));
        let mut e = a.clone();
        e.channels.enabled.pop();
        assert!(restart_required(&a, &e).contains(&"channels.enabled".to_string()));
        // Removing the HA section entirely counts too.
        let mut f = a.clone();
        f.homeassistant = None;
        assert!(!restart_required(&a, &f).is_empty());
    }
}
