//! Process identity (executable path, command line, start time) used to
//! describe and re-verify callers.
//!
//! [`ProcInfoReader`] is the seam: the Linux implementation reads `/proc/<pid>`,
//! the macOS one uses libproc and `sysctl(KERN_PROCARGS2)` (see
//! [`crate::macos`]). Tests inject a [`StaticProcReader`].

use secret_proto::sanitize;
use std::collections::HashMap;
use std::io;
use std::sync::Mutex;

/// Maximum bytes of the command line that are kept.
pub const CMDLINE_MAX: usize = 256;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcInfo {
    /// Path of the executable. Linux: target of `/proc/<pid>/exe` (may end in
    /// ` (deleted)`). macOS: `proc_pidpath` (no `(deleted)` concept; a binary
    /// whose vnode cannot be resolved makes the lookup fail instead).
    pub exe: String,
    /// Sanitised, truncated command line (arguments separated by spaces).
    pub cmdline: String,
    /// Process start time. Linux: clock ticks since boot
    /// (`/proc/<pid>/stat` field 22). macOS: microseconds since the epoch
    /// (`pbi_start_tvsec * 1e6 + pbi_start_tvusec`). Only ever compared for
    /// equality between two reads of the same process.
    pub start_time: u64,
}

pub trait ProcInfoReader: Send + Sync {
    /// Identity of `pid`. An error means the process is gone (`NotFound`) or
    /// cannot be inspected (`PermissionDenied`, ...); callers treat every
    /// error as "unresolvable": the request is denied.
    fn read(&self, pid: u32) -> io::Result<ProcInfo>;
}

/// Reads the real process table of this OS (`/proc` on Linux, libproc on
/// macOS).
pub struct RealProcReader;

/// Joins NUL-separated argument bytes into one sanitised, truncated line.
pub fn cmdline_from_raw(raw: &[u8]) -> String {
    let joined: String = String::from_utf8_lossy(raw)
        .split('\0')
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>()
        .join(" ");
    sanitize::clean(&joined, CMDLINE_MAX)
}

/// The argument vector inside a `sysctl(KERN_PROCARGS2)` buffer (macOS).
///
/// Layout: an `int argc`, the executable path and NUL padding, then `argc`
/// NUL-terminated arguments, then the environment (never looked at: it may
/// hold secrets). `None` if the buffer is malformed. Pure so it is testable on
/// every OS.
pub fn parse_procargs2(buf: &[u8]) -> Option<Vec<&[u8]>> {
    let argc = i32::from_ne_bytes(buf.get(..4)?.try_into().ok()?);
    if argc < 0 {
        return None;
    }
    let mut rest = &buf[4..];
    // Skip the saved exec path, then the padding NULs after it.
    let end = rest.iter().position(|b| *b == 0)?;
    rest = &rest[end..];
    let pad = rest.iter().position(|b| *b != 0).unwrap_or(rest.len());
    rest = &rest[pad..];
    let mut argv = Vec::new();
    for _ in 0..argc {
        if rest.is_empty() {
            break;
        }
        let end = rest.iter().position(|b| *b == 0).unwrap_or(rest.len());
        argv.push(&rest[..end]);
        rest = &rest[(end + 1).min(rest.len())..];
    }
    Some(argv)
}

/// macOS start time from `proc_bsdinfo`.
pub fn start_time_micros(tv_sec: u64, tv_usec: u64) -> u64 {
    tv_sec.saturating_mul(1_000_000).saturating_add(tv_usec)
}

#[cfg(target_os = "linux")]
impl ProcInfoReader for RealProcReader {
    fn read(&self, pid: u32) -> io::Result<ProcInfo> {
        use std::io::Read;
        let exe = std::fs::read_link(format!("/proc/{pid}/exe"))?
            .to_string_lossy()
            .into_owned();
        let mut raw = Vec::new();
        std::fs::File::open(format!("/proc/{pid}/cmdline"))?
            .take(CMDLINE_MAX as u64)
            .read_to_end(&mut raw)?;
        let cmdline = cmdline_from_raw(&raw);
        let stat = std::fs::read_to_string(format!("/proc/{pid}/stat"))?;
        let start_time = parse_start_time(&stat)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "bad /proc stat"))?;
        // Re-check the exe link: if the pid was recycled between the reads the
        // start time will not match later, but a vanished process is an error.
        Ok(ProcInfo {
            exe,
            cmdline,
            start_time,
        })
    }
}

#[cfg(target_os = "macos")]
impl ProcInfoReader for RealProcReader {
    fn read(&self, pid: u32) -> io::Result<ProcInfo> {
        use crate::macos;
        // The start time first: it also fails with ESRCH for a vanished pid,
        // and a pid that is recycled between these calls shows up as a start
        // time that differs from the one captured at connect.
        let start_time = macos::start_time_micros(pid)?;
        let exe = macos::pid_path(pid)?;
        // argv is best effort (it needs the same access as the rest, but
        // sysctl can refuse for hardened processes): an unreadable command
        // line only makes the notification less informative.
        let cmdline = match macos::proc_args(pid) {
            Ok(buf) => {
                let mut raw: Vec<u8> = Vec::new();
                for a in parse_procargs2(&buf).unwrap_or_default() {
                    raw.extend_from_slice(a);
                    raw.push(0);
                }
                raw.truncate(CMDLINE_MAX);
                cmdline_from_raw(&raw)
            }
            Err(_) => String::new(),
        };
        Ok(ProcInfo {
            exe,
            cmdline,
            start_time,
        })
    }
}

/// Field 22 of `/proc/<pid>/stat`. The comm field (2) may contain spaces and
/// parentheses, so parse after the last `)`.
pub fn parse_start_time(stat: &str) -> Option<u64> {
    let rest = &stat[stat.rfind(')')? + 1..];
    // rest starts at field 3 (state); starttime is field 22 => index 19.
    rest.split_whitespace().nth(19)?.parse().ok()
}

/// In-memory table for tests.
#[derive(Default)]
pub struct StaticProcReader(Mutex<HashMap<u32, ProcInfo>>);

impl StaticProcReader {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn set(&self, pid: u32, info: ProcInfo) {
        self.0.lock().unwrap().insert(pid, info);
    }
    pub fn remove(&self, pid: u32) {
        self.0.lock().unwrap().remove(&pid);
    }
}

impl ProcInfoReader for StaticProcReader {
    fn read(&self, pid: u32) -> io::Result<ProcInfo> {
        self.0
            .lock()
            .unwrap()
            .get(&pid)
            .cloned()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no such process"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stat_parsing_handles_odd_comm() {
        let stat = "1234 (my (weird) prog) S 1 1234 1234 0 -1 4194560 100 0 0 0 1 2 0 0 20 0 1 0 987654 1000 100 18446744073709551615";
        assert_eq!(parse_start_time(stat), Some(987654));
        assert_eq!(parse_start_time("garbage"), None);
    }

    #[test]
    fn procargs2_yields_argv_and_ignores_the_environment() {
        let mut b = 3i32.to_ne_bytes().to_vec();
        b.extend_from_slice(b"/usr/bin/psql\0\0\0\0");
        b.extend_from_slice(b"psql\0-h\0db\0SECRET=hunter2\0HOME=/x\0");
        let argv = parse_procargs2(&b).unwrap();
        assert_eq!(argv, vec![&b"psql"[..], b"-h", b"db"]);
        // Fewer strings than argc (truncated buffer): what is there is kept.
        let mut t = 5i32.to_ne_bytes().to_vec();
        t.extend_from_slice(b"/bin/x\0\0a\0b");
        assert_eq!(parse_procargs2(&t).unwrap(), vec![&b"a"[..], b"b"]);
        // Malformed.
        assert!(parse_procargs2(b"ab").is_none());
        assert!(parse_procargs2(&(-1i32).to_ne_bytes()).is_none());
        let no_nul = [&1i32.to_ne_bytes()[..], b"/bin/x"].concat();
        assert!(parse_procargs2(&no_nul).is_none());
    }

    #[test]
    fn cmdline_is_joined_and_sanitised() {
        assert_eq!(cmdline_from_raw(b"psql\0-h\0db\0"), "psql -h db");
        assert_eq!(cmdline_from_raw(b"a\0\0b\x1b[31m\0"), "a b?[31m");
        assert_eq!(cmdline_from_raw(b""), "");
    }

    #[test]
    fn macos_start_time_is_microseconds() {
        assert_eq!(start_time_micros(2, 5), 2_000_005);
        assert_eq!(start_time_micros(u64::MAX, 1), u64::MAX);
    }

    #[test]
    fn reads_own_process() {
        let me = std::process::id();
        let info = RealProcReader.read(me).unwrap();
        assert_eq!(
            info.exe,
            std::env::current_exe()
                .unwrap()
                .canonicalize()
                .unwrap()
                .to_string_lossy()
        );
        assert!(info.start_time > 0);
        assert!(!info.cmdline.is_empty());
        let again = RealProcReader.read(me).unwrap();
        assert_eq!(info.start_time, again.start_time);
    }

    #[test]
    fn missing_process_errors() {
        assert!(RealProcReader.read(u32::MAX - 1).is_err());
    }
}
