//! `/proc/<pid>` introspection used to describe and re-verify callers.

use secret_proto::sanitize;
use std::collections::HashMap;
use std::io;
use std::sync::Mutex;

/// Maximum bytes of `/proc/<pid>/cmdline` that are kept.
pub const CMDLINE_MAX: usize = 256;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcInfo {
    /// Target of `/proc/<pid>/exe` (may end in ` (deleted)`).
    pub exe: String,
    /// Sanitised, truncated command line (arguments separated by spaces).
    pub cmdline: String,
    /// Process start time in clock ticks since boot (`/proc/<pid>/stat` field 22).
    pub start_time: u64,
}

pub trait ProcReader: Send + Sync {
    fn read(&self, pid: u32) -> io::Result<ProcInfo>;
}

/// Reads the real `/proc` (Linux) or libproc/sysctl (macOS).
pub struct RealProcReader;

#[cfg(target_os = "macos")]
impl ProcReader for RealProcReader {
    fn read(&self, pid: u32) -> io::Result<ProcInfo> {
        // Executable path.
        let mut buf = vec![0u8; 4096];
        // SAFETY: buffer is valid for `buf.len()` bytes.
        let n =
            unsafe { libc::proc_pidpath(pid as i32, buf.as_mut_ptr().cast(), buf.len() as u32) };
        if n <= 0 {
            return Err(io::Error::last_os_error());
        }
        let exe = String::from_utf8_lossy(&buf[..n as usize]).into_owned();

        // Start time (microseconds since the epoch) from the BSD info.
        // SAFETY: zeroed POD struct, size passed matches.
        let mut bsd: libc::proc_bsdinfo = unsafe { std::mem::zeroed() };
        let sz = std::mem::size_of::<libc::proc_bsdinfo>() as i32;
        let got = unsafe {
            libc::proc_pidinfo(
                pid as i32,
                libc::PROC_PIDTBSDINFO,
                0,
                (&mut bsd as *mut libc::proc_bsdinfo).cast(),
                sz,
            )
        };
        if got != sz {
            return Err(io::Error::new(io::ErrorKind::NotFound, "no such process"));
        }
        let start_time = bsd.pbi_start_tvsec * 1_000_000 + bsd.pbi_start_tvusec;

        let cmdline = sanitize::clean(&macos_cmdline(pid)?, CMDLINE_MAX);
        Ok(ProcInfo {
            exe,
            cmdline,
            start_time,
        })
    }
}

/// Arguments via `sysctl(KERN_PROCARGS2)`: argc, exec path, NULs, then argv.
#[cfg(target_os = "macos")]
fn macos_cmdline(pid: u32) -> io::Result<String> {
    let mut mib = [libc::CTL_KERN, libc::KERN_PROCARGS2, pid as libc::c_int];
    let mut size: libc::size_t = 0;
    // SAFETY: standard two-step sysctl size query then fetch.
    unsafe {
        if libc::sysctl(
            mib.as_mut_ptr(),
            3,
            std::ptr::null_mut(),
            &mut size,
            std::ptr::null_mut(),
            0,
        ) != 0
        {
            return Err(io::Error::last_os_error());
        }
    }
    let mut buf = vec![0u8; size];
    // SAFETY: buffer has `size` bytes.
    unsafe {
        if libc::sysctl(
            mib.as_mut_ptr(),
            3,
            buf.as_mut_ptr().cast(),
            &mut size,
            std::ptr::null_mut(),
            0,
        ) != 0
        {
            return Err(io::Error::last_os_error());
        }
    }
    buf.truncate(size);
    if buf.len() < 4 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "short procargs"));
    }
    let argc = i32::from_ne_bytes(buf[..4].try_into().unwrap()).max(0) as usize;
    let rest = &buf[4..];
    // Skip the exec path, then the NUL padding before argv[0].
    let after_exe = rest.iter().position(|&b| b == 0).unwrap_or(rest.len());
    let rest = &rest[after_exe..];
    let start = rest.iter().position(|&b| b != 0).unwrap_or(rest.len());
    let args: Vec<String> = rest[start..]
        .split(|&b| b == 0)
        .take(argc)
        .map(|a| String::from_utf8_lossy(a).into_owned())
        .filter(|a| !a.is_empty())
        .collect();
    Ok(args.join(" "))
}

#[cfg(target_os = "linux")]
impl ProcReader for RealProcReader {
    fn read(&self, pid: u32) -> io::Result<ProcInfo> {
        use std::io::Read;
        let exe = std::fs::read_link(format!("/proc/{pid}/exe"))?
            .to_string_lossy()
            .into_owned();
        let mut raw = Vec::new();
        std::fs::File::open(format!("/proc/{pid}/cmdline"))?
            .take(CMDLINE_MAX as u64)
            .read_to_end(&mut raw)?;
        let joined: String = String::from_utf8_lossy(&raw)
            .split('\0')
            .filter(|s| !s.is_empty())
            .collect::<Vec<_>>()
            .join(" ");
        let cmdline = sanitize::clean(&joined, CMDLINE_MAX);
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

/// Field 22 of `/proc/<pid>/stat`. The comm field (2) may contain spaces and
/// parentheses, so parse after the last `)`.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
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

impl ProcReader for StaticProcReader {
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
