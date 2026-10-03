//! The secret store: a single age file encrypted to one scrypt passphrase.
//!
//! The plaintext is a JSON document `{"version":1,"secrets":{name:{encoding,value}}}`.
//! Plaintext and passphrase buffers are zeroized; [`unseal_one`] extracts a
//! single secret and drops everything else.

use crate::mem;
use crate::rpc::Encoding;
use age::secrecy::SecretString;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;
use zeroize::{Zeroize, Zeroizing};

pub const STORE_VERSION: u32 = 1;

/// A passphrase held in a zeroize-on-drop buffer.
pub type Passphrase = Zeroizing<String>;

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("store file already exists")]
    AlreadyExists,
    #[error("store file not found")]
    NotFound,
    #[error("wrong passphrase")]
    WrongPassphrase,
    #[error("store is corrupt or has been tampered with")]
    Corrupt,
    #[error("unsupported store format")]
    Format,
    #[error("no such secret")]
    NoSuchSecret,
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),
}

/// One stored secret. The value is zeroized on drop.
#[derive(Serialize, Deserialize)]
pub struct Entry {
    pub encoding: Encoding,
    pub value: Zeroizing<String>,
}

impl Entry {
    /// Build an entry from raw bytes: UTF-8 text is stored as `utf8`, anything
    /// else as `base64`.
    pub fn from_bytes(bytes: &[u8]) -> Entry {
        match std::str::from_utf8(bytes) {
            Ok(s) => Entry {
                encoding: Encoding::Utf8,
                value: Zeroizing::new(s.to_owned()),
            },
            Err(_) => Entry {
                encoding: Encoding::Base64,
                value: Zeroizing::new(base64_encode(bytes)),
            },
        }
    }
}

impl std::fmt::Debug for Entry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Entry")
            .field("encoding", &self.encoding)
            .field("value", &"<redacted>")
            .finish()
    }
}

#[derive(Serialize, Deserialize)]
struct Document {
    version: u32,
    secrets: BTreeMap<String, Entry>,
}

/// The decrypted map of all secrets. Values zeroize on drop.
#[derive(Default)]
pub struct Secrets {
    map: BTreeMap<String, Entry>,
}

impl std::fmt::Debug for Secrets {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Secrets")
            .field("names", &self.map.keys().collect::<Vec<_>>())
            .finish()
    }
}

impl Secrets {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn names(&self) -> Vec<String> {
        self.map.keys().cloned().collect()
    }
    pub fn len(&self) -> usize {
        self.map.len()
    }
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }
    pub fn insert(&mut self, name: &str, entry: Entry) {
        self.map.insert(name.to_string(), entry);
    }
    pub fn remove(&mut self, name: &str) -> bool {
        self.map.remove(name).is_some()
    }
    pub fn get(&self, name: &str) -> Option<&Entry> {
        self.map.get(name)
    }
}

/// scrypt work factor (log2 N). `None` uses the age default (~1s on this host).
pub type WorkFactor = Option<u8>;

fn to_secret(p: &Passphrase) -> SecretString {
    SecretString::new(Box::from(p.as_str()))
}

fn encrypt(plain: &[u8], pass: &Passphrase, wf: WorkFactor) -> Result<Vec<u8>, StoreError> {
    let mut recipient = age::scrypt::Recipient::new(to_secret(pass));
    if let Some(n) = wf {
        recipient.set_work_factor(n);
    }
    let enc = age::Encryptor::with_recipients(std::iter::once(&recipient as &dyn age::Recipient))
        .map_err(|_| StoreError::Format)?;
    let mut out = Vec::new();
    let mut w = enc.wrap_output(&mut out)?;
    w.write_all(plain)?;
    w.finish()?;
    Ok(out)
}

/// Decrypt age bytes into a zeroizing plaintext buffer (mlocked best effort
/// by the caller via [`Locked`]).
fn decrypt(cipher: &[u8], pass: &Passphrase) -> Result<Zeroizing<Vec<u8>>, StoreError> {
    let dec = age::Decryptor::new_buffered(cipher).map_err(|_| StoreError::Format)?;
    if !dec.is_scrypt() {
        return Err(StoreError::Format);
    }
    let mut ident = age::scrypt::Identity::new(to_secret(pass));
    ident.set_max_work_factor(26);
    let mut reader = dec
        .decrypt(std::iter::once(&ident as &dyn age::Identity))
        .map_err(|e| match e {
            age::DecryptError::DecryptionFailed => StoreError::WrongPassphrase,
            _ => StoreError::Format,
        })?;
    // Capacity is at least the ciphertext length so reading never reallocates
    // (a realloc would leave an unzeroized copy of the plaintext behind).
    let mut buf = Zeroizing::new(Vec::with_capacity(cipher.len() + 64));
    reader
        .read_to_end(&mut buf)
        .map_err(|_| StoreError::Corrupt)?;
    Ok(buf)
}

/// RAII guard that mlocks a buffer and munlocks it on drop (after the owner
/// has zeroized it, drop order permitting).
struct Locked {
    ptr: *const u8,
    len: usize,
}

impl Locked {
    fn new(s: &[u8]) -> Self {
        mem::lock(s.as_ptr(), s.len());
        Locked {
            ptr: s.as_ptr(),
            len: s.len(),
        }
    }
}

impl Drop for Locked {
    fn drop(&mut self) {
        mem::unlock(self.ptr, self.len);
    }
}

fn parse(plain: &[u8]) -> Result<Document, StoreError> {
    let doc: Document = serde_json::from_slice(plain).map_err(|_| StoreError::Corrupt)?;
    if doc.version != STORE_VERSION {
        return Err(StoreError::Format);
    }
    Ok(doc)
}

/// Atomically write `bytes` to `path` with mode 0600: temp file in the same
/// directory, fsync, rename, fsync directory.
pub fn atomic_write(path: &Path, bytes: &[u8]) -> Result<(), StoreError> {
    let dir = path.parent().filter(|p| !p.as_os_str().is_empty());
    let dir = dir.unwrap_or_else(|| Path::new("."));
    let mut rnd = [0u8; 8];
    getrandom::getrandom(&mut rnd).map_err(|e| std::io::Error::other(e.to_string()))?;
    let tmp = dir.join(format!(
        ".{}.tmp.{}",
        path.file_name().and_then(|n| n.to_str()).unwrap_or("store"),
        rnd.iter().map(|b| format!("{b:02x}")).collect::<String>()
    ));
    let res = (|| -> std::io::Result<()> {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
        drop(f);
        // Preserve an existing store's mode/ownership is not needed: 0600.
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))?;
        std::fs::rename(&tmp, path)?;
        std::fs::File::open(dir)?.sync_all()?;
        Ok(())
    })();
    if res.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    res.map_err(StoreError::from)
}

/// Create a new, empty store. Fails if the file already exists.
pub fn create(path: &Path, pass: &Passphrase, wf: WorkFactor) -> Result<(), StoreError> {
    if path.exists() {
        return Err(StoreError::AlreadyExists);
    }
    save(path, pass, &Secrets::new(), wf)
}

/// Encrypt and atomically write the whole map.
pub fn save(
    path: &Path,
    pass: &Passphrase,
    secrets: &Secrets,
    wf: WorkFactor,
) -> Result<(), StoreError> {
    let doc = DocumentRef {
        version: STORE_VERSION,
        secrets: &secrets.map,
    };
    let plain = Zeroizing::new(serde_json::to_vec(&doc).map_err(|_| StoreError::Format)?);
    let _guard = Locked::new(&plain);
    let cipher = encrypt(&plain, pass, wf)?;
    atomic_write(path, &cipher)
}

#[derive(Serialize)]
struct DocumentRef<'a> {
    version: u32,
    secrets: &'a BTreeMap<String, Entry>,
}

fn read_store(path: &Path) -> Result<Vec<u8>, StoreError> {
    std::fs::read(path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            StoreError::NotFound
        } else {
            StoreError::Io(e)
        }
    })
}

/// Decrypt the full store (admin tooling only; the daemon uses
/// [`unseal_one`]).
pub fn load(path: &Path, pass: &Passphrase) -> Result<Secrets, StoreError> {
    let cipher = read_store(path)?;
    let plain = decrypt(&cipher, pass)?;
    let _guard = Locked::new(&plain);
    let doc = parse(&plain)?;
    Ok(Secrets { map: doc.secrets })
}

/// Unseal the store for one request: decrypt, extract only `name`, then
/// zeroize the passphrase (in place), the plaintext and every other secret.
pub fn unseal_one(path: &Path, pass: &mut Passphrase, name: &str) -> Result<Entry, StoreError> {
    let pass_lock = Locked::new(pass.as_bytes());
    let result = (|| {
        let cipher = read_store(path)?;
        let plain = decrypt(&cipher, pass)?;
        let _guard = Locked::new(&plain);
        let mut doc = parse(&plain)?;
        let entry = doc.secrets.remove(name).ok_or(StoreError::NoSuchSecret)?;
        // `doc` (remaining secrets) and `plain` are zeroized on drop here.
        Ok(entry)
    })();
    pass.zeroize();
    drop(pass_lock);
    result
}

pub fn base64_encode(data: &[u8]) -> String {
    crate::b64::encode(data)
}

pub fn base64_decode(s: &str) -> Option<Vec<u8>> {
    crate::b64::decode(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    const WF: WorkFactor = Some(8);

    fn pw(s: &str) -> Passphrase {
        Zeroizing::new(s.to_string())
    }

    fn store_with(dir: &Path) -> std::path::PathBuf {
        let path = dir.join("store.age");
        create(&path, &pw("correct horse"), WF).unwrap();
        let mut s = load(&path, &pw("correct horse")).unwrap();
        s.insert("a", Entry::from_bytes(b"alpha-value"));
        s.insert("b", Entry::from_bytes(&[0xff, 0x00, 0xfe]));
        s.insert("c", Entry::from_bytes(b"gamma-value"));
        save(&path, &pw("correct horse"), &s, WF).unwrap();
        path
    }

    #[test]
    fn round_trip() {
        let d = tempfile::tempdir().unwrap();
        let path = store_with(d.path());
        let s = load(&path, &pw("correct horse")).unwrap();
        assert_eq!(s.names(), vec!["a", "b", "c"]);
        assert_eq!(s.get("a").unwrap().encoding, Encoding::Utf8);
        assert_eq!(s.get("a").unwrap().value.as_str(), "alpha-value");
        assert_eq!(s.get("b").unwrap().encoding, Encoding::Base64);
        assert_eq!(
            base64_decode(&s.get("b").unwrap().value).unwrap(),
            vec![0xff, 0x00, 0xfe]
        );
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    #[test]
    fn file_does_not_contain_plaintext() {
        let d = tempfile::tempdir().unwrap();
        let path = store_with(d.path());
        let raw = std::fs::read(&path).unwrap();
        assert!(raw.starts_with(b"age-encryption.org/v1"));
        assert!(!raw.windows(11).any(|w| w == b"alpha-value"));
    }

    #[test]
    fn create_refuses_to_overwrite() {
        let d = tempfile::tempdir().unwrap();
        let path = store_with(d.path());
        assert!(matches!(
            create(&path, &pw("x"), WF),
            Err(StoreError::AlreadyExists)
        ));
    }

    #[test]
    fn wrong_passphrase() {
        let d = tempfile::tempdir().unwrap();
        let path = store_with(d.path());
        assert!(matches!(
            load(&path, &pw("nope")),
            Err(StoreError::WrongPassphrase)
        ));
        let mut p = pw("nope");
        assert!(matches!(
            unseal_one(&path, &mut p, "a"),
            Err(StoreError::WrongPassphrase)
        ));
    }

    #[test]
    fn tamper_detection() {
        let d = tempfile::tempdir().unwrap();
        let path = store_with(d.path());
        let orig = std::fs::read(&path).unwrap();
        // Flip a bit in the payload (last byte is part of the final chunk's tag).
        let mut t = orig.clone();
        let last = t.len() - 1;
        t[last] ^= 1;
        std::fs::write(&path, &t).unwrap();
        assert!(matches!(
            load(&path, &pw("correct horse")),
            Err(StoreError::Corrupt)
        ));
        // Flip a bit in the header MAC region.
        let mut t = orig.clone();
        let idx = t.windows(3).position(|w| w == b"---").unwrap() + 6;
        t[idx] = if t[idx] == b'A' { b'B' } else { b'A' };
        std::fs::write(&path, &t).unwrap();
        assert!(load(&path, &pw("correct horse")).is_err());
        // Truncate.
        std::fs::write(&path, &orig[..orig.len() - 20]).unwrap();
        assert!(load(&path, &pw("correct horse")).is_err());
        // Garbage.
        std::fs::write(&path, b"not an age file").unwrap();
        assert!(matches!(
            load(&path, &pw("correct horse")),
            Err(StoreError::Format)
        ));
    }

    #[test]
    fn unseal_returns_only_requested_and_zeroizes_passphrase() {
        let d = tempfile::tempdir().unwrap();
        let path = store_with(d.path());
        let mut p = pw("correct horse");
        let (ptr, cap) = (p.as_ptr(), p.capacity());
        let e = unseal_one(&path, &mut p, "c").unwrap();
        assert_eq!(e.value.as_str(), "gamma-value");
        assert_eq!(e.encoding, Encoding::Utf8);
        // The passphrase buffer was zeroized in place (still allocated here).
        assert!(p.is_empty());
        // SAFETY: `p` still owns the allocation of `cap` bytes.
        let raw = unsafe { std::slice::from_raw_parts(ptr, cap) };
        assert!(raw.iter().all(|&b| b == 0));
        // The returned type holds exactly one secret; the others are gone.
        assert!(!format!("{e:?}").contains("alpha"));
    }

    #[test]
    fn unseal_zeroizes_passphrase_on_failure_too() {
        let d = tempfile::tempdir().unwrap();
        let path = store_with(d.path());
        let mut p = pw("wrong");
        assert!(unseal_one(&path, &mut p, "a").is_err());
        assert!(p.is_empty());
        let mut p = pw("correct horse");
        assert!(matches!(
            unseal_one(&path, &mut p, "missing"),
            Err(StoreError::NoSuchSecret)
        ));
        assert!(p.is_empty());
    }

    #[test]
    fn rotate_by_resave() {
        let d = tempfile::tempdir().unwrap();
        let path = store_with(d.path());
        let s = load(&path, &pw("correct horse")).unwrap();
        save(&path, &pw("new pass"), &s, WF).unwrap();
        assert!(load(&path, &pw("correct horse")).is_err());
        assert_eq!(load(&path, &pw("new pass")).unwrap().len(), 3);
    }

    #[test]
    fn no_temp_files_left() {
        let d = tempfile::tempdir().unwrap();
        let _ = store_with(d.path());
        let n = std::fs::read_dir(d.path()).unwrap().count();
        assert_eq!(n, 1);
    }

    #[test]
    fn base64_round_trip() {
        for data in [&b""[..], b"f", b"fo", b"foo", b"foob", b"fooba", b"foobar"] {
            assert_eq!(base64_decode(&base64_encode(data)).unwrap(), data);
        }
        assert_eq!(base64_encode(b"foobar"), "Zm9vYmFy");
        assert!(base64_decode("a$b").is_none());
    }
}
