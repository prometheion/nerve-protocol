//! The backup file of a node or a center (docs/dev/backup.md).
//!
//! One file, encrypted with a passphrase the owner types, so that the keys in
//! it are as safe as the passphrase while the file lies on a stick, in a mail
//! or in a cloud folder. This module is the container: the header, the key
//! derivation, the encryption and the reading and writing of the file. What
//! goes into it, and what a restore does with it, is the business of
//! `nerve-node` and `nerve-center`.
//!
//! Nothing here puts a passphrase or the text of a file into an error, a
//! `Debug` output or a log: a message names the file or the setting, never
//! its content.

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::path::Path;

use ring::aead::{Aad, CHACHA20_POLY1305, LessSafeKey, NONCE_LEN, Nonce, UnboundKey};
use serde::{Deserialize, Serialize};

/// The first bytes of every backup file.
const MAGIC: &[u8; 8] = b"NERVEBAK";
/// The layout of the container below. A file of a higher number was made by
/// a newer program.
pub const FORMAT: u8 = 1;
/// The key derivation: PBKDF2 with HMAC-SHA256.
const KDF_PBKDF2_SHA256: u8 = 1;
/// The cipher: ChaCha20-Poly1305 with a random nonce per file.
const CIPHER_CHACHA20_POLY1305: u8 = 1;
/// The header: magic, format, kind, kdf, cipher, iterations, salt, nonce. All
/// of it is authenticated with the text, so a changed header opens nothing.
const HEADER_LEN: usize = 8 + 4 + 4 + SALT_LEN + NONCE_LEN;
const SALT_LEN: usize = 16;
const TAG_LEN: usize = 16;

/// PBKDF2 rounds of a file made now (the OWASP 2023 figure for SHA-256).
pub const ITERATIONS: u32 = 600_000;
/// The most rounds a file may ask for. A file is read before the passphrase
/// is known to fit it, so a damaged or hostile count must not keep the CPU.
const MAX_ITERATIONS: u32 = 10_000_000;

/// The shortest passphrase a new backup takes (in characters). PBKDF2 can be
/// run on a graphics card, so the length is what keeps the file closed.
pub const MIN_PASSPHRASE: usize = 12;

/// The largest backup file read or written. A node's config and keys, or a
/// center's state, are far below it; a file above it is not one of ours.
pub const MAX_FILE: u64 = 32 * 1024 * 1024;

/// What a backup file holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    Node,
    Center,
}

impl Kind {
    fn byte(self) -> u8 {
        match self {
            Kind::Node => 1,
            Kind::Center => 2,
        }
    }

    fn from_byte(b: u8) -> Option<Kind> {
        match b {
            1 => Some(Kind::Node),
            2 => Some(Kind::Center),
            _ => None,
        }
    }

    /// How a message names it.
    pub fn word(self) -> &'static str {
        match self {
            Kind::Node => "node",
            Kind::Center => "center",
        }
    }
}

/// A passphrase. It is not shown by `Debug` and is overwritten when dropped
/// (as far as the compiler lets a program do that).
pub struct Passphrase(String);

impl Passphrase {
    pub fn new(text: String) -> Passphrase {
        Passphrase(text)
    }

    /// The text, for a program that hands it on (an owner's CLI to the
    /// node).
    pub fn text(&self) -> &str {
        &self.0
    }

    /// Whether the passphrase is one a new backup may have.
    pub fn check_new(&self) -> Result<(), String> {
        if self.0.chars().count() < MIN_PASSPHRASE {
            return Err(format!(
                "the passphrase must be at least {MIN_PASSPHRASE} characters: the backup holds the node's private keys, and a short one can be guessed"
            ));
        }
        Ok(())
    }

    fn bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

impl std::fmt::Debug for Passphrase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Passphrase(..)")
    }
}

impl Drop for Passphrase {
    fn drop(&mut self) {
        let mut b = std::mem::take(&mut self.0).into_bytes();
        b.fill(0);
        std::hint::black_box(&b);
    }
}

/// What a backup file holds once opened: texts by their logical names
/// (`node.toml`, `key/<center>`, `tls.pem`, ...), never by a path. The
/// restore decides where each goes, so a file cannot name a place.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Contents {
    pub kind: Kind,
    /// When the backup was made, in milliseconds since the Unix epoch.
    pub created_ms: u64,
    /// The program that made it (`nerve-node 0.0.4`).
    pub program: String,
    pub files: BTreeMap<String, String>,
}

impl std::fmt::Debug for Contents {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The texts are keys: only their names are shown.
        f.debug_struct("Contents")
            .field("kind", &self.kind)
            .field("created_ms", &self.created_ms)
            .field("program", &self.program)
            .field("files", &self.files.keys().collect::<Vec<_>>())
            .finish()
    }
}

/// The key of this file: PBKDF2 of the passphrase, the salt and the rounds.
fn derive(pass: &Passphrase, salt: &[u8], iterations: u32) -> Result<LessSafeKey, String> {
    let rounds = std::num::NonZeroU32::new(iterations).ok_or("the backup asks for no rounds")?;
    let mut key = [0u8; 32];
    ring::pbkdf2::derive(
        ring::pbkdf2::PBKDF2_HMAC_SHA256,
        rounds,
        salt,
        pass.bytes(),
        &mut key,
    );
    let unbound =
        UnboundKey::new(&CHACHA20_POLY1305, &key).map_err(|_| "cannot set up the cipher")?;
    key.fill(0);
    Ok(LessSafeKey::new(unbound))
}

/// Encrypts `contents` into a backup file's bytes.
pub fn seal(contents: &Contents, pass: &Passphrase) -> Result<Vec<u8>, String> {
    seal_with(contents, pass, ITERATIONS)
}

/// [`seal`] with another number of rounds: a test does not wait for 600 000.
#[doc(hidden)]
pub fn seal_with(
    contents: &Contents,
    pass: &Passphrase,
    iterations: u32,
) -> Result<Vec<u8>, String> {
    let mut plain = serde_json::to_vec(contents).map_err(|e| e.to_string())?;
    // The file, not only its text: a file above the cap is one `read_file`
    // refuses, so a backup that size must not be written.
    if (plain.len() + HEADER_LEN + TAG_LEN) as u64 > MAX_FILE {
        plain.fill(0);
        return Err(format!(
            "what the backup would hold is larger than {} MiB, which is more than a node or a center has; refusing",
            MAX_FILE / (1024 * 1024)
        ));
    }
    let salt = crate::keys::random_bytes(SALT_LEN);
    let nonce = crate::keys::random_bytes(NONCE_LEN);
    let mut out = Vec::with_capacity(HEADER_LEN + plain.len() + TAG_LEN);
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&[
        FORMAT,
        contents.kind.byte(),
        KDF_PBKDF2_SHA256,
        CIPHER_CHACHA20_POLY1305,
    ]);
    out.extend_from_slice(&iterations.to_be_bytes());
    out.extend_from_slice(&salt);
    out.extend_from_slice(&nonce);
    debug_assert_eq!(out.len(), HEADER_LEN);
    let key = derive(pass, &salt, iterations)?;
    let header = out.clone();
    let nonce = Nonce::try_assume_unique_for_key(&nonce).map_err(|_| "bad nonce")?;
    key.seal_in_place_append_tag(nonce, Aad::from(&header), &mut plain)
        .map_err(|_| "cannot encrypt the backup")?;
    out.extend_from_slice(&plain);
    Ok(out)
}

/// The header of a file: what it holds and the numbers it was made with.
struct Header {
    kind: Kind,
    iterations: u32,
}

fn parse_header(bytes: &[u8]) -> Result<Header, String> {
    if bytes.len() < 8 || &bytes[..8] != MAGIC {
        return Err("this is not a Nerve backup file".into());
    }
    if bytes.len() < HEADER_LEN + TAG_LEN {
        return Err("the backup file is cut short".into());
    }
    let format = bytes[8];
    if format != FORMAT {
        return Err(if format > FORMAT {
            format!(
                "this backup is format {format}, made by a newer program; update this one first"
            )
        } else {
            format!("this backup is format {format}, which this program does not read")
        });
    }
    let kind = Kind::from_byte(bytes[9]).ok_or("the backup file names no node or center")?;
    if bytes[10] != KDF_PBKDF2_SHA256 || bytes[11] != CIPHER_CHACHA20_POLY1305 {
        return Err("the backup uses a key derivation or cipher this program does not know".into());
    }
    let iterations = u32::from_be_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]);
    if iterations == 0 || iterations > MAX_ITERATIONS {
        return Err("the backup file is damaged (its number of rounds is out of range)".into());
    }
    Ok(Header { kind, iterations })
}

/// What a file holds, from its header alone: a restore can refuse the wrong
/// kind before it asks for the passphrase.
pub fn kind_of(bytes: &[u8]) -> Result<Kind, String> {
    parse_header(bytes).map(|h| h.kind)
}

/// Decrypts a backup file. A wrong passphrase and a changed file cannot be
/// told apart, so the message says both.
pub fn open(bytes: &[u8], pass: &Passphrase) -> Result<Contents, String> {
    let header = parse_header(bytes)?;
    let salt = &bytes[16..16 + SALT_LEN];
    let nonce = Nonce::try_assume_unique_for_key(&bytes[16 + SALT_LEN..HEADER_LEN])
        .map_err(|_| "bad nonce")?;
    let key = derive(pass, salt, header.iterations)?;
    let mut text = bytes[HEADER_LEN..].to_vec();
    let plain = key
        .open_in_place(nonce, Aad::from(&bytes[..HEADER_LEN]), &mut text)
        .map_err(|_| "cannot open the backup: the passphrase is wrong, or the file was changed")?;
    // The parse error is not shown: it could quote a key.
    let contents: Contents = serde_json::from_slice(plain)
        .map_err(|_| "the backup opened but does not hold what a Nerve backup does")?;
    text.fill(0);
    if contents.kind != header.kind {
        return Err(
            "the backup file is inconsistent (its header and its content name different kinds)"
                .into(),
        );
    }
    Ok(contents)
}

/// Reads a backup file, refusing what is not a regular file or is larger than
/// [`MAX_FILE`] before it is read into memory.
pub fn read_file(path: &Path) -> Result<Vec<u8>, String> {
    let name = path.display().to_string();
    // Before it is opened: Windows refuses to open a folder, and the message
    // would be "Access is denied" instead of what is wrong.
    check_file(
        &name,
        &std::fs::metadata(path).map_err(|e| format!("cannot open {name}: {e}"))?,
    )?;
    let file = std::fs::File::open(path).map_err(|e| format!("cannot open {name}: {e}"))?;
    read_open(file, &name)
}

/// Whether `meta` is of a file that can be a backup.
fn check_file(name: &str, meta: &std::fs::Metadata) -> Result<(), String> {
    if !meta.is_file() {
        return Err(format!("{name} is not a file"));
    }
    if meta.len() > MAX_FILE {
        return Err(format!(
            "{name} is larger than {} MiB, so it is not a Nerve backup",
            MAX_FILE / (1024 * 1024)
        ));
    }
    Ok(())
}

/// Reads the backup in `file`, opened already (by [`read_file`], or by an
/// owner's own process that handed it over), named `name` in errors.
pub fn read_open(file: std::fs::File, name: &str) -> Result<Vec<u8>, String> {
    // Checked on the open file, which may be another one than was looked at.
    let meta = file
        .metadata()
        .map_err(|e| format!("cannot read {name}: {e}"))?;
    check_file(name, &meta)?;
    let mut bytes = Vec::with_capacity(meta.len() as usize);
    file.take(MAX_FILE + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| format!("cannot read {name}: {e}"))?;
    if bytes.len() as u64 > MAX_FILE {
        return Err(format!("{name} grew while it was read"));
    }
    Ok(bytes)
}

/// Checks the folder `path` is to be written in. A folder that is not there
/// is a typo more often than a wish. One that this process may not search is
/// there all the same, and is said so: the caller may be another user than
/// whoever typed the path (root's command on a service's folders runs as the
/// service's user).
pub fn check_folder(path: &Path) -> Result<(), String> {
    if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
        match std::fs::metadata(dir) {
            Ok(m) if m.is_dir() => {}
            Ok(_) => return Err(format!("{} is not a folder", dir.display())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err(format!("the folder {} does not exist", dir.display()));
            }
            Err(e) => return Err(format!("cannot use the folder {}: {e}", dir.display())),
        }
    }
    Ok(())
}

/// Writes a backup file, readable by its owner only (mode 0600 on Unix).
/// Without `overwrite` an existing file, a link included, is never touched.
pub fn write_file(path: &Path, bytes: &[u8], overwrite: bool) -> Result<(), String> {
    let name = path.display();
    check_folder(path)?;
    if overwrite {
        // Through a temporary file and a rename: the old backup stays whole
        // until the new one is complete.
        return crate::files::write_private(path, bytes)
            .map_err(|e| format!("cannot write {name}: {e}"));
    }
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut file = opts.open(path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::AlreadyExists {
            format!("{name} exists already; name another file or pass --overwrite")
        } else {
            format!("cannot write {name}: {e}")
        }
    })?;
    let r = file.write_all(bytes).and_then(|()| file.sync_all());
    drop(file);
    if let Err(e) = r {
        let _ = std::fs::remove_file(path);
        return Err(format!("cannot write {name}: {e}"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pass(s: &str) -> Passphrase {
        Passphrase::new(s.into())
    }

    fn contents() -> Contents {
        Contents {
            kind: Kind::Node,
            created_ms: 7,
            program: "nerve-node test".into(),
            files: BTreeMap::from([
                ("node.toml".to_string(), "version = 3\n".to_string()),
                ("key/home".to_string(), "SECRET-KEY-TEXT".to_string()),
            ]),
        }
    }

    /// Few rounds: the container does not care how many.
    fn sealed(c: &Contents, p: &str) -> Vec<u8> {
        seal_with(c, &pass(p), 1000).unwrap()
    }

    #[test]
    fn a_backup_opens_with_its_passphrase_and_only_with_it() {
        let bytes = sealed(&contents(), "correct horse battery");
        let back = open(&bytes, &pass("correct horse battery")).unwrap();
        assert_eq!(back.kind, Kind::Node);
        assert_eq!(back.created_ms, 7);
        assert_eq!(back.files["key/home"], "SECRET-KEY-TEXT");
        let err = open(&bytes, &pass("correct horse batterz")).unwrap_err();
        assert!(err.contains("passphrase is wrong"), "{err}");
        // Nothing of the content is readable in the file.
        let text = String::from_utf8_lossy(&bytes);
        assert!(!text.contains("SECRET-KEY-TEXT") && !text.contains("node.toml"));
    }

    #[test]
    fn two_backups_of_one_content_differ() {
        let a = sealed(&contents(), "correct horse battery");
        let b = sealed(&contents(), "correct horse battery");
        assert_ne!(a, b, "salt and nonce are new every time");
    }

    #[test]
    fn a_changed_byte_anywhere_after_the_magic_opens_nothing() {
        let bytes = sealed(&contents(), "correct horse battery");
        for at in 8..bytes.len() {
            let mut bad = bytes.clone();
            bad[at] ^= 1;
            assert!(
                open(&bad, &pass("correct horse battery")).is_err(),
                "byte {at} changed and the file still opened"
            );
        }
    }

    #[test]
    fn a_file_that_is_not_ours_or_cut_short_is_said_so() {
        let p = pass("correct horse battery");
        assert!(open(b"", &p).unwrap_err().contains("not a Nerve backup"));
        assert!(
            open(b"PK\x03\x04 a zip", &p)
                .unwrap_err()
                .contains("not a Nerve backup")
        );
        let bytes = sealed(&contents(), "correct horse battery");
        for cut in [9, 44, bytes.len() - 1] {
            assert!(open(&bytes[..cut], &p).is_err(), "cut at {cut}");
        }
        // The magic alone is cut short, not foreign.
        assert!(open(MAGIC, &p).unwrap_err().contains("cut short"));
    }

    #[test]
    fn a_newer_format_asks_for_an_update() {
        let mut bytes = sealed(&contents(), "correct horse battery");
        bytes[8] = FORMAT + 1;
        let err = open(&bytes, &pass("correct horse battery")).unwrap_err();
        assert!(err.contains("newer program"), "{err}");
        bytes[8] = 0;
        let err = open(&bytes, &pass("correct horse battery")).unwrap_err();
        assert!(err.contains("does not read"), "{err}");
    }

    #[test]
    fn a_hostile_number_of_rounds_is_refused_before_any_work() {
        let mut bytes = sealed(&contents(), "correct horse battery");
        for rounds in [0u32, MAX_ITERATIONS + 1, u32::MAX] {
            bytes[12..16].copy_from_slice(&rounds.to_be_bytes());
            let t = std::time::Instant::now();
            let err = open(&bytes, &pass("correct horse battery")).unwrap_err();
            assert!(err.contains("out of range"), "{err}");
            assert!(t.elapsed() < std::time::Duration::from_secs(1));
        }
    }

    #[test]
    fn the_kind_is_known_from_the_header_alone() {
        let node = sealed(&contents(), "correct horse battery");
        assert_eq!(kind_of(&node).unwrap(), Kind::Node);
        let mut c = contents();
        c.kind = Kind::Center;
        let center = sealed(&c, "correct horse battery");
        assert_eq!(kind_of(&center).unwrap(), Kind::Center);
        // A header that says one kind over a content of the other is refused
        // (the header is authenticated, so only the maker could have done it).
        let mut mixed = center.clone();
        mixed[9] = Kind::Node.byte();
        assert!(open(&mixed, &pass("correct horse battery")).is_err());
    }

    #[test]
    fn a_backup_is_written_only_when_it_can_be_read_again() {
        // The most a file holds is MAX_FILE with its header and tag; a text
        // that fits the cap by itself but not the file is refused when the
        // backup is made, not when it is needed.
        let base = Contents {
            kind: Kind::Node,
            created_ms: 0,
            program: String::new(),
            files: BTreeMap::from([("a".to_string(), String::new())]),
        };
        let empty = serde_json::to_vec(&base).unwrap().len();
        let room = MAX_FILE as usize - HEADER_LEN - TAG_LEN;
        let with = |plain: usize| {
            let mut c = base.clone();
            c.files.insert("a".into(), "x".repeat(plain - empty));
            c
        };
        let p = pass("correct horse battery");
        let exact = seal_with(&with(room), &p, 4).unwrap();
        assert_eq!(exact.len() as u64, MAX_FILE);
        let d = tempfile::tempdir().unwrap();
        let path = d.path().join("big.bak");
        write_file(&path, &exact, false).unwrap();
        let back = read_file(&path).unwrap();
        assert_eq!(open(&back, &p).unwrap().files["a"].len(), room - empty);
        // One byte more would be a file that `read_file` refuses.
        let err = seal_with(&with(room + 1), &p, 4).unwrap_err();
        assert!(err.contains("larger than"), "{err}");
        // Also the old bound, the text alone at the cap.
        let err = seal_with(&with(MAX_FILE as usize), &p, 4).unwrap_err();
        assert!(err.contains("larger than"), "{err}");
    }

    #[test]
    fn passphrases_are_not_shown_and_must_be_long_enough() {
        let p = pass("correct horse battery");
        assert!(!format!("{p:?}").contains("correct"));
        assert!(p.check_new().is_ok());
        assert!(
            pass("short")
                .check_new()
                .unwrap_err()
                .contains("12 characters")
        );
        // Characters, not bytes.
        assert!(pass("ääääääääääää").check_new().is_ok());
        assert!(pass("äääääääääää").check_new().is_err());
    }

    #[test]
    fn contents_do_not_show_their_texts() {
        let shown = format!("{:?}", contents());
        assert!(shown.contains("key/home") && !shown.contains("SECRET-KEY-TEXT"));
    }

    #[test]
    fn a_new_file_is_private_and_an_old_one_is_kept_without_overwrite() {
        let d = tempfile::tempdir().unwrap();
        let path = d.path().join("a.bak");
        write_file(&path, b"first", false).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        let err = write_file(&path, b"second", false).unwrap_err();
        assert!(
            err.contains("exists already") && err.contains("--overwrite"),
            "{err}"
        );
        assert_eq!(std::fs::read(&path).unwrap(), b"first");
        write_file(&path, b"third", true).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"third");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        // Only the backup is left in the folder.
        assert_eq!(std::fs::read_dir(d.path()).unwrap().count(), 1);
        // A folder that is not there is not made.
        let err = write_file(&d.path().join("no/such/a.bak"), b"x", true).unwrap_err();
        assert!(err.contains("does not exist"), "{err}");
        assert!(!d.path().join("no").exists());
        // Nor is a file taken for one.
        std::fs::write(d.path().join("file"), b"x").unwrap();
        let err = write_file(&d.path().join("file/a.bak"), b"x", true).unwrap_err();
        assert!(err.contains("is not a folder"), "{err}");
    }

    /// A folder this process may not search is there: the message says
    /// what stops it, not that the folder is missing. (Root searches every
    /// folder, so this needs another user.)
    #[cfg(unix)]
    #[test]
    fn a_folder_that_may_not_be_searched_is_not_called_missing() {
        use std::os::unix::fs::PermissionsExt;
        if crate::net::euid() == 0 {
            return;
        }
        let d = tempfile::tempdir().unwrap();
        let closed = d.path().join("closed");
        std::fs::create_dir_all(closed.join("sub")).unwrap();
        std::fs::set_permissions(&closed, std::fs::Permissions::from_mode(0o000)).unwrap();
        let r = write_file(&closed.join("sub/a.bak"), b"x", false);
        std::fs::set_permissions(&closed, std::fs::Permissions::from_mode(0o700)).unwrap();
        let err = r.unwrap_err();
        assert!(!err.contains("does not exist"), "{err}");
        assert!(
            err.contains(&format!(
                "cannot use the folder {}",
                closed.join("sub").display()
            )),
            "{err}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_link_in_the_way_is_not_followed() {
        let d = tempfile::tempdir().unwrap();
        let target = d.path().join("target");
        std::fs::write(&target, b"keep").unwrap();
        let link = d.path().join("link.bak");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert!(write_file(&link, b"x", false).is_err());
        assert_eq!(std::fs::read(&target).unwrap(), b"keep");
        // A dangling link is in the way as well.
        let dangling = d.path().join("dangling.bak");
        std::os::unix::fs::symlink(d.path().join("nowhere"), &dangling).unwrap();
        assert!(write_file(&dangling, b"x", false).is_err());
        assert!(!d.path().join("nowhere").exists());
    }

    #[test]
    fn reading_refuses_what_is_no_file_or_too_large() {
        let d = tempfile::tempdir().unwrap();
        let err = read_file(d.path()).unwrap_err();
        assert!(err.contains("is not a file"), "{err}");
        let err = read_file(&d.path().join("missing")).unwrap_err();
        assert!(err.contains("cannot open"), "{err}");
        let big = d.path().join("big");
        let f = std::fs::File::create(&big).unwrap();
        // A sparse file: no memory or disk for the test.
        f.set_len(MAX_FILE + 1).unwrap();
        let err = read_file(&big).unwrap_err();
        assert!(err.contains("not a Nerve backup"), "{err}");
        let small = d.path().join("small");
        std::fs::write(&small, b"abc").unwrap();
        assert_eq!(read_file(&small).unwrap(), b"abc");
    }
}
