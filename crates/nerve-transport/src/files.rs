//! Writing state files: atomically, and readable by the owner only; and the
//! format they are in.

use std::io::Write;
use std::path::Path;

/// Writes `data` to `path` through a temporary file in the same folder and a
/// rename, so a reader never sees half a file. On Unix the file is created
/// 0600; the folder is created 0700 when missing, and synced after the
/// rename, so the new file is there after a power cut.
pub fn write_private(path: &Path, data: &[u8]) -> std::io::Result<()> {
    let dir = path.parent().unwrap_or(Path::new("."));
    create_private_dir(dir)?;
    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("state");
    let tmp = dir.join(format!(".{name}.{}.tmp", crate::keys::random_token(8)));
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let result = (|| {
        let mut f = opts.open(&tmp)?;
        f.write_all(data)?;
        f.sync_all()?;
        std::fs::rename(&tmp, path)
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    // Some file systems cannot sync a folder; the file is written all the
    // same.
    #[cfg(unix)]
    if result.is_ok() {
        let _ = std::fs::File::open(dir).and_then(|d| d.sync_all());
    }
    result
}

/// Creates `dir` (and its parents) with mode 0700 on Unix.
pub fn create_private_dir(dir: &Path) -> std::io::Result<()> {
    if dir.as_os_str().is_empty() || dir.is_dir() {
        return Ok(());
    }
    let mut b = std::fs::DirBuilder::new();
    b.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        b.mode(0o700);
    }
    b.create(dir)
}

/// How often [`retry_busy`] starts a program again.
#[cfg(unix)]
const BUSY_TRIES: u32 = 5;
/// How long apart.
#[cfg(unix)]
const BUSY_PAUSE: std::time::Duration = std::time::Duration::from_millis(50);

/// Runs `start`, the start of a program, again up to five times 50 ms apart
/// while Linux answers ETXTBSY ("Text file busy"): a program written a moment
/// ago is still open for writing in a child another thread forked meanwhile,
/// until that child's `exec` closes it, and Linux runs no file that is open
/// for writing (#168). Cargo and Go retry for the same reason. Any other
/// answer, and the last one, is given as it is. Blocks while it waits.
pub fn retry_busy<T>(mut start: impl FnMut() -> std::io::Result<T>) -> std::io::Result<T> {
    #[cfg(unix)]
    for _ in 0..BUSY_TRIES {
        match start() {
            Err(e) if e.raw_os_error() == Some(libc::ETXTBSY) => std::thread::sleep(BUSY_PAUSE),
            r => return r,
        }
    }
    start()
}

/// Writes the program `text` to `path`, mode 755, through a shell of its
/// own: this process never holds the file open for writing, so no child
/// another of its threads forks meanwhile can hold it either, and a run of
/// it right after does not fail with ETXTBSY ([`retry_busy`]). For tests
/// that write a script and run it.
#[cfg(unix)]
pub fn write_program(path: &Path, text: &str) -> std::io::Result<()> {
    let mut sh = std::process::Command::new("/bin/sh")
        .args(["-c", "cat > \"$1\" && chmod 755 \"$1\"", "sh"])
        .arg(path)
        .stdin(std::process::Stdio::piped())
        .spawn()?;
    let mut input = sh.stdin.take().expect("piped");
    let wrote = input.write_all(text.as_bytes());
    drop(input);
    let status = sh.wait()?;
    wrote?;
    if !status.success() {
        return Err(std::io::Error::other(format!(
            "{}: the program could not be written ({status})",
            path.display()
        )));
    }
    Ok(())
}

/// The format of a file the node or the center keeps for itself (`format`
/// in `node.toml`, `state.json`, `acl.json`, `grants.json`): it counts the
/// changes an earlier version cannot read. A file without it is at format
/// 1, the first. Not the `version` of `node.toml`, which counts its saves.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(transparent)]
pub struct Format(pub u64);

impl Format {
    /// The format this version reads and writes, the same for every file
    /// so far.
    pub const CURRENT: Format = Format(1);

    /// Refuses a format this version does not read: a higher one comes from
    /// a newer version, and reading it could drop what that version keeps.
    pub fn check(self) -> Result<(), String> {
        let (n, current) = (self.0, Format::CURRENT.0);
        match n {
            n if n == current => Ok(()),
            n if n > current => Err(format!(
                "format {n}: a newer version of Nerve wrote this file; this version reads format {current}"
            )),
            n => Err(format!(
                "format {n}: not a format of this file; this version reads format {current}"
            )),
        }
    }

    /// The format a JSON file names, read before its typed parse, so that a
    /// file of a newer version is refused for its format and not for a
    /// field this version does not know. A file this cannot read (not JSON,
    /// not an object, a `format` that is no number) reads as format 1: its
    /// typed parse says what is wrong.
    pub fn of_json(bytes: &[u8]) -> Format {
        #[derive(serde::Deserialize)]
        struct Peek {
            #[serde(default)]
            format: Format,
        }
        serde_json::from_slice::<Peek>(bytes)
            .map(|p| p.format)
            .unwrap_or_default()
    }
}

impl Default for Format {
    fn default() -> Format {
        Format(1)
    }
}

impl std::fmt::Display for Format {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Format 1 is read, and a file without one is at format 1; a higher
    /// one is refused as a newer version's, also when the file has fields
    /// this version does not know.
    #[test]
    fn a_newer_format_is_refused_and_none_is_format_one() {
        assert_eq!(Format::default(), Format::CURRENT);
        assert_eq!(Format::of_json(br#"{"a": 1}"#), Format(1));
        assert_eq!(Format::of_json(br#"{"format": 1}"#), Format(1));
        assert_eq!(Format::of_json(br#"{"format": 2, "new": [1]}"#), Format(2));
        assert_eq!(Format::of_json(b"[1, 2]"), Format(1));
        assert_eq!(Format::of_json(b"not json"), Format(1));
        assert!(Format(1).check().is_ok());
        let e = Format(2).check().unwrap_err();
        assert!(e.contains("format 2") && e.contains("newer version"), "{e}");
        assert!(Format(0).check().unwrap_err().contains("format 0"));
    }

    /// A program open for writing elsewhere a moment longer than its start
    /// takes runs once it is closed; another error is given at once.
    #[cfg(unix)]
    #[test]
    fn a_program_still_open_for_writing_starts_once_it_is_closed() {
        use std::os::unix::fs::PermissionsExt;
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("prog");
        let mut f = std::fs::File::create(&p).unwrap();
        f.write_all(b"#!/bin/sh\nexit 7\n").unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
        // The race, made sure: the handle stays open while the start is
        // tried, and goes after two pauses.
        let e = std::process::Command::new(&p).status().unwrap_err();
        assert_eq!(e.raw_os_error(), Some(libc::ETXTBSY));
        let closer = std::thread::spawn(move || {
            std::thread::sleep(BUSY_PAUSE * 2);
            drop(f);
        });
        let status = retry_busy(|| std::process::Command::new(&p).status()).unwrap();
        assert_eq!(status.code(), Some(7));
        closer.join().unwrap();
        let tries = std::cell::Cell::new(0);
        let gone = retry_busy(|| {
            tries.set(tries.get() + 1);
            std::process::Command::new(d.path().join("none")).status()
        });
        assert!(gone.is_err());
        assert_eq!(tries.get(), 1);
    }

    /// A program written by [`write_program`] runs at once, also while
    /// other threads start programs.
    #[cfg(unix)]
    #[test]
    fn a_written_program_runs_at_once() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("prog");
        write_program(&p, "#!/bin/sh\necho made\n").unwrap();
        let o = std::process::Command::new(&p).output().unwrap();
        assert_eq!(o.stdout, b"made\n");
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o755);
    }

    #[test]
    fn writes_privately() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("sub/state.toml");
        write_private(&p, b"one").unwrap();
        write_private(&p, b"two").unwrap();
        assert_eq!(std::fs::read(&p).unwrap(), b"two");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&p).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
        assert_eq!(std::fs::read_dir(p.parent().unwrap()).unwrap().count(), 1);
    }
}
