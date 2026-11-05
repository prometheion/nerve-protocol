//! Asking the owner for the passphrase of a backup file. Used by `backup` and
//! `restore` of both programs.
//!
//! The passphrase comes from a terminal without echo, from the first line of
//! a file (`--passphrase-file`), or, when stdin is not a terminal, from one
//! line of stdin. It is never a command-line argument or an environment
//! variable: both are visible to every process of the user.

use std::io::{BufRead, Write};
use std::path::Path;

use nerve_transport::backup::Passphrase;

/// The longest passphrase file read.
const MAX_FILE: u64 = 4096;

/// The passphrase from `file` when one is named, else from the owner. With
/// `confirm`, a terminal asks twice (a new backup: a typo there would make
/// the file unreadable).
pub fn passphrase(
    file: Option<&Path>,
    out: &mut dyn Write,
    confirm: bool,
) -> Result<Passphrase, String> {
    if let Some(f) = file {
        return from_file(f);
    }
    let (first, tty) = hidden_line(out, "Passphrase: ")?;
    if tty && confirm {
        let (again, _) = hidden_line(out, "Passphrase again: ")?;
        if first != again {
            return Err("the two passphrases differ".into());
        }
    }
    non_empty(first)
}

/// The first line of `path`. A file that other users can read is refused on
/// Unix, as `ssh` does for a key: the passphrase would be theirs too.
fn from_file(path: &Path) -> Result<Passphrase, String> {
    let name = path.display();
    let check = |meta: &std::fs::Metadata| -> Result<(), String> {
        if !meta.is_file() {
            return Err(format!("{name} is not a file"));
        }
        if meta.len() > MAX_FILE {
            return Err(format!(
                "{name} is larger than {MAX_FILE} bytes, which is no passphrase"
            ));
        }
        Ok(())
    };
    // Before it is opened: Windows refuses to open a folder, and the message
    // would be "Access is denied" instead of what is wrong.
    check(&std::fs::metadata(path).map_err(|e| format!("cannot open {name}: {e}"))?)?;
    let file = std::fs::File::open(path).map_err(|e| format!("cannot open {name}: {e}"))?;
    // And again on the open file, which may be another one by now.
    let meta = file
        .metadata()
        .map_err(|e| format!("cannot read {name}: {e}"))?;
    check(&meta)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if meta.permissions().mode() & 0o077 != 0 {
            return Err(format!(
                "{name} can be read by other users; make it private first (chmod 600), the passphrase protects the keys of the backup"
            ));
        }
    }
    let mut line = String::new();
    std::io::BufReader::new(file)
        .read_line(&mut line)
        .map_err(|e| format!("cannot read {name}: {e}"))?;
    non_empty(trim_eol(&line))
}

/// One line of `input`, for a stdin that is not a terminal.
pub fn from_reader(input: &mut dyn BufRead) -> Result<Passphrase, String> {
    let mut line = String::new();
    input.read_line(&mut line).map_err(|e| e.to_string())?;
    non_empty(trim_eol(&line))
}

fn trim_eol(line: &str) -> String {
    let s = line.strip_suffix('\n').unwrap_or(line);
    s.strip_suffix('\r').unwrap_or(s).to_string()
}

fn non_empty(text: String) -> Result<Passphrase, String> {
    if text.is_empty() {
        return Err("no passphrase given".into());
    }
    Ok(Passphrase::new(text))
}

/// One line from the terminal without echo, and whether stdin is a
/// terminal; else one line of stdin as it comes.
#[cfg(unix)]
fn hidden_line(out: &mut dyn Write, prompt: &str) -> Result<(String, bool), String> {
    use std::os::fd::AsRawFd;
    let stdin = std::io::stdin();
    let fd = stdin.as_raw_fd();
    // SAFETY: plain termios calls on stdin with a zeroed struct to fill.
    let mut old: libc::termios = unsafe { std::mem::zeroed() };
    let tty = unsafe { libc::isatty(fd) == 1 && libc::tcgetattr(fd, &mut old) == 0 };
    if tty {
        let _ = write!(out, "{prompt}");
        let _ = out.flush();
        let mut quiet = old;
        quiet.c_lflag &= !libc::ECHO;
        // SAFETY: as above; restored below.
        unsafe { libc::tcsetattr(fd, libc::TCSANOW, &quiet) };
    }
    let mut line = String::new();
    let r = stdin.lock().read_line(&mut line);
    if tty {
        // SAFETY: restores what tcgetattr returned.
        unsafe { libc::tcsetattr(fd, libc::TCSANOW, &old) };
        let _ = writeln!(out);
    }
    r.map_err(|e| e.to_string())?;
    Ok((trim_eol(&line), tty))
}

#[cfg(windows)]
fn hidden_line(out: &mut dyn Write, prompt: &str) -> Result<(String, bool), String> {
    use windows_sys::Win32::System::Console::{
        ENABLE_ECHO_INPUT, GetConsoleMode, GetStdHandle, STD_INPUT_HANDLE, SetConsoleMode,
    };
    // SAFETY: plain calls on this process's stdin; the mode is restored.
    let console = unsafe {
        let h = GetStdHandle(STD_INPUT_HANDLE);
        let mut mode = 0;
        (GetConsoleMode(h, &mut mode) != 0).then(|| {
            SetConsoleMode(h, mode & !ENABLE_ECHO_INPUT);
            (h, mode)
        })
    };
    if console.is_some() {
        let _ = write!(out, "{prompt}");
        let _ = out.flush();
    }
    let mut line = String::new();
    let r = std::io::stdin().lock().read_line(&mut line);
    if let Some((h, mode)) = console {
        // SAFETY: as above.
        unsafe { SetConsoleMode(h, mode) };
        let _ = writeln!(out);
    }
    r.map_err(|e| e.to_string())?;
    Ok((trim_eol(&line), console.is_some()))
}

#[cfg(not(any(unix, windows)))]
fn hidden_line(_out: &mut dyn Write, _prompt: &str) -> Result<(String, bool), String> {
    let mut line = String::new();
    std::io::stdin()
        .lock()
        .read_line(&mut line)
        .map_err(|e| e.to_string())?;
    Ok((trim_eol(&line), false))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn private(dir: &Path, name: &str, text: &str) -> std::path::PathBuf {
        let p = dir.join(name);
        nerve_transport::files::write_private(&p, text.as_bytes()).unwrap();
        p
    }

    #[test]
    fn the_first_line_of_a_file_is_the_passphrase() {
        let d = tempfile::tempdir().unwrap();
        for text in [
            "correct horse battery\n",
            "correct horse battery\r\nignored\n",
            "correct horse battery",
        ] {
            let p = private(d.path(), "pass", text);
            let mut out = Vec::new();
            let got = passphrase(Some(&p), &mut out, true).unwrap();
            // Same bytes as the passphrase: it opens what that one seals.
            let c = nerve_transport::backup::Contents {
                kind: nerve_transport::backup::Kind::Node,
                created_ms: 0,
                program: String::new(),
                files: Default::default(),
            };
            let sealed = nerve_transport::backup::seal_with(&c, &got, 4).unwrap();
            nerve_transport::backup::open(
                &sealed,
                &Passphrase::new("correct horse battery".into()),
            )
            .unwrap();
            assert!(out.is_empty(), "nothing is asked when a file is named");
        }
    }

    #[test]
    fn an_empty_or_odd_file_is_refused() {
        let d = tempfile::tempdir().unwrap();
        let empty = private(d.path(), "empty", "\n");
        let err = passphrase(Some(&empty), &mut Vec::new(), false).unwrap_err();
        assert!(err.contains("no passphrase"), "{err}");
        let err = passphrase(Some(d.path()), &mut Vec::new(), false).unwrap_err();
        assert!(err.contains("is not a file"), "{err}");
        let err = passphrase(Some(&d.path().join("missing")), &mut Vec::new(), false).unwrap_err();
        assert!(err.contains("cannot open"), "{err}");
        let big = private(d.path(), "big", &"x".repeat(5000));
        let err = passphrase(Some(&big), &mut Vec::new(), false).unwrap_err();
        assert!(err.contains("no passphrase"), "{err}");
    }

    #[cfg(unix)]
    #[test]
    fn a_file_other_users_can_read_is_refused() {
        use std::os::unix::fs::PermissionsExt;
        let d = tempfile::tempdir().unwrap();
        let p = private(d.path(), "pass", "correct horse battery\n");
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o640)).unwrap();
        let err = passphrase(Some(&p), &mut Vec::new(), false).unwrap_err();
        assert!(err.contains("can be read by other users"), "{err}");
        // The text of the file is not in the message.
        assert!(!err.contains("horse"), "{err}");
    }

    #[test]
    fn a_line_of_stdin_is_the_passphrase() {
        let mut input = std::io::Cursor::new(b"correct horse battery\r\n".to_vec());
        assert!(from_reader(&mut input).is_ok());
        let mut none = std::io::Cursor::new(Vec::new());
        assert!(from_reader(&mut none).is_err());
    }
}
