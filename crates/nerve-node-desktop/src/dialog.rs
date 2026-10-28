//! The system's file dialogs ([`crate::app::Choose`]). On Linux the app
//! asks for one through a process of its own, this program started as
//! [`ARG`]: once the app holds the administrator rights it is closed to the
//! other processes of its user (crate::broker), and the desktop portal
//! refuses a caller it cannot look at in `/proc`. The process is started
//! fresh, so the portal can, and it holds nothing of the rights.

use std::io::Write;
use std::path::PathBuf;

use crate::app::Choose;

/// The argument that starts this program as one file dialog, with the
/// [`Choose`] by its name.
pub const ARG: &str = "__desktop-choose";

const ALL: [Choose; 5] = [
    Choose::Folder,
    Choose::SaveBackup,
    Choose::OpenBackup,
    Choose::Program,
    Choose::Provider,
];

fn name(c: Choose) -> &'static str {
    match c {
        Choose::Folder => "folder",
        Choose::SaveBackup => "save-backup",
        Choose::OpenBackup => "open-backup",
        Choose::Program => "program",
        Choose::Provider => "provider",
    }
}

/// Shows the dialog in this process: what the owner picked, `None` when
/// they closed it.
pub fn show(c: Choose) -> Result<Option<PathBuf>, String> {
    // The dialogs on Linux are the desktop portal's; without it rfd shows
    // nothing and says nothing.
    #[cfg(target_os = "linux")]
    crate::deps::portal_here()?;
    let d = rfd::FileDialog::new();
    Ok(match c {
        Choose::Folder => d.set_title("A folder for the center").pick_folder(),
        Choose::SaveBackup => d
            .set_title("Back up the node")
            .set_file_name("nerve-node.backup")
            .save_file(),
        Choose::OpenBackup => d.set_title("Restore a backup").pick_file(),
        Choose::Program => d.set_title("The new nerve-node-desktop").pick_file(),
        Choose::Provider => d.set_title("A program to allow as a provider").pick_file(),
    })
}

/// [`show`] in `exe` started as [`ARG`]: the path it printed, `None` when
/// it printed nothing, its stderr when it failed.
#[cfg(unix)]
pub fn apart(exe: &std::path::Path, c: Choose) -> Result<Option<PathBuf>, String> {
    use std::os::unix::ffi::OsStringExt;
    let out = std::process::Command::new(exe)
        .args([ARG, name(c)])
        .stdin(std::process::Stdio::null())
        .output()
        .map_err(|e| format!("the file dialog did not start: {e}"))?;
    if !out.status.success() {
        let said = String::from_utf8_lossy(&out.stderr).trim().to_string();
        return Err(if said.is_empty() {
            "the file dialog did not open".into()
        } else {
            said
        });
    }
    Ok((!out.stdout.is_empty()).then(|| std::ffi::OsString::from_vec(out.stdout).into()))
}

/// `__desktop-choose <what>`: shows the dialog and prints the path picked,
/// as it is and nothing else, or nothing when the owner closed it. The
/// exit code.
pub fn main(args: &[String]) -> i32 {
    let Some(c) = ALL
        .into_iter()
        .find(|c| args.first().map(String::as_str) == Some(name(*c)))
    else {
        return 2;
    };
    match show(c) {
        Ok(None) => 0,
        Ok(Some(path)) => {
            #[cfg(unix)]
            let bytes = {
                use std::os::unix::ffi::OsStrExt;
                path.as_os_str().as_bytes().to_vec()
            };
            #[cfg(not(unix))]
            let bytes = path.to_string_lossy().into_owned().into_bytes();
            let mut out = std::io::stdout();
            match out.write_all(&bytes).and_then(|_| out.flush()) {
                Ok(()) => 0,
                Err(_) => 1,
            }
        }
        Err(e) => {
            eprintln!("{e}");
            1
        }
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    /// What the dialog's process says comes back as the app's answer; here
    /// the process is a script that answers as the dialog would.
    #[test]
    fn a_dialog_apart_answers_with_what_it_printed() {
        let d = tempfile::tempdir().unwrap();
        let mut n = 0;
        let mut script = |body: &str| {
            n += 1;
            let p = d.path().join(format!("dialog{n}"));
            // Written by a process of its own (see the broker's tests).
            let mut sh = std::process::Command::new("/bin/sh")
                .args(["-c", "cat > \"$0\" && chmod 755 \"$0\""])
                .arg(&p)
                .stdin(std::process::Stdio::piped())
                .spawn()
                .unwrap();
            let mut input = sh.stdin.take().unwrap();
            input
                .write_all(format!("#!/bin/sh\n{body}\n").as_bytes())
                .unwrap();
            drop(input);
            assert!(sh.wait().unwrap().success());
            p
        };
        let asked = d.path().join("asked");
        let p = script(&format!(
            "echo \"$*\" > '{}'\nprintf '/home/me/a b\\n.backup'",
            asked.display()
        ));
        assert_eq!(
            apart(&p, Choose::OpenBackup).unwrap(),
            Some(PathBuf::from("/home/me/a b\n.backup"))
        );
        assert_eq!(
            std::fs::read_to_string(&asked).unwrap().trim(),
            format!("{ARG} open-backup")
        );
        assert_eq!(apart(&script("true"), Choose::Folder).unwrap(), None);
        let e = apart(
            &script("echo 'No file dialog: none' >&2\nexit 1"),
            Choose::Program,
        );
        assert_eq!(e.unwrap_err(), "No file dialog: none");
        // Every dialog has a name its process knows.
        for c in ALL {
            assert_eq!(ALL.iter().filter(|o| name(**o) == name(c)).count(), 1);
        }
        assert_eq!(main(&["nothing".into()]), 2);
    }
}
