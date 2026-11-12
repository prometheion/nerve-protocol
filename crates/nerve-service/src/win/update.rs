//! `update` of a Windows service's program, the node's and the center's
//! alike: the new program (the latest release, checked against its
//! `SHA256SUMS`, or a file the owner gives) is staged beside the installed
//! one, asked its version and its services' settings, swapped in, and its
//! settings given to the services ([`crate::win::service::configure`]); one
//! that does not start goes back with the old settings. Linux's
//! [`crate::update`] does the same with the service's files.
//!
//! What it does to the machine goes through [`Installed`], so it runs on
//! every platform in the tests.

use std::path::{Path, PathBuf};

use crate::win::service::{Named, Settings, settings_from};
use crate::{Steps, Version, fetch_release, write_file};

/// What `update` asks of the machine: the service that runs the program,
/// and the program asked as a standard user would run it.
pub trait Installed {
    fn start(&self) -> Result<(), String>;
    /// Stops the service and waits until it has; a stopped one is fine.
    fn stop(&self) -> Result<(), String>;
    /// Waits until the program the service started runs.
    fn wait_running(&self) -> Result<(), String>;
    /// What `<program> --version` prints, run without the administrators'
    /// rights.
    fn version_of(&self, program: &Path) -> Result<String, String>;
    /// What `<program> service-files <args>` prints, run so too: its
    /// services' settings ([`crate::win::service::settings_text`]).
    fn settings_of(&self, program: &Path, args: &[String]) -> Result<String, String>;
    /// Gives the registered service `name` the settings `s`.
    fn configure(&self, name: &str, s: &Settings) -> Result<(), String>;
    /// Removes the program file ([`remove_program`]); `false` when Windows
    /// holds it, and it goes at the next restart.
    fn remove_program(&self, path: &Path) -> Result<bool, String>;
}

/// The installed program `update` replaces.
pub struct Program<'a> {
    /// Its name: the first word of its `--version`.
    pub name: &'a str,
    pub bin: &'a Path,
    /// Where the programs of the latest release and their `SHA256SUMS` are.
    pub release: &'a str,
    /// Its release file for this machine, or why there is none.
    pub asset: Result<String, String>,
    /// The service that runs it.
    pub service: &'a str,
    /// The services whose settings it names, the one that runs it among
    /// them.
    pub services: &'a [&'a str],
    /// What `service-files` is asked besides that word (the node's owner).
    pub settings_args: Vec<String>,
    /// What gives the services what an update cannot (a service or a
    /// setting this program does not know).
    pub install: &'a str,
}

/// The program's name without `.exe`.
fn stem(bin: &Path) -> String {
    bin.file_stem()
        .map_or_else(String::new, |s| s.to_string_lossy().into_owned())
}

/// Where `update` puts the new program before it replaces the old one.
pub fn staged(bin: &Path) -> PathBuf {
    bin.with_file_name(format!("{}.new.exe", stem(bin)))
}

/// Where the old program waits until the new one runs.
pub fn previous(bin: &Path) -> PathBuf {
    bin.with_file_name(format!("{}.old.exe", stem(bin)))
}

/// Deletes what an update or an uninstall left beside `bin` when it ran
/// from the program it replaced or removed, or moved aside because Windows
/// held it: [`staged`], [`previous`], and the names that start with
/// `aside` and end in `.del`.
pub fn clean_aside(bin: &Path, aside: &str) {
    let _ = std::fs::remove_file(previous(bin));
    let _ = std::fs::remove_file(staged(bin));
    if let Some(dir) = bin.parent()
        && let Ok(entries) = std::fs::read_dir(dir)
    {
        for e in entries.flatten() {
            let name = e.file_name();
            let name = name.to_string_lossy();
            if name.starts_with(aside) && name.ends_with(".del") {
                let _ = std::fs::remove_file(e.path());
            }
        }
    }
}

/// Removes the program `path`, and its folder when nothing else is in it;
/// `false` when Windows holds the program (this command started from it, or
/// the Event Log reads the text of its entries from it): a program that runs
/// cannot be deleted, but it can be renamed. It moves aside to a name that
/// starts with `aside`, so its own name is free for a later install, and
/// Windows deletes it at its next start, with the folder if that is empty by
/// then.
#[cfg(windows)]
pub fn remove_program(path: &Path, aside: &str) -> Result<bool, String> {
    use windows_sys::Win32::Foundation::ERROR_ACCESS_DENIED;
    let at = |e: std::io::Error| format!("{}: {e}", path.display());
    let dir = path.parent().unwrap_or(Path::new("."));
    match std::fs::remove_file(path) {
        Ok(()) => {
            let _ = std::fs::remove_dir(dir);
            Ok(true)
        }
        Err(e) if e.raw_os_error() == Some(ERROR_ACCESS_DENIED as i32) => {
            let moved = dir.join(format!(
                "{aside}{}.del",
                nerve_transport::keys::random_token(8)
            ));
            std::fs::rename(path, &moved).map_err(at)?;
            crate::win::service::delete_at_restart(&moved)?;
            let _ = crate::win::service::delete_at_restart(dir);
            Ok(false)
        }
        Err(e) => Err(at(e)),
    }
}

/// The settings `program` names for the services of `p`, and what it names
/// that this update cannot give.
fn settings_of(
    p: &Program<'_>,
    sys: &dyn Installed,
    program: &Path,
) -> Result<(Named, Vec<String>), String> {
    sys.settings_of(program, &p.settings_args)
        .and_then(|said| settings_from(&said, p.services))
}

/// Gives each service of `to` its settings where they differ from `from`'s
/// (or `from` is not known); the services it changed.
fn give(
    sys: &dyn Installed,
    to: &[(String, Settings)],
    from: Option<&[(String, Settings)]>,
) -> Result<Vec<String>, String> {
    let mut changed = Vec::new();
    for (name, s) in to {
        let was = from.and_then(|f| f.iter().find(|(n, _)| n == name).map(|(_, s)| s));
        if was == Some(s) {
            continue;
        }
        sys.configure(name, s)?;
        changed.push(name.clone());
    }
    Ok(changed)
}

/// Replaces the program `p` with the new one and restarts its service, with
/// the services' settings as the new program has them. A program that is
/// not `p.name`, is older than the installed one, or does not say its
/// settings is refused before anything changes; one that does not start is
/// replaced by the old one again, with the old one's settings. `Ok(false)`:
/// the installed program is that one already, and nothing changed.
pub async fn update(
    p: &Program<'_>,
    sys: &dyn Installed,
    from: Option<&Path>,
    steps: &mut Steps<'_>,
) -> Result<bool, String> {
    let program = p.name;
    let new = match from {
        Some(f) => {
            let b = std::fs::read(f).map_err(|e| format!("{}: {e}", f.display()))?;
            steps.did(format!("read the new program from {}", f.display()));
            b
        }
        None => {
            let asset = p.asset.clone()?;
            let b = fetch_release(p.release, &asset).await?;
            steps.did(format!(
                "downloaded {asset} from {} and checked it against its SHA256SUMS",
                p.release
            ));
            b
        }
    };
    let bin = p.bin;
    let old = std::fs::read(bin).map_err(|e| format!("{}: {e}", bin.display()))?;
    if new == old {
        steps.did("the installed program is that one already; nothing to update");
        return Ok(false);
    }
    let new_path = staged(bin);
    write_file(&new_path, &new, 0o755)?;
    let checked = (|| {
        let said = sys.version_of(&new_path)?;
        let new_v = Version::parse_of(program, &said)
            .ok_or_else(|| format!("the new program is not {program}: it says {said:?}"))?;
        let old_v = sys
            .version_of(bin)
            .ok()
            .and_then(|s| Version::parse_of(program, &s));
        if let Some(o) = old_v
            && new_v < o
        {
            return Err(format!(
                "the new program is {program} {new_v}, older than the installed {o}; nothing changed"
            ));
        }
        // The new program's own settings: it runs under what it was made
        // for, not under what the installed one registered.
        let want = settings_of(p, sys, &new_path)
            .map_err(|e| format!("the new program does not say its services' settings: {e}"))?;
        Ok((old_v, new_v, want))
    })();
    let (old_v, new_v, (want, unknown)) = match checked {
        Ok(v) => v,
        Err(e) => {
            let _ = std::fs::remove_file(&new_path);
            return Err(e);
        }
    };
    // What the old one goes back with when the new one does not start. One
    // that cannot say them leaves the new settings in place then.
    let had = settings_of(p, sys, bin).ok().map(|(s, _)| s);
    // A running program cannot be overwritten, but it can be renamed: the
    // old one moves aside, also when this command runs from it.
    if let Err(e) = sys.stop() {
        let _ = std::fs::remove_file(&new_path);
        return Err(e);
    }
    let old_path = previous(bin);
    let _ = std::fs::remove_file(&old_path);
    let swap = |from: &Path, to: &Path| {
        std::fs::rename(from, to)
            .map_err(|e| format!("{} to {}: {e}", from.display(), to.display()))
    };
    // When the new one cannot be put in place, the old one runs on.
    let moved = swap(bin, &old_path).and_then(|()| {
        swap(&new_path, bin).inspect_err(|_| {
            let _ = swap(&old_path, bin);
        })
    });
    if let Err(e) = moved {
        let _ = std::fs::remove_file(&new_path);
        let _ = sys.start();
        return Err(e);
    }
    let old_v = old_v.map_or_else(|| "?".to_string(), |v| v.to_string());
    steps.did(format!("replaced {program} {old_v} with {new_v}"));
    let mut changed = Vec::new();
    let started = give(sys, &want, had.as_deref())
        .inspect(|c| changed.clone_from(c))
        .and_then(|_| sys.start())
        .and_then(|()| sys.wait_running());
    if let Err(e) = started {
        let _ = sys.stop();
        let settings_back = || match &had {
            Some(had) => give(sys, had, Some(&want)).map(|_| ()),
            None => Ok(()),
        };
        let back = swap(bin, &new_path)
            .and_then(|()| swap(&old_path, bin))
            .and_then(|()| settings_back())
            .and_then(|()| sys.start())
            .and_then(|()| sys.wait_running());
        let _ = std::fs::remove_file(&new_path);
        steps.did(if changed.is_empty() || had.is_none() {
            format!("put {program} {old_v} back")
        } else {
            format!("put {program} {old_v} and its services' settings back")
        });
        return Err(match back {
            Ok(()) => format!("the new program did not start ({e}); the old one runs again"),
            Err(e2) => format!(
                "the new program did not start ({e}), and the old one does not either ({e2})"
            ),
        });
    }
    for name in &changed {
        steps.did(format!(
            "gave the service {name} the new program's settings: its privileges, who may control it, what follows a failure and what it needs first"
        ));
    }
    steps.did(format!("restarted the service {}", p.service));
    if !unknown.is_empty() {
        steps.did(format!(
            "Warning: the new program has settings this update cannot give ({}): {} gives them",
            unknown.join(", "),
            p.install
        ));
    }
    // This command may run from the old program; then it goes at the next
    // restart, or with the next update or install.
    let _ = sys.remove_program(&old_path);
    Ok(true)
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;

    use super::*;
    use crate::win::service::settings_text;

    /// A machine whose programs are text files: the first line is what the
    /// program says on `--version`, the second its settings, where it has a
    /// second; the service runs what was in the program's place at its
    /// start.
    struct Fake {
        bin: PathBuf,
        calls: RefCell<Vec<String>>,
        /// What the service started, by its version.
        started: RefCell<Vec<String>>,
        /// The settings each service has now.
        given: RefCell<Vec<(String, Settings)>>,
        /// The version that does not start.
        broken: Option<String>,
    }

    impl Fake {
        fn new(bin: &Path, broken: Option<&str>) -> Fake {
            Fake {
                bin: bin.to_path_buf(),
                calls: RefCell::new(Vec::new()),
                started: RefCell::new(Vec::new()),
                given: RefCell::new(Vec::new()),
                broken: broken.map(String::from),
            }
        }

        fn line(&self, program: &Path, n: usize) -> Result<String, String> {
            let text = std::fs::read_to_string(program).map_err(|e| e.to_string())?;
            text.lines()
                .nth(n)
                .map(String::from)
                .ok_or_else(|| "it said nothing".to_string())
        }
    }

    impl Installed for Fake {
        fn start(&self) -> Result<(), String> {
            self.calls.borrow_mut().push("start".into());
            let runs = self.version_of(&self.bin)?;
            self.started.borrow_mut().push(runs);
            Ok(())
        }
        fn stop(&self) -> Result<(), String> {
            self.calls.borrow_mut().push("stop".into());
            Ok(())
        }
        fn wait_running(&self) -> Result<(), String> {
            let runs = self.started.borrow().last().cloned();
            if runs.is_some() && runs != self.broken {
                Ok(())
            } else {
                Err("the service stopped at its start".into())
            }
        }
        fn version_of(&self, program: &Path) -> Result<String, String> {
            self.line(program, 0)
        }
        fn settings_of(&self, program: &Path, args: &[String]) -> Result<String, String> {
            assert_eq!(args, ["--owner", "S-1-5-21-1-2-3-1001"]);
            self.line(program, 1)
        }
        fn configure(&self, name: &str, s: &Settings) -> Result<(), String> {
            self.calls
                .borrow_mut()
                .push(format!("configure {name} {}", s.privileges.join(",")));
            let mut given = self.given.borrow_mut();
            given.retain(|(n, _)| n != name);
            given.push((name.to_string(), s.clone()));
            Ok(())
        }
        fn remove_program(&self, path: &Path) -> Result<bool, String> {
            std::fs::remove_file(path).map_err(|e| e.to_string())?;
            Ok(true)
        }
    }

    fn program(bin: &Path) -> Program<'_> {
        Program {
            name: "nerve-node",
            bin,
            release: "https://example.invalid",
            asset: Err("no release here".into()),
            service: "nerve-node",
            services: &["nerve-node", "nerve-run-profile"],
            settings_args: vec!["--owner".into(), "S-1-5-21-1-2-3-1001".into()],
            install: "the installer",
        }
    }

    /// A program file of `version` that names `privileges` for the node's
    /// service, and its profile service's settings.
    fn file(version: &str, privileges: &[&str]) -> String {
        let settings = settings_text(&[
            (
                "nerve-node",
                Settings::new(privileges, &["nerve-run-profile"], None),
            ),
            (
                "nerve-run-profile",
                Settings::new(&["SeChangeNotifyPrivilege"], &[], None),
            ),
        ]);
        format!("nerve-node {version}\n{settings}\n")
    }

    fn given(sys: &Fake, name: &str) -> Option<Vec<String>> {
        sys.given
            .borrow()
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, s)| s.privileges.clone())
    }

    /// A new program that names other privileges for its service gets them
    /// before it starts; the service it names the same for is left alone
    /// (node-5).
    #[tokio::test]
    async fn the_new_program_s_settings_come_with_it() {
        let d = tempfile::tempdir().unwrap();
        let bin = d.path().join("nerve-node.exe");
        std::fs::write(&bin, file("1.0.0", &["SeChangeNotifyPrivilege"])).unwrap();
        let new = d.path().join("new.exe");
        let wanted = ["SeChangeNotifyPrivilege", "SeIncreaseQuotaPrivilege"];
        std::fs::write(&new, file("1.1.0", &wanted)).unwrap();
        let sys = Fake::new(&bin, None);
        let mut out = Vec::new();
        let changed = update(&program(&bin), &sys, Some(&new), &mut Steps::new(&mut out))
            .await
            .unwrap();
        assert!(changed);
        assert_eq!(
            *sys.calls.borrow(),
            [
                "stop",
                "configure nerve-node SeChangeNotifyPrivilege,SeIncreaseQuotaPrivilege",
                "start"
            ]
        );
        assert_eq!(given(&sys, "nerve-node").unwrap(), wanted);
        let out = String::from_utf8(out).unwrap();
        assert!(
            out.contains("gave the service nerve-node the new program's settings"),
            "{out}"
        );
        assert!(!out.contains("nerve-run-profile the new"), "{out}");
        assert!(!staged(&bin).exists() && !previous(&bin).exists());
    }

    /// A new program that does not start goes back with the old program's
    /// settings; the old one runs again under them.
    #[tokio::test]
    async fn the_old_settings_go_back_with_the_old_program() {
        let d = tempfile::tempdir().unwrap();
        let bin = d.path().join("nerve-node.exe");
        let before = file("1.0.0", &["SeChangeNotifyPrivilege"]);
        std::fs::write(&bin, &before).unwrap();
        let new = d.path().join("new.exe");
        std::fs::write(&new, file("1.1.0", &["SeDebugPrivilege"])).unwrap();
        let sys = Fake::new(&bin, Some("nerve-node 1.1.0"));
        let mut out = Vec::new();
        let e = update(&program(&bin), &sys, Some(&new), &mut Steps::new(&mut out))
            .await
            .unwrap_err();
        assert!(e.contains("the old one runs again"), "{e}");
        assert_eq!(
            *sys.calls.borrow(),
            [
                "stop",
                "configure nerve-node SeDebugPrivilege",
                "start",
                "stop",
                "configure nerve-node SeChangeNotifyPrivilege",
                "start"
            ]
        );
        assert_eq!(
            given(&sys, "nerve-node").unwrap(),
            ["SeChangeNotifyPrivilege"]
        );
        assert_eq!(std::fs::read_to_string(&bin).unwrap(), before);
        let out = String::from_utf8(out).unwrap();
        assert!(
            out.contains("put nerve-node 1.0.0 and its services' settings back"),
            "{out}"
        );
        assert!(!staged(&bin).exists() && !previous(&bin).exists());
    }

    /// A program that does not say its settings is refused before anything
    /// changes; what a later program names that this one does not know is
    /// said.
    #[tokio::test]
    async fn settings_the_update_cannot_give_are_said() {
        let d = tempfile::tempdir().unwrap();
        let bin = d.path().join("nerve-node.exe");
        let before = file("1.0.0", &["SeChangeNotifyPrivilege"]);
        std::fs::write(&bin, &before).unwrap();
        let new = d.path().join("new.exe");
        std::fs::write(&new, "nerve-node 1.1.0\n").unwrap();
        let sys = Fake::new(&bin, None);
        let e = update(
            &program(&bin),
            &sys,
            Some(&new),
            &mut Steps::new(&mut Vec::new()),
        )
        .await
        .unwrap_err();
        assert!(e.contains("does not say its services' settings"), "{e}");
        assert!(sys.calls.borrow().is_empty());
        assert_eq!(std::fs::read_to_string(&bin).unwrap(), before);
        assert!(!staged(&bin).exists());

        let mut later: serde_json::Value = serde_json::from_str(
            file("1.1.0", &["SeChangeNotifyPrivilege"])
                .lines()
                .nth(1)
                .unwrap(),
        )
        .unwrap();
        later["nerve-helper"] = later["nerve-run-profile"].clone();
        std::fs::write(&new, format!("nerve-node 1.1.0\n{later}\n")).unwrap();
        let mut out = Vec::new();
        update(&program(&bin), &sys, Some(&new), &mut Steps::new(&mut out))
            .await
            .unwrap();
        let out = String::from_utf8(out).unwrap();
        assert!(
            out.contains("cannot give (nerve-helper): the installer gives them"),
            "{out}"
        );
        // The same settings: no service changed.
        assert_eq!(*sys.calls.borrow(), ["stop", "start"]);
    }

    #[test]
    fn what_an_update_leaves_goes_at_the_next_install() {
        let d = tempfile::tempdir().unwrap();
        let bin = d.path().join("nerve-node-desktop.exe");
        assert_eq!(
            staged(&bin).file_name().unwrap(),
            "nerve-node-desktop.new.exe"
        );
        assert_eq!(
            previous(&bin).file_name().unwrap(),
            "nerve-node-desktop.old.exe"
        );
        for f in [
            staged(&bin),
            previous(&bin),
            d.path().join("nerve-node.abc.del"),
            d.path().join("nerve-node.keep"),
        ] {
            std::fs::write(f, "x").unwrap();
        }
        clean_aside(&bin, "nerve-node.");
        let mut left: Vec<String> = std::fs::read_dir(d.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        left.sort();
        assert_eq!(left, ["nerve-node.keep"]);
    }
}
