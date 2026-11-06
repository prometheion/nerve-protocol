//! What the app needs of the desktop, and what it says when that is missing
//! (docs/dev/desktop.md, "What the app needs"): a display, a renderer that
//! draws on it, polkit's `pkexec` with an authentication agent that asks the
//! owner, and a desktop portal whose file chooser opens files and folders.
//! GNOME and KDE Plasma bring all of it; another desktop may not. Each check
//! takes what it looks at as arguments, so the tests can leave each part out.

use std::path::{Path, PathBuf};

/// The variable that chooses Slint's backend and renderer.
pub const BACKEND_VAR: &str = "SLINT_BACKEND";
/// Slint's winit backend drawing in software, without OpenGL.
pub const SOFTWARE: &str = "winit-software";

/// Why no window can open in this session, or `None` when one can:
/// neither Wayland nor X11 is there. `var` reads the session's variables,
/// `exists` whether a path is there.
pub fn no_display(
    var: impl Fn(&str) -> Option<String>,
    exists: impl Fn(&Path) -> bool,
) -> Option<String> {
    if cfg!(windows) {
        return None;
    }
    let set = |k: &str| var(k).filter(|v| !v.is_empty());
    // Wayland's socket: an absolute path, or a name in the runtime folder.
    let wayland = set("WAYLAND_SOCKET").is_some()
        || set("WAYLAND_DISPLAY").is_some_and(|name| {
            let p = Path::new(&name);
            if p.is_absolute() {
                exists(p)
            } else {
                set("XDG_RUNTIME_DIR").is_some_and(|dir| exists(&Path::new(&dir).join(p)))
            }
        });
    // An X11 display may be on another host, so its name alone counts.
    if wayland || set("DISPLAY").is_some() {
        return None;
    }
    Some(
        "no display: the app's window needs a desktop session, Wayland (WAYLAND_DISPLAY) or X11 (DISPLAY), and neither is there. Open Nerve from the desktop's application menu; in a terminal without a desktop, run its commands instead (nerve-node-desktop --help).".into(),
    )
}

/// [`no_display`] for this process.
pub fn no_display_here() -> Option<String> {
    no_display(|k| std::env::var(k).ok(), Path::exists)
}

/// What to do when the window did not open.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Next {
    /// Start again, drawing in software.
    Software,
    /// Say this and end.
    Fail(String),
}

/// After the window failed with `error`: the GPU renderer (OpenGL, EGL)
/// may be what is missing, so the app starts once more in software, unless
/// the renderer was chosen already (`chosen`, [`BACKEND_VAR`]).
pub fn after_window_error(error: &str, chosen: Option<&str>) -> Next {
    match chosen.filter(|c| !c.is_empty()) {
        None => Next::Software,
        Some(c) => Next::Fail(format!(
            "the window did not open ({error}), drawing with {BACKEND_VAR}={c}. If neither OpenGL nor software drawing works here, the display is not reachable or its graphics libraries are missing: install Mesa's libEGL and libGL (libegl1 and libgl1 on Debian and Ubuntu, mesa-libEGL on Fedora)."
        )),
    }
}

/// Runs this program again with the same arguments, drawing in software;
/// its exit code.
pub fn rerun_in_software() -> i32 {
    let Ok(exe) = std::env::current_exe() else {
        return 1;
    };
    std::process::Command::new(exe)
        .args(std::env::args_os().skip(1))
        .env(BACKEND_VAR, SOFTWARE)
        .status()
        .ok()
        .and_then(|s| s.code())
        .unwrap_or(1)
}

/// Shows `text` as a desktop notification where one can be shown; a
/// program started from the menu has no terminal to print to.
pub fn notify(title: &str, text: &str) {
    #[cfg(target_os = "linux")]
    let _ = std::process::Command::new("notify-send")
        .args(["--app-name=Nerve", "--icon=nerve-node-desktop", title, text])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();
    #[cfg(not(target_os = "linux"))]
    let _ = (title, text);
}

/// Whether pkexec can ask for root here: `pkexec` is the program found, if
/// any. Whether an authentication agent answers shows when pkexec runs
/// ([`pkexec_failed`]).
pub fn polkit(pkexec: Option<&Path>) -> Result<(), String> {
    if pkexec.is_none() {
        return Err("There is no pkexec on this machine, so the app cannot ask for administrator rights. Install polkit (the package polkit, or policykit-1 on older Debian and Ubuntu), then try again.".into());
    }
    Ok(())
}

/// What the app says when no polkit authentication agent answered pkexec.
pub fn no_agent() -> String {
    "No polkit authentication agent is running, so nobody can be asked for the administrator password. Install and start one for your desktop, for example polkit-gnome or polkit-kde-agent-1 (GNOME and KDE Plasma bring theirs), then try again.".into()
}

/// What pkexec says on stderr when no authentication agent answered, in
/// polkit 0.105 (Ubuntu 22.04) to 127 alike: its own words, and those of the
/// text agent it tries in a terminal instead unless told not to.
const NO_AGENT_SAID: [&str; 3] = [
    "No authentication agent found",
    "Error creating textual authentication agent",
    "Error registering local authentication agent",
];

/// Why pkexec did not start the program, from its exit code and what it
/// said on stderr, when that was a missing authentication agent: pkexec
/// exits with 127 then (as when the owner is not authorized; 126 when they
/// dismissed the question), so its words tell which.
pub fn pkexec_failed(code: Option<i32>, said: &str) -> Option<String> {
    (code == Some(127) && NO_AGENT_SAID.iter().any(|s| said.contains(s))).then(no_agent)
}

/// `program` in the folders of `path` (`PATH`, split as this system splits
/// it: `;` on Windows, where a drive letter is followed by `:`), or in
/// `/usr/bin`.
pub fn find_program(program: &str, path: Option<&std::ffi::OsStr>) -> Option<PathBuf> {
    path.map(std::env::split_paths)
        .into_iter()
        .flatten()
        .filter(|d| !d.as_os_str().is_empty())
        .chain([PathBuf::from("/usr/bin")])
        .map(|d| d.join(program))
        .find(|p| p.is_file())
}

/// pkexec on this machine, before the app asks ([`polkit`]).
#[cfg(unix)]
pub fn pkexec_here() -> Result<PathBuf, String> {
    let path = std::env::var_os("PATH");
    let pkexec = find_program("pkexec", path.as_deref());
    polkit(pkexec.as_deref())?;
    Ok(pkexec.unwrap_or_default())
}

/// The interface of the portal that opens the file dialogs.
const FILE_CHOOSER: &str = "org.freedesktop.portal.FileChooser";

/// Whether the desktop portal's file chooser answers on the session bus,
/// from what `busctl --user introspect org.freedesktop.portal.Desktop
/// /org/freedesktop/portal/desktop` did: `None` when busctl is not there
/// to ask (the dialog then tries), else whether it succeeded and what it
/// printed.
pub fn portal(asked: Option<(bool, &str)>) -> Result<(), String> {
    match asked {
        None => Ok(()),
        Some((true, out)) if out.contains(FILE_CHOOSER) => Ok(()),
        Some(_) => Err("No file dialog: the app opens files and folders through the desktop portal (org.freedesktop.portal.Desktop with a FileChooser), and none answers here. Install xdg-desktop-portal and the backend for your desktop: xdg-desktop-portal-gnome, -kde, -gtk or -wlr, then log out and in.".into()),
    }
}

/// [`portal`] on this session.
#[cfg(target_os = "linux")]
pub fn portal_here() -> Result<(), String> {
    let out = std::process::Command::new("busctl")
        .args([
            "--user",
            "--no-pager",
            "--timeout=5",
            "introspect",
            "org.freedesktop.portal.Desktop",
            "/org/freedesktop/portal/desktop",
        ])
        .stdin(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .output()
        .ok();
    let text = out
        .as_ref()
        .map(|o| String::from_utf8_lossy(&o.stdout).into_owned());
    portal(
        out.as_ref()
            .zip(text.as_deref())
            .map(|(o, t)| (o.status.success(), t)),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(not(windows))]
    #[test]
    fn no_display_is_said_and_either_display_will_do() {
        let vars = |set: &'static [(&'static str, &'static str)]| {
            move |k: &str| {
                set.iter()
                    .find(|(n, _)| *n == k)
                    .map(|(_, v)| v.to_string())
            }
        };
        let none = |_: &Path| false;
        let e = no_display(vars(&[]), none).unwrap();
        assert!(e.contains("Wayland") && e.contains("X11"), "{e}");
        // A Wayland name without its socket is no display.
        assert!(
            no_display(
                vars(&[
                    ("WAYLAND_DISPLAY", "wayland-0"),
                    ("XDG_RUNTIME_DIR", "/run/user/1000")
                ]),
                none
            )
            .is_some()
        );
        assert!(no_display(vars(&[("DISPLAY", "")]), none).is_some());
        let socket = |p: &Path| p == Path::new("/run/user/1000/wayland-0");
        assert_eq!(
            no_display(
                vars(&[
                    ("WAYLAND_DISPLAY", "wayland-0"),
                    ("XDG_RUNTIME_DIR", "/run/user/1000")
                ]),
                socket
            ),
            None
        );
        assert_eq!(no_display(vars(&[("DISPLAY", ":0")]), none), None);
    }

    #[test]
    fn a_window_that_fails_tries_software_once() {
        assert_eq!(after_window_error("no EGL", None), Next::Software);
        assert_eq!(after_window_error("no EGL", Some("")), Next::Software);
        let Next::Fail(e) = after_window_error("no EGL", Some(SOFTWARE)) else {
            panic!("software failed too");
        };
        assert!(e.contains("no EGL") && e.contains("libEGL"), "{e}");
        // A renderer the owner chose is not changed behind them.
        assert!(matches!(
            after_window_error("x", Some("winit-femtovg")),
            Next::Fail(_)
        ));
    }

    #[test]
    fn pkexec_needs_the_program_and_says_when_no_agent_answered() {
        assert_eq!(polkit(Some(Path::new("/usr/bin/pkexec"))), Ok(()));
        assert!(polkit(None).unwrap_err().contains("Install polkit"));

        // What pkexec of polkit 0.105 to 127 says, with its exit code.
        let none = "Error executing command as another user: No authentication agent found.\n";
        let no_tty = "Error creating textual authentication agent: Error opening current controlling terminal for the process (`/dev/tty'): No such device or address\n";
        for said in [none, no_tty] {
            let e = pkexec_failed(Some(127), said).unwrap();
            assert!(e.contains("No polkit authentication agent"), "{e}");
            assert!(
                e.contains("polkit-gnome") && e.contains("polkit-kde-agent"),
                "{e}"
            );
        }
        // Dismissed, refused, or ended otherwise: no rights, but an agent
        // asked.
        assert_eq!(
            pkexec_failed(
                Some(126),
                "Error executing command as another user: Request dismissed\n"
            ),
            None
        );
        assert_eq!(
            pkexec_failed(
                Some(127),
                "Error executing command as another user: Not authorized\n\nThis incident has been reported.\n"
            ),
            None
        );
        assert_eq!(pkexec_failed(None, none), None);

        let d = tempfile::tempdir().unwrap();
        std::fs::write(d.path().join("pkexec-test"), "").unwrap();
        let path = std::env::join_paths([Path::new("/nowhere"), d.path()]).unwrap();
        assert_eq!(
            find_program("pkexec-test", Some(&path)),
            Some(d.path().join("pkexec-test"))
        );
        assert_eq!(find_program("pkexec-test", Some("/nowhere".as_ref())), None);
    }

    #[test]
    fn the_file_dialogs_need_the_portals_file_chooser() {
        let found = "NAME TYPE SIGNATURE\norg.freedesktop.portal.FileChooser interface - - -\n.OpenFile method ssa{sv} o -\n";
        assert_eq!(portal(Some((true, found))), Ok(()));
        // Not there to ask: the dialog tries itself.
        assert_eq!(portal(None), Ok(()));
        for asked in [
            (false, ""),
            (true, "org.freedesktop.portal.Settings interface - - -\n"),
        ] {
            let e = portal(Some(asked)).unwrap_err();
            assert!(e.contains("xdg-desktop-portal-gnome"), "{e}");
        }
    }
}
