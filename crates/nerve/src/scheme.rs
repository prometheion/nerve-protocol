//! Whether the desktop is dark, for the app's "System" appearance. Slint's
//! own reading of it missed the dark mode of GNOME on Zorin OS, so on Linux
//! the app asks as the desktops themselves keep it: the desktop portal's
//! `color-scheme` first (GNOME, KDE and others answer it), then GNOME's
//! `color-scheme` setting, then the name of the GTK theme (`…-dark`), and
//! on KDE its colour scheme in `kdeglobals`. On Windows Slint reads the
//! system's choice itself.

use std::path::PathBuf;
use std::time::{Duration, Instant};

/// How long one question to the desktop may take: the portal may be
/// started for it.
const WAIT: Duration = Duration::from_secs(2);

/// Whether the desktop here is dark; none when it does not say, and the
/// app then leaves it to Slint.
pub fn dark_here() -> Option<bool> {
    if cfg!(windows) {
        return None;
    }
    let desktop = std::env::var("XDG_CURRENT_DESKTOP").unwrap_or_default();
    let kdeglobals = kdeglobals().and_then(|p| std::fs::read_to_string(p).ok());
    detect(&ask, kdeglobals.as_deref(), &desktop)
}

/// The output of `program args`, if it ran well within [`WAIT`].
pub(crate) fn ask(program: &str, args: &[&str]) -> Option<String> {
    let mut child = std::process::Command::new(program)
        .args(args)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .ok()?;
    let until = Instant::now() + WAIT;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                let mut out = String::new();
                use std::io::Read;
                child.stdout.take()?.read_to_string(&mut out).ok()?;
                return status.success().then_some(out);
            }
            Ok(None) if Instant::now() < until => std::thread::sleep(Duration::from_millis(20)),
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return None;
            }
        }
    }
}

/// KDE's settings file of this user.
pub(crate) fn kdeglobals() -> Option<PathBuf> {
    let base = std::env::var_os("XDG_CONFIG_HOME")
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
        .or_else(|| Some(PathBuf::from(std::env::var_os("HOME")?).join(".config")))?;
    Some(base.join("kdeglobals"))
}

/// The decision, with `ask` running a program and `kdeglobals` the text of
/// KDE's settings file, for tests.
pub fn detect(
    ask: &dyn Fn(&str, &[&str]) -> Option<String>,
    kdeglobals: Option<&str>,
    desktop: &str,
) -> Option<bool> {
    if let Some(dark) = portal(ask) {
        return Some(dark);
    }
    let kde = desktop.split(':').any(|d| d.eq_ignore_ascii_case("KDE"));
    if kde && let Some(dark) = kdeglobals.and_then(kde_scheme) {
        return Some(dark);
    }
    if let Some(dark) = gnome(ask) {
        return Some(dark);
    }
    kdeglobals.and_then(kde_scheme)
}

/// The portal's `org.freedesktop.appearance color-scheme`: 1 dark, 2 light,
/// 0 no preference (none here).
fn portal(ask: &dyn Fn(&str, &[&str]) -> Option<String>) -> Option<bool> {
    match portal_number(ask, "org.freedesktop.appearance", "color-scheme") {
        Some(1) => Some(true),
        Some(2) => Some(false),
        _ => None,
    }
}

/// The number the desktop portal keeps as `key` of `namespace`, none when it
/// does not answer. `ReadOne` is the newer method, `Read` the one of older
/// portals (Ubuntu 22.04); `busctl`, or `gdbus` without it.
pub(crate) fn portal_number(
    ask: &dyn Fn(&str, &[&str]) -> Option<String>,
    namespace: &str,
    key: &str,
) -> Option<u32> {
    let dest = "org.freedesktop.portal.Desktop";
    let path = "/org/freedesktop/portal/desktop";
    let iface = "org.freedesktop.portal.Settings";
    for method in ["ReadOne", "Read"] {
        let busctl = ask(
            "busctl",
            &[
                "--user", "call", dest, path, iface, method, "ss", namespace, key,
            ],
        );
        let gdbus = || {
            let m = format!("{iface}.{method}");
            ask(
                "gdbus",
                &[
                    "call",
                    "--session",
                    "--dest",
                    dest,
                    "--object-path",
                    path,
                    "--method",
                    &m,
                    namespace,
                    key,
                ],
            )
        };
        if let Some(out) = busctl.or_else(gdbus) {
            return last_number(&out);
        }
    }
    None
}

/// The last number in `out`: the value in `v u 1`, `v v u 1` or
/// `(<<uint32 1>>,)`.
fn last_number(out: &str) -> Option<u32> {
    out.rsplit(|c: char| !c.is_ascii_digit())
        .find(|w| !w.is_empty())?
        .parse()
        .ok()
}

/// GNOME's `color-scheme`, then its GTK theme: a theme named `…-dark` (as
/// Zorin's are, which leave `color-scheme` at `default`) is dark.
fn gnome(ask: &dyn Fn(&str, &[&str]) -> Option<String>) -> Option<bool> {
    let get = |key: &str| {
        ask("gsettings", &["get", "org.gnome.desktop.interface", key])
            .map(|v| v.trim().trim_matches('\'').to_ascii_lowercase())
    };
    match get("color-scheme").as_deref() {
        Some("prefer-dark") => return Some(true),
        Some("prefer-light") => return Some(false),
        _ => {}
    }
    let theme = get("gtk-theme")?;
    if theme.is_empty() {
        return None;
    }
    Some(theme.contains("dark"))
}

/// KDE's colour scheme: by the background of its windows, or by its name.
fn kde_scheme(text: &str) -> Option<bool> {
    let mut section = "";
    let mut name = None;
    let mut background = None;
    for line in text.lines().map(str::trim) {
        if line.starts_with('[') {
            section = line;
            continue;
        }
        let Some((k, v)) = line.split_once('=') else {
            continue;
        };
        match (section, k.trim()) {
            ("[General]", "ColorScheme") => name = Some(v.trim().to_ascii_lowercase()),
            ("[Colors:Window]", "BackgroundNormal") => {
                let rgb: Vec<f64> = v.split(',').filter_map(|c| c.trim().parse().ok()).collect();
                if let [r, g, b, ..] = rgb[..] {
                    background = Some(0.2126 * r + 0.7152 * g + 0.0722 * b < 128.0);
                }
            }
            _ => {}
        }
    }
    background.or_else(|| name.map(|n| n.contains("dark")))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A desktop that answers `answers` (program and first words, output).
    fn desktop(
        answers: &'static [(&'static str, &'static str)],
    ) -> impl Fn(&str, &[&str]) -> Option<String> {
        move |program: &str, args: &[&str]| {
            let line = format!("{program} {}", args.join(" "));
            answers
                .iter()
                .find(|(asked, _)| line.contains(asked))
                .map(|(_, out)| out.to_string())
        }
    }

    #[test]
    fn the_portal_answers_first() {
        let dark = desktop(&[(
            "busctl --user call org.freedesktop.portal.Desktop /org/freedesktop/portal/desktop org.freedesktop.portal.Settings ReadOne",
            "v u 1\n",
        )]);
        assert_eq!(detect(&dark, None, "GNOME"), Some(true));
        let light = desktop(&[("ReadOne", "v u 2\n"), ("gsettings", "'prefer-dark'\n")]);
        assert_eq!(detect(&light, None, "GNOME"), Some(false));
        // An older portal knows only Read; gdbus where busctl is missing.
        let old = desktop(&[(
            "busctl --user call org.freedesktop.portal.Desktop /org/freedesktop/portal/desktop org.freedesktop.portal.Settings Read ss",
            "v v u 1\n",
        )]);
        assert_eq!(detect(&old, None, "GNOME"), Some(true));
        let gdbus = desktop(&[(
            "gdbus call --session --dest org.freedesktop.portal.Desktop --object-path /org/freedesktop/portal/desktop --method org.freedesktop.portal.Settings.ReadOne",
            "(<<uint32 1>>,)\n",
        )]);
        assert_eq!(detect(&gdbus, None, "GNOME"), Some(true));
    }

    /// Zorin OS: the portal has no preference and `color-scheme` is
    /// `default`, but the GTK theme is a dark one.
    #[test]
    fn gnome_falls_back_to_its_setting_and_its_theme() {
        let zorin = desktop(&[
            ("ReadOne", "v u 0\n"),
            ("color-scheme", "'default'\n"),
            ("gtk-theme", "'ZorinBlue-Dark'\n"),
        ]);
        assert_eq!(detect(&zorin, None, "zorin:GNOME"), Some(true));
        let no_portal = desktop(&[("color-scheme", "'prefer-dark'\n")]);
        assert_eq!(detect(&no_portal, None, "GNOME"), Some(true));
        let light = desktop(&[("color-scheme", "'default'\n"), ("gtk-theme", "'Yaru'\n")]);
        assert_eq!(detect(&light, None, "ubuntu:GNOME"), Some(false));
        assert_eq!(detect(&desktop(&[]), None, "GNOME"), None);
    }

    #[test]
    fn kde_says_it_in_its_colour_scheme() {
        let none = desktop(&[]);
        let breeze_dark =
            "[General]\nColorScheme=BreezeDark\n\n[Colors:Window]\nBackgroundNormal=32,35,38\n";
        assert_eq!(detect(&none, Some(breeze_dark), "KDE"), Some(true));
        let light =
            "[General]\nColorScheme=BreezeLight\n[Colors:Window]\nBackgroundNormal=239,240,241\n";
        assert_eq!(detect(&none, Some(light), "KDE"), Some(false));
        // A scheme of another name: its windows' colour decides.
        let custom = "[Colors:Window]\nBackgroundNormal=20,20,20\n[General]\nColorScheme=Nordic\n";
        assert_eq!(detect(&none, Some(custom), "KDE"), Some(true));
        assert_eq!(
            detect(&none, Some("[General]\nColorScheme=SomethingDark\n"), "KDE"),
            Some(true)
        );
        // The portal, when it answers, comes first.
        let portal = desktop(&[("ReadOne", "v u 2\n")]);
        assert_eq!(detect(&portal, Some(breeze_dark), "KDE"), Some(false));
    }

    #[cfg(unix)]
    #[test]
    fn a_program_that_hangs_gives_no_answer() {
        let start = Instant::now();
        assert_eq!(ask("sleep", &["30"]), None);
        assert!(start.elapsed() < Duration::from_secs(10));
        assert_eq!(ask("sh", &["-c", "echo v u 1"]).as_deref(), Some("v u 1\n"));
        assert_eq!(ask("nerve-no-such-program", &[]), None);
    }
}
