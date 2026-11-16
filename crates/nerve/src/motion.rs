//! Whether the desktop asks for less motion, for the app's animations
//! (`Motion` in ui/theme.slint). On Linux the app asks as it asks for the
//! light or dark (crate::scheme): the desktop portal's `reduced-motion`
//! first, then on KDE its animation speed in `kdeglobals`
//! (`AnimationDurationFactor`, 0 when Plasma's animations are off), then
//! GNOME's `enable-animations`, then GTK's own setting in its
//! `settings.ini`, and KDE's speed on other desktops last. On Windows it is
//! the system's "Animation effects" (`SPI_GETCLIENTAREAANIMATION`).

#[cfg(not(windows))]
use std::path::PathBuf;

/// Whether the desktop here asks for less motion; none when it does not
/// say, and the app then moves.
pub fn reduced_here() -> Option<bool> {
    #[cfg(windows)]
    {
        windows()
    }
    #[cfg(not(windows))]
    {
        let desktop = std::env::var("XDG_CURRENT_DESKTOP").unwrap_or_default();
        let kdeglobals = crate::scheme::kdeglobals().and_then(|p| std::fs::read_to_string(p).ok());
        let gtk = gtk_settings()
            .into_iter()
            .find_map(|p| std::fs::read_to_string(p).ok());
        detect(
            &crate::scheme::ask,
            kdeglobals.as_deref(),
            gtk.as_deref(),
            &desktop,
        )
    }
}

/// The system's "Animation effects" (Settings, Accessibility, Visual
/// effects), which Windows' own windows follow.
#[cfg(windows)]
fn windows() -> Option<bool> {
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        SPI_GETCLIENTAREAANIMATION, SystemParametersInfoW,
    };
    let mut on: windows_sys::core::BOOL = 0;
    // SAFETY: the action writes one BOOL to the pointer it gets.
    let answered =
        unsafe { SystemParametersInfoW(SPI_GETCLIENTAREAANIMATION, 0, (&raw mut on).cast(), 0) };
    windows_said(answered != 0, on != 0)
}

/// What Windows' answer means: less motion when its animations are off,
/// none when it did not answer.
pub fn windows_said(answered: bool, animations: bool) -> Option<bool> {
    answered.then_some(!animations)
}

/// GTK's settings files of this user, the newer GTK's first.
#[cfg(not(windows))]
fn gtk_settings() -> Vec<PathBuf> {
    let base = std::env::var_os("XDG_CONFIG_HOME")
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
        .or_else(|| Some(PathBuf::from(std::env::var_os("HOME")?).join(".config")));
    base.map(|b| {
        ["gtk-4.0", "gtk-3.0"]
            .iter()
            .map(|v| b.join(v).join("settings.ini"))
            .collect()
    })
    .unwrap_or_default()
}

/// The decision, with `ask` running a program, `kdeglobals` the text of
/// KDE's settings file and `gtk` that of GTK's, for tests.
pub fn detect(
    ask: &dyn Fn(&str, &[&str]) -> Option<String>,
    kdeglobals: Option<&str>,
    gtk: Option<&str>,
    desktop: &str,
) -> Option<bool> {
    // 1 asks for less motion; 0 is no preference, which the desktop's own
    // setting below may still say.
    if crate::scheme::portal_number(ask, "org.freedesktop.appearance", "reduced-motion") == Some(1)
    {
        return Some(true);
    }
    let kde = desktop.split(':').any(|d| d.eq_ignore_ascii_case("KDE"));
    if kde && let Some(reduced) = kdeglobals.and_then(kde_speed) {
        return Some(reduced);
    }
    if let Some(reduced) = gnome(ask) {
        return Some(reduced);
    }
    if let Some(reduced) = gtk.and_then(gtk_setting) {
        return Some(reduced);
    }
    kdeglobals.and_then(kde_speed)
}

/// GNOME's `enable-animations`, which its "Reduce Animation" in the
/// accessibility settings turns off.
fn gnome(ask: &dyn Fn(&str, &[&str]) -> Option<String>) -> Option<bool> {
    let out = ask(
        "gsettings",
        &["get", "org.gnome.desktop.interface", "enable-animations"],
    )?;
    match out.trim() {
        "false" => Some(true),
        "true" => Some(false),
        _ => None,
    }
}

/// `gtk-enable-animations` in GTK's `settings.ini`.
fn gtk_setting(text: &str) -> Option<bool> {
    let value = setting(text, "[Settings]", "gtk-enable-animations")?;
    match value.to_ascii_lowercase().as_str() {
        "0" | "false" => Some(true),
        "1" | "true" => Some(false),
        _ => None,
    }
}

/// KDE's animation speed: 0 is Plasma's "Instant", its animations off.
fn kde_speed(text: &str) -> Option<bool> {
    let factor: f64 = setting(text, "[KDE]", "AnimationDurationFactor")?
        .parse()
        .ok()?;
    Some(factor <= 0.0)
}

/// The value of `key` in `section` of an ini file.
fn setting<'a>(text: &'a str, section: &str, key: &str) -> Option<&'a str> {
    let mut here = false;
    for line in text.lines().map(str::trim) {
        if line.starts_with('[') {
            here = line == section;
            continue;
        }
        if here
            && let Some((k, v)) = line.split_once('=')
            && k.trim() == key
        {
            return Some(v.trim());
        }
    }
    None
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

    const OFF: &str = "[KDE]\nAnimationDurationFactor=0\n";

    #[test]
    fn the_portal_answers_first() {
        let reduced = desktop(&[(
            "busctl --user call org.freedesktop.portal.Desktop /org/freedesktop/portal/desktop org.freedesktop.portal.Settings ReadOne ss org.freedesktop.appearance reduced-motion",
            "v u 1\n",
        )]);
        assert_eq!(detect(&reduced, None, None, "GNOME"), Some(true));
        // An older portal knows only Read; gdbus where busctl is missing.
        let old = desktop(&[(
            "busctl --user call org.freedesktop.portal.Desktop /org/freedesktop/portal/desktop org.freedesktop.portal.Settings Read ss org.freedesktop.appearance reduced-motion",
            "v v u 1\n",
        )]);
        assert_eq!(detect(&old, None, None, "GNOME"), Some(true));
        let gdbus = desktop(&[(
            "gdbus call --session --dest org.freedesktop.portal.Desktop --object-path /org/freedesktop/portal/desktop --method org.freedesktop.portal.Settings.ReadOne org.freedesktop.appearance reduced-motion",
            "(<<uint32 1>>,)\n",
        )]);
        assert_eq!(detect(&gdbus, None, None, "GNOME"), Some(true));
        // It comes before KDE's own speed.
        assert_eq!(detect(&reduced, None, None, "KDE"), Some(true));
        let kde = "[KDE]\nAnimationDurationFactor=1\n";
        assert_eq!(detect(&reduced, Some(kde), None, "KDE"), Some(true));
    }

    /// No preference from the portal: the desktop's own setting decides.
    #[test]
    fn no_preference_of_the_portal_asks_the_desktop() {
        let gnome_off = desktop(&[
            ("reduced-motion", "v u 0\n"),
            ("enable-animations", "false\n"),
        ]);
        assert_eq!(detect(&gnome_off, None, None, "GNOME"), Some(true));
        let gnome_on = desktop(&[
            ("reduced-motion", "v u 0\n"),
            ("enable-animations", "true\n"),
        ]);
        assert_eq!(detect(&gnome_on, None, None, "GNOME"), Some(false));
    }

    #[test]
    fn gnome_says_it_in_enable_animations() {
        let off = desktop(&[(
            "gsettings get org.gnome.desktop.interface enable-animations",
            "false\n",
        )]);
        assert_eq!(detect(&off, None, None, "ubuntu:GNOME"), Some(true));
        let on = desktop(&[("enable-animations", "true\n")]);
        assert_eq!(detect(&on, None, None, "zorin:GNOME"), Some(false));
        assert_eq!(detect(&desktop(&[]), None, None, "GNOME"), None);
        assert_eq!(
            detect(
                &desktop(&[("enable-animations", "\n")]),
                None,
                None,
                "GNOME"
            ),
            None
        );
    }

    #[test]
    fn kde_says_it_in_its_animation_speed() {
        let none = desktop(&[]);
        assert_eq!(detect(&none, Some(OFF), None, "KDE"), Some(true));
        let slow = "[General]\nColorScheme=BreezeDark\n[KDE]\nAnimationDurationFactor=0.25\n";
        assert_eq!(detect(&none, Some(slow), None, "KDE"), Some(false));
        // On KDE its own speed comes before gsettings, whose default says
        // that animations are on.
        let gsettings = desktop(&[("enable-animations", "true\n")]);
        assert_eq!(detect(&gsettings, Some(OFF), None, "KDE"), Some(true));
        // Elsewhere gsettings comes first, and KDE's speed last.
        assert_eq!(detect(&gsettings, Some(OFF), None, "GNOME"), Some(false));
        assert_eq!(detect(&none, Some(OFF), None, "XFCE"), Some(true));
        // The key only counts in its section, and the default is to move.
        let elsewhere = "[General]\nAnimationDurationFactor=0\n";
        assert_eq!(detect(&none, Some(elsewhere), None, "KDE"), None);
        assert_eq!(detect(&none, Some("[KDE]\n"), None, "KDE"), None);
    }

    #[test]
    fn gtk_says_it_in_its_settings_file() {
        let none = desktop(&[]);
        let off = "[Settings]\ngtk-theme-name=Adwaita\ngtk-enable-animations=0\n";
        assert_eq!(detect(&none, None, Some(off), "XFCE"), Some(true));
        let on = "[Settings]\ngtk-enable-animations = true\n";
        assert_eq!(detect(&none, None, Some(on), "XFCE"), Some(false));
        assert_eq!(
            detect(
                &none,
                None,
                Some("[Settings]\ngtk-enable-animations=false\n"),
                ""
            ),
            Some(true)
        );
        // GTK's file comes after gsettings, before KDE's speed off KDE.
        let gsettings = desktop(&[("enable-animations", "true\n")]);
        assert_eq!(detect(&gsettings, None, Some(off), "GNOME"), Some(false));
        let kde_on = "[KDE]\nAnimationDurationFactor=1\n";
        assert_eq!(detect(&none, Some(kde_on), Some(off), "XFCE"), Some(true));
    }

    #[test]
    fn windows_says_it_in_its_animation_effects() {
        assert_eq!(windows_said(true, false), Some(true));
        assert_eq!(windows_said(true, true), Some(false));
        assert_eq!(windows_said(false, false), None);
    }

    /// The call itself answers on Windows.
    #[cfg(windows)]
    #[test]
    fn windows_answers() {
        assert!(windows().is_some());
    }
}
