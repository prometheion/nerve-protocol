//! The app's own settings, kept for each user apart from the node's: the
//! appearance the owner chose (system, light or dark), whether Update
//! takes the pre-releases too, whether the center's log-in is kept in
//! the user's keyring (crate::hub::keep), and the shares of the panes the
//! owner dragged on each page. A small JSON file in
//! the user's config folder, `nerve-app/settings.json` (not `nerve`, which is
//! the node's); the node's
//! settings stay the node's (`nerve-node config`).

use std::path::{Path, PathBuf};

use serde_json::{Value, json};

const WORDS: [&str; 3] = ["system", "light", "dark"];

/// Where this user's settings of the app are: `$XDG_CONFIG_HOME` or
/// `~/.config` on Linux, `%APPDATA%` on Windows.
pub fn file() -> Option<PathBuf> {
    let var = |k: &str| {
        std::env::var_os(k)
            .filter(|v| !v.is_empty())
            .map(PathBuf::from)
    };
    let base = if cfg!(windows) {
        var("APPDATA")?
    } else {
        var("XDG_CONFIG_HOME").or_else(|| Some(var("HOME")?.join(".config")))?
    };
    Some(base.join("nerve-app").join("settings.json"))
}

/// The appearance saved in `path`: 0 follows the system, 1 light, 2 dark.
/// A file that is not there, or not readable, follows the system.
pub fn appearance(path: &Path) -> i32 {
    let v: Value = std::fs::read(path)
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_default();
    WORDS
        .iter()
        .position(|w| v["appearance"] == *w)
        .unwrap_or_default() as i32
}

/// Saves `appearance` in `path`, the rest of the file as it was.
pub fn save_appearance(path: &Path, appearance: i32) -> Result<(), String> {
    let word = WORDS.get(appearance as usize).copied().unwrap_or("system");
    change(path, |v| v["appearance"] = json!(word))
}

/// Whether Update takes the pre-releases too, as saved in `path`: off
/// unless the owner turned it on.
pub fn pre_releases(path: &Path) -> bool {
    read(path).is_some_and(|v| v["pre_releases"] == true)
}

/// Saves whether Update takes the pre-releases in `path`, the rest of the
/// file as it was.
pub fn save_pre_releases(path: &Path, on: bool) -> Result<(), String> {
    change(path, |v| v["pre_releases"] = json!(on))
}

/// Whether the center's log-in is kept in the user's keyring, as saved in
/// `path`: off unless the owner turned it on (owner decision on #232).
pub fn keep_login(path: &Path) -> bool {
    read(path).is_some_and(|v| v["keep_center_login"] == true)
}

/// Saves whether the center's log-in is kept in the keyring, the rest of
/// the file as it was.
pub fn save_keep_login(path: &Path, on: bool) -> Result<(), String> {
    change(path, |v| v["keep_center_login"] = json!(on))
}

/// The shares of a page's panes the owner dragged, as saved in `path`
/// under the page's `key`: the list's share of the list and the details,
/// and the side pane's of the whole; `None` for one not dragged, which
/// takes the page's default.
pub fn pane_shares(path: &Path, key: &str) -> (Option<f32>, Option<f32>) {
    let v = read(path).unwrap_or_default();
    let share = |which: &str| {
        v["panes"][key][which]
            .as_f64()
            .map(|f| f as f32)
            .filter(|f| (0.0..=1.0).contains(f))
    };
    (share("list"), share("side"))
}

/// Saves a page's shares in `path` (`None` forgets one: the page's default
/// again), the rest of the file as it was.
pub fn save_pane_shares(
    path: &Path,
    key: &str,
    list: Option<f32>,
    side: Option<f32>,
) -> Result<(), String> {
    change(path, |v| {
        if !v["panes"].is_object() {
            v["panes"] = json!({});
        }
        match (list, side) {
            (None, None) => {
                if let Some(panes) = v["panes"].as_object_mut() {
                    panes.remove(key);
                }
            }
            _ => v["panes"][key] = json!({"list": list, "side": side}),
        }
    })
}

/// The file at `path` with `f` applied, the rest as it was.
fn change(path: &Path, f: impl FnOnce(&mut Value)) -> Result<(), String> {
    let mut v = read(path)
        .filter(Value::is_object)
        .unwrap_or_else(|| json!({}));
    f(&mut v);
    let dir = path.parent().unwrap_or(Path::new("."));
    std::fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    std::fs::write(path, format!("{v:#}\n")).map_err(|e| format!("{}: {e}", path.display()))
}

fn read(path: &Path) -> Option<Value> {
    std::fs::read(path)
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_appearance_is_kept_and_the_rest_stays() {
        let d = tempfile::tempdir().unwrap();
        let f = d.path().join("nerve/settings.json");
        assert_eq!(appearance(&f), 0);
        save_appearance(&f, 2).unwrap();
        assert_eq!(appearance(&f), 2);
        std::fs::write(&f, r#"{"appearance": "light", "later": 1}"#).unwrap();
        assert_eq!(appearance(&f), 1);
        save_appearance(&f, 0).unwrap();
        let v: Value = serde_json::from_slice(&std::fs::read(&f).unwrap()).unwrap();
        assert_eq!(v, json!({"appearance": "system", "later": 1}));
        std::fs::write(&f, "not json").unwrap();
        assert_eq!(appearance(&f), 0);
    }

    /// Pre-releases are off until the owner turns them on, and the switch
    /// keeps the rest of the file (#213).
    #[test]
    fn pre_releases_are_off_until_turned_on() {
        let d = tempfile::tempdir().unwrap();
        let f = d.path().join("nerve/settings.json");
        assert!(!pre_releases(&f));
        save_appearance(&f, 2).unwrap();
        save_pre_releases(&f, true).unwrap();
        assert!(pre_releases(&f));
        assert_eq!(appearance(&f), 2);
        save_pre_releases(&f, false).unwrap();
        assert!(!pre_releases(&f));
    }

    /// A page's shares are kept by its key, apart from the other pages',
    /// and a reset forgets them; a share out of 0 to 1 is not taken (#213).
    #[test]
    fn the_panes_shares_are_kept_per_page() {
        let d = tempfile::tempdir().unwrap();
        let f = d.path().join("nerve/settings.json");
        assert_eq!(pane_shares(&f, "node-capabilities"), (None, None));
        save_appearance(&f, 1).unwrap();
        save_pane_shares(&f, "node-capabilities", Some(0.25), Some(0.125)).unwrap();
        save_pane_shares(&f, "node-audit", Some(0.5), None).unwrap();
        assert_eq!(
            pane_shares(&f, "node-capabilities"),
            (Some(0.25), Some(0.125))
        );
        assert_eq!(pane_shares(&f, "node-audit"), (Some(0.5), None));
        assert_eq!(appearance(&f), 1);
        save_pane_shares(&f, "node-capabilities", None, None).unwrap();
        assert_eq!(pane_shares(&f, "node-capabilities"), (None, None));
        assert_eq!(pane_shares(&f, "node-audit"), (Some(0.5), None));
        std::fs::write(&f, r#"{"panes": {"x": {"list": 7}}}"#).unwrap();
        assert_eq!(pane_shares(&f, "x"), (None, None));
    }

    /// The center's log-in stays in memory until the owner turns the
    /// keyring on (#232).
    #[test]
    fn the_center_log_in_is_kept_only_when_turned_on() {
        let d = tempfile::tempdir().unwrap();
        let f = d.path().join("nerve/settings.json");
        assert!(!keep_login(&f));
        save_pre_releases(&f, true).unwrap();
        save_keep_login(&f, true).unwrap();
        assert!(keep_login(&f));
        assert!(pre_releases(&f));
        save_keep_login(&f, false).unwrap();
        assert!(!keep_login(&f));
    }
}
