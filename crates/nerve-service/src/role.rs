//! What this machine is to the app: a node or a center. The app's program
//! (`nerve`) installs one role per machine, so one file never serves two
//! services; the terminal programs `nerve-node` and `nerve-center` are
//! files of their own and may install both, for tests. The role is read
//! from the installed services (root's units, the administrators' services),
//! never from a setting of the app, which any program of its user could
//! write.

use std::path::{Path, PathBuf};

/// A role of a machine, by its service.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Node,
    Center,
}

impl Role {
    /// The name of its service: the systemd unit's without `.service`, the
    /// Windows service's.
    pub fn service(self) -> &'static str {
        match self {
            Role::Node => "nerve-node",
            Role::Center => "nerve-center",
        }
    }

    /// The other role.
    pub fn other(self) -> Role {
        match self {
            Role::Node => Role::Center,
            Role::Center => Role::Node,
        }
    }

    /// The role in words: "a node", "a center".
    pub fn named(self) -> &'static str {
        match self {
            Role::Node => "a node",
            Role::Center => "a center",
        }
    }
}

/// The roles installed on this machine.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Roles {
    pub node: bool,
    pub center: bool,
}

impl Roles {
    pub fn has(self, role: Role) -> bool {
        match role {
            Role::Node => self.node,
            Role::Center => self.center,
        }
    }

    /// The roles whose units are in the systemd folder `units`.
    pub fn in_units(units: &Path) -> Roles {
        let at = |r: Role| units.join(format!("{}.service", r.service())).is_file();
        Roles {
            node: at(Role::Node),
            center: at(Role::Center),
        }
    }

    /// The roles installed here: the units of systemd's system folder on
    /// Linux, the services the service control manager has on Windows.
    pub fn here() -> Roles {
        #[cfg(windows)]
        {
            let at = |r: Role| crate::win::service::registered(r.service());
            Roles {
                node: at(Role::Node),
                center: at(Role::Center),
            }
        }
        #[cfg(not(windows))]
        Roles::in_units(Path::new("/etc/systemd/system"))
    }

    /// The roles of these that are the app's to show and change: where both
    /// are installed, a terminal program installed one of them
    /// (`in_terminal`), since the app installs one role per machine, and
    /// that one is left to the terminal.
    pub fn of_app(self, in_terminal: impl Fn(Role) -> bool) -> Roles {
        if !(self.node && self.center) {
            return self;
        }
        match (in_terminal(Role::Node), in_terminal(Role::Center)) {
            (true, false) => Roles {
                node: false,
                center: true,
            },
            (false, true) => Roles {
                node: true,
                center: false,
            },
            _ => self,
        }
    }

    /// [`Roles::of_app`] for the units in the systemd folder `units` and the
    /// app's program `app` (a name without its path).
    pub fn of_app_in(units: &Path, app: &str) -> Roles {
        Roles::in_units(units).of_app(|r| in_terminal_units(units, r, app))
    }

    /// [`Roles::of_app`] for this machine.
    pub fn of_app_here(app: &str) -> Roles {
        Roles::here().of_app(|r| in_terminal(r, app))
    }
}

/// Whether the unit of `role` in the systemd folder `units` starts a program
/// other than `app` (a name without its path): the role was installed in the
/// terminal, by `nerve-node` or `nerve-center`, and runs that file, which the
/// app leaves as it is.
pub fn in_terminal_units(units: &Path, role: Role, app: &str) -> bool {
    std::fs::read_to_string(units.join(format!("{}.service", role.service())))
        .ok()
        .and_then(|unit| started_by(&unit))
        .is_some_and(|program| program != app)
}

/// [`in_terminal_units`] for the units of this machine; Windows has no
/// terminal programs.
pub fn in_terminal(role: Role, app: &str) -> bool {
    cfg!(not(windows)) && in_terminal_units(Path::new("/etc/systemd/system"), role, app)
}

/// The name of the program a unit's `ExecStart` starts.
fn started_by(unit: &str) -> Option<String> {
    exec_start(unit)?.rsplit('/').next().map(str::to_string)
}

/// The path of the program a unit's `ExecStart` starts.
fn exec_start(unit: &str) -> Option<&str> {
    let line = unit
        .lines()
        .find_map(|l| l.trim().strip_prefix("ExecStart="))?;
    // systemd's prefixes (`-`, `@`, `+`, `!`, `:`) come before the path.
    line.trim_start_matches(['-', '@', '+', '!', ':'])
        .split_whitespace()
        .next()
}

/// The program the unit of `role` in the systemd folder `units` starts,
/// with its path; `None` where the role is not installed there.
pub fn program_in_units(units: &Path, role: Role) -> Option<PathBuf> {
    let unit = std::fs::read_to_string(units.join(format!("{}.service", role.service()))).ok()?;
    exec_start(&unit).map(PathBuf::from)
}

/// The program a Windows service's command line starts: its first word, in
/// quotes where the path has a space.
pub fn program_in_command_line(line: &str) -> Option<PathBuf> {
    let line = line.trim_start();
    let path = match line.strip_prefix('"') {
        Some(rest) => rest.split_once('"')?.0,
        None => line.split_whitespace().next()?,
    };
    (!path.is_empty()).then(|| PathBuf::from(path))
}

/// Whether a service that starts `started` runs the program at `bin`: on
/// Windows by any case of the letters, as its file system names files.
pub fn same_program(started: &Path, bin: &Path) -> bool {
    if cfg!(windows) {
        started.to_string_lossy().to_lowercase() == bin.to_string_lossy().to_lowercase()
    } else {
        started == bin
    }
}

/// Refuses an install of `want` by the app's program where the other role's
/// service is installed (`other`): one role per machine.
pub fn one_role(want: Role, other: bool) -> Result<(), String> {
    if !other {
        return Ok(());
    }
    // Windows has no terminal programs: the app is the only way there.
    let both = match cfg!(windows) {
        true => "",
        false => {
            "; for both roles on one machine use the terminal programs nerve-node and nerve-center"
        }
    };
    Err(format!(
        "this machine is {} already: the app installs one role per machine{both}",
        want.other().named()
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_roles_are_read_from_the_installed_units() {
        let d = tempfile::tempdir().unwrap();
        assert_eq!(Roles::in_units(d.path()), Roles::default());
        std::fs::write(d.path().join("nerve-center.service"), "").unwrap();
        let r = Roles::in_units(d.path());
        assert!(r.center && !r.node && r.has(Role::Center));
        std::fs::write(d.path().join("nerve-node.service"), "").unwrap();
        assert!(Roles::in_units(d.path()).node);
    }

    #[test]
    fn a_role_that_runs_another_program_than_the_apps_was_installed_in_the_terminal() {
        let d = tempfile::tempdir().unwrap();
        let unit = |name: &str, exec: &str| {
            std::fs::write(
                d.path().join(format!("{name}.service")),
                format!("[Service]\nUser=x\nExecStart={exec}\n"),
            )
            .unwrap()
        };
        let in_terminal = |role| in_terminal_units(d.path(), role, "nerve");
        // Nothing installed.
        assert!(!in_terminal(Role::Center));
        unit(
            "nerve-center",
            "/usr/local/bin/nerve-center --state-dir /var/lib/nerve-center",
        );
        assert!(in_terminal(Role::Center));
        // The app's own: its program, and its word.
        unit(
            "nerve-center",
            "/usr/bin/nerve __center --state-dir /var/lib/nerve-center",
        );
        assert!(!in_terminal(Role::Center));
        unit("nerve-node", "/usr/local/bin/nerve-node --state-dir x run");
        assert!(in_terminal(Role::Node));
        unit("nerve-node", "/usr/bin/nerve run");
        assert!(!in_terminal(Role::Node));
        assert_eq!(
            started_by("[Service]\nExecStart=-/opt/n/x y\n").as_deref(),
            Some("x")
        );
        assert_eq!(started_by("[Service]\n"), None);
    }

    /// Where both roles are installed, the one a terminal program installed
    /// is not the app's: the app shows and changes only its own.
    #[test]
    fn the_app_s_roles_leave_out_the_one_installed_in_the_terminal() {
        let d = tempfile::tempdir().unwrap();
        let unit = |name: &str, exec: &str| {
            std::fs::write(
                d.path().join(format!("{name}.service")),
                format!("[Service]\nExecStart={exec}\n"),
            )
            .unwrap()
        };
        let apps = || Roles::of_app_in(d.path(), "nerve");
        let (node, center) = (
            Roles {
                node: true,
                center: false,
            },
            Roles {
                node: false,
                center: true,
            },
        );
        // The app's center, and a node of the terminal beside it.
        unit(
            "nerve-center",
            "/usr/local/bin/nerve __center --state-dir x",
        );
        assert_eq!(apps(), center);
        unit("nerve-node", "/usr/local/bin/nerve-node --state-dir y run");
        assert_eq!(apps(), center);
        // The app's node, and a center of the terminal beside it.
        unit("nerve-node", "/usr/local/bin/nerve --state-dir y run");
        unit("nerve-center", "/usr/local/bin/nerve-center --state-dir x");
        assert_eq!(apps(), node);
        // Both the terminal's: as they are.
        unit("nerve-node", "/usr/local/bin/nerve-node --state-dir y run");
        assert_eq!(
            apps(),
            Roles {
                node: true,
                center: true
            }
        );
        assert_eq!(
            program_in_units(d.path(), Role::Node).as_deref(),
            Some(Path::new("/usr/local/bin/nerve-node"))
        );
    }

    #[test]
    fn a_windows_service_s_program_is_its_first_word() {
        assert_eq!(
            program_in_command_line(
                r#""C:\Program Files\Nerve\nerve.exe" __center service --state-dir "C:\x""#
            ),
            Some(PathBuf::from(r"C:\Program Files\Nerve\nerve.exe"))
        );
        assert_eq!(
            program_in_command_line(r"C:\Nerve\nerve.exe run"),
            Some(PathBuf::from(r"C:\Nerve\nerve.exe"))
        );
        assert_eq!(program_in_command_line("\"\" x"), None);
        // Windows names a file in any case of its letters.
        assert_eq!(
            same_program(
                Path::new(r"C:\Program Files\Nerve\nerve.exe"),
                Path::new(r"c:\program files\nerve\NERVE.EXE")
            ),
            cfg!(windows)
        );
        assert_eq!(program_in_command_line(""), None);
    }

    #[test]
    fn the_app_installs_one_role_per_machine() {
        assert!(one_role(Role::Node, false).is_ok());
        let e = one_role(Role::Node, true).unwrap_err();
        assert!(e.starts_with("this machine is a center already"), "{e}");
        let e = one_role(Role::Center, true).unwrap_err();
        assert!(e.starts_with("this machine is a node already"), "{e}");
        assert_eq!(e.contains("terminal"), !cfg!(windows), "{e}");
    }
}
