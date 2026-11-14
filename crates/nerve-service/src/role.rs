//! What this machine is to the app: a node or a center. The app's program
//! (`nerve`) installs one role per machine, so one file never serves two
//! services; the terminal programs `nerve-node` and `nerve-center` are
//! files of their own and may install both, for tests. The role is read
//! from the installed services (root's units, the administrators' services),
//! never from a setting of the app, which any program of its user could
//! write.

use std::path::Path;

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
    fn the_app_installs_one_role_per_machine() {
        assert!(one_role(Role::Node, false).is_ok());
        let e = one_role(Role::Node, true).unwrap_err();
        assert!(e.starts_with("this machine is a center already"), "{e}");
        let e = one_role(Role::Center, true).unwrap_err();
        assert!(e.starts_with("this machine is a node already"), "{e}");
        assert_eq!(e.contains("terminal"), !cfg!(windows), "{e}");
    }
}
