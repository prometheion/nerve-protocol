//! Installing, updating and removing Nerve: the installer, which a program
//! that is not the installed one shows (the file just downloaded), and the
//! update and uninstall of Settings. Each runs this program's `install`,
//! `update` or `uninstall` (the node's, with the app's parts,
//! crate::parts) with the rights the system gives, through the broker.

use std::path::{Path, PathBuf};
use std::rc::Rc;

use serde_json::Value;
use slint::{ComponentHandle, ModelRc, SharedString, VecModel};

use super::{Choose, Ctl, Exec, Launcher};
use crate::Install;
use crate::broker::{self, Launch};
use crate::runner::Runner;

/// Starts `bin` without arguments, as the menu entry does, apart from this
/// program: it opens the installed app.
pub(super) fn system_launcher() -> Launcher {
    std::sync::Arc::new(|bin: &Path| {
        std::process::Command::new(bin)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .map(|_| ())
            .map_err(|e| format!("cannot start {}: {e}", bin.display()))
    })
}

/// The version of the program at `file`, from its `--version`
/// (`nerve-node-desktop 0.0.6`); none when it does not say.
pub fn version_of(file: &Path) -> Option<String> {
    let out = std::process::Command::new(file)
        .arg("--version")
        .stdin(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .output()
        .ok()?;
    let text = String::from_utf8(out.stdout).ok()?;
    let (name, version) = text.trim().split_once(' ')?;
    (out.status.success() && name == crate::parts::PROGRAM).then(|| version.to_string())
}

/// Whether version `a` is newer than `b` (both `x.y.z`).
pub fn newer(a: &str, b: &str) -> bool {
    let parse =
        |v: &str| -> Option<Vec<u64>> { v.trim().split('.').map(|p| p.parse().ok()).collect() };
    match (parse(a), parse(b)) {
        (Some(a), Some(b)) => a > b,
        _ => false,
    }
}

/// Whether the installer adds the app to a node installed alone: on Linux,
/// where the app takes it over. Windows has no node alone (#176): there the
/// installer installs Nerve as on a machine without it.
fn adds_the_app(installed: bool, app: bool, windows: bool) -> bool {
    installed && !app && !windows
}

/// What a service command said, as the steps it did and what it warned
/// about. Its advice for what comes next (`Next: …`) is the app's to give,
/// in its own words: the app asked for root through pkexec, and opens its
/// first-run steps. Where the Windows password is entered again the node
/// says in the app's words itself (nerve_node::account::NO_ACCOUNT_INSTALL).
pub fn steps(v: &Value) -> (Vec<String>, Vec<String>) {
    let (mut did, mut warn) = (Vec::new(), Vec::new());
    for line in v["messages"].as_array().into_iter().flatten() {
        let Some(line) = line.as_str() else { continue };
        if line.starts_with("Next:") {
            continue;
        }
        let line = line.to_string();
        if line.starts_with("Warning:") || line.starts_with("no account for commands") {
            warn.push(line);
        } else {
            did.push(line);
        }
    }
    (did, warn)
}

fn shared(lines: Vec<String>) -> ModelRc<SharedString> {
    ModelRc::new(VecModel::from(
        lines
            .into_iter()
            .map(SharedString::from)
            .collect::<Vec<_>>(),
    ))
}

impl Ctl {
    /// Makes the window the installer for the app at `bin`: what will be
    /// installed, or, when Nerve is installed, what it can do with it. `how`
    /// starts the broker once the owner goes on.
    pub fn installer(self: &Rc<Self>, how: Launch, bin: &Path) {
        self.elevate.set(Some(how));
        *self.program.borrow_mut() = bin.to_path_buf();
        // The service's commands work on the installed node's folders only.
        let plain = Runner::new(self.runner().exe().clone(), None, None);
        *self.runner.borrow_mut() = plain;
        self.with_install(|i| {
            i.set_shown(true);
            i.set_program(bin.display().to_string().into());
            i.set_windows(cfg!(windows));
            i.set_account(
                std::env::var("USERNAME")
                    .or_else(|_| std::env::var("USER"))
                    .unwrap_or_default()
                    .into(),
            );
            i.set_step("working".into());
        });
        // The service's state, in `status`, needs no rights.
        self.command(vec!["status".into()], None, |c, answer| {
            let v = answer.unwrap_or_default()["service"].clone();
            let app = v["present"] == true;
            let installed = v["installed"] == true;
            let version = v["version"].as_str().unwrap_or_default().to_string();
            c.with_install(|i| {
                i.set_installed_version(version.as_str().into());
                i.set_newer(app && newer(&i.get_version(), &version));
                i.set_node_only(adds_the_app(installed, app, cfg!(windows)));
                i.set_step(if app { "installed" } else { "welcome" }.into());
            });
        });
    }

    /// The app at its installed place: its service's state is asked for
    /// when `service` (the node is the service's), and Settings updates and
    /// removes `bin`.
    pub fn watch_service(&self, service: bool, bin: &Path) {
        self.service.set(service);
        *self.program.borrow_mut() = bin.to_path_buf();
        self.with_install(|i| i.set_program(bin.display().to_string().into()));
    }

    /// Opens the installed app with `launcher` instead of starting it.
    pub fn set_launcher(&self, launcher: Launcher) {
        *self.launcher.borrow_mut() = launcher;
    }

    /// Runs `then` with a runner that has the rights `args` needs: the
    /// app's own when it needs none or has them, else one through a broker
    /// started after the system's question, which ends with that runner.
    fn with_rights(
        self: &Rc<Self>,
        args: &[String],
        then: impl FnOnce(&Rc<Ctl>, Runner) + Send + 'static,
    ) {
        let Some(how) = self.admin_for(args) else {
            let r = self.runner();
            return then(self, r);
        };
        let exe = self.runner().exe().clone();
        self.with_install(|i| {
            i.set_asking(true);
            i.set_step("working".into());
        });
        self.job(
            move |_| broker::launch(&exe, how),
            move |c, launched| {
                c.with_install(|i| i.set_asking(false));
                match launched {
                    Ok(b) => {
                        let r = c.runner().through(b);
                        then(c, r);
                    }
                    Err(e) => c.failed(e),
                }
            },
        );
    }

    /// A step that did not finish: back where the owner was, with why.
    fn failed(&self, e: String) {
        self.with_install(|i| {
            let back = match i.get_action().as_str() {
                "uninstall" => "choose",
                "update" if !i.get_shown() => "choose",
                "update" => "installed",
                _ => "welcome",
            };
            i.set_error(e.into());
            i.set_error_title(SharedString::new());
            i.set_step(back.into());
        });
    }

    /// Runs a service command with the rights, then shows what it did; the
    /// installed version comes after it.
    fn run_service_command(
        self: &Rc<Self>,
        action: &str,
        args: Vec<String>,
        input: Option<String>,
    ) {
        self.with_install(|i| {
            i.set_action(action.into());
            i.set_error(SharedString::new());
            i.set_error_title(SharedString::new());
            i.set_did(ModelRc::default());
            i.set_warnings(ModelRc::default());
        });
        self.with_rights(&args.clone(), move |c, runner| {
            c.with_install(|i| i.set_step("working".into()));
            c.job_on(
                runner,
                move |r| r.run_with(&super::strings(&args), input.as_deref()),
                |c, answer| match answer {
                    Ok(v) => {
                        let (did, warn) = steps(&v);
                        c.with_install(|i| {
                            i.set_password(SharedString::new());
                            i.set_did(shared(did));
                            i.set_warnings(shared(warn));
                        });
                        c.command(vec!["status".into()], None, |c, v| {
                            let version = v
                                .ok()
                                .and_then(|v| v["service"]["version"].as_str().map(str::to_string))
                                .unwrap_or_default();
                            c.with_install(|i| {
                                if i.get_action() != "uninstall" {
                                    i.set_installed_version(version.into());
                                }
                                i.set_step("done".into());
                            });
                        });
                    }
                    Err(e) => c.failed(e),
                },
            );
        });
    }

    fn install_go(self: &Rc<Self>) {
        // Windows asks for the password of the account commands run as;
        // it goes on stdin, never as an argument.
        let input = self
            .with_install(|i| i.get_password().to_string())
            .filter(|p| !p.is_empty());
        self.run_service_command("install", vec!["install".into()], input);
    }

    /// The update: the installer's from this program, Settings' from the
    /// latest release or the file chosen.
    fn update_go(self: &Rc<Self>) {
        let Some((shown, source, file)) =
            self.with_install(|i| (i.get_shown(), i.get_source(), i.get_file().to_string()))
        else {
            return;
        };
        let mut args = vec!["update".to_string()];
        // The installer updates with itself: the program its commands run.
        let from = if shown {
            Some(self.runner().exe().display().to_string())
        } else {
            (source == 1).then_some(file)
        };
        if let Some(from) = from {
            args.push(format!("--from={from}"));
        }
        self.run_service_command("update", args, None);
    }

    fn uninstall_go(self: &Rc<Self>) {
        let purge = self.with_install(|i| i.get_purge()).unwrap_or(false);
        let mut args = vec!["uninstall".to_string()];
        if purge {
            args.push("--purge".into());
        }
        self.run_service_command("uninstall", args, None);
    }

    /// Another copy of the program was started while the app is open, such
    /// as the file just downloaded: the app says which version it is and
    /// offers the update with it, or the uninstall, as the installer would.
    pub(super) fn offer_other(self: &Rc<Self>, file: PathBuf) {
        let shown = file.display().to_string();
        self.job(
            move |_| version_of(&file),
            move |c, version| {
                c.with_install(|i| {
                    let version = version.unwrap_or_default();
                    i.set_other_newer(!version.is_empty() && newer(&version, &i.get_version()));
                    i.set_other_version(version.into());
                    i.set_other_file(shown.into());
                    i.set_other_open(true);
                });
            },
        );
    }

    /// The update with the other copy's program.
    fn other_update(self: &Rc<Self>) {
        let Some(file) = self.with_install(|i| i.get_other_file()) else {
            return;
        };
        self.ask_update();
        self.with_install(|i| {
            i.set_other_open(false);
            i.set_source(1);
            i.set_file(file);
        });
        self.update_go();
    }

    /// Opens the uninstall: keep or delete the node's data, then go.
    pub fn ask_uninstall(&self) {
        self.with_install(|i| {
            i.set_action("uninstall".into());
            i.set_purge(false);
            i.set_error(SharedString::new());
            i.set_step("choose".into());
            if !i.get_shown() {
                i.set_uninstall_open(true);
            }
        });
    }

    fn ask_update(&self) {
        self.with_install(|i| {
            i.set_action("update".into());
            i.set_source(0);
            i.set_file(SharedString::new());
            i.set_error(SharedString::new());
            i.set_error_title(SharedString::new());
            i.set_step("choose".into());
            i.set_update_open(true);
        });
    }

    fn choose_file(self: &Rc<Self>) {
        let chooser = self.chooser.borrow().clone();
        self.job(
            move |_| chooser(Choose::Program),
            |c, picked: Result<Option<PathBuf>, String>| match picked {
                // The update dialog is open: it says why, under its own
                // heading, since the update did not start.
                Err(e) => {
                    c.with_install(|i| {
                        i.set_error(e.into());
                        i.set_error_title("No file dialog".into());
                    });
                }
                Ok(None) => {}
                Ok(Some(p)) => {
                    c.with_install(|i| {
                        i.set_source(1);
                        i.set_file(p.display().to_string().into());
                        i.set_error(SharedString::new());
                        i.set_error_title(SharedString::new());
                    });
                }
            },
        );
    }

    /// Opens the installed app and closes this window: the installer's
    /// end, and the app's start again after an update.
    fn open_app(self: &Rc<Self>) {
        let bin = self.program.borrow().clone();
        let launcher = self.launcher.borrow().clone();
        // The new window is the user's one window from its start; this one
        // lets go first.
        self.instance.borrow_mut().take();
        match launcher(&bin) {
            Ok(()) => self.close_app(),
            Err(e) => {
                self.with_install(|i| i.set_error(e.into()));
            }
        }
    }

    fn close_app(&self) {
        self.with_install(|i| i.set_closed(true));
        self.end();
        if self.exec == Exec::Threads {
            let _ = slint::quit_event_loop();
        }
    }
}

pub(super) fn wire(ctl: &Rc<Ctl>, window: &crate::AppWindow) {
    let i = window.global::<Install>();
    let c = ctl.clone();
    i.on_install(move || c.install_go());
    let c = ctl.clone();
    i.on_update(move || c.update_go());
    let c = ctl.clone();
    i.on_uninstall(move || c.uninstall_go());
    let c = ctl.clone();
    i.on_ask_uninstall(move || c.ask_uninstall());
    let c = ctl.clone();
    i.on_ask_update(move || c.ask_update());
    let c = ctl.clone();
    i.on_other_update(move || c.other_update());
    let c = ctl.clone();
    i.on_choose_file(move || c.choose_file());
    let c = ctl.clone();
    i.on_open_app(move || c.open_app());
    let c = ctl.clone();
    i.on_close(move || c.close_app());
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Only Linux takes a node installed alone over.
    #[test]
    fn the_app_is_added_to_a_node_alone_on_linux_only() {
        assert!(adds_the_app(true, false, false));
        assert!(!adds_the_app(true, false, true));
        assert!(!adds_the_app(true, true, false));
        assert!(!adds_the_app(false, false, false));
    }

    #[test]
    fn a_newer_version_and_the_steps_of_an_install() {
        assert!(newer("0.0.6", "0.0.5"));
        assert!(newer("0.10.0", "0.9.9"));
        assert!(!newer("0.0.5", "0.0.5"));
        assert!(!newer("0.0.5", ""));
        let v = serde_json::json!({"messages": [
            "made the user nerve (uid 991)",
            "Warning: no owner: there is no account bob; only root changes the node and user mode runs no command",
            format!("no account for commands: the password of alice is wrong; {}", nerve_node::account::NO_ACCOUNT_INSTALL),
            "the service nerve-node.service runs as nerve and starts with the machine",
            "Next: `nerve-node center add -` pairs the node with a center.",
        ]});
        let (did, warn) = steps(&v);
        assert_eq!(did.len(), 2);
        assert_eq!(warn.len(), 2);
        assert!(warn[0].starts_with("Warning: no owner"), "{}", warn[0]);
        assert!(
            warn[1].starts_with("no account")
                && warn[1].ends_with(
                    "enter its password under Settings › General › Account for commands in the app"
                )
        );
        // Nothing sends the owner to a terminal.
        for line in did.iter().chain(&warn) {
            assert!(!line.contains('`'), "{line}");
        }
    }
}
