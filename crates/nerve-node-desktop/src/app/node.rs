//! The node itself: the rights the app asks for when the node is installed
//! as a service, the service's start and stop, and the first-run steps.

use std::rc::Rc;

use slint::{ComponentHandle, SharedString};

use super::Ctl;
use crate::broker;
use crate::{Store, Tone};

impl Ctl {
    /// The app ends: so does what follows the audit or the log. A restart
    /// the app said would come runs now, while the app still has the rights
    /// for it, or the service would go on without the change; its answer,
    /// `None` when none waited.
    pub fn end(&self) -> Option<Result<(), String>> {
        self.stop_follow();
        if !self.restart_waits.replace(false) {
            return None;
        }
        self.restart_timer.stop();
        Some(self.runner().run(&["service", "restart"]).map(|_| ()))
    }

    /// The installed service's state, from `service status`, which needs no
    /// rights; asked only for the node of the service's folders.
    pub(super) fn refresh_service(self: &Rc<Self>) {
        if !self.service.get() || self.asking_service.replace(true) {
            return;
        }
        self.command(
            vec!["service".into(), "status".into()],
            None,
            |c, answer| {
                c.asking_service.set(false);
                if let Ok(v) = answer {
                    let state = v["state"].as_str().unwrap_or("none").to_string();
                    c.with_store(|s| {
                        s.set_service_state(state.into());
                        s.set_service_enabled(v["enabled"] == true);
                    });
                }
            },
        );
    }

    /// Restarts the installed service for the changes that wait for it
    /// ([`Ctl::restart_for`]).
    pub(super) fn restart_service(self: &Rc<Self>) {
        self.restart_waits.set(false);
        self.restart_timer.stop();
        self.with_store(|s| s.set_busy("service-restart".into()));
        self.command(
            vec!["service".into(), "restart".into()],
            None,
            |c, answer| {
                c.with_store(|s| s.set_busy(SharedString::new()));
                match answer {
                    Ok(_) => {
                        c.with_store(|s| s.set_restart_due(false));
                        c.toast("The node restarted and took the change.", Tone::Ok);
                    }
                    // The Overview still offers the restart.
                    Err(e) => c.toast(
                        format!("The node did not restart: {e}. Restart it on the Overview."),
                        Tone::Danger,
                    ),
                }
                c.refresh_service();
                c.refresh_status();
            },
        );
    }

    /// Starts, stops or restarts the installed service.
    fn service_action(self: &Rc<Self>, what: &str) {
        let key = format!("service-{what}");
        let said = match what {
            "start" => "The service started, and the node answers.",
            "stop" => "The service stopped: the node ended its links.",
            _ => "The service restarted, and the node answers.",
        };
        // The owner's own start, stop or restart replaces one the app
        // planned: a stopped service stays stopped.
        self.restart_waits.set(false);
        self.restart_timer.stop();
        self.with_store(|s| s.set_busy(key.as_str().into()));
        self.command(
            vec!["service".into(), what.to_string()],
            None,
            move |c, answer| {
                c.with_store(|s| s.set_busy(SharedString::new()));
                match answer {
                    Ok(_) => {
                        // A start takes every change the node waited with.
                        c.with_store(|s| s.set_restart_due(false));
                        c.toast(said, Tone::Ok);
                    }
                    Err(e) => c.toast(e, Tone::Danger),
                }
                c.refresh_service();
                c.refresh_status();
            },
        );
    }

    /// Starts the broker with the rights the owner gives, after the app said
    /// why it needs them.
    fn elevate_allow(self: &Rc<Self>) {
        let Some(how) = self.elevate.get() else {
            return;
        };
        let exe = self.runner().exe().clone();
        self.with_store(|s| {
            s.set_elevate_busy(true);
            s.set_elevate_error(SharedString::new());
        });
        self.job(
            move |_| broker::launch(&exe, how),
            |c, launched| {
                c.with_store(|s| s.set_elevate_busy(false));
                match launched {
                    Ok(b) => {
                        let r = c.runner().through(b);
                        *c.runner.borrow_mut() = r;
                        c.with_store(|s| {
                            s.set_elevate_needed(false);
                            s.set_elevate_open(false);
                        });
                        c.refresh_status();
                        c.take_link();
                    }
                    Err(e) => {
                        c.with_store(|s| s.set_elevate_error(e.into()));
                    }
                }
            },
        );
    }

    /// The broker ended (the owner's session, a crash): the app asks again.
    pub(super) fn rights_gone(&self) {
        if !self.session_rights.get() {
            return;
        }
        let plain = self.runner().direct();
        *self.runner.borrow_mut() = plain;
        self.with_store(|s| s.set_elevate_needed(true));
    }

    pub(super) fn setup_start(self: &Rc<Self>) {
        let host = nerve_node::descriptor::node_name(&nerve_policy::NodeConfig::default());
        self.with_store(|s| {
            s.set_setup_step(0);
            s.set_setup_name(host.as_str().into());
            s.set_setup_storage(0);
            s.set_setup_mode("allowlist".into());
            s.set_setup_error(SharedString::new());
            s.set_setup_busy(false);
            s.set_pair_step(0);
            s.set_pair_link(SharedString::new());
            s.set_pair_name(SharedString::new());
            s.set_pair_error(SharedString::new());
            s.set_setup_open(true);
        });
        // What is set already.
        self.command(
            vec!["config".into(), "get".into(), "node.name".into()],
            None,
            |c, v| {
                if let Some(n) = v.ok().and_then(|v| v["value"].as_str().map(str::to_string)) {
                    c.with_store(|s| s.set_setup_name(n.into()));
                }
            },
        );
        self.command(
            vec![
                "config".into(),
                "get".into(),
                "machine.secret_storage".into(),
            ],
            None,
            |c, v| {
                if let Ok(v) = &v {
                    c.keyring_state(v);
                }
                if v.is_ok_and(|v| v["value"] == "keyring") {
                    c.with_store(|s| s.set_setup_storage(1));
                }
            },
        );
    }

    fn setup_go(&self, step: i32) {
        self.with_store(|s| {
            s.set_setup_busy(false);
            s.set_setup_error(SharedString::new());
            s.set_setup_step(step);
        });
    }

    /// Runs a step's command, then goes to `next`. With `say`, what the
    /// command said comes in a toast: where the keys went, and what that
    /// changes.
    fn setup_run(self: &Rc<Self>, args: Vec<String>, next: i32, say: bool) {
        self.with_store(|s| s.set_setup_busy(true));
        self.command(args, None, move |c, answer| match answer {
            Ok(v) => {
                if say && !super::said_of(&v).is_empty() {
                    c.done(&v, "");
                } else {
                    c.restart_for(&v);
                }
                c.setup_go(next)
            }
            Err(e) => {
                c.with_store(|s| {
                    s.set_setup_busy(false);
                    s.set_setup_error(e.into());
                });
            }
        });
    }

    fn setup_next(self: &Rc<Self>) {
        let Some((step, name, storage, mode, center, pair_step, link, pair_name)) = self
            .with_store(|s| {
                (
                    s.get_setup_step(),
                    s.get_setup_name().to_string(),
                    s.get_setup_storage(),
                    s.get_setup_mode().to_string(),
                    s.get_setup_center().to_string(),
                    s.get_pair_step(),
                    s.get_pair_link().to_string(),
                    s.get_pair_name().to_string(),
                )
            })
        else {
            return;
        };
        match step {
            0 => {
                let host = nerve_node::descriptor::node_name(&nerve_policy::NodeConfig::default());
                let name = name.trim();
                if name.is_empty() || name == host {
                    self.setup_go(1);
                } else {
                    let args = vec![
                        "config".into(),
                        "set".into(),
                        "--".into(),
                        "node.name".into(),
                        name.into(),
                    ];
                    self.setup_run(args, 1, false);
                }
            }
            1 => {
                let to = if storage == 1 { "keyring" } else { "file" };
                let args = vec![
                    "config".into(),
                    "set".into(),
                    "machine.secret_storage".into(),
                    to.into(),
                ];
                self.setup_run(args, 2, true);
            }
            // Back from the mode: the center is paired, on to its mode.
            2 if pair_step == 2 => self.setup_go(3),
            2 => self.pair(&link, &pair_name, pair_step == 1),
            3 => {
                let args = vec!["mode".into(), mode, format!("--center={center}")];
                self.setup_run(args, 4, false);
            }
            _ => {
                let (state, due) = self
                    .with_store(|s| (s.get_service_state().to_string(), s.get_restart_due()))
                    .unwrap_or_default();
                self.with_store(|s| s.set_setup_open(false));
                // The service takes the steps' changes when it starts: it
                // starts, or starts again.
                match state.as_str() {
                    "stopped" => self.service_action("start"),
                    "running" if due => self.service_action("restart"),
                    _ => {}
                }
            }
        }
    }

    /// The first-run steps paired `name`: its mode is next.
    pub(super) fn setup_paired(&self, name: &str) {
        self.with_store(|s| s.set_setup_center(name.into()));
        self.setup_go(3);
    }

    /// The steps closed before their end, with × or Escape: the restart
    /// their changes wait for runs now, as at their end.
    fn setup_close(self: &Rc<Self>) {
        let (running, due) = self
            .with_store(|s| {
                s.set_setup_open(false);
                (s.get_service_state() == "running", s.get_restart_due())
            })
            .unwrap_or_default();
        if running && due {
            self.restart_service();
        }
    }

    /// One step back. The pairing's confirmation goes back to its link; the
    /// mode, to the center it paired, which stays paired; the end, to the
    /// mode, or to the pairing when it was skipped.
    fn setup_back(&self) {
        let Some((step, pair_step, center)) = self.with_store(|s| {
            (
                s.get_setup_step(),
                s.get_pair_step(),
                s.get_setup_center().to_string(),
            )
        }) else {
            return;
        };
        match step {
            0 => {}
            2 if pair_step == 1 => {
                self.with_store(|s| {
                    s.set_pair_error(SharedString::new());
                    s.set_pair_step(0);
                });
            }
            3 => {
                self.with_store(|s| s.set_pair_step(2));
                self.setup_go(2);
            }
            4 if center.is_empty() => self.setup_go(2),
            _ => self.setup_go(step - 1),
        }
    }

    fn setup_skip(&self) {
        let step = self.with_store(|s| s.get_setup_step()).unwrap_or(0);
        // Without a center there is no mode to choose.
        self.setup_go(if step >= 2 { 4 } else { step + 1 });
    }
}

pub(super) fn wire(ctl: &Rc<Ctl>, window: &crate::AppWindow) {
    let store = window.global::<Store>();
    let c = ctl.clone();
    store.on_service(move |what| c.service_action(&what));
    let c = ctl.clone();
    store.on_elevate_allow(move || c.elevate_allow());
    let c = ctl.clone();
    store.on_setup_start(move || c.setup_start());
    let c = ctl.clone();
    store.on_setup_next(move || c.setup_next());
    let c = ctl.clone();
    store.on_setup_skip(move || c.setup_skip());
    let c = ctl.clone();
    store.on_setup_back(move || c.setup_back());
    let c = ctl.clone();
    store.on_setup_close(move || c.setup_close());
}
