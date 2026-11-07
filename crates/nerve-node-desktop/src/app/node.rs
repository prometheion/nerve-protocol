//! The node itself: the rights the app asks for when the node is installed
//! as a service, the service's start and stop, and the first-run steps.

use std::rc::Rc;

use slint::{ComponentHandle, SharedString};

use super::Ctl;
use crate::broker;
use crate::{Store, Tone};

impl Ctl {
    /// The app ends: so does what follows the audit or the log.
    pub fn end(&self) {
        self.stop_follow();
    }

    /// The installed service's state, from `status`, which needs no rights;
    /// asked only for the node of the service's folders.
    pub(super) fn refresh_service(self: &Rc<Self>) {
        if !self.service.get() || self.asking_service.replace(true) {
            return;
        }
        self.command(vec!["status".into()], None, |c, answer| {
            c.asking_service.set(false);
            if let Ok(v) = answer.map(|v| v["service"].clone()) {
                let state = v["state"].as_str().unwrap_or("none").to_string();
                c.with_store(|s| {
                    s.set_service_state(state.into());
                    s.set_service_enabled(v["enabled"] == true);
                });
            }
        });
    }

    /// Starts, stops or restarts the installed service.
    fn service_action(self: &Rc<Self>, what: &str) {
        let key = format!("service-{what}");
        let said = match what {
            "start" => "The service started, and the node answers.",
            "stop" => "The service stopped: the node ended its links.",
            _ => "The service restarted, and the node answers.",
        };
        self.with_store(|s| s.set_busy(key.as_str().into()));
        self.command(
            vec!["service".into(), what.to_string()],
            None,
            move |c, answer| {
                c.with_store(|s| s.set_busy(SharedString::new()));
                match answer {
                    Ok(_) => c.toast(said, Tone::Ok),
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

    /// The first-run steps: the first center and its mode, as `setup` asks
    /// in a terminal. The machine's name and where the keys live keep their
    /// defaults; Settings changes them.
    pub(super) fn setup_start(self: &Rc<Self>) {
        self.with_store(|s| {
            s.set_setup_step(0);
            s.set_setup_mode("allowlist".into());
            s.set_setup_error(SharedString::new());
            s.set_setup_busy(false);
            s.set_pair_step(0);
            s.set_pair_link(SharedString::new());
            s.set_pair_name(SharedString::new());
            s.set_pair_error(SharedString::new());
            s.set_setup_open(true);
        });
    }

    fn setup_go(&self, step: i32) {
        self.with_store(|s| {
            s.set_setup_busy(false);
            s.set_setup_error(SharedString::new());
            s.set_setup_step(step);
        });
    }

    /// Runs a step's command, then goes to `next`.
    fn setup_run(self: &Rc<Self>, args: Vec<String>, next: i32) {
        self.with_store(|s| s.set_setup_busy(true));
        self.command(args, None, move |c, answer| match answer {
            Ok(_) => c.setup_go(next),
            Err(e) => {
                c.with_store(|s| {
                    s.set_setup_busy(false);
                    s.set_setup_error(e.into());
                });
            }
        });
    }

    fn setup_next(self: &Rc<Self>) {
        let Some((step, mode, center, pair_step, link, pair_name)) = self.with_store(|s| {
            (
                s.get_setup_step(),
                s.get_setup_mode().to_string(),
                s.get_setup_center().to_string(),
                s.get_pair_step(),
                s.get_pair_link().to_string(),
                s.get_pair_name().to_string(),
            )
        }) else {
            return;
        };
        match step {
            // Back from the mode: the center is paired, on to its mode.
            0 if pair_step == 2 => self.setup_go(1),
            0 => self.pair(&link, &pair_name, pair_step == 1),
            1 => {
                let args = vec!["mode".into(), mode, format!("--center={center}")];
                self.setup_run(args, 2);
            }
            _ => {
                let state = self
                    .with_store(|s| s.get_service_state().to_string())
                    .unwrap_or_default();
                self.with_store(|s| s.set_setup_open(false));
                // A stopped service takes the steps' changes when it starts.
                if state == "stopped" {
                    self.service_action("start");
                }
            }
        }
    }

    /// The first-run steps paired `name`: its mode is next.
    pub(super) fn setup_paired(&self, name: &str) {
        self.with_store(|s| s.set_setup_center(name.into()));
        self.setup_go(1);
    }

    /// The steps closed before their end, with × or Escape. A running node
    /// took their changes already.
    fn setup_close(self: &Rc<Self>) {
        self.with_store(|s| s.set_setup_open(false));
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
            0 if pair_step == 1 => {
                self.with_store(|s| {
                    s.set_pair_error(SharedString::new());
                    s.set_pair_step(0);
                });
            }
            0 => {}
            1 => {
                self.with_store(|s| s.set_pair_step(2));
                self.setup_go(0);
            }
            2 if center.is_empty() => self.setup_go(0),
            _ => self.setup_go(step - 1),
        }
    }

    fn setup_skip(&self) {
        // Without a center there is no mode to choose: past the pairing, or
        // past the mode, the steps are done.
        self.setup_go(2);
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
