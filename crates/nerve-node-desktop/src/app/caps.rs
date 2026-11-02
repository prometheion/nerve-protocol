//! The Capabilities page: what the node offers, read with `cap ls`, each
//! unit's switch for one center (`cap set`), the capabilities of node.toml
//! (`cap add`, `cap edit` and `cap rm`, through a dialog that checks them as
//! the owner types), and the programs allowed as providers (`cap provider
//! allow` and `rm`).

use std::rc::Rc;

use serde_json::Value;
use slint::{ComponentHandle, ModelRc, SharedString, VecModel};

use super::{Choose, Ctl, Pending};
use crate::{Caps, Load, Page, Tone, view};

impl Ctl {
    pub(super) fn with_caps<R>(&self, f: impl FnOnce(&Caps<'_>) -> R) -> Option<R> {
        let w = self.window.upgrade()?;
        let c = w.global::<Caps>();
        Some(f(&c))
    }

    /// The centers to choose from, as the status said them; the page keeps
    /// its center while it is paired, and reads the page again when the
    /// center it showed is gone.
    pub(super) fn caps_centers(self: &Rc<Self>, names: &[String]) {
        let Some(center) = self.with_caps(|c| c.get_center().to_string()) else {
            return;
        };
        let at = names.iter().position(|n| *n == center);
        let model: Vec<SharedString> = names.iter().map(|n| n.as_str().into()).collect();
        let now = match at {
            Some(_) => center.clone(),
            None => names.first().cloned().unwrap_or_default(),
        };
        self.with_caps(|c| {
            c.set_centers(ModelRc::new(VecModel::from(model)));
            c.set_current(at.unwrap_or(0) as i32);
            c.set_center(now.as_str().into());
        });
        if now != center && self.with_store(|s| s.get_page()) == Some(Page::Capabilities) {
            self.caps_load();
        }
    }

    pub(super) fn caps_load(self: &Rc<Self>) {
        if self.waiting_for_rights() {
            return;
        }
        let installed = self.with_store(|s| s.get_installed()).unwrap_or(false);
        let (programs_note, config_note) = view::caps_notes(cfg!(windows), installed);
        let Some(center) = self.with_caps(|c| {
            c.set_windows(cfg!(windows));
            c.set_programs_note(programs_note.into());
            c.set_config_note(config_note.into());
            c.set_load(Load::Loading);
            c.get_center().to_string()
        }) else {
            return;
        };
        let asked = self.caps_asked.get() + 1;
        self.caps_asked.set(asked);
        // Not set: the default, which node.toml leaves out.
        let default_max = nerve_policy::config::Limits::default().max_timeout_secs;
        self.job(
            move |r| {
                let mut args = vec!["cap".to_string(), "ls".into()];
                if !center.is_empty() {
                    args.push(format!("--center={center}"));
                }
                // The dialog holds a time limit to the node's own maximum.
                let max = view::max_timeout(
                    &r.run(&["config", "get", "limits.max_timeout_secs"]),
                    default_max,
                );
                (center, r.run(&super::strings(&args)), max)
            },
            move |c, (center, answer, max)| {
                if let Some(max) = max {
                    c.caps_max_timeout.set(max);
                }
                c.caps_loaded(asked, &center, answer)
            },
        );
    }

    /// Shows what reading `asked` of the page found for `center`, unless
    /// the page asked again since (another center picked meanwhile).
    pub fn caps_loaded(&self, asked: u64, center: &str, answer: Result<Value, String>) {
        if asked != self.caps_asked.get() {
            return;
        }
        match answer {
            Ok(v) => {
                let rows = view::cap_rows(&v, center);
                let programs = view::programs(&v);
                let declared = view::declared(&v);
                *self.caps_listing.borrow_mut() = v.clone();
                self.with_caps(|c| {
                    c.set_rows(ModelRc::new(VecModel::from(rows)));
                    c.set_declared(ModelRc::new(VecModel::from(declared)));
                    c.set_programs(ModelRc::new(VecModel::from(programs)));
                    c.set_running(v["running"] == true);
                    c.set_load(Load::Ready);
                    c.set_error(SharedString::new());
                    c.set_read(true);
                });
            }
            Err(e) => {
                self.with_caps(|c| {
                    c.set_load(Load::Failed);
                    c.set_error(e.into());
                });
            }
        }
    }

    /// The reading of the page that runs now, or ran last.
    pub fn caps_asked(&self) -> u64 {
        self.caps_asked.get()
    }

    /// A change of the page: says `said` (what the command said when
    /// empty), then reads the page again; `failed` gets the error.
    pub(super) fn caps_change(
        self: &Rc<Self>,
        args: Vec<String>,
        input: Option<String>,
        said: String,
        failed: impl FnOnce(&Rc<Ctl>, String) + Send + 'static,
    ) {
        self.command(args, input, move |c, answer| {
            match answer {
                Ok(v) => c.done(&v, said),
                Err(e) => failed(c, e),
            }
            c.caps_load();
        });
    }

    fn caps_set(self: &Rc<Self>, name: &str, setting: i32) {
        let Some(center) = self.with_caps(|c| c.get_center().to_string()) else {
            return;
        };
        let word = view::cap_word(setting);
        let args = vec![
            "cap".into(),
            "set".into(),
            name.into(),
            word.into(),
            format!("--center={center}"),
        ];
        self.caps_change(
            args,
            None,
            format!("{name} is {word} for {center}."),
            |c, e| c.toast(e, Tone::Danger),
        );
    }

    /// Opens the dialog with `form`: a new capability, or the one it names.
    fn cap_dialog(&self, form: &view::CapForm, new: bool) {
        let at = |all: &[&str], v: &str| all.iter().position(|e| *e == v).unwrap_or(0) as i32;
        self.with_caps(|c| {
            c.set_edit_new(new);
            c.set_edit_name(form.name.as_str().into());
            c.set_edit_summary(form.summary.as_str().into());
            c.set_edit_effect(at(&view::EFFECTS, &form.effect));
            c.set_edit_command(form.command.as_str().into());
            c.set_edit_params(form.params.as_str().into());
            c.set_edit_result(form.result.as_str().into());
            c.set_edit_timeout(form.timeout.as_str().into());
            c.set_edit_platform(at(&view::PLATFORMS, &form.platform));
            c.set_edit_error(SharedString::new());
            c.set_edit_busy(false);
            c.set_params_scrolled(Default::default());
            c.set_edit_open(true);
        });
        self.cap_dialogs.set(self.cap_dialogs.get() + 1);
        self.cap_tried.set(false);
        self.cap_check();
    }

    fn cap_add(&self) {
        let form = view::CapForm {
            effect: "read".into(),
            platform: "any".into(),
            ..Default::default()
        };
        self.cap_dialog(&form, true);
    }

    fn cap_edit(&self, name: &str) {
        let entry = self.caps_listing.borrow()["config"]
            .as_array()
            .into_iter()
            .flatten()
            .find(|c| c["name"] == name)
            .cloned();
        if let Some(entry) = entry {
            self.cap_dialog(&view::cap_form_of(&entry), false);
        }
    }

    /// What the dialog holds now.
    fn cap_form(&self) -> Option<view::CapForm> {
        let pick =
            |all: &[&str], i: i32| all.get(i as usize).copied().unwrap_or(all[0]).to_string();
        self.with_caps(|c| view::CapForm {
            name: c.get_edit_name().to_string(),
            summary: c.get_edit_summary().to_string(),
            effect: pick(&view::EFFECTS, c.get_edit_effect()),
            command: c.get_edit_command().to_string(),
            params: c.get_edit_params().to_string(),
            result: c.get_edit_result().to_string(),
            timeout: c.get_edit_timeout().to_string(),
            platform: pick(&view::PLATFORMS, c.get_edit_platform()),
        })
    }

    /// Checks the dialog's fields as the node will, and says what is wrong
    /// with each: a field left empty only once the owner tried to save
    /// (`cap_tried`), so a new dialog does not open full of errors. Whether
    /// it may be saved.
    fn cap_check(&self) -> bool {
        let Some(form) = self.cap_form() else {
            return false;
        };
        let e = view::cap_form_check(&form, self.caps_max_timeout.get());
        let typed = |text: &str, error: &str| -> SharedString {
            if self.cap_tried.get() || !text.trim().is_empty() {
                error.into()
            } else {
                SharedString::new()
            }
        };
        let filled = !form.name.trim().is_empty() && !form.command.trim().is_empty();
        self.with_caps(|c| {
            c.set_name_error(typed(&form.name, &e.name));
            c.set_summary_error(e.summary.as_str().into());
            c.set_command_error(typed(&form.command, &e.command));
            c.set_params_error(e.params.as_str().into());
            c.set_result_error(e.result.as_str().into());
            c.set_timeout_error(e.timeout.as_str().into());
            c.set_edit_ready(filled && e.none());
        });
        filled && e.none()
    }

    /// `cap add` or `cap edit` of what the dialog holds, once the app found
    /// nothing wrong with it; the node checks it again, and what it refuses
    /// stays in the dialog with its reason.
    fn cap_save(self: &Rc<Self>) {
        if self.with_caps(|c| c.get_edit_busy()) != Some(false) {
            return;
        }
        self.cap_tried.set(true);
        if !self.cap_check() {
            return;
        }
        let (Some(form), Some(new)) = (self.cap_form(), self.with_caps(|c| c.get_edit_new()))
        else {
            return;
        };
        let (args, input) = view::cap_form_args(&form, new);
        self.with_caps(|c| {
            c.set_edit_busy(true);
            c.set_edit_error(SharedString::new());
        });
        let dialog = self.cap_dialogs.get();
        self.command(args, input, move |c, answer| c.cap_saved(dialog, answer));
    }

    /// The answer of the save that `dialog` started. The dialog closes on
    /// success, or keeps the node's reason; when the owner closed it
    /// meanwhile, or opened another, the reason goes to a toast instead and
    /// the other dialog stays as it is.
    pub fn cap_saved(self: &Rc<Self>, dialog: u64, answer: Result<Value, String>) {
        let open =
            dialog == self.cap_dialogs.get() && self.with_caps(|k| k.get_edit_open()) == Some(true);
        if open {
            self.with_caps(|k| k.set_edit_busy(false));
        }
        match answer {
            Ok(v) => {
                if open {
                    self.with_caps(|k| k.set_edit_open(false));
                }
                self.done(&v, "");
            }
            Err(e) if open => {
                self.with_caps(|k| k.set_edit_error(e.into()));
            }
            Err(e) => self.toast(e, Tone::Danger),
        }
        self.caps_load();
    }

    /// The capability dialog that is open now, or was last.
    pub fn cap_dialog_id(&self) -> u64 {
        self.cap_dialogs.get()
    }

    fn ask_cap_remove(&self, name: &str) {
        self.confirm(
            Pending::CapRemove(name.to_string()),
            format!("Remove {name}?"),
            format!("It leaves node.toml, and every center at once. Its switches and rules stay, and count again if you add {name} anew."),
            "Remove",
        );
    }

    pub(super) fn cap_remove(self: &Rc<Self>, name: &str) {
        let args = vec!["cap".into(), "rm".into(), name.into()];
        self.caps_change(args, None, format!("{name} is removed."), |c, e| {
            c.toast(e, Tone::Danger)
        });
    }

    fn program_choose(self: &Rc<Self>) {
        let chooser = self.chooser.borrow().clone();
        self.job(
            move |_| chooser(Choose::Provider),
            |c, picked| match picked {
                Err(e) => c.no_chooser(e),
                Ok(None) => {}
                Ok(Some(path)) => {
                    c.with_caps(|p| p.set_program_exe(path.display().to_string().into()));
                }
            },
        );
    }

    fn program_allow(self: &Rc<Self>) {
        let Some((name, exe)) = self.with_caps(|c| {
            (
                c.get_program_name().trim().to_string(),
                c.get_program_exe().trim().to_string(),
            )
        }) else {
            return;
        };
        if name.is_empty() || exe.is_empty() {
            return;
        }
        self.with_caps(|c| {
            c.set_program_busy(true);
            c.set_program_error(SharedString::new());
        });
        let args = vec![
            "cap".into(),
            "provider".into(),
            "allow".into(),
            "--".into(),
            name.clone(),
            exe,
        ];
        self.command(args, None, move |c, answer| {
            c.with_caps(|p| p.set_program_busy(false));
            match answer {
                Ok(v) => {
                    c.with_caps(|p| {
                        p.set_program_name(SharedString::new());
                        p.set_program_exe(SharedString::new());
                    });
                    c.done(&v, format!("{name} may attach as a provider."));
                }
                Err(e) => {
                    c.with_caps(|p| p.set_program_error(e.into()));
                }
            }
            c.caps_load();
        });
    }

    fn program_remove(self: &Rc<Self>, name: &str) {
        let args = vec![
            "cap".into(),
            "provider".into(),
            "rm".into(),
            "--".into(),
            name.into(),
        ];
        self.caps_change(
            args,
            None,
            format!("{name} is no provider any more; its capabilities left."),
            |c, e| c.toast(e, Tone::Danger),
        );
    }
}

pub(super) fn wire(ctl: &Rc<Ctl>, window: &crate::AppWindow) {
    let k = window.global::<Caps>();
    let c = ctl.clone();
    k.on_pick(move |i| {
        let name = c
            .with_caps(|k| slint::Model::row_data(&k.get_centers(), i as usize))
            .flatten();
        if let Some(name) = name {
            c.with_caps(|k| {
                k.set_current(i);
                k.set_center(name);
            });
            c.caps_load();
        }
    });
    let c = ctl.clone();
    k.on_refresh(move || {
        c.refresh_status();
        c.caps_load();
    });
    let c = ctl.clone();
    k.on_cap_set(move |name, s| c.caps_set(&name, s));
    let c = ctl.clone();
    k.on_program_choose(move || c.program_choose());
    let c = ctl.clone();
    k.on_program_allow(move || c.program_allow());
    let c = ctl.clone();
    k.on_program_remove(move |name| c.program_remove(&name));
    let c = ctl.clone();
    k.on_add(move || c.cap_add());
    let c = ctl.clone();
    k.on_edit(move |name| c.cap_edit(&name));
    let c = ctl.clone();
    k.on_edit_check(move || {
        c.cap_check();
    });
    let c = ctl.clone();
    k.on_edit_save(move || c.cap_save());
    let c = ctl.clone();
    k.on_remove(move |name| c.ask_cap_remove(&name));
}
