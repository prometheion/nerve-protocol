//! The Capabilities page: what the node offers, read with `cap ls`, each
//! unit's switch for one center (`cap set`), and the programs allowed as
//! providers (`cap provider allow` and `rm`).

use std::rc::Rc;

use serde_json::Value;
use slint::{ComponentHandle, ModelRc, SharedString, VecModel};

use super::{Choose, Ctl};
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
        self.job(
            move |r| {
                let mut args = vec!["cap".to_string(), "ls".into()];
                if !center.is_empty() {
                    args.push(format!("--center={center}"));
                }
                (center, r.run(&super::strings(&args)))
            },
            move |c, (center, answer)| c.caps_loaded(asked, &center, answer),
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
                self.with_caps(|c| {
                    c.set_rows(ModelRc::new(VecModel::from(rows)));
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
}
