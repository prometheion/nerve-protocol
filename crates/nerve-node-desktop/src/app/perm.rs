//! The Permissions page: what one center may do, read with `folder ls`,
//! `rule ls`, `cap ls` and `sudo status`, changed with their siblings.

use std::rc::Rc;

use serde_json::Value;
use slint::{ComponentHandle, Model, ModelRc, SharedString, VecModel};

use super::{Choose, Ctl, now_ms};
use crate::{Load, Perm, Tone, view};

const LISTS: [&str; 3] = ["allow", "deny", "sudo"];

/// What `folder ls`, `rule ls`, `cap ls` and `sudo status` answered for the
/// page's center.
pub type PermAnswers = (
    Result<Value, String>,
    Result<Value, String>,
    Result<Value, String>,
    Result<Value, String>,
);

impl Ctl {
    /// The centers to choose from, as the status said them; the page keeps
    /// its center while it is paired.
    pub(super) fn perm_centers(self: &Rc<Self>, names: &[String]) {
        let Some((current, center)) =
            self.with_perm(|p| (p.get_current(), p.get_center().to_string()))
        else {
            return;
        };
        let at = names.iter().position(|n| *n == center);
        let model: Vec<SharedString> = names.iter().map(|n| n.as_str().into()).collect();
        self.with_perm(|p| {
            p.set_centers(ModelRc::new(VecModel::from(model)));
            match at {
                Some(i) => p.set_current(i as i32),
                None => {
                    p.set_current(0);
                    p.set_center(names.first().map(String::as_str).unwrap_or("").into());
                }
            }
        });
        // A center that was unpaired: show the one that takes its place.
        if at.is_none() && !names.is_empty() && (current != 0 || !center.is_empty()) {
            self.perm_load();
        }
        self.perm_mode();
    }

    /// The mode and its end, from the last status.
    fn perm_mode(&self) {
        let center = self
            .with_perm(|p| p.get_center().to_string())
            .unwrap_or_default();
        let st = self.status.borrow();
        let c = st["centers"]
            .as_array()
            .into_iter()
            .flatten()
            .find(|c| c["name"] == center.as_str())
            .cloned()
            .unwrap_or(Value::Null);
        // The installed Linux node runs folder and allowlist mode as
        // nerve-run (nerve_node::account): it names its owner, and a
        // pairing's account, also when `install` found no owner.
        let run = nerve_node::account::RUN_USER;
        let account = c["account"].as_str().unwrap_or_default().to_string();
        let separate = cfg!(target_os = "linux")
            && (st["owner"].is_string()
                || st["centers"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .any(|c| c["account"] == run));
        let built_in = if cfg!(target_os = "linux") && account == run {
            format!(
                "/tmp, /var/tmp and its home {}",
                nerve_node::account::RUN_HOME
            )
        } else {
            String::new()
        };
        // Access nerve-run keeps although it should have lost it, which
        // stops every command of it, goes on every center that runs as it;
        // the failed grants of this center's folders on this one alone: the
        // node's lists are for all of them.
        let texts = |v: &Value| -> Vec<String> {
            v.as_array()
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
                .map(String::from)
                .collect()
        };
        let errors = texts(&st["folder_grants"]["errors"]);
        let stale = texts(&st["folder_grants"]["stale"]);
        let (stale, errors) = view::stale_grants(&stale, &errors);
        let folders: Vec<String> = self
            .with_perm(|p| p.get_folders().iter().map(|f| f.path.to_string()).collect())
            .unwrap_or_default();
        let (stale, errors) = if account == run {
            (
                stale,
                view::grant_errors_for(&errors, &folders, &nerve_node::paths::home_dir()),
            )
        } else {
            (Vec::new(), Vec::new())
        };
        self.with_perm(|p| {
            p.set_mode(c["mode"].as_str().unwrap_or_default().into());
            p.set_mode_until(view::mode_until(&c, now_ms()).into());
            p.set_separate(separate);
            p.set_account(account.as_str().into());
            p.set_as_owner(c["as_owner"] == true);
            p.set_owner_is_root(st["owner_is_root"] == true);
            p.set_built_in(built_in.as_str().into());
            p.set_grant_errors(errors.join("\n").into());
            p.set_stale(stale.join("\n").into());
            // A pairing of the installed Linux node that runs as nerve-run
            // says whether Landlock holds it; any other shows nothing.
            p.set_landlock(c["landlock"] != false);
            p.set_home_warning(
                st["home_warning"]["warning"]
                    .as_str()
                    .unwrap_or_default()
                    .into(),
            );
        });
    }

    /// Allowlist mode as the owner (`mode set allowlist --as-owner`), or as
    /// nerve-run again.
    fn as_owner_set(self: &Rc<Self>, on: bool) {
        let center = self.perm_center();
        let mut args = vec!["mode".into(), "set".into(), "allowlist".into()];
        let root = self.with_perm(|p| p.get_owner_is_root()).unwrap_or(false);
        let said = if on {
            args.push("--as-owner".into());
            let whom = if root { "root" } else { "you" };
            format!("{center}'s allowed commands run as {whom}.")
        } else {
            format!("{center}'s allowed commands run as nerve-run.")
        };
        self.perm_change(args, None, said, |_| {}, |c, e| c.toast(e, Tone::Danger));
    }

    pub(super) fn perm_load(self: &Rc<Self>) {
        let Some(center) = self.with_perm(|p| p.get_center().to_string()) else {
            return;
        };
        if center.is_empty() || self.waiting_for_rights() {
            return;
        }
        let asked = self.perm_asked.get() + 1;
        self.perm_asked.set(asked);
        self.with_perm(|p| p.set_load(Load::Loading));
        self.perm_mode();
        self.job(
            move |r| {
                let center = format!("--center={center}");
                let c = [center.as_str()];
                let ask = |what: &[&str]| r.run(&[what, &c[..]].concat());
                (
                    ask(&["folder", "ls"]),
                    ask(&["rule", "ls"]),
                    ask(&["cap", "ls"]),
                    r.run(&["sudo", "status"]),
                )
            },
            move |c, answers| c.perm_loaded(asked, answers),
        );
    }

    /// The reading of the page that runs now, or ran last.
    pub fn perm_asked(&self) -> u64 {
        self.perm_asked.get()
    }

    /// Shows what reading `asked` of the page found, unless the page asked
    /// again since: two readings run at once when the owner picks one
    /// center and then another, and the one that ends last must not put the
    /// first center's folders and rules under the second one's name.
    pub fn perm_loaded(&self, asked: u64, answers: PermAnswers) {
        if asked != self.perm_asked.get() {
            return;
        }
        let (folders, rules, caps, sudo) = answers;
        let all = folders.and_then(|f| Ok((f, rules?, caps?, sudo?)));
        match all {
            Ok((f, r, k, s)) => {
                self.with_perm(|p| {
                    // A row being edited may be another one now.
                    if !p.get_edit_busy() {
                        p.set_edit_list(-1);
                    }
                    p.set_folders(ModelRc::new(VecModel::from(view::folders(&f))));
                    p.set_allow(ModelRc::new(VecModel::from(view::rule_list_of(
                        &r, "allow",
                    ))));
                    p.set_deny(ModelRc::new(VecModel::from(view::rule_list_of(&r, "deny"))));
                    p.set_guard_missing(view::guard_missing(&r));
                    p.set_guard_older(view::guard_older(&r));
                    p.set_sudo_list(ModelRc::new(VecModel::from(view::rule_list_of(&r, "sudo"))));
                    p.set_caps(ModelRc::new(VecModel::from(view::caps(&k))));
                    p.set_sudo_on(s["sudo"] == "on");
                    p.set_load(Load::Ready);
                    p.set_error(SharedString::new());
                });
                // Its failed grants follow its folders.
                self.perm_mode();
            }
            Err(e) => {
                self.with_perm(|p| {
                    p.set_load(Load::Failed);
                    p.set_error(e.into());
                });
            }
        }
    }

    fn perm_center(&self) -> String {
        self.with_perm(|p| p.get_center().to_string())
            .unwrap_or_default()
    }

    /// A change of the page's center: says `said`, then reads the page
    /// again. `close` runs on success (a dialog that closes).
    fn perm_change(
        self: &Rc<Self>,
        mut args: Vec<String>,
        input: Option<String>,
        said: String,
        close: fn(&Ctl),
        failed: fn(&Ctl, String),
    ) {
        args.push(format!("--center={}", self.perm_center()));
        self.command(args, input, move |c, answer| {
            match answer {
                Ok(v) => {
                    close(c);
                    c.done(&v, said);
                }
                Err(e) => failed(c, e),
            }
            c.refresh_status();
            c.perm_load();
        });
    }

    fn mode_pick(self: &Rc<Self>, mode: &str) {
        if mode == "allowlist" {
            // The tile of the mode it is in: nothing to change, and setting
            // it again would turn "Run them as you" off.
            if self.with_perm(|p| p.get_mode() == "allowlist") == Some(true) {
                return;
            }
            let center = self.perm_center();
            self.perm_change(
                vec!["mode".into(), "set".into(), "allowlist".into()],
                None,
                format!("{center} is in allowlist mode."),
                |_| {},
                |c, e| c.toast(e, Tone::Danger),
            );
            return;
        }
        self.with_perm(|p| {
            p.set_mode_choice(mode.into());
            p.set_mode_timed(false);
            p.set_mode_error(SharedString::new());
            p.set_mode_open(true);
        });
    }

    fn mode_apply(self: &Rc<Self>) {
        let Some((mode, timed, hours)) = self.with_perm(|p| {
            (
                p.get_mode_choice().to_string(),
                p.get_mode_timed(),
                p.get_mode_hours().trim().to_string(),
            )
        }) else {
            return;
        };
        let mut args = vec!["mode".into(), "set".into(), mode.clone()];
        if timed {
            args.push(format!("--for={hours}"));
        }
        let center = self.perm_center();
        let said = if timed {
            format!("{center} is in {mode} mode for {hours} h.")
        } else {
            format!("{center} is in {mode} mode.")
        };
        self.perm_change(
            args,
            None,
            said,
            |c| {
                c.with_perm(|p| p.set_mode_open(false));
            },
            |c, e| {
                c.with_perm(|p| p.set_mode_error(e.into()));
            },
        );
    }

    fn folder_choose(self: &Rc<Self>) {
        let chooser = self.chooser.borrow().clone();
        self.job(
            move |_| chooser(Choose::Folder),
            |c, picked| match picked {
                Err(e) => c.no_chooser(e),
                Ok(None) => {}
                Ok(Some(path)) => {
                    c.with_perm(|p| {
                        p.set_folder_path(path.display().to_string().into());
                        p.set_folder_read(true);
                        p.set_folder_write(false);
                        p.set_folder_execute(false);
                        p.set_folder_error(SharedString::new());
                        p.set_folder_open(true);
                    });
                }
            },
        );
    }

    fn folder_add(self: &Rc<Self>) {
        let Some((path, r, w, x)) = self.with_perm(|p| {
            (
                p.get_folder_path().to_string(),
                p.get_folder_read(),
                p.get_folder_write(),
                p.get_folder_execute(),
            )
        }) else {
            return;
        };
        let mut args = vec!["folder".into(), "add".into(), path.clone()];
        for (on, right) in [(r, "+r"), (w, "+w"), (x, "+x")] {
            if on {
                args.push(right.into());
            }
        }
        self.perm_change(
            args,
            None,
            format!("{path} is added."),
            |c| {
                c.with_perm(|p| p.set_folder_open(false));
            },
            |c, e| {
                c.with_perm(|p| p.set_folder_error(e.into()));
            },
        );
    }

    fn folder_set(self: &Rc<Self>, path: &str, r: bool, w: bool, x: bool) {
        let rights = view::rights(r, w, x);
        let args = vec!["folder".into(), "set".into(), path.into(), rights];
        self.perm_change(
            args,
            None,
            format!("The rights of {path} changed."),
            |_| {},
            |c, e| c.toast(e, Tone::Danger),
        );
    }

    fn folder_remove(self: &Rc<Self>, path: &str) {
        let args = vec!["folder".into(), "rm".into(), path.into()];
        self.perm_change(
            args,
            None,
            format!("{path} is removed."),
            |_| {},
            |c, e| c.toast(e, Tone::Danger),
        );
    }

    /// What the field of `list` holds for a new rule, and its Wildcard.
    fn new_rule(&self, list: i32) -> Option<(String, bool)> {
        self.with_perm(|p| match list {
            0 => (p.get_allow_text(), p.get_allow_wild()),
            1 => (p.get_deny_text(), p.get_deny_wild()),
            _ => (p.get_sudo_text(), p.get_sudo_wild()),
        })
        .map(|(t, w)| (t.trim().to_string(), w))
    }

    fn rule_add(self: &Rc<Self>, list: i32) {
        let Some((text, wildcard)) = self.new_rule(list) else {
            return;
        };
        if text.is_empty() {
            return;
        }
        let word = LISTS[list.clamp(0, 2) as usize];
        let cleared: fn(&Ctl) = match list {
            0 => |c| {
                c.with_perm(|p| {
                    p.set_allow_text(SharedString::new());
                    p.set_allow_wild(false);
                });
            },
            1 => |c| {
                c.with_perm(|p| {
                    p.set_deny_text(SharedString::new());
                    p.set_deny_wild(false);
                });
            },
            _ => |c| {
                c.with_perm(|p| {
                    p.set_sudo_text(SharedString::new());
                    p.set_sudo_wild(false);
                });
            },
        };
        // A pattern for files or another action goes into the list as it
        // is, as `config add` puts it there; `rule remove` takes it out
        // again as `rule ls` shows it.
        if word != "sudo" && view::pattern_rule(&text) {
            let key = format!("center.{}.policy.{word}", self.perm_center());
            let args = vec!["config".into(), "add".into(), "--".into(), key, text];
            self.command(args, None, move |c, answer| {
                match answer {
                    Ok(v) => {
                        cleared(c);
                        c.done(&v, format!("Added to the {word} list."));
                    }
                    Err(e) => c.toast(e, Tone::Danger),
                }
                c.refresh_status();
                c.perm_load();
            });
            return;
        }
        let mut args = vec!["rule".into(), "add".into(), word.into(), text.clone()];
        if wildcard {
            args.push("--wildcard".into());
        }
        self.perm_change(
            args,
            None,
            format!("Added to the {word} list."),
            cleared,
            |c, e| c.toast(e, Tone::Danger),
        );
    }

    /// `rule edit`: the rule in its row becomes what its field holds, in
    /// one change.
    fn rule_edit_save(self: &Rc<Self>) {
        let Some((list, index, text)) = self.with_perm(|p| {
            (
                p.get_edit_list(),
                p.get_edit_index(),
                p.get_edit_text().trim().to_string(),
            )
        }) else {
            return;
        };
        let rules = self.with_perm(|p| match list {
            0 => p.get_allow(),
            1 => p.get_deny(),
            _ => p.get_sudo_list(),
        });
        let Some(old) = rules.and_then(|r| slint::Model::row_data(&r, index as usize)) else {
            return;
        };
        if list < 0 || text.is_empty() || text == old.as_str() {
            self.with_perm(|p| p.set_edit_list(-1));
            return;
        }
        let word = LISTS[list.clamp(0, 2) as usize];
        self.with_perm(|p| p.set_edit_busy(true));
        let args = vec![
            "rule".into(),
            "edit".into(),
            word.into(),
            old.to_string(),
            text,
        ];
        self.perm_change(
            args,
            None,
            "The rule is changed.".into(),
            |c| {
                c.with_perm(|p| {
                    p.set_edit_busy(false);
                    p.set_edit_list(-1);
                });
            },
            |c, e| {
                c.with_perm(|p| p.set_edit_busy(false));
                c.toast(e, Tone::Danger);
            },
        );
    }

    fn rule_remove(self: &Rc<Self>, list: i32, rule: &str) {
        let word = LISTS[list.clamp(0, 2) as usize];
        let args = vec!["rule".into(), "rm".into(), word.into(), rule.into()];
        self.perm_change(
            args,
            None,
            format!("Removed from the {word} list."),
            |_| {},
            |c, e| c.toast(e, Tone::Danger),
        );
    }

    fn cap_set(self: &Rc<Self>, name: &str, setting: i32) {
        let word = view::cap_word(setting);
        let args = vec!["cap".into(), "set".into(), name.into(), word.into()];
        self.perm_change(
            args,
            None,
            format!("{name} is {word}."),
            |_| {},
            |c, e| c.toast(e, Tone::Danger),
        );
    }

    fn sudo_confirm(self: &Rc<Self>) {
        let Some(password) = self.with_perm(|p| p.get_sudo_password().to_string()) else {
            return;
        };
        self.with_perm(|p| {
            p.set_sudo_busy(true);
            p.set_sudo_error(SharedString::new());
        });
        // The password goes in on stdin, never as an argument.
        self.command(
            vec!["sudo".into(), "on".into()],
            Some(password),
            |c, answer| {
                c.with_perm(|p| {
                    p.set_sudo_busy(false);
                    p.set_sudo_password(SharedString::new());
                });
                match answer {
                    Ok(v) => {
                        c.with_perm(|p| p.set_sudo_open(false));
                        c.done(&v, "Sudo is on.");
                    }
                    Err(e) => {
                        c.with_perm(|p| p.set_sudo_error(e.into()));
                    }
                }
                c.perm_load();
            },
        );
    }

    /// Puts the guard's deny rules the page's center lacks on its list.
    fn guard_add(self: &Rc<Self>) {
        self.with_perm(|p| p.set_guard_busy(true));
        self.perm_change(
            vec!["rule".into(), "guard".into()],
            None,
            String::new(),
            |c| {
                c.with_perm(|p| p.set_guard_busy(false));
            },
            |c, e| {
                c.with_perm(|p| p.set_guard_busy(false));
                c.toast(e, Tone::Danger);
            },
        );
    }

    fn sudo_off(self: &Rc<Self>) {
        self.command(vec!["sudo".into(), "off".into()], None, |c, answer| {
            match answer {
                Ok(v) => c.done(&v, "Sudo is off."),
                Err(e) => c.toast(e, Tone::Danger),
            }
            c.perm_load();
        });
    }
}

pub(super) fn wire(ctl: &Rc<Ctl>, window: &crate::AppWindow) {
    let p = window.global::<Perm>();
    let c = ctl.clone();
    p.on_pick(move |i| {
        let name = c
            .with_perm(|p| slint::Model::row_data(&p.get_centers(), i as usize))
            .flatten();
        if let Some(name) = name {
            c.with_perm(|p| {
                p.set_current(i);
                p.set_center(name);
            });
            c.perm_load();
        }
    });
    let c = ctl.clone();
    p.on_refresh(move || {
        c.refresh_status();
        c.perm_load();
    });
    let c = ctl.clone();
    p.on_mode_pick(move |m| c.mode_pick(&m));
    let c = ctl.clone();
    p.on_mode_apply(move || c.mode_apply());
    let c = ctl.clone();
    p.on_as_owner_set(move |on| c.as_owner_set(on));
    let c = ctl.clone();
    p.on_folder_choose(move || c.folder_choose());
    let c = ctl.clone();
    p.on_folder_add(move || c.folder_add());
    let c = ctl.clone();
    p.on_folder_set(move |path, r, w, x| c.folder_set(&path, r, w, x));
    let c = ctl.clone();
    p.on_folder_remove(move |path| c.folder_remove(&path));
    let c = ctl.clone();
    p.on_rule_add(move |list| c.rule_add(list));
    let c = ctl.clone();
    p.on_rule_edit_save(move || c.rule_edit_save());
    let c = ctl.clone();
    p.on_rule_remove(move |list, rule| c.rule_remove(list, &rule));
    let c = ctl.clone();
    p.on_cap_set(move |name, s| c.cap_set(&name, s));
    let c = ctl.clone();
    p.on_sudo_ask(move || {
        c.with_perm(|p| {
            p.set_sudo_password(SharedString::new());
            p.set_sudo_error(SharedString::new());
            p.set_sudo_open(true);
        });
    });
    let c = ctl.clone();
    p.on_sudo_confirm(move || c.sudo_confirm());
    let c = ctl.clone();
    p.on_sudo_off(move || c.sudo_off());
    let c = ctl.clone();
    p.on_guard_add(move || c.guard_add());
}
