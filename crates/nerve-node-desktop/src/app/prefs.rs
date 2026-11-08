//! The Settings page: the machine's name and where its keys live (`config`),
//! the proxy, the relay, backups, and any setting by its name.

use std::rc::Rc;

use serde_json::{Value, json};
use slint::{ComponentHandle, Model, ModelRc, SharedString, VecModel};

use super::{Choose, Ctl, Pending};
use crate::{Limit, Load, Pick, Prefs, Tone, view};

/// The words of `log.level`, as Settings' choice orders them.
const LOG_LEVELS: [&str; 4] = ["error", "warn", "info", "debug"];

/// A limit of Settings: its setting, its words, its unit, and how many of
/// the setting's units make one of the field's (seconds in a minute).
type LimitDef = (&'static str, &'static str, &'static str, u64);

const MIB: u64 = 1024 * 1024;

/// The limits of Settings by group, as `limits_save` names them.
const LIMITS: [(&str, &[LimitDef]); 4] = [
    (
        "command",
        &[
            ("limits.command.memory_mb", "Memory", "MiB", 1),
            (
                "limits.command.memory_max_mb",
                "Memory a call may ask for",
                "MiB",
                1,
            ),
            ("limits.command.cpu_percent", "CPU", "% of a CPU", 1),
            (
                "limits.command.cpu_max_percent",
                "CPU a call may ask for",
                "% of a CPU",
                1,
            ),
            ("limits.command.processes", "Processes", "", 1),
            (
                "limits.command.processes_max",
                "Processes a call may ask for",
                "",
                1,
            ),
        ],
    ),
    (
        "time",
        &[
            (
                "limits.default_timeout_secs",
                "When the call names none",
                "minutes",
                60,
            ),
            ("limits.max_timeout_secs", "At most", "minutes", 60),
        ],
    ),
    (
        "node",
        &[
            ("limits.max_running", "Commands at once", "", 1),
            (
                "limits.output_cap_bytes",
                "Output kept of a command",
                "MiB",
                MIB,
            ),
        ],
    ),
    (
        "relay",
        &[
            ("relay.max_links", "Tunnels at once", "", 1),
            ("relay.max_links_per_node", "Tunnels of one node", "", 1),
            (
                "relay.max_opens_per_minute",
                "Tunnels one node opens",
                "a minute",
                1,
            ),
        ],
    ),
];

/// The defaults of the limits, in the shape of the settings.
fn limit_defaults() -> Value {
    let l = nerve_policy::config::Limits::default();
    let c = l.command;
    let r = nerve_policy::config::Relay::default();
    json!({
        "limits": {
            "max_running": l.max_running,
            "output_cap_bytes": l.output_cap_bytes,
            "default_timeout_secs": l.default_timeout_secs,
            "max_timeout_secs": l.max_timeout_secs,
            "command": {
                "memory_mb": c.memory_mb,
                "memory_max_mb": c.memory_max_mb,
                "cpu_percent": c.cpu_percent,
                "cpu_max_percent": c.cpu_max_percent,
                "processes": c.processes,
                "processes_max": c.processes_max,
            },
        },
        "relay": {
            "max_links": r.max_links,
            "max_links_per_node": r.max_links_per_node,
            "max_opens_per_minute": r.max_opens_per_minute,
        },
    })
}

/// The setting `key` of `v`, by its dotted name.
fn at<'a>(v: &'a Value, key: &str) -> &'a Value {
    key.split('.').fold(v, |v, k| &v[k])
}

/// `n` of the setting's units in the field's, whole when it is.
pub(crate) fn in_unit(n: u64, scale: u64) -> String {
    if n.is_multiple_of(scale) {
        (n / scale).to_string()
    } else {
        let f = format!("{:.2}", n as f64 / scale as f64);
        f.trim_end_matches('0').trim_end_matches('.').to_string()
    }
}

/// What a field holds in the setting's units, or why not.
pub(crate) fn from_unit(text: &str, scale: u64, label: &str) -> Result<u64, String> {
    let t = text.trim();
    let n: f64 = t
        .parse()
        .ok()
        .filter(|n: &f64| n.is_finite() && *n > 0.0)
        .ok_or_else(|| format!("{label}: {t:?} is not a number above 0"))?;
    Ok((n * scale as f64).round() as u64)
}

/// The rows of the group `defs`: each limit as `set` has it (the node's
/// settings: `limits` and `relay`), else its default.
pub(crate) fn limit_rows(defs: &[LimitDef], set: &Value) -> Vec<Limit> {
    let defaults = limit_defaults();
    defs.iter()
        .map(|&(key, label, unit, scale)| {
            let default = at(&defaults, key).as_u64().unwrap_or_default();
            let value = at(set, key).as_u64().unwrap_or(default);
            let shown: SharedString = in_unit(value, scale).into();
            Limit {
                key: key.into(),
                label: label.into(),
                unit: unit.into(),
                value: shown.clone(),
                was: shown,
                default: in_unit(default, scale).into(),
            }
        })
        .collect()
}

/// The commands that save what changed in `rows`: `config set`, or `config
/// unset` for an emptied field, so the default counts again.
pub(crate) fn limit_changes(rows: &[Limit]) -> Result<Vec<Vec<String>>, String> {
    let mut out = Vec::new();
    for row in rows {
        if row.value == row.was {
            continue;
        }
        let scale = LIMITS
            .iter()
            .flat_map(|(_, defs)| defs.iter())
            .find(|d| d.0 == row.key.as_str())
            .map_or(1, |d| d.3);
        let key = row.key.to_string();
        if row.value.trim().is_empty() {
            if row.was != row.default {
                out.push(vec!["config".into(), "unset".into(), key]);
            }
            continue;
        }
        let n = from_unit(&row.value, scale, &row.label)?;
        out.push(vec!["config".into(), "set".into(), key, n.to_string()]);
    }
    Ok(out)
}

impl Ctl {
    pub(super) fn prefs_load(self: &Rc<Self>) {
        if self.waiting_for_rights() {
            return;
        }
        let host = nerve_node::descriptor::node_name(&nerve_policy::NodeConfig::default());
        self.with_prefs(|p| {
            p.set_name_shown(host.as_str().into());
            p.set_load(Load::Loading);
        });
        self.with_prefs(|p| {
            p.set_shell_default(nerve_node::exec::shell_command(None, "").0.as_str().into())
        });
        self.job(
            |r| {
                (
                    (
                        r.run(&["config", "get", "node.name"]),
                        r.run(&["config", "get", "machine.secret_storage"]),
                        r.run(&["proxy"]),
                        r.run(&["relay"]),
                        r.run(&["config", "get", "machine.user"]),
                    ),
                    (
                        r.run(&["config", "get", "limits"]),
                        r.run(&["config", "get", "log.level"]),
                        r.run(&["config", "get", "machine.shell"]),
                    ),
                )
            },
            |c, ((name, storage, proxy, relay, account), (limits, level, shell))| {
                // Not set: the default, which the CLI leaves out.
                let value =
                    |v: Result<Value, String>| v.map(|v| v["value"].clone()).unwrap_or_default();
                let level = value(level);
                let shell = value(shell);
                let set = json!({
                    "limits": value(limits),
                    "relay": relay.as_ref().cloned().unwrap_or_default(),
                });
                c.with_prefs(|p| {
                    let level = LOG_LEVELS.iter().position(|l| level == *l).unwrap_or(2);
                    p.set_log_level(level as i32);
                    p.set_shell(shell.as_str().unwrap_or_default().into());
                    for (group, defs) in LIMITS {
                        let rows = ModelRc::new(VecModel::from(limit_rows(defs, &set)));
                        match group {
                            "command" => p.set_limits_command(rows),
                            "time" => p.set_limits_time(rows),
                            "node" => p.set_limits_node(rows),
                            _ => p.set_limits_relay(rows),
                        }
                    }
                });
                // A setting that is not set has its default: no name, keys
                // in files.
                let name = name
                    .ok()
                    .and_then(|v| v["value"].as_str().map(str::to_string))
                    .unwrap_or_default();
                if let Ok(v) = &storage {
                    c.keyring_state(v);
                }
                let keyring = storage.is_ok_and(|v| v["value"] == "keyring");
                let all = proxy.and_then(|p| Ok((p, relay?)));
                // Not set: no account, and the node runs no command.
                let account = account
                    .ok()
                    .and_then(|v| v["value"].as_str().map(str::to_string))
                    .unwrap_or_default();
                c.with_prefs(|p| {
                    p.set_name(name.into());
                    p.set_storage(i32::from(keyring));
                    p.set_account(account.into());
                });
                match all {
                    Ok((proxy, relay)) => {
                        let s = |v: &serde_json::Value| v.as_str().unwrap_or_default().to_string();
                        let headers: Vec<String> = proxy["headers"]
                            .as_array()
                            .into_iter()
                            .flatten()
                            .filter_map(|h| h.as_str().map(str::to_string))
                            .collect();
                        c.with_prefs(|p| {
                            p.set_proxy(s(&proxy["proxy"]).into());
                            p.set_proxy_pin(s(&proxy["pin"]).into());
                            p.set_proxy_login(s(&proxy["login"]).into());
                            p.set_proxy_headers(headers.join(", ").into());
                            p.set_proxy_problem(s(&proxy["problem"]).into());
                            p.set_relay_listen(s(&relay["listen"]).into());
                            p.set_relay_status(s(&relay["status"]).into());
                            p.set_relay_pin(s(&relay["pin"]).into());
                            p.set_relay_nodes(ModelRc::new(VecModel::from(view::relay_nodes(
                                &relay,
                            ))));
                            p.set_tunnels(ModelRc::new(VecModel::from(view::tunnels(
                                &relay,
                                super::now_ms(),
                            ))));
                            p.set_load(Load::Ready);
                            p.set_error(SharedString::new());
                        });
                        *c.relay_address.borrow_mut() = s(&relay["address"]);
                        c.via_relay(&proxy);
                    }
                    Err(e) => {
                        c.with_prefs(|p| {
                            p.set_load(Load::Failed);
                            p.set_error(e.into());
                        });
                    }
                }
            },
        );
    }

    /// Whether this node reaches its centers through a relay (its proxy is
    /// one: https, with a pin and a login), where, and how its links fare.
    fn via_relay(&self, proxy: &Value) {
        let (via, address, node) = view::relay_of(proxy);
        let st = self.status.borrow();
        let running = st["daemon"] == "running";
        let all = st["centers"].as_array().map_or(0, Vec::len);
        let up = st["centers"]
            .as_array()
            .into_iter()
            .flatten()
            .filter(|c| c["status"] == "connected")
            .count();
        let (state, tone) = if !running {
            ("The node does not run.".to_string(), Tone::Warn)
        } else if all == 0 {
            ("No center paired yet.".to_string(), Tone::Neutral)
        } else if up == all {
            (
                format!("{up} of {all} centers linked through it."),
                Tone::Ok,
            )
        } else if up > 0 {
            (
                format!("{up} of {all} centers linked through it."),
                Tone::Warn,
            )
        } else {
            ("No center linked through it yet.".to_string(), Tone::Danger)
        };
        self.with_prefs(|p| {
            p.set_via_relay(via);
            p.set_via_address(address.into());
            p.set_via_node(node.into());
            p.set_via_state(state.into());
            p.set_via_tone(tone);
        });
    }

    /// Opens the dialog that takes a relay's link.
    pub(super) fn connect_start(&self) {
        self.with_prefs(|p| {
            p.set_connect_link(SharedString::new());
            p.set_connect_apart(false);
            p.set_connect_address(SharedString::new());
            p.set_connect_node(SharedString::new());
            p.set_connect_token(SharedString::new());
            p.set_connect_pin(SharedString::new());
            p.set_connect_summary(SharedString::new());
            p.set_connect_error(SharedString::new());
            p.set_connect_busy(false);
            p.set_connect_open(true);
        });
    }

    /// What a pasted link says, once it reads as a relay's link.
    pub(super) fn connect_read(&self, link: &str) {
        let summary = match nerve_proto::link::RelayLink::parse(link) {
            Ok(l) => format!("The relay at {}, this node as {} there.", l.address, l.node),
            Err(_) => String::new(),
        };
        self.with_prefs(|p| {
            p.set_connect_summary(summary.into());
            p.set_connect_error(SharedString::new());
        });
    }

    /// `proxy set` with the relay as the proxy: its address with this
    /// node's name, and the pin as arguments, the token on stdin, never as
    /// an argument, which every process of the machine can read.
    fn connect_save(self: &Rc<Self>) {
        let Some((apart, link, address, node, token, pin)) = self.with_prefs(|p| {
            (
                p.get_connect_apart(),
                p.get_connect_link().trim().to_string(),
                p.get_connect_address().trim().to_string(),
                p.get_connect_node().trim().to_string(),
                p.get_connect_token().trim().to_string(),
                p.get_connect_pin().trim().to_string(),
            )
        }) else {
            return;
        };
        let parsed = if apart {
            // The parts as one link, so they are read as the link is.
            nerve_proto::link::RelayLink::parse(
                &nerve_proto::link::RelayLink {
                    address,
                    node,
                    token,
                    pin,
                }
                .render(),
            )
        } else {
            nerve_proto::link::RelayLink::parse(&link)
        };
        let l = match parsed {
            Ok(l) => l,
            Err(e) => {
                self.with_prefs(|p| p.set_connect_error(view::sentence_of(&e).into()));
                return;
            }
        };
        let args = vec![
            "proxy".into(),
            "set".into(),
            format!("https://{}@{}", l.node, l.address),
            // `=`: a pin starting with `-` is no flag to the CLI then. A
            // user name without a password: the token comes on stdin.
            format!("--pin={}", l.pin),
        ];
        self.with_prefs(|p| {
            p.set_connect_busy(true);
            p.set_connect_error(SharedString::new());
        });
        let address = l.address.clone();
        self.command(args, Some(l.token), move |c, answer| {
            c.with_prefs(|p| p.set_connect_busy(false));
            match answer {
                Ok(v) => {
                    c.with_prefs(|p| {
                        p.set_connect_open(false);
                        p.set_connect_token(SharedString::new());
                        p.set_connect_link(SharedString::new());
                    });
                    c.done(
                        &v,
                        format!("This node reaches its centers through {address} now."),
                    );
                }
                Err(e) => {
                    c.with_prefs(|p| p.set_connect_error(e.into()));
                }
            }
            c.prefs_load();
            c.refresh_status();
        });
    }

    /// Opens the dialog that makes a node's link: a new node, or with
    /// `token_for` a new link for that one. The address is the relay's
    /// guess (`relay`), which the owner may change.
    fn relay_add_start(&self, token_for: &str) {
        let address = self.relay_address.borrow().clone();
        self.with_prefs(|p| {
            p.set_relay_add_for(token_for.into());
            p.set_relay_add_name(SharedString::new());
            p.set_relay_add_address(address.into());
            p.set_relay_add_error(SharedString::new());
            p.set_relay_add_busy(false);
            p.set_relay_add_open(true);
        });
    }

    /// `relay add` or `relay token` with the address, then the link once.
    fn relay_add_confirm(self: &Rc<Self>) {
        let Some((token_for, name, address)) = self.with_prefs(|p| {
            (
                p.get_relay_add_for().to_string(),
                p.get_relay_add_name().trim().to_string(),
                p.get_relay_add_address().trim().to_string(),
            )
        }) else {
            return;
        };
        let (mut args, title) = if token_for.is_empty() {
            (
                vec!["relay".into(), "add".into()],
                format!("Link for {name}"),
            )
        } else {
            (
                vec!["relay".into(), "token".into()],
                format!("New link for {token_for}"),
            )
        };
        if !address.is_empty() {
            args.push(format!("--address={address}"));
        }
        // The name is typed, so it goes behind `--`: no value reads as a flag.
        args.extend([
            "--".into(),
            if token_for.is_empty() {
                name
            } else {
                token_for
            },
        ]);
        self.with_prefs(|p| {
            p.set_relay_add_busy(true);
            p.set_relay_add_error(SharedString::new());
        });
        self.relay_token_shown(args, title);
    }

    /// A change on the Settings page: says `said` (or what the command
    /// said, when `said` is empty), then reads the page again.
    fn prefs_change(self: &Rc<Self>, args: Vec<String>, input: Option<String>, said: String) {
        self.command(args, input, move |c, answer| {
            match answer {
                Ok(v) => c.done(&v, said),
                Err(e) => c.toast(e, Tone::Danger),
            }
            c.prefs_load();
            c.refresh_status();
        });
    }

    fn name_save(self: &Rc<Self>, name: &str) {
        let name = name.trim();
        let args = if name.is_empty() {
            vec!["config".into(), "unset".into(), "node.name".into()]
        } else {
            vec![
                "config".into(),
                "set".into(),
                "--".into(),
                "node.name".into(),
                name.into(),
            ]
        };
        self.prefs_change(
            args,
            None,
            "The name is saved; centers see it at the next link.".into(),
        );
    }

    fn storage_set(self: &Rc<Self>, i: i32) {
        let to = if i == 1 { "keyring" } else { "file" };
        let args = vec![
            "config".into(),
            "set".into(),
            "machine.secret_storage".into(),
            to.into(),
        ];
        self.prefs_change(args, None, String::new());
    }

    fn proxy_edit(&self) {
        self.with_prefs(|p| {
            p.set_proxy_new_url(p.get_proxy());
            p.set_proxy_new_pin(p.get_proxy_pin());
            p.set_proxy_new_headers(SharedString::new());
            p.set_proxy_new_password(SharedString::new());
            p.set_proxy_error(SharedString::new());
            p.set_proxy_open(true);
        });
    }

    fn proxy_set(self: &Rc<Self>) {
        let Some((url, pin, headers, password)) = self.with_prefs(|p| {
            (
                p.get_proxy_new_url().trim().to_string(),
                p.get_proxy_new_pin().trim().to_string(),
                p.get_proxy_new_headers().to_string(),
                p.get_proxy_new_password().to_string(),
            )
        }) else {
            return;
        };
        // The address (a relay link holds a token), the password and the
        // header values go on stdin, never as arguments, which every
        // process of the machine can read.
        let (url, password) = view::proxy_login(&url, &password);
        if password.is_some() && !nerve_node::cli::proxy_wants_password(&url) {
            self.with_prefs(|p| {
                p.set_proxy_error(
                    "A password needs the user's name in the address: http://user@host:port."
                        .into(),
                )
            });
            return;
        }
        let (args, input) = view::proxy_set_command(&url, &pin, &headers, password);
        self.command(args, Some(input), |c, answer| {
            match answer {
                Ok(v) => {
                    c.with_prefs(|p| {
                        p.set_proxy_open(false);
                        p.set_proxy_new_password(SharedString::new());
                    });
                    c.done(&v, "");
                }
                Err(e) => {
                    c.with_prefs(|p| p.set_proxy_error(e.into()));
                }
            }
            c.prefs_load();
        });
    }

    /// Opens the dialog of the relayed node in row `i`: the centers this
    /// node has paired, and those the relayed node may reach, ticked.
    fn relay_edit(&self, i: usize) {
        let Some(row) = self
            .with_prefs(|p| p.get_relay_nodes().row_data(i))
            .flatten()
        else {
            return;
        };
        let reach: Vec<String> = row.centers.iter().map(|c| c.to_string()).collect();
        let mut names = self.centers.borrow().clone();
        // One it may reach that is no longer paired stays in sight.
        for c in &reach {
            if !names.contains(c) {
                names.push(c.clone());
            }
        }
        let picks: Vec<Pick> = names
            .into_iter()
            .map(|n| Pick {
                on: reach.contains(&n),
                name: n.into(),
            })
            .collect();
        self.with_prefs(|p| {
            p.set_relay_edit_name(row.name.clone());
            p.set_relay_edit_centers(ModelRc::new(VecModel::from(picks)));
            p.set_relay_edit_own(row.own_limits);
            p.set_relay_edit_links(row.max_links.to_string().into());
            p.set_relay_edit_opens(row.max_opens.to_string().into());
            p.set_relay_edit_error(SharedString::new());
            p.set_relay_edit_busy(false);
            p.set_relay_edit_open(true);
        });
    }

    fn relay_edit_pick(&self, i: usize, on: bool) {
        self.with_prefs(|p| {
            let picks = p.get_relay_edit_centers();
            if let Some(mut pick) = picks.row_data(i) {
                pick.on = on;
                picks.set_row_data(i, pick);
            }
        });
    }

    /// `relay set`: the centers it may reach, and its own limits or the
    /// relay's again.
    fn relay_edit_save(self: &Rc<Self>) {
        let Some((name, centers, own, links, opens)) = self.with_prefs(|p| {
            (
                p.get_relay_edit_name().to_string(),
                p.get_relay_edit_centers()
                    .iter()
                    .filter(|c| c.on)
                    .map(|c| c.name.to_string())
                    .collect::<Vec<_>>(),
                p.get_relay_edit_own(),
                p.get_relay_edit_links().trim().to_string(),
                p.get_relay_edit_opens().trim().to_string(),
            )
        }) else {
            return;
        };
        // The flags come first and the name behind `--`, so the name is
        // never read as a flag.
        let mut set = vec!["relay".to_string(), "set".into()];
        if centers.is_empty() {
            set.push("--to=*".into());
        }
        for c in centers {
            set.push(format!("--to={c}"));
        }
        let (links, opens) = match own {
            true => (links, opens),
            false => ("default".into(), "default".into()),
        };
        set.extend([
            format!("--max-links={links}"),
            format!("--max-opens-per-minute={opens}"),
        ]);
        set.extend(["--".into(), name.clone()]);
        let failed = |c: &Rc<Ctl>, e: String| {
            c.with_prefs(|p| {
                p.set_relay_edit_busy(false);
                p.set_relay_edit_error(e.into());
            });
            c.prefs_load();
        };
        self.with_prefs(|p| {
            p.set_relay_edit_busy(true);
            p.set_relay_edit_error(SharedString::new());
        });
        self.command(set, None, move |c, answer| match answer {
            Ok(v) => {
                c.with_prefs(|p| {
                    p.set_relay_edit_busy(false);
                    p.set_relay_edit_open(false);
                });
                c.done(&v, format!("{name}'s centers and limits are saved."));
                c.prefs_load();
            }
            Err(e) => failed(c, e),
        });
    }

    /// A relay change whose answer holds a link shown once.
    fn relay_token_shown(self: &Rc<Self>, args: Vec<String>, title: String) {
        self.command(args, None, move |c, answer| {
            c.with_prefs(|p| p.set_relay_add_busy(false));
            match answer {
                Ok(v) => {
                    c.with_prefs(|p| p.set_relay_add_open(false));
                    let (mut text, copy) = view::relay_token(&v);
                    if super::waits_for_start(&v) {
                        text.push_str(" The relay takes it when this node starts.");
                    }
                    c.show_once(&title, super::KEY_NOTE, &text, &copy);
                }
                Err(e) => {
                    c.with_prefs(|p| p.set_relay_add_error(e.into()));
                }
            }
            c.prefs_load();
        });
    }

    fn log_level_set(self: &Rc<Self>, i: i32) {
        let Some(level) = LOG_LEVELS.get(i as usize) else {
            return;
        };
        let args = vec![
            "config".into(),
            "set".into(),
            "log.level".into(),
            (*level).into(),
        ];
        self.prefs_change(args, None, String::new());
    }

    fn shell_save(self: &Rc<Self>) {
        let shell = self
            .with_prefs(|p| p.get_shell().trim().to_string())
            .unwrap_or_default();
        let args = if shell.is_empty() {
            vec!["config".into(), "unset".into(), "machine.shell".into()]
        } else {
            vec![
                "config".into(),
                "set".into(),
                "--".into(),
                "machine.shell".into(),
                shell,
            ]
        };
        self.prefs_change(args, None, String::new());
    }

    /// The model of the limits of `group`.
    fn limits_of(&self, group: &str) -> Option<ModelRc<Limit>> {
        self.with_prefs(|p| match group {
            "command" => p.get_limits_command(),
            "time" => p.get_limits_time(),
            "node" => p.get_limits_node(),
            _ => p.get_limits_relay(),
        })
    }

    fn limit_edit(&self, group: &str, i: usize, text: SharedString) {
        let Some(rows) = self.limits_of(group) else {
            return;
        };
        if let Some(mut row) = rows.row_data(i) {
            row.value = text;
            rows.set_row_data(i, row);
        }
    }

    /// Saves the changed limits of `group`, one command each, and stops at
    /// the first the node refuses.
    fn limits_save(self: &Rc<Self>, group: &str) {
        let Some(rows) = self.limits_of(group) else {
            return;
        };
        let rows: Vec<Limit> = rows.iter().collect();
        let changes = match limit_changes(&rows) {
            Ok(c) => c,
            Err(e) => {
                self.with_prefs(|p| p.set_limits_error(e.into()));
                return;
            }
        };
        self.with_prefs(|p| p.set_limits_error(SharedString::new()));
        if changes.is_empty() {
            return;
        }
        self.with_prefs(|p| p.set_limits_busy(group.into()));
        self.limits_apply(changes, None);
    }

    fn limits_apply(self: &Rc<Self>, mut changes: Vec<Vec<String>>, last: Option<Value>) {
        if changes.is_empty() {
            self.with_prefs(|p| p.set_limits_busy(SharedString::new()));
            if let Some(v) = last {
                self.done(&v, "The limits are saved.");
            }
            self.prefs_load();
            return;
        }
        let args = changes.remove(0);
        self.command(args, None, move |c, answer| match answer {
            Ok(v) => c.limits_apply(changes, Some(v)),
            Err(e) => {
                c.with_prefs(|p| {
                    p.set_limits_busy(SharedString::new());
                    p.set_limits_error(e.into());
                });
                c.prefs_load();
            }
        });
    }

    fn raw_get(self: &Rc<Self>) {
        let key = self
            .with_prefs(|p| p.get_raw_key().trim().to_string())
            .unwrap_or_default();
        if key.is_empty() {
            return;
        }
        self.command(
            vec!["config".into(), "get".into(), key],
            None,
            |c, answer| {
                c.with_prefs(|p| match answer {
                    Ok(v) => {
                        p.set_raw_shown(view::setting(&v["value"]).into());
                        p.set_raw_error(SharedString::new());
                    }
                    Err(e) => {
                        p.set_raw_shown(SharedString::new());
                        p.set_raw_error(e.into());
                    }
                });
            },
        );
    }

    /// `config set`, `unset`, `add` or `remove` (`verb`) of the setting
    /// the page names.
    fn raw_change(self: &Rc<Self>, verb: &'static str) {
        let Some((key, value)) = self.with_prefs(|p| {
            (
                p.get_raw_key().trim().to_string(),
                p.get_raw_value().to_string(),
            )
        }) else {
            return;
        };
        let mut args = vec!["config".into(), verb.into(), "--".into(), key];
        if verb != "unset" {
            args.push(value);
        }
        self.command(args, None, |c, answer| {
            match answer {
                Ok(v) => {
                    c.with_prefs(|p| {
                        p.set_raw_value(SharedString::new());
                        p.set_raw_error(SharedString::new());
                    });
                    c.done(&v, "");
                    c.raw_get();
                }
                Err(e) => {
                    c.with_prefs(|p| p.set_raw_error(e.into()));
                }
            }
            c.refresh_status();
        });
    }

    /// `install` again with the account's new password on stdin: on
    /// Windows the service starts commands with it.
    fn account_password_save(self: &Rc<Self>) {
        let Some(password) = self.with_prefs(|p| p.get_account_password().to_string()) else {
            return;
        };
        if password.is_empty() {
            return;
        }
        // No account yet: install takes the user of the app, as at install.
        let account = self
            .with_prefs(|p| p.get_account().to_string())
            .filter(|a| !a.is_empty())
            .or_else(|| self.with_install(|i| i.get_account().to_string()))
            .unwrap_or_default();
        self.account_change(
            vec!["install".into()],
            Some(password),
            format!("The service has the new password of {account}"),
        );
    }

    fn account_change(self: &Rc<Self>, args: Vec<String>, input: Option<String>, title: String) {
        self.with_prefs(|p| {
            p.set_account_busy(true);
            p.set_account_error(SharedString::new());
        });
        self.command(args, input, move |c, answer| {
            c.with_prefs(|p| {
                p.set_account_busy(false);
                p.set_account_password(SharedString::new());
            });
            match answer {
                Ok(v) => {
                    let (_, warnings) = super::install::steps(&v);
                    // install says a password that does not log the account
                    // on as a warning, and goes on without it.
                    if let Some(no) = warnings
                        .iter()
                        .find(|w| w.starts_with("no account for commands"))
                    {
                        c.with_prefs(|p| p.set_account_error(no.as_str().into()));
                    } else if warnings.is_empty() {
                        c.toast(format!("{title}."), Tone::Ok);
                    } else {
                        c.show_once(&title, "", &warnings.join("\n"), "");
                    }
                }
                Err(e) => {
                    c.with_prefs(|p| p.set_account_error(e.into()));
                }
            }
            c.prefs_load();
        });
    }

    fn backup_choose(self: &Rc<Self>, restore: bool) {
        let chooser = self.chooser.borrow().clone();
        let what = if restore {
            Choose::OpenBackup
        } else {
            Choose::SaveBackup
        };
        self.job(
            move |_| chooser(what),
            move |c, picked| {
                let path = match picked {
                    Ok(Some(path)) => path,
                    Ok(None) => return,
                    Err(e) => return c.no_chooser(e),
                };
                let file: SharedString = path.display().to_string().into();
                c.with_prefs(|p| {
                    if restore {
                        p.set_restore_file(file);
                        p.set_restore_pass(SharedString::new());
                        p.set_restore_replace(false);
                        p.set_restore_without_proxy(false);
                        p.set_restore_in_files(false);
                        p.set_restore_error(SharedString::new());
                        p.set_restore_open(true);
                    } else {
                        p.set_backup_file(file);
                        p.set_backup_pass(SharedString::new());
                        p.set_backup_pass2(SharedString::new());
                        p.set_backup_keyring(false);
                        p.set_backup_error(SharedString::new());
                        p.set_backup_open(true);
                    }
                });
            },
        );
    }

    fn backup_confirm(self: &Rc<Self>) {
        let Some((file, pass, again, keyring)) = self.with_prefs(|p| {
            (
                p.get_backup_file().to_string(),
                p.get_backup_pass().to_string(),
                p.get_backup_pass2().to_string(),
                p.get_backup_keyring(),
            )
        }) else {
            return;
        };
        if pass != again {
            self.with_prefs(|p| p.set_backup_error("The two passphrases differ.".into()));
            return;
        }
        // The system's save dialog asked before it named a file that is
        // there.
        let mut args = vec!["backup".into(), file, "--overwrite".into()];
        if keyring {
            args.push("--include-keyring".into());
        }
        self.with_prefs(|p| p.set_backup_busy(true));
        self.command(args, Some(pass), |c, answer| {
            c.with_prefs(|p| {
                p.set_backup_busy(false);
                p.set_backup_pass(SharedString::new());
                p.set_backup_pass2(SharedString::new());
            });
            match answer {
                Ok(v) => {
                    c.with_prefs(|p| p.set_backup_open(false));
                    c.show_once("The backup is written", "", &view::backup_written(&v), "");
                }
                Err(e) => {
                    c.with_prefs(|p| p.set_backup_error(e.into()));
                }
            }
        });
    }

    fn restore_confirm(self: &Rc<Self>) {
        let Some((file, pass, replace, without_proxy, in_files)) = self.with_prefs(|p| {
            (
                p.get_restore_file().to_string(),
                p.get_restore_pass().to_string(),
                p.get_restore_replace(),
                p.get_restore_without_proxy(),
                p.get_restore_in_files(),
            )
        }) else {
            return;
        };
        let mut args = vec!["restore".into(), file];
        if replace {
            args.push("--replace".into());
        }
        if without_proxy {
            args.push("--without-proxy".into());
        }
        if in_files {
            args.push("--secret-storage=file".into());
        }
        let running = self
            .with_store(|s| s.get_service_state() == "running")
            .unwrap_or(false);
        self.with_prefs(|p| p.set_restore_busy(true));
        if self.owner_path() {
            return self.restore_as_owner(args, pass, running);
        }
        self.restore_stopped(args, pass, running, false);
    }

    /// An owner's restore: through the running node, which stops for it
    /// and starts again by itself (nerve_node::owner). A node that does not
    /// run is started for it. A backup that changes the account commands
    /// run as is an administrator's to restore: then the app asks for the
    /// rights and restores the way an administrator does.
    fn restore_as_owner(self: &Rc<Self>, args: Vec<String>, pass: String, running: bool) {
        let restore = move |c: &Rc<Ctl>| {
            let (again, pass_again) = (args.clone(), pass.clone());
            c.command(args, Some(pass), move |c, answer| match answer {
                Err(e) if e.contains(nerve_node::owner::RESTORE_BY_ADMIN) => {
                    c.restore_stopped(again, pass_again, true, true)
                }
                answer => {
                    c.with_prefs(|p| p.set_restore_pass(SharedString::new()));
                    let then = view::started_after_restore(answer.is_ok(), Ok(()));
                    c.restored(answer, then, false);
                }
            });
        };
        if running {
            return restore(self);
        }
        self.command(
            vec!["service".into(), "start".into()],
            None,
            move |c, answer| match answer {
                Ok(_) => restore(c),
                Err(e) => {
                    c.with_prefs(|p| {
                        p.set_restore_busy(false);
                        p.set_restore_error(
                            format!("The node did not start for the restore: {e}").into(),
                        );
                    });
                    c.refresh_service();
                }
            },
        );
    }

    /// A restore under a stopped node, as an administrator does it: the
    /// app stops the service for it and starts it again after, also when
    /// the restore failed. `admin` asks for the rights for the restore.
    fn restore_stopped(
        self: &Rc<Self>,
        args: Vec<String>,
        pass: String,
        running: bool,
        admin: bool,
    ) {
        if !running {
            return self.restore_run(args, pass, false, admin);
        }
        self.command(
            vec!["service".into(), "stop".into()],
            None,
            move |c, answer| match answer {
                Ok(_) => c.restore_run(args, pass, true, admin),
                Err(e) => {
                    c.with_prefs(|p| {
                        p.set_restore_busy(false);
                        p.set_restore_error(
                            format!("The node did not stop for the restore: {e}").into(),
                        );
                    });
                    c.refresh_service();
                }
            },
        );
    }

    /// The restore itself, then the start of the service when `start`;
    /// with the administrator's rights asked for it when `admin`.
    fn restore_run(self: &Rc<Self>, args: Vec<String>, pass: String, start: bool, admin: bool) {
        let done = move |c: &Rc<Ctl>, answer: Result<serde_json::Value, String>| {
            c.with_prefs(|p| p.set_restore_pass(SharedString::new()));
            if !start {
                let stopped = c
                    .with_store(|s| s.get_service_state() == "stopped")
                    .unwrap_or(false);
                let then = if stopped {
                    "Start the node on the Overview: it works with what is restored once it runs."
                } else {
                    "The node works with what is restored once it starts."
                };
                return c.restored(answer, then.into(), false);
            }
            c.command(
                vec!["service".into(), "start".into()],
                None,
                move |c, started| {
                    let started = started.as_ref().map(|_| ()).map_err(String::as_str);
                    let then = view::started_after_restore(answer.is_ok(), started);
                    c.restored(answer, then, true);
                },
            );
        };
        if admin {
            self.command_with_rights(args, Some(pass), done);
        } else {
            self.command(args, Some(pass), done);
        }
    }

    /// Shows what a restore did, or why it did not, with what became of
    /// the node (`then`); after an error that only when the app stopped
    /// and started it (`said_start`).
    fn restored(
        self: &Rc<Self>,
        answer: Result<serde_json::Value, String>,
        then: String,
        said_start: bool,
    ) {
        self.with_prefs(|p| p.set_restore_busy(false));
        match answer {
            Ok(v) => {
                self.with_prefs(|p| p.set_restore_open(false));
                self.show_once("The backup is restored", "", &view::restored(&v, &then), "");
            }
            Err(e) => {
                let e = if said_start {
                    format!("{e}\n{then}")
                } else {
                    e
                };
                self.with_prefs(|p| p.set_restore_error(e.into()));
            }
        }
        self.refresh_service();
        self.refresh_status();
        self.prefs_load();
    }
}

pub(super) fn wire(ctl: &Rc<Ctl>, window: &crate::AppWindow) {
    let p = window.global::<Prefs>();
    let c = ctl.clone();
    p.on_name_save(move |n| c.name_save(&n));
    let c = ctl.clone();
    p.on_storage_set(move |i| c.storage_set(i));
    let c = ctl.clone();
    p.on_proxy_edit(move || c.proxy_edit());
    let c = ctl.clone();
    p.on_proxy_set(move || c.proxy_set());
    let c = ctl.clone();
    p.on_proxy_remove(move || {
        c.prefs_change(vec!["proxy".into(), "off".into()], None, String::new())
    });
    let c = ctl.clone();
    p.on_relay_on(move || {
        let address = c
            .with_prefs(|p| p.get_relay_address().trim().to_string())
            .unwrap_or_default();
        c.prefs_change(
            vec!["relay".into(), "on".into(), address],
            None,
            String::new(),
        );
    });
    let c = ctl.clone();
    p.on_relay_off(move || c.prefs_change(vec!["relay".into(), "off".into()], None, String::new()));
    let c = ctl.clone();
    p.on_relay_add(move || c.relay_add_start(""));
    let c = ctl.clone();
    p.on_relay_token(move |name| c.relay_add_start(&name));
    let c = ctl.clone();
    p.on_relay_add_confirm(move || c.relay_add_confirm());
    let c = ctl.clone();
    p.on_connect_start(move || c.connect_start());
    let c = ctl.clone();
    p.on_connect_read(move |link| c.connect_read(&link));
    let c = ctl.clone();
    p.on_connect_save(move || c.connect_save());
    let c = ctl.clone();
    p.on_disconnect(move || {
        c.prefs_change(
            vec!["proxy".into(), "off".into()],
            None,
            "This node reaches its centers directly again.".into(),
        )
    });
    let c = ctl.clone();
    p.on_relay_remove(move |name| {
        c.prefs_change(
            vec!["relay".into(), "rm".into(), "--".into(), name.to_string()],
            None,
            String::new(),
        )
    });
    let c = ctl.clone();
    p.on_relay_edit(move |i| c.relay_edit(i as usize));
    let c = ctl.clone();
    p.on_relay_edit_pick(move |i, on| c.relay_edit_pick(i as usize, on));
    let c = ctl.clone();
    p.on_relay_edit_save(move || c.relay_edit_save());
    let c = ctl.clone();
    p.on_log_level_set(move |i| c.log_level_set(i));
    let c = ctl.clone();
    p.on_shell_save(move || c.shell_save());
    let c = ctl.clone();
    p.on_limit_edit(move |group, i, text| c.limit_edit(&group, i as usize, text));
    let c = ctl.clone();
    p.on_limits_save(move |group| c.limits_save(&group));
    let c = ctl.clone();
    p.on_raw_get(move || c.raw_get());
    let c = ctl.clone();
    p.on_raw_set(move || c.raw_change("set"));
    let c = ctl.clone();
    p.on_raw_unset(move || c.raw_change("unset"));
    let c = ctl.clone();
    p.on_raw_add(move || c.raw_change("add"));
    let c = ctl.clone();
    p.on_account_password_save(move || c.account_password_save());
    let c = ctl.clone();
    p.on_raw_remove(move || c.raw_change("rm"));
    let c = ctl.clone();
    p.on_accept_file(move || {
        c.confirm(
            Pending::Accept,
            "Take node.toml as it is?".into(),
            "The node refuses a node.toml changed outside nerve-node. Taking it signs the file as it is now, with every change in it: read it first.".into(),
            "Take it",
        )
    });
    let c = ctl.clone();
    p.on_backup_choose(move || c.backup_choose(false));
    let c = ctl.clone();
    p.on_backup_confirm(move || c.backup_confirm());
    let c = ctl.clone();
    p.on_restore_choose(move || c.backup_choose(true));
    let c = ctl.clone();
    p.on_restore_confirm(move || c.restore_confirm());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_limit_shows_in_the_fields_unit_and_its_default_when_unset() {
        // As `config get limits` and `relay` answer on a new node, with
        // one limit set.
        let set = json!({
            "limits": {"max_running": 16, "output_cap_bytes": 16777216, "max_timeout_secs": 5400},
            "relay": {"max_links": 16, "max_links_per_node": 4, "max_opens_per_minute": 30},
        });
        let rows = |group: &str| {
            let defs = LIMITS.iter().find(|(g, _)| *g == group).unwrap().1;
            limit_rows(defs, &set)
        };
        let time = rows("time");
        assert_eq!(time[0].value, "10");
        assert_eq!(time[0].unit, "minutes");
        assert_eq!(time[1].value, "90");
        assert_eq!(time[1].default, "60");
        let node = rows("node");
        assert_eq!(
            (node[1].value.as_str(), node[1].unit.as_str()),
            ("16", "MiB")
        );
        let command = rows("command");
        assert_eq!(command[0].value, "4096");
        assert_eq!(command[0].key, "limits.command.memory_mb");
        assert_eq!(rows("relay")[2].value, "30");
        assert_eq!(in_unit(90, 60), "1.5");
    }

    #[test]
    fn a_save_sets_what_changed_and_an_empty_field_unsets_it() {
        let set = json!({"limits": {"max_timeout_secs": 5400}});
        let defs = LIMITS.iter().find(|(g, _)| *g == "time").unwrap().1;
        let mut rows = limit_rows(defs, &set);
        assert_eq!(limit_changes(&rows).unwrap(), Vec::<Vec<String>>::new());
        rows[0].value = "1.5".into();
        rows[1].value = "".into();
        assert_eq!(
            limit_changes(&rows).unwrap(),
            vec![
                vec!["config", "set", "limits.default_timeout_secs", "90"],
                vec!["config", "unset", "limits.max_timeout_secs"],
            ]
        );
        // A field emptied while it shows the default changes nothing.
        let mut rows = limit_rows(defs, &json!({}));
        rows[1].value = "".into();
        assert!(limit_changes(&rows).unwrap().is_empty());
        rows[0].value = "a day".into();
        let e = limit_changes(&rows).unwrap_err();
        assert!(
            e.contains("When the call names none") && e.contains("a day"),
            "{e}"
        );
        rows[0].value = "0".into();
        assert!(limit_changes(&rows).is_err());
        let node = LIMITS.iter().find(|(g, _)| *g == "node").unwrap().1;
        let mut rows = limit_rows(node, &json!({}));
        rows[1].value = "8".into();
        assert_eq!(
            limit_changes(&rows).unwrap(),
            vec![vec!["config", "set", "limits.output_cap_bytes", "8388608"]]
        );
    }
}
