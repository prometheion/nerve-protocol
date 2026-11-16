//! The center role's pages: the log-in and every page of the center, from
//! its web UI API on loopback (crate::hub), and the administrator's
//! commands (`nerve __center ...`), each through a broker of its own that
//! ends with it (design of #232, sections 2 and 3).

use std::cell::{Cell, RefCell};
use std::path::PathBuf;
use std::rc::Rc;
use std::sync::Arc;
use std::time::Duration;

use nerve_proto::msg::now_ms;
use serde_json::{Value, json};
use slint::{ComponentHandle, Model, ModelRc, SharedString, VecModel};

use super::{Choose, Ctl, Exec};
use crate::broker::Launch;
use crate::hub::{self, Failed, Found, Hub as Client, keep, view};
use crate::{Hub, HubPage, HubRef, HubTask, HubWhere, Tone};

/// Runs an administrator's command (`__center` and its words) with `input`
/// as stdin's first line, and gives its JSON answer; tests answer for it.
pub type Admin = Arc<dyn Fn(&[String], Option<&str>) -> Result<Value, String> + Send + Sync>;

/// The center role's state, kept by the app's controller.
pub struct HubState {
    /// The center's run folder, where its address file is.
    run: RefCell<PathBuf>,
    client: RefCell<Option<Client>>,
    judge: RefCell<hub::Judge>,
    keyring: RefCell<keep::Shared>,
    /// The owner token the app logged in with, in memory until it closes:
    /// a restart of the center ends the session, and the app logs in again.
    token: RefCell<Option<String>>,
    /// How an administrator's command runs: through a broker of its own
    /// (`None`), or as a test says.
    admin: RefCell<Option<Admin>>,
    /// How that broker starts.
    launch: Cell<Launch>,
    /// What the pages read last.
    overview: RefCell<Value>,
    checker: RefCell<Value>,
    audit: RefCell<Vec<Value>>,
    stats: RefCell<Value>,
    /// The center's settings as Settings read them last.
    center: RefCell<Value>,
    /// The machine the Capabilities page shows, by id.
    cap_node: RefCell<String>,
    /// Which reading of a page is the latest: an answer for an earlier
    /// one is dropped.
    asked: Cell<u64>,
    /// The pairing code the overlay shows, and its check.
    pair_code: RefCell<String>,
    pair_timer: slint::Timer,
    /// A copied secret, until it leaves the clipboard.
    clip: RefCell<Option<hub::clip::Mark>>,
    clip_timer: slint::Timer,
    /// Reads the Overview's state now and then while logged in.
    poll: slint::Timer,
}

impl Default for HubState {
    fn default() -> HubState {
        HubState {
            run: RefCell::new(nerve_center::service::Layout::system().run),
            client: RefCell::new(None),
            judge: RefCell::new(hub::system_judge()),
            keyring: RefCell::new(Arc::new(keep::System)),
            token: RefCell::new(None),
            admin: RefCell::new(None),
            launch: Cell::new(Launch::Elevated),
            overview: RefCell::new(Value::Null),
            checker: RefCell::new(Value::Null),
            audit: RefCell::new(Vec::new()),
            stats: RefCell::new(Value::Null),
            center: RefCell::new(Value::Null),
            cap_node: RefCell::new(String::new()),
            asked: Cell::new(0),
            pair_code: RefCell::new(String::new()),
            pair_timer: slint::Timer::default(),
            clip: RefCell::new(None),
            clip_timer: slint::Timer::default(),
            poll: slint::Timer::default(),
        }
    }
}

/// What a page read: each part it needs.
#[derive(Default)]
struct Read {
    overview: Option<Value>,
    checker: Option<Value>,
    tokens: Option<Value>,
    caps: Option<Value>,
    stats: Option<Value>,
    audit: Option<Value>,
    log: Option<Value>,
    center: Option<Value>,
    help: Option<Value>,
    service: Option<Value>,
}

/// The task map of the Help page: its groups, then each task with its
/// group, where it is, and the page (and section) its link opens.
fn task_map() -> (Vec<&'static str>, Vec<HubTask>) {
    let groups = vec![
        "Machines and harnesses",
        "What the agent may do",
        "This center",
        "When something is wrong",
    ];
    let t = |group: i32, task: &str, place: &str, page: HubPage, at: i32| HubTask {
        group,
        task: task.into(),
        r#where: place.into(),
        page,
        at,
    };
    let tasks = vec![
        t(
            0,
            "Pair a machine",
            "Nodes › Pair a machine",
            HubPage::Nodes,
            1,
        ),
        t(
            0,
            "Connect a harness",
            "Harnesses › Connect a harness",
            HubPage::Harnesses,
            0,
        ),
        t(
            0,
            "End a harness's session",
            "Harnesses › Sessions",
            HubPage::Harnesses,
            1,
        ),
        t(
            1,
            "Refuse a kind of call",
            "Action checker › Blocklist",
            HubPage::Checker,
            0,
        ),
        t(
            1,
            "Let calls skip the model",
            "Action checker › Skip the model",
            HubPage::Checker,
            1,
        ),
        t(
            1,
            "See what a machine offers",
            "Capabilities",
            HubPage::Caps,
            -1,
        ),
        t(
            2,
            "Its name and addresses",
            "Settings › Center",
            HubPage::Settings,
            0,
        ),
        t(
            2,
            "Make a new center key",
            "Settings › Center key",
            HubPage::Settings,
            3,
        ),
        t(
            2,
            "Back up, restore",
            "Settings › Backup",
            HubPage::Settings,
            4,
        ),
        t(
            2,
            "Update, uninstall, change the role",
            "Settings › This machine",
            HubPage::Settings,
            1,
        ),
        t(3, "See what happened", "Audit", HubPage::Audit, -1),
        t(3, "Read the center's log", "Log", HubPage::Log, -1),
    ];
    (groups, tasks)
}

fn model<T: Clone + 'static>(items: Vec<T>) -> ModelRc<T> {
    ModelRc::new(VecModel::from(items))
}

impl Ctl {
    fn with_hub<R>(&self, f: impl FnOnce(&Hub<'_>) -> R) -> Option<R> {
        let w = self.window.upgrade()?;
        let h = w.global::<Hub>();
        Some(f(&h))
    }

    /// Who holds a port, for tests: the test's center runs as the test's
    /// user, not as the center's service.
    pub fn set_hub_judge(&self, judge: hub::Judge) {
        *self.hub.judge.borrow_mut() = judge;
    }

    /// The keyring of a kept log-in, for tests.
    pub fn set_hub_keyring(&self, keyring: keep::Shared) {
        *self.hub.keyring.borrow_mut() = keyring;
    }

    /// How the administrator's commands run, for tests.
    pub fn set_hub_admin(&self, admin: Admin) {
        *self.hub.admin.borrow_mut() = Some(admin);
    }

    /// The window shows the center's pages: this machine is a center the
    /// app installed, its address file in `run`. It logs in at once with a
    /// token kept in the keyring, where the owner chose so.
    pub fn center_role(self: &Rc<Self>, run: PathBuf) {
        *self.hub.run.borrow_mut() = run;
        let (groups, tasks) = task_map();
        let counts: Vec<i32> = (0..groups.len() as i32)
            .map(|g| tasks.iter().filter(|t| t.group == g).count() as i32)
            .collect();
        let keep_login = self
            .settings
            .borrow()
            .as_deref()
            .is_some_and(crate::settings::keep_login);
        self.with_hub(|h| {
            h.set_shown(true);
            h.set_page(HubPage::Overview);
            h.set_version(env!("CARGO_PKG_VERSION").into());
            h.set_task_groups(model(groups.into_iter().map(SharedString::from).collect()));
            h.set_task_counts(model(counts));
            h.set_tasks(model(tasks));
            h.set_keep_login(keep_login);
        });
        self.hub_connect();
        if keep_login {
            let keyring = self.hub.keyring.borrow().clone();
            if let Ok(Some(token)) = keyring.get() {
                self.hub_login_with(token, true);
            }
        }
        if self.exec == Exec::Threads {
            let c = Rc::downgrade(self);
            self.hub.poll.start(
                slint::TimerMode::Repeated,
                Duration::from_secs(5),
                move || {
                    if let Some(c) = c.upgrade() {
                        c.hub_poll();
                    }
                },
            );
        }
    }

    /// Finds the center's web UI and checks that its port is the center
    /// service's: the log-in says what it found.
    fn hub_connect(self: &Rc<Self>) -> Option<Client> {
        let run = self.hub.run.borrow().clone();
        let found = hub::find(&run);
        let (client, checked, line, off, not_running) = match found {
            Err(e) => (None, false, e, false, false),
            Ok(Found::NotRunning) => (None, false, hub::NOT_RUNNING.to_string(), false, true),
            Ok(Found::Off) => (None, false, hub::UI_OFF.to_string(), true, false),
            Ok(Found::Ui(address)) => {
                let client = Client::new(address.clone(), self.hub.judge.borrow().clone());
                match client.check() {
                    Ok(()) => (
                        Some(client),
                        true,
                        format!("This is the center's service on {}.", address.at),
                        false,
                        false,
                    ),
                    Err(Failed::NotTheCenter(e)) if e == hub::NOT_RUNNING => {
                        (None, false, e, false, true)
                    }
                    Err(e) => (None, false, e.text(), false, false),
                }
            }
        };
        // A client of an earlier check keeps its session where the address
        // is the same.
        let kept = self.hub.client.borrow().clone();
        let client = match (kept, client) {
            (Some(k), Some(c)) if k.address() == c.address() => Some(k),
            (_, c) => c,
        };
        *self.hub.client.borrow_mut() = client.clone();
        self.with_hub(|h| {
            h.set_login_checked(checked);
            h.set_login_check(line.into());
            h.set_ui_off(off);
            h.set_not_running(not_running);
            if not_running {
                h.set_state("stopped".into());
                h.set_state_tone(Tone::Warn);
                h.set_state_line("Start it in Settings".into());
            }
        });
        client
    }

    /// The log-in with the token typed in.
    fn hub_login(self: &Rc<Self>) {
        let Some(token) = self.with_hub(|h| h.get_login_token().trim().to_string()) else {
            return;
        };
        if token.is_empty() {
            return;
        }
        self.hub_login_with(token, false);
    }

    /// Logs in with `token`; `quiet` for a kept or remembered one, whose
    /// refusal only shows the log-in.
    fn hub_login_with(self: &Rc<Self>, token: String, quiet: bool) {
        let Some(client) = self.hub_connect() else {
            return;
        };
        self.with_hub(|h| {
            h.set_login_busy(true);
            h.set_login_error(SharedString::new());
        });
        // On Linux the app closes itself to the user's other programs before
        // it holds the token (crate::broker::shut_out_the_user), as it does
        // before it holds the broker's pipe.
        #[cfg(target_os = "linux")]
        if self.exec == Exec::Threads
            && let Err(e) = crate::broker::shut_out_the_user()
        {
            self.with_hub(|h| {
                h.set_login_busy(false);
                h.set_login_error(e.into());
            });
            return;
        }
        let tried = token.clone();
        self.job(
            move |_| client.login(&tried),
            move |c, r| {
                c.with_hub(|h| h.set_login_busy(false));
                match r {
                    Ok(()) => {
                        let on = c.with_hub(|h| h.get_keep_login()).unwrap_or(false);
                        let keyring = c.hub.keyring.borrow().clone();
                        if let Err(e) = keep::after_login(keyring.as_ref(), on, &token) {
                            c.toast(
                                format!("The keyring did not keep the log-in: {e}"),
                                Tone::Warn,
                            );
                        }
                        *c.hub.token.borrow_mut() = Some(token);
                        c.with_hub(|h| {
                            h.set_login_token(SharedString::new());
                            h.set_logged_in(true);
                        });
                        let page = c.with_hub(|h| h.get_page()).unwrap_or(HubPage::Overview);
                        c.hub_load(page);
                    }
                    Err(e) => {
                        // A kept token that no longer works is forgotten.
                        if quiet && matches!(e, Failed::Refused(401, _)) {
                            let _ = c.hub.keyring.borrow().delete();
                        }
                        c.hub.token.borrow_mut().take();
                        c.with_hub(|h| {
                            h.set_logged_in(false);
                            if !quiet {
                                h.set_login_error(e.text().into());
                            }
                        });
                    }
                }
            },
        );
    }

    /// Reads the owner token from this machine, with one administrator's
    /// prompt, and logs in with it.
    fn hub_login_read(self: &Rc<Self>) {
        self.with_hub(|h| {
            h.set_login_busy(true);
            h.set_login_error(SharedString::new());
        });
        self.hub_admin(vec!["owner-token".into()], None, |c, answer| {
            let said = match answer.map(|v| v["token"].as_str().map(str::to_string)) {
                Ok(Some(token)) => return c.hub_login_with(token, false),
                Ok(None) => "The center did not say its token.".to_string(),
                Err(e) => e,
            };
            c.with_hub(|h| {
                h.set_login_busy(false);
                h.set_login_error(said.into());
            });
        });
    }

    /// Logs out here; the token is forgotten, a kept one too.
    fn hub_logout(self: &Rc<Self>) {
        let client = self.hub.client.borrow().clone();
        if let Some(client) = client {
            self.job(move |_| client.logout(), |_, ()| {});
        }
        self.hub.token.borrow_mut().take();
        let _ = self.hub.keyring.borrow().delete();
        self.with_hub(|h| {
            h.set_logged_in(false);
            h.set_keep_login(false);
            h.set_owner_token(SharedString::new());
        });
        self.hub_save_keep(false);
    }

    /// The session ended: logs in again with the token in memory, else
    /// shows the log-in.
    fn hub_logged_out(self: &Rc<Self>) {
        self.with_hub(|h| h.set_logged_in(false));
        let token = self.hub.token.borrow_mut().take();
        if let Some(token) = token {
            self.hub_login_with(token, true);
        }
    }

    /// Runs an administrator's command of the center (`args` after
    /// `__center`) through a broker of its own, which ends with it: the
    /// center role keeps no broker (design of #232, section 3).
    fn hub_admin(
        self: &Rc<Self>,
        args: Vec<String>,
        input: Option<String>,
        done: impl FnOnce(&Rc<Ctl>, Result<Value, String>) + Send + 'static,
    ) {
        self.hub_admin_all(vec![args], input, move |c, mut answers| {
            done(
                c,
                answers.pop().unwrap_or_else(|| Err("nothing ran".into())),
            )
        });
    }

    /// [`Ctl::hub_admin`] for several commands of one action (a Save that
    /// changes two addresses), through one broker; they stop at the first
    /// that fails.
    fn hub_admin_all(
        self: &Rc<Self>,
        commands: Vec<Vec<String>>,
        input: Option<String>,
        done: impl FnOnce(&Rc<Ctl>, Vec<Result<Value, String>>) + Send + 'static,
    ) {
        let word = nerve_center::edition::APP_WORD.to_string();
        let commands: Vec<Vec<String>> = commands
            .into_iter()
            .map(|a| std::iter::once(word.clone()).chain(a).collect())
            .collect();
        let admin = self.hub.admin.borrow().clone();
        let how = self.hub.launch.get();
        let exe = self.runner().exe().clone();
        self.job(
            move |r| {
                let mut out = Vec::new();
                let through = match &admin {
                    Some(_) => None,
                    None => match crate::broker::launch(&exe, how) {
                        Ok(b) => Some(r.through(b)),
                        Err(e) => return vec![Err(e)],
                    },
                };
                for args in commands {
                    let answer = match (&admin, &through) {
                        (Some(a), _) => a(&args, input.as_deref()),
                        (None, Some(r)) => {
                            let a: Vec<&str> = args.iter().map(String::as_str).collect();
                            r.run_with(&a, input.as_deref())
                        }
                        (None, None) => Err("no broker".into()),
                    };
                    let failed = answer.is_err();
                    out.push(answer);
                    if failed {
                        break;
                    }
                }
                // The broker ends here, with its runner.
                drop(through);
                out
            },
            done,
        );
    }

    /// Opens `page` of the center and reads it.
    fn hub_show(self: &Rc<Self>, page: HubPage) {
        self.with_hub(|h| {
            h.set_page(page);
            h.set_details_open(false);
            h.set_asking(SharedString::new());
            h.set_error(SharedString::new());
        });
        if self.with_hub(|h| h.get_logged_in()) == Some(true) {
            self.hub_load(page);
        }
    }

    fn hub_reload(self: &Rc<Self>) {
        if self.with_hub(|h| h.get_logged_in()) != Some(true) {
            self.hub_connect();
            return;
        }
        if let Some(page) = self.with_hub(|h| h.get_page()) {
            self.hub_load(page);
        }
    }

    /// The state of the sidebar and the Overview, every few seconds.
    fn hub_poll(self: &Rc<Self>) {
        if self.with_hub(|h| h.get_logged_in()) != Some(true) {
            self.hub_connect();
            return;
        }
        let page = self.with_hub(|h| h.get_page());
        if matches!(page, Some(HubPage::Overview)) {
            self.hub_load(HubPage::Overview);
        }
    }

    /// Reads what `page` shows, and shows it.
    fn hub_load(self: &Rc<Self>, page: HubPage) {
        let Some(client) = self.hub.client.borrow().clone() else {
            return;
        };
        let asked = self.hub.asked.get() + 1;
        self.hub.asked.set(asked);
        let cap_node = self.hub.cap_node.borrow().clone();
        let (problems, search) = self
            .with_hub(|h| (h.get_log_problems(), h.get_log_search().to_string()))
            .unwrap_or_default();
        self.with_hub(|h| h.set_loading(true));
        self.job(
            move |r| -> Result<Read, Failed> {
                let mut read = Read {
                    overview: Some(client.get("/api/overview")?),
                    ..Read::default()
                };
                let first_node = || {
                    let o = read.overview.as_ref().map(|o| &o["nodes"]);
                    let names = o.map(view::names).unwrap_or_default();
                    match names.iter().any(|(id, _)| *id == cap_node) {
                        true => cap_node.clone(),
                        false => names.first().map(|(id, _)| id.clone()).unwrap_or_default(),
                    }
                };
                match page {
                    HubPage::Overview | HubPage::Checker => {
                        read.checker = Some(client.get("/api/checker")?);
                        read.service = service_status(r);
                    }
                    HubPage::Harnesses => read.tokens = Some(client.get("/api/tokens")?),
                    HubPage::Caps => {
                        let id = first_node();
                        if !id.is_empty() {
                            read.caps = Some(
                                client.get(&format!("/api/caps?id={}", view::query_value(&id)))?,
                            );
                        }
                    }
                    HubPage::Stats => read.stats = Some(client.get("/api/stats")?),
                    HubPage::Audit => read.audit = Some(client.get("/api/audit")?),
                    HubPage::Log => {
                        read.log = Some(client.get(&view::log_query(problems, &search))?)
                    }
                    HubPage::Settings => {
                        read.center = Some(client.get("/api/center")?);
                        read.service = service_status(r);
                    }
                    HubPage::Help => read.help = Some(client.get("/api/help")?),
                    HubPage::Nodes | HubPage::Login => {}
                }
                Ok(read)
            },
            move |c, read| {
                if c.hub.asked.get() != asked {
                    return;
                }
                c.with_hub(|h| h.set_loading(false));
                match read {
                    Ok(read) => {
                        c.with_hub(|h| h.set_error(SharedString::new()));
                        c.hub_shown(read);
                    }
                    Err(Failed::LoggedOut) => c.hub_logged_out(),
                    Err(Failed::NotTheCenter(e)) => {
                        c.with_hub(|h| {
                            h.set_logged_in(false);
                            h.set_login_check(e.into());
                            h.set_login_checked(false);
                        });
                        c.hub_connect();
                    }
                    Err(e) => c
                        .with_hub(|h| h.set_error(e.text().into()))
                        .unwrap_or_default(),
                }
            },
        );
    }

    /// Shows what a page read.
    fn hub_shown(self: &Rc<Self>, read: Read) {
        let now = now_ms();
        if let Some(o) = read.overview {
            self.hub_overview(&o, now);
            *self.hub.overview.borrow_mut() = o;
        }
        if let Some(v) = read.service {
            self.hub_service(&v);
        }
        if let Some(v) = read.checker {
            self.hub_checker(&v);
            *self.hub.checker.borrow_mut() = v;
        }
        if let Some(v) = read.tokens {
            let tokens = view::tokens(&v, now);
            self.with_hub(|h| h.set_tokens(model(tokens)));
        }
        if read.caps.is_some() || self.with_hub(|h| h.get_page()) == Some(HubPage::Caps) {
            self.hub_caps(read.caps.as_ref());
        }
        if let Some(v) = read.stats {
            *self.hub.stats.borrow_mut() = v;
            let pick = self.with_hub(|h| h.get_stat_pick()).unwrap_or(0);
            self.hub_stats_pick(pick);
        }
        if let Some(v) = read.audit {
            *self.hub.audit.borrow_mut() = v["decisions"].as_array().cloned().unwrap_or_default();
            self.hub_audit_shown();
        }
        if let Some(v) = read.log {
            let rows = view::log(&v, now);
            let foot = if rows.len() >= view::LOG_LIMIT {
                format!(
                    "The newest {} entries. Download keeps the whole log.",
                    view::LOG_LIMIT
                )
            } else {
                String::new()
            };
            self.with_hub(|h| {
                h.set_log(model(rows));
                h.set_log_foot(foot.into());
            });
        }
        if let Some(v) = read.center {
            self.hub_center(&v, now);
        }
        if let Some(v) = read.help {
            let refs: Vec<HubRef> = view::commands(&v)
                .into_iter()
                .map(|(name, line)| HubRef {
                    name: name.into(),
                    line: line.into(),
                })
                .collect();
            self.with_hub(|h| h.set_commands(model(refs)));
        }
    }

    fn hub_overview(&self, o: &Value, now: u64) {
        let nodes = view::nodes(&o["nodes"], now);
        let sessions = view::sessions(&o["sessions"], now);
        let (http, url, why) = view::mcp(&o["mcp"]);
        let alerts: Vec<SharedString> = o["alerts"]
            .as_array()
            .map(Vec::as_slice)
            .unwrap_or_default()
            .iter()
            .rev()
            .take(3)
            .map(|a| SharedString::from(a["text"].as_str().unwrap_or_default()))
            .collect();
        let count = view::nodes_count(&o["nodes"]);
        self.with_hub(|h| {
            h.set_state("running".into());
            h.set_state_tone(Tone::Ok);
            h.set_state_line(
                format!("{count} nodes")
                    .replace("None paired nodes", "No node paired")
                    .into(),
            );
            h.set_center_name(o["center"]["name"].as_str().unwrap_or_default().into());
            h.set_public_url(o["center"]["url"].as_str().unwrap_or_default().into());
            h.set_mcp_line(view::mcp_line(&o["mcp"]).into());
            h.set_mcp_http(http);
            h.set_mcp_url(url.into());
            h.set_mcp_why(why.into());
            h.set_nodes_count(count.into());
            h.set_sessions_count(sessions.len().to_string().into());
            h.set_alerts(model(alerts));
            h.set_nodes(model(nodes));
            h.set_sessions(model(sessions));
        });
    }

    /// The installed service's state, from `status --json`.
    fn hub_service(&self, v: &Value) {
        let state = match v["service"].as_str().unwrap_or_default() {
            "active" | "running" => "running",
            "failed" => "failed",
            "" => "",
            _ => "stopped",
        };
        let line = match state {
            "running" => {
                if cfg!(windows) {
                    "Runs as its own service account and starts with the machine."
                } else {
                    "Runs as the user nerve-center and starts with the machine."
                }
            }
            "failed" => "It stopped with an error: the Log says why.",
            "stopped" => "Nodes and harnesses reach nothing while it is stopped.",
            _ => "",
        };
        let older = v["older"] == true;
        self.with_hub(|h| {
            h.set_service_state(state.into());
            h.set_service_line(
                if older {
                    "It still runs an older program: restart it to run the new one."
                } else {
                    line
                }
                .into(),
            );
        });
    }

    fn hub_names(&self) -> Vec<(String, String)> {
        view::names(&self.hub.overview.borrow()["nodes"])
    }

    fn hub_checker(&self, v: &Value) {
        let names = self.hub_names();
        let c = &v["config"];
        let m = view::model(v);
        let block = view::rules(v, false, &names);
        let skip = view::rules(v, true, &names);
        let machines = view::machines(v, &names);
        let line = view::checker_line(v);
        self.with_hub(|h| {
            h.set_blocklist_on(c["blocklist_on"] != false);
            h.set_model_on(c["model_on"] == true);
            h.set_taint_on(c["taint_on"] != false);
            h.set_checker_line(line.into());
            h.set_block_rules(model(block));
            h.set_skip_rules(model(skip));
            h.set_machines(model(machines));
            h.set_model_local(m.local);
            h.set_model_line(m.line.into());
            h.set_model_tone(m.tone);
            h.set_model_installed(m.installed);
            h.set_model_installing(m.installing);
            h.set_model_gpu(m.gpu);
            h.set_model_supported(m.supported);
            h.set_model_gpu_hint(m.gpu_hint.into());
            h.set_model_has_token(m.has_token);
            h.set_model_wanted(v["model_wanted"] == true);
            h.set_chk_warning(view::checker_warning(v).into());
        });
        let pick = self.with_hub(|h| h.get_chk_pick()).unwrap_or(0);
        self.hub_rule_where(pick);
    }

    /// Where the picked blocklist rule counts.
    fn hub_rule_where(&self, pick: i32) {
        let names = self.hub_names();
        let view_of = self.with_hub(|h| h.get_chk_view()).unwrap_or(0);
        let w = match (view_of, usize::try_from(pick)) {
            (0, Ok(i)) => view::rule_where(&self.hub.checker.borrow(), i, &names),
            _ => Vec::new(),
        };
        self.with_hub(|h| h.set_rule_where(model(w)));
    }

    /// A row of the checker's list picked: -1 the Add a rule form.
    fn hub_rule_pick(&self, pick: i32) {
        self.with_hub(|h| {
            h.set_chk_pick(pick);
            h.set_asking(SharedString::new());
        });
        self.hub_rule_where(pick);
    }

    /// Opens the form of a new rule.
    fn hub_rule_add(&self) {
        let names = self.hub_names();
        let chosen: Vec<HubWhere> = names
            .iter()
            .map(|(id, name)| HubWhere {
                id: id.as_str().into(),
                name: name.as_str().into(),
                on: false,
            })
            .collect();
        self.with_hub(|h| {
            h.set_rule_text(SharedString::new());
            h.set_rule_note(SharedString::new());
            h.set_rule_all(true);
            h.set_rule_chosen(model(chosen));
            h.set_rule_error(SharedString::new());
            h.set_chk_pick(-1);
        });
    }

    /// Posts the checker's config as `change` makes it of the one read,
    /// with that one's version: the center refuses it when another change
    /// came in between, and the page reads it again.
    fn hub_checker_change(
        self: &Rc<Self>,
        change: impl FnOnce(&Value) -> Value,
        said: &'static str,
        after: impl FnOnce(&Rc<Ctl>) + Send + 'static,
    ) {
        let Some(client) = self.hub.client.borrow().clone() else {
            return;
        };
        let config = change(&self.hub.checker.borrow()["config"]);
        self.with_hub(|h| {
            h.set_busy("checker".into());
            h.set_rule_error(SharedString::new());
        });
        self.job(
            move |_| client.post("/api/checker", &json!({ "config": config })),
            move |c, r| {
                c.with_hub(|h| h.set_busy(SharedString::new()));
                match r {
                    Ok(_) => {
                        if !said.is_empty() {
                            c.toast(said, Tone::Ok);
                        }
                        after(c);
                    }
                    Err(Failed::LoggedOut) => c.hub_logged_out(),
                    Err(Failed::Refused(409, _)) => {
                        c.toast(
                            "The checker changed meanwhile: here it is as it is now. Make your change again.",
                            Tone::Warn,
                        );
                    }
                    Err(e) => {
                        c.with_hub(|h| h.set_rule_error(e.text().into()));
                        c.toast(e.text(), Tone::Danger);
                    }
                }
                c.hub_load(HubPage::Checker);
            },
        );
    }

    fn hub_rule_save(self: &Rc<Self>) {
        let Some((skip, rule, note, all, chosen)) = self.with_hub(|h| {
            let chosen: Vec<String> = h
                .get_rule_chosen()
                .iter()
                .filter(|w| w.on)
                .map(|w| w.id.to_string())
                .collect();
            (
                h.get_chk_view() == 1,
                h.get_rule_text().trim().to_string(),
                h.get_rule_note().to_string(),
                h.get_rule_all(),
                chosen,
            )
        }) else {
            return;
        };
        if !all && chosen.is_empty() {
            self.with_hub(|h| h.set_rule_error("Choose at least one machine.".into()));
            return;
        }
        let nodes = if all { Vec::new() } else { chosen };
        let at = if skip {
            self.hub.checker.borrow()["config"]["allow_rules"]
                .as_array()
                .map_or(0, Vec::len)
        } else {
            self.hub.checker.borrow()["config"]["blocklist"]
                .as_array()
                .map_or(0, Vec::len)
        };
        self.hub_checker_change(
            move |c| view::with_rule(c, skip, &rule, &note, &nodes),
            "The rule counts from the next call.",
            move |c| {
                c.with_hub(|h| h.set_chk_pick(at as i32))
                    .unwrap_or_default()
            },
        );
    }

    fn hub_caps(&self, v: Option<&Value>) {
        let names = self.hub_names();
        let id = self.hub.cap_node.borrow().clone();
        let at = names.iter().position(|(i, _)| *i == id).unwrap_or(0);
        if let Some((first, _)) = names.get(at) {
            *self.hub.cap_node.borrow_mut() = first.clone();
        }
        let (caps, counts) = v.map(view::caps).unwrap_or_default();
        let note = v.map(view::caps_note).unwrap_or_default();
        let write = v.is_some_and(|v| v["settings_write"] == true && v["online"] == true);
        self.with_hub(|h| {
            h.set_cap_machines(model(
                names
                    .iter()
                    .map(|(_, n)| SharedString::from(n.as_str()))
                    .collect(),
            ));
            h.set_cap_machine(at as i32);
            h.set_caps(model(caps));
            h.set_cap_counts(model(counts.to_vec()));
            h.set_cap_note(note.into());
            h.set_cap_write(write);
        });
    }

    fn hub_stats_pick(&self, pick: i32) {
        let v = self.hub.stats.borrow();
        let rows = view::stat_rows(&v);
        let pick = pick.clamp(0, rows.len() as i32 - 1);
        let row = &rows[pick as usize];
        let (figures, calls, errors) = view::stat_detail(&v, &row.id);
        let days = v["retention_days"].as_u64().unwrap_or(30);
        let name = row.name.clone();
        self.with_hub(|h| {
            h.set_stat_rows(model(rows.clone()));
            h.set_stat_pick(pick);
            h.set_stat_name(name);
            h.set_stat_kept(format!("Kept for {days} days.").into());
            h.set_figures(model(figures));
            h.set_calls(model(calls));
            h.set_errors(model(errors));
        });
    }

    fn hub_audit_filter(&self) -> view::AuditFilter {
        let names = self.hub_names();
        self.with_hub(|h| view::AuditFilter {
            decision: h.get_audit_decision(),
            text: h.get_audit_text().to_string(),
            node: usize::try_from(h.get_audit_node() - 1)
                .ok()
                .and_then(|i| names.get(i))
                .map(|(id, _)| id.clone()),
        })
        .unwrap_or_default()
    }

    fn hub_audit_shown(&self) {
        let names = self.hub_names();
        let nodes = self.hub.overview.borrow()["nodes"].clone();
        let write = move |id: &str| {
            nodes
                .as_array()
                .and_then(|n| n.iter().find(|x| x["id"] == id))
                .map(|x| x["settings_write"] == true)
        };
        let f = self.hub_audit_filter();
        let (rows, counts) = view::audit(&self.hub.audit.borrow(), &f, &write, now_ms());
        let options: Vec<SharedString> = std::iter::once("Every machine".to_string())
            .chain(names.into_iter().map(|(_, n)| n))
            .map(SharedString::from)
            .collect();
        self.with_hub(|h| {
            h.set_audit(model(rows));
            h.set_audit_counts(model(counts.to_vec()));
            h.set_audit_node_options(model(options));
        });
    }

    /// A rule of the machine from an audit entry: `list` allow or deny.
    fn hub_audit_rule(self: &Rc<Self>, index: usize, list: &str, wildcard: bool, pin: i32) {
        let Some(e) = self.hub.audit.borrow().get(index).cloned() else {
            return;
        };
        let body = view::audit_body(&e, Some(list), wildcard, pin);
        self.hub_post_said("/api/audit/rule", body, "audit", |v| {
            format!(
                "The machine took the rule {}.",
                v["rule"].as_str().unwrap_or_default()
            )
        });
    }

    /// A rule of the checker that skips the model, from its refusal.
    fn hub_audit_trust(self: &Rc<Self>, index: usize, wildcard: bool, pin: i32) {
        let Some(e) = self.hub.audit.borrow().get(index).cloned() else {
            return;
        };
        let body = view::audit_body(&e, None, wildcard, pin);
        self.hub_post_said("/api/checker/allow", body, "audit", |v| {
            format!(
                "This now skips the model: {}.",
                v["rule"].as_str().unwrap_or_default()
            )
        });
    }

    /// Posts `body` to `path` with `busy` set, says what it did, and reads
    /// the page again.
    fn hub_post_said(
        self: &Rc<Self>,
        path: &'static str,
        body: Value,
        busy: &str,
        said: impl FnOnce(&Value) -> String + Send + 'static,
    ) {
        let Some(client) = self.hub.client.borrow().clone() else {
            return;
        };
        self.with_hub(|h| h.set_busy(busy.into()));
        self.job(
            move |_| client.post(path, &body),
            move |c, r| {
                c.with_hub(|h| {
                    h.set_busy(SharedString::new());
                    h.set_asking(SharedString::new());
                });
                match r {
                    Ok(v) => c.toast(said(&v), Tone::Ok),
                    Err(Failed::LoggedOut) => return c.hub_logged_out(),
                    Err(e) => c.toast(e.text(), Tone::Danger),
                }
                c.hub_reload();
            },
        );
    }

    fn hub_center(&self, v: &Value, now: u64) {
        let started = &v["started"];
        let (pin, next, line, rotating) = view::key(v, now);
        let public = self.hub.overview.borrow()["center"]["url"]
            .as_str()
            .unwrap_or_default()
            .to_string();
        let s = |x: &Value| x.as_str().unwrap_or_default().to_string();
        self.with_hub(|h| {
            h.set_set_name(s(&v["name"]).into());
            h.set_set_public_url(public.into());
            h.set_set_listen(s(&started["listen"]).into());
            h.set_set_ui(s(&started["ui"]).into());
            h.set_set_mcp(s(&started["mcp"]).into());
            h.set_set_days(
                v["retention_days"]
                    .as_u64()
                    .unwrap_or(30)
                    .to_string()
                    .into(),
            );
            h.set_set_minutes(
                v["pair_code_minutes"]
                    .as_u64()
                    .unwrap_or(15)
                    .to_string()
                    .into(),
            );
            h.set_set_debug(v["log_level"] == "debug");
            h.set_set_error(SharedString::new());
            h.set_key_pin(pin.into());
            h.set_key_next(next.into());
            h.set_key_line(line.into());
            h.set_key_rotating(rotating);
        });
        self.hub.center.replace(v.clone());
    }

    /// Saves the Center section: what the API changes at once, then each
    /// address `set` changes, through one administrator's prompt.
    fn hub_settings_save(self: &Rc<Self>) {
        let Some(client) = self.hub.client.borrow().clone() else {
            return;
        };
        let Some((name, public, listen, ui, mcp, days, minutes, debug)) = self.with_hub(|h| {
            (
                h.get_set_name().trim().to_string(),
                h.get_set_public_url().trim().to_string(),
                h.get_set_listen().trim().to_string(),
                h.get_set_ui().trim().to_string(),
                h.get_set_mcp().trim().to_string(),
                h.get_set_days().trim().to_string(),
                h.get_set_minutes().trim().to_string(),
                h.get_set_debug(),
            )
        }) else {
            return;
        };
        let (Ok(days), Ok(minutes)) = (days.parse::<u64>(), minutes.parse::<u64>()) else {
            self.with_hub(|h| {
                h.set_set_error("The days and the minutes are whole numbers.".into())
            });
            return;
        };
        let was = self.hub.center.borrow().clone();
        let started = &was["started"];
        let old_public = self.hub.overview.borrow()["center"]["url"]
            .as_str()
            .unwrap_or_default()
            .to_string();
        let mut sets: Vec<Vec<String>> = Vec::new();
        let mut set = |key: &str, new: &str, old: &str| {
            if !new.is_empty() && new != old {
                sets.push(vec!["set".into(), key.into(), new.into()]);
            }
        };
        set("public-url", &public, &old_public);
        set(
            "listen",
            &listen,
            started["listen"].as_str().unwrap_or_default(),
        );
        set("ui", &ui, started["ui"].as_str().unwrap_or_default());
        set("mcp", &mcp, started["mcp"].as_str().unwrap_or_default());
        let body = json!({"name": name, "retention_days": days, "pair_code_minutes": minutes,
                          "log_level": if debug { "debug" } else { "info" }});
        self.with_hub(|h| {
            h.set_busy("settings".into());
            h.set_set_error(SharedString::new());
        });
        self.job(
            move |_| client.post("/api/center", &body),
            move |c, r| match r {
                Err(e) => {
                    c.with_hub(|h| {
                        h.set_busy(SharedString::new());
                        h.set_set_error(e.text().into());
                    });
                }
                Ok(_) if sets.is_empty() => {
                    c.with_hub(|h| h.set_busy(SharedString::new()));
                    c.toast("Saved.", Tone::Ok);
                    c.hub_reload();
                }
                Ok(_) => c.hub_admin_all(sets, None, |c, answers| {
                    c.with_hub(|h| h.set_busy(SharedString::new()));
                    match answers.into_iter().find_map(Result::err) {
                        Some(e) => {
                            c.with_hub(|h| h.set_set_error(e.into()));
                        }
                        None => c.toast("Saved: the center restarts with it.", Tone::Ok),
                    }
                    // Its address may have changed: found again.
                    c.with_hub(|h| h.set_logged_in(false));
                    c.hub_logged_out();
                }),
            },
        );
    }

    /// Starts, stops or restarts the installed service.
    fn hub_service_action(self: &Rc<Self>, what: &str) {
        let key = format!("service-{what}");
        self.with_hub(|h| h.set_busy(key.as_str().into()));
        let said = match what {
            "start" => "The center started.",
            "stop" => "The center stopped.",
            _ => "The center restarted.",
        };
        self.hub_admin(
            vec!["service".into(), what.to_string()],
            None,
            move |c, answer| {
                c.with_hub(|h| h.set_busy(SharedString::new()));
                match answer {
                    Ok(_) => c.toast(said, Tone::Ok),
                    Err(e) => c.toast(e, Tone::Danger),
                }
                c.hub_connect();
                c.hub_reload();
            },
        );
    }

    /// Updates the center (the app) from the release.
    fn hub_update(self: &Rc<Self>) {
        self.with_hub(|h| h.set_busy("update".into()));
        let pre = self
            .settings
            .borrow()
            .as_deref()
            .is_some_and(crate::settings::pre_releases);
        let mut args = vec!["update".to_string()];
        if pre {
            args.push("--pre".into());
        }
        self.hub_admin(args, None, |c, answer| {
            c.with_hub(|h| h.set_busy(SharedString::new()));
            match answer {
                Ok(v) => {
                    let said = super::said_of(&v);
                    c.with_hub(|h| h.set_update_line(said.as_str().into()));
                    c.toast(said, Tone::Ok);
                }
                Err(e) => c.toast(e, Tone::Danger),
            }
        });
    }

    /// Uninstalls the center, its data too where `purge`.
    fn hub_uninstall(self: &Rc<Self>, purge: bool) {
        self.with_hub(|h| h.set_busy("uninstall".into()));
        let mut args = vec!["uninstall".to_string()];
        if purge {
            args.push("--purge".into());
        }
        self.hub_admin(args, None, |c, answer| {
            c.with_hub(|h| {
                h.set_busy(SharedString::new());
                h.set_uninstall_open(false);
            });
            match answer {
                Ok(_) => {
                    let _ = c.hub.keyring.borrow().delete();
                    c.toast("The center is uninstalled.", Tone::Ok);
                    if c.exec == Exec::Threads {
                        let _ = slint::quit_event_loop();
                    }
                }
                Err(e) => c.toast(e, Tone::Danger),
            }
        });
    }

    /// Shows the owner token (`new`: a new one first), read through one
    /// administrator's prompt.
    fn hub_owner_token(self: &Rc<Self>, new: bool) {
        let busy = if new {
            "owner-token-new"
        } else {
            "owner-token"
        };
        self.with_hub(|h| h.set_busy(busy.into()));
        let mut args = vec!["owner-token".to_string()];
        if new {
            args.push("--new".into());
        }
        self.hub_admin(args, None, move |c, answer| {
            c.with_hub(|h| h.set_busy(SharedString::new()));
            match answer.map(|v| v["token"].as_str().map(str::to_string)) {
                Ok(Some(token)) => {
                    c.with_hub(|h| h.set_owner_token(token.as_str().into()));
                    if new {
                        // The old session ended with the old token: the
                        // app logs in with the new one, and keeps that one
                        // where it kept the old.
                        c.toast(
                            "A new owner token: every log-in with the old one ended.",
                            Tone::Ok,
                        );
                        c.hub_login_with(token, false);
                    }
                }
                Ok(None) => c.toast("The center did not say its token.", Tone::Danger),
                Err(e) => c.toast(e, Tone::Danger),
            }
        });
    }

    /// The keyring switch: on keeps the token the app holds, off forgets
    /// it.
    fn hub_keep_login(&self, on: bool) {
        let keyring = self.hub.keyring.borrow().clone();
        let token = self.hub.token.borrow().clone();
        match keep::switch(keyring.as_ref(), on, token.as_deref()) {
            Ok(()) => {
                self.with_hub(|h| h.set_keep_login(on));
                self.hub_save_keep(on);
            }
            Err(e) => {
                self.with_hub(|h| h.set_keep_login(false));
                self.toast(format!("The keyring cannot keep it: {e}"), Tone::Danger);
            }
        }
    }

    fn hub_save_keep(&self, on: bool) {
        if let Some(file) = self.settings.borrow().as_deref()
            && let Err(e) = crate::settings::save_keep_login(file, on)
        {
            self.toast(format!("The setting was not saved: {e}"), Tone::Warn);
        }
    }

    /// Copies a secret: it leaves the clipboard after a minute, while the
    /// clipboard still holds it.
    fn hub_copy(self: &Rc<Self>, text: &str) {
        let Some(w) = self.window.upgrade() else {
            return;
        };
        match hub::clip::copy(w.window(), text) {
            Ok(mark) => {
                *self.hub.clip.borrow_mut() = Some(mark);
                let c = Rc::downgrade(self);
                self.hub.clip_timer.start(
                    slint::TimerMode::SingleShot,
                    hub::clip::KEEP,
                    move || {
                        if let Some(c) = c.upgrade() {
                            c.hub_clip_expired();
                        }
                    },
                );
            }
            Err(e) => self.toast(format!("Not copied: {e}"), Tone::Danger),
        }
    }

    /// A minute after a secret was copied: it leaves the clipboard, unless
    /// something else was copied since.
    pub fn hub_clip_expired(&self) {
        let Some(mark) = self.hub.clip.borrow_mut().take() else {
            return;
        };
        if let Some(w) = self.window.upgrade() {
            hub::clip::clear_if_still(w.window(), &mark);
        }
    }

    /// Opens the Pair a machine overlay with a new code.
    fn hub_pair_start(self: &Rc<Self>) {
        self.with_hub(|h| {
            h.set_pair_open(true);
            h.set_pair_link(SharedString::new());
            h.set_pair_done(SharedString::new());
            h.set_pair_error(SharedString::new());
        });
        self.hub_pair_new();
    }

    fn hub_pair_new(self: &Rc<Self>) {
        let Some(client) = self.hub.client.borrow().clone() else {
            return;
        };
        self.with_hub(|h| h.set_pair_busy(true));
        self.job(
            move |_| client.post("/api/pair", &json!({})),
            |c, r| {
                c.with_hub(|h| h.set_pair_busy(false));
                match r {
                    Ok(v) => {
                        let (link, command, until) = view::pair(&v, now_ms());
                        *c.hub.pair_code.borrow_mut() =
                            v["code"].as_str().unwrap_or_default().to_string();
                        c.with_hub(|h| {
                            h.set_pair_link(link.into());
                            h.set_pair_command(command.into());
                            h.set_pair_until(until.into());
                            h.set_pair_done(SharedString::new());
                            h.set_pair_error(SharedString::new());
                        });
                        c.hub_pair_watch();
                    }
                    Err(Failed::LoggedOut) => c.hub_logged_out(),
                    Err(e) => c
                        .with_hub(|h| h.set_pair_error(e.text().into()))
                        .unwrap_or_default(),
                }
            },
        );
    }

    /// Asks every two seconds, while the overlay is open, whether a machine
    /// used the code.
    fn hub_pair_watch(self: &Rc<Self>) {
        if self.exec != Exec::Threads {
            return;
        }
        let c = Rc::downgrade(self);
        self.hub.pair_timer.start(
            slint::TimerMode::Repeated,
            Duration::from_secs(2),
            move || {
                if let Some(c) = c.upgrade() {
                    c.hub_pair_check();
                }
            },
        );
    }

    /// Whether a machine used the code; says so in the overlay.
    pub fn hub_pair_check(self: &Rc<Self>) {
        if self.with_hub(|h| h.get_pair_open()) != Some(true) {
            self.hub.pair_timer.stop();
            return;
        }
        let (Some(client), code) = (
            self.hub.client.borrow().clone(),
            self.hub.pair_code.borrow().clone(),
        ) else {
            return;
        };
        self.job(
            move |_| client.post("/api/pair/status", &json!({ "code": code })),
            |c, r| {
                if let Some(done) = r.ok().as_ref().and_then(view::paired) {
                    c.hub.pair_timer.stop();
                    c.with_hub(|h| h.set_pair_done(done.into()));
                    c.hub_reload();
                }
            },
        );
    }

    /// Renames the picked machine.
    fn hub_node_rename(self: &Rc<Self>) {
        let Some((id, name)) = self.with_hub(|h| {
            let i = h.get_node_pick().max(0) as usize;
            let id = h.get_nodes().row_data(i).map(|n| n.id.to_string());
            (id, h.get_rename_text().trim().to_string())
        }) else {
            return;
        };
        let Some(id) = id else {
            return;
        };
        let Some(client) = self.hub.client.borrow().clone() else {
            return;
        };
        self.with_hub(|h| h.set_busy(id.as_str().into()));
        let body = json!({"id": id, "name": name});
        self.job(
            move |_| client.post("/api/nodes/rename", &body),
            |c, r| {
                c.with_hub(|h| h.set_busy(SharedString::new()));
                match r {
                    Ok(_) => {
                        c.with_hub(|h| h.set_rename_open(false));
                        c.hub_reload();
                    }
                    Err(Failed::LoggedOut) => c.hub_logged_out(),
                    Err(e) => c
                        .with_hub(|h| h.set_rename_error(e.text().into()))
                        .unwrap_or_default(),
                }
            },
        );
    }

    fn hub_node_sudo_ask(self: &Rc<Self>, id: String) {
        let Some(client) = self.hub.client.borrow().clone() else {
            return;
        };
        self.with_hub(|h| h.set_busy(id.as_str().into()));
        let target = format!("/api/nodes/settings?id={}", view::query_value(&id));
        self.job(
            move |_| client.get(&target),
            |c, r| {
                c.with_hub(|h| h.set_busy(SharedString::new()));
                match r {
                    Ok(v) => c
                        .with_hub(|h| {
                            h.set_node_sudo(if v["sudo"] == "on" { "on" } else { "off" }.into())
                        })
                        .unwrap_or_default(),
                    Err(Failed::LoggedOut) => c.hub_logged_out(),
                    Err(e) => c
                        .with_hub(|h| h.set_sudo_error(e.text().into()))
                        .unwrap_or_default(),
                }
            },
        );
    }

    /// Sudo on (with the password, sealed here for the machine's one-shot
    /// offer, which the center relays without opening) or off.
    fn hub_node_sudo(self: &Rc<Self>, id: String, on: bool) {
        let Some(client) = self.hub.client.borrow().clone() else {
            return;
        };
        let password = self
            .with_hub(|h| {
                let p = h.get_sudo_password().to_string();
                h.set_sudo_password(SharedString::new());
                h.set_sudo_error(SharedString::new());
                p
            })
            .unwrap_or_default();
        if on && password.is_empty() {
            self.with_hub(|h| h.set_sudo_error("Enter the machine's sudo password first.".into()));
            return;
        }
        self.with_hub(|h| h.set_busy(id.as_str().into()));
        self.job(
            move |_| -> Result<Value, Failed> {
                if !on {
                    return client.post("/api/nodes/sudo", &json!({"id": id, "on": false}));
                }
                let offer = client.post("/api/nodes/sudo/offer", &json!({ "id": id }))?;
                let offer: nerve_transport::sudo::Offer = serde_json::from_value(offer)
                    .map_err(|e| Failed::Unreachable(format!("the machine's offer: {e}")))?;
                let sealed = nerve_transport::sudo::seal(&offer, &password, now_ms())
                    .map_err(Failed::Unreachable)?;
                client.post(
                    "/api/nodes/sudo",
                    &json!({"id": id, "on": true, "sealed": sealed}),
                )
            },
            move |c, r| {
                c.with_hub(|h| h.set_busy(SharedString::new()));
                match r {
                    Ok(v) => {
                        let now_on = v["sudo"] == "on";
                        c.with_hub(|h| h.set_node_sudo(if now_on { "on" } else { "off" }.into()));
                        c.toast(
                            if now_on {
                                "Sudo is on: the sudo list's commands run with sudo."
                            } else {
                                "Sudo is off."
                            },
                            Tone::Ok,
                        );
                    }
                    Err(Failed::LoggedOut) => c.hub_logged_out(),
                    Err(e) => c
                        .with_hub(|h| h.set_sudo_error(e.text().into()))
                        .unwrap_or_default(),
                }
            },
        );
    }

    /// A machine picked on the Capabilities page.
    fn hub_caps_machine(self: &Rc<Self>, i: i32) {
        let names = self.hub_names();
        if let Some((id, _)) = usize::try_from(i).ok().and_then(|i| names.get(i)) {
            *self.hub.cap_node.borrow_mut() = id.clone();
        }
        self.with_hub(|h| {
            h.set_cap_pick(0);
            h.set_cap_form(false);
        });
        self.hub_load(HubPage::Caps);
    }

    fn hub_cap_save(self: &Rc<Self>) {
        let Some(form) = self.with_hub(|h| {
            view::cap_form(
                &h.get_cap_name(),
                h.get_cap_kind(),
                &h.get_cap_command(),
                &h.get_cap_summary(),
            )
        }) else {
            return;
        };
        let Some(client) = self.hub.client.borrow().clone() else {
            return;
        };
        let id = self.hub.cap_node.borrow().clone();
        self.with_hub(|h| {
            h.set_busy("cap".into());
            h.set_cap_error(SharedString::new());
        });
        let body = json!({"id": id, "form": form, "adding": true});
        self.job(
            move |_| client.post("/api/caps/save", &body),
            |c, r| {
                c.with_hub(|h| h.set_busy(SharedString::new()));
                match r {
                    Ok(_) => {
                        c.with_hub(|h| h.set_cap_form(false));
                        c.toast("The machine took the capability.", Tone::Ok);
                        c.hub_load(HubPage::Caps);
                    }
                    Err(Failed::LoggedOut) => c.hub_logged_out(),
                    Err(e) => c
                        .with_hub(|h| h.set_cap_error(e.text().into()))
                        .unwrap_or_default(),
                }
            },
        );
    }

    /// The file a backup goes to, or a restore comes from.
    fn hub_backup_choose(self: &Rc<Self>, restore: bool) {
        let chooser = self.chooser.borrow().clone();
        let what = if restore {
            Choose::OpenBackup
        } else {
            Choose::SaveCenterBackup
        };
        self.job(
            move |_| chooser(what),
            move |c, picked| {
                let path = match picked {
                    Ok(Some(path)) => path,
                    Ok(None) => return,
                    Err(e) => return c.no_chooser(e),
                };
                c.with_hub(|h| {
                    h.set_backup_file(path.display().to_string().into());
                    h.set_backup_pass(SharedString::new());
                    h.set_backup_pass2(SharedString::new());
                    h.set_backup_error(SharedString::new());
                    h.set_backup_open(!restore);
                    h.set_restore_open(restore);
                });
            },
        );
    }

    /// Backs the center up: its administrator's command writes the sealed
    /// backup into its answer, and the app writes that into the file the
    /// owner chose. The broker names no file (crate::broker::allowed).
    fn hub_backup(self: &Rc<Self>) {
        let Some((file, pass)) = self.with_hub(|h| {
            (
                PathBuf::from(h.get_backup_file().as_str()),
                h.get_backup_pass().to_string(),
            )
        }) else {
            return;
        };
        self.with_hub(|h| {
            h.set_backup_busy(true);
            h.set_backup_error(SharedString::new());
        });
        self.hub_admin(backup_args(), Some(pass), move |c, answer| {
            let written = answer.and_then(|v| {
                let sealed = v["backup"].as_str().ok_or("the center gave no backup")?;
                let bytes = nerve_transport::tls::unb64url(sealed)
                    .ok_or("the center's backup did not read")?;
                nerve_transport::files::write_private(&file, &bytes)
                    .map_err(|e| format!("{}: {e}", file.display()))
            });
            c.with_hub(|h| h.set_backup_busy(false));
            match written {
                Ok(()) => {
                    c.with_hub(|h| h.set_backup_open(false));
                    c.toast(format!("Backed up to {}.", file.display()), Tone::Ok);
                }
                Err(e) => c
                    .with_hub(|h| h.set_backup_error(e.into()))
                    .unwrap_or_default(),
            }
        });
    }

    /// Restores a backup: the app reads the file the owner chose and hands
    /// its bytes to the administrator's command on its input.
    fn hub_restore(self: &Rc<Self>) {
        let Some((file, pass)) = self.with_hub(|h| {
            (
                PathBuf::from(h.get_backup_file().as_str()),
                h.get_backup_pass().to_string(),
            )
        }) else {
            return;
        };
        let bytes = match std::fs::read(&file) {
            Ok(b) => b,
            Err(e) => {
                self.with_hub(|h| h.set_backup_error(format!("{}: {e}", file.display()).into()));
                return;
            }
        };
        let input = format!("{}\n{pass}", nerve_transport::tls::b64url(&bytes));
        self.with_hub(|h| {
            h.set_backup_busy(true);
            h.set_backup_error(SharedString::new());
        });
        self.hub_admin(restore_args(), Some(input), |c, answer| {
            c.with_hub(|h| h.set_backup_busy(false));
            match answer {
                Ok(_) => {
                    c.with_hub(|h| h.set_restore_open(false));
                    c.toast("Restored: the center restarted with the backup.", Tone::Ok);
                    c.hub_logged_out();
                }
                Err(e) => c
                    .with_hub(|h| h.set_backup_error(e.into()))
                    .unwrap_or_default(),
            }
        });
    }

    /// Opens the center's web UI in the browser, once its service holds the
    /// port.
    fn hub_open_web_ui(&self) {
        let run = self.hub.run.borrow().clone();
        let judge = self.hub.judge.borrow().clone();
        if let Err(e) =
            super::install::open_center_ui_in(&run, |at| judge(at), crate::browser::open)
        {
            self.toast(e, Tone::Danger);
        }
    }
}

/// The center's backup through the broker: into its answer, the
/// passphrase on its input (crate::broker::allowed takes only these).
pub fn backup_args() -> Vec<String> {
    ["backup", "-", "--passphrase-file", "-"]
        .map(String::from)
        .to_vec()
}

/// The center's restore through the broker: the backup and the passphrase
/// on its input.
pub fn restore_args() -> Vec<String> {
    ["restore", "-", "--passphrase-file", "-"]
        .map(String::from)
        .to_vec()
}

/// What `__center status --json` says, run as the app's user: the
/// service's state needs no rights.
fn service_status(r: &crate::runner::Runner) -> Option<Value> {
    r.direct()
        .run(&[nerve_center::edition::APP_WORD, "status"])
        .ok()
}

pub(super) fn wire(ctl: &Rc<Ctl>, window: &crate::AppWindow) {
    let h = window.global::<Hub>();
    let c = ctl.clone();
    h.on_show(move |page| c.hub_show(page));
    let c = ctl.clone();
    h.on_reload(move || c.hub_reload());
    let c = ctl.clone();
    h.on_login(move || c.hub_login());
    let c = ctl.clone();
    h.on_login_read(move || c.hub_login_read());
    let c = ctl.clone();
    h.on_logout(move || c.hub_logout());
    let c = ctl.clone();
    h.on_check_again(move || {
        c.hub_connect();
    });
    let c = ctl.clone();
    h.on_start_service(move || c.hub_service_action("start"));
    let c = ctl.clone();
    h.on_turn_ui_on(move || {
        // The web UI's default address, on loopback.
        let ui = "127.0.0.1:7480".to_string();
        c.hub_admin(vec!["set".into(), "ui".into(), ui], None, |c, answer| {
            if let Err(e) = answer {
                c.toast(e, Tone::Danger);
            }
            c.hub_connect();
        });
    });
    let c = ctl.clone();
    h.on_service(move |what| c.hub_service_action(&what));
    let c = ctl.clone();
    h.on_update(move || c.hub_update());
    let c = ctl.clone();
    h.on_uninstall(move |purge| c.hub_uninstall(purge));
    let c = ctl.clone();
    h.on_open_web_ui(move || c.hub_open_web_ui());
    let c = ctl.clone();
    h.on_pair_start(move || c.hub_pair_start());
    let c = ctl.clone();
    h.on_pair_new(move || c.hub_pair_new());
    let c = ctl.clone();
    h.on_node_rename(move || c.hub_node_rename());
    let c = ctl.clone();
    h.on_node_disable(move |id, off| {
        c.hub_post_said(
            "/api/nodes/disable",
            json!({"id": id.as_str(), "disabled": off}),
            &id,
            move |_| {
                if off {
                    "The machine is off: the agent cannot use it until it is on again.".into()
                } else {
                    "The machine is on again.".into()
                }
            },
        );
    });
    let c = ctl.clone();
    h.on_node_remove(move |id| {
        c.hub_post_said(
            "/api/nodes/remove",
            json!({ "id": id.as_str() }),
            &id,
            |_| "The machine is removed: it needs a new pairing to come back.".into(),
        );
    });
    let c = ctl.clone();
    h.on_node_sudo_ask(move |id| c.hub_node_sudo_ask(id.to_string()));
    let c = ctl.clone();
    h.on_node_sudo_set(move |id, on| c.hub_node_sudo(id.to_string(), on));
    let c = ctl.clone();
    h.on_token_create(move || {
        let Some(client) = c.hub.client.borrow().clone() else {
            return;
        };
        let label = c
            .with_hub(|h| h.get_token_label().trim().to_string())
            .unwrap_or_default();
        c.with_hub(|h| h.set_busy("token-create".into()));
        c.job(
            move |_| client.post("/api/tokens/create", &json!({ "label": label })),
            |c, r| {
                c.with_hub(|h| h.set_busy(SharedString::new()));
                match r {
                    Ok(v) => {
                        let token = v["token"].as_str().unwrap_or_default().to_string();
                        let url = c
                            .with_hub(|h| h.get_mcp_url().to_string())
                            .unwrap_or_default();
                        let (clear, masked) = view::connect_lines(&url, &token);
                        c.with_hub(|h| {
                            h.set_new_token(token.into());
                            h.set_token_shown(false);
                            h.set_token_label(SharedString::new());
                            h.set_connect_lines(model(clear));
                            h.set_connect_masked(model(masked));
                        });
                        c.hub_reload();
                    }
                    Err(Failed::LoggedOut) => c.hub_logged_out(),
                    Err(e) => c.toast(e.text(), Tone::Danger),
                }
            },
        );
    });
    let c = ctl.clone();
    h.on_token_delete(move |id| {
        c.with_hub(|h| h.set_harn_pick(-1));
        c.hub_post_said(
            "/api/tokens/delete",
            json!({ "id": id.as_str() }),
            &id,
            |_| "The token is removed: its harness is stopped.".into(),
        );
    });
    let c = ctl.clone();
    h.on_session_end(move |id| {
        c.with_hub(|h| h.set_harn_pick(-1));
        c.hub_post_said(
            "/api/sessions/end",
            json!({ "id": id.as_str() }),
            &id,
            |_| "The session ended.".into(),
        );
    });
    let c = ctl.clone();
    h.on_copy_secret(move |text| c.hub_copy(&text));
    let c = ctl.clone();
    h.on_checker_switch(move |which, on| {
        c.hub_checker_change(
            move |cfg| view::with_switch(cfg, which, on),
            "The change counts from the next call.",
            |_| {},
        );
    });
    let c = ctl.clone();
    h.on_rule_pick(move |i| c.hub_rule_pick(i));
    let c = ctl.clone();
    h.on_rule_add(move || c.hub_rule_add());
    let c = ctl.clone();
    h.on_rule_save(move || c.hub_rule_save());
    let c = ctl.clone();
    h.on_rule_remove(move |skip, i| {
        c.with_hub(|h| h.set_asking(SharedString::new()));
        c.hub_checker_change(
            move |cfg| view::without_rule(cfg, skip, i.max(0) as usize),
            "The rule is removed.",
            |c| c.hub_rule_pick(0),
        );
    });
    let c = ctl.clone();
    h.on_rule_on(move |_, i, on| {
        c.hub_checker_change(
            move |cfg| view::with_rule_on(cfg, i.max(0) as usize, on),
            "",
            |_| {},
        );
    });
    let c = ctl.clone();
    h.on_rule_where_set(move |_, i, node, on| {
        c.hub_checker_change(
            move |cfg| view::with_rule_where(cfg, i.max(0) as usize, &node, on),
            "",
            |_| {},
        );
    });
    let c = ctl.clone();
    h.on_machine_set(move |node, which, value| {
        c.hub_checker_change(
            move |cfg| view::with_machine(cfg, &node, which, value),
            "",
            |_| {},
        );
    });
    let c = ctl.clone();
    h.on_model_install(move |gpu| {
        c.with_hub(|h| h.set_busy("model".into()));
        c.hub_post_said(
            "/api/checker/install",
            json!({ "gpu": gpu }),
            "model",
            |_| "The local model installs; it takes a few minutes.".into(),
        );
    });
    let c = ctl.clone();
    h.on_model_remove(move || {
        c.hub_post_said("/api/checker/remove", json!({}), "model", |_| {
            "The local model is removed.".into()
        });
    });
    let c = ctl.clone();
    h.on_model_token_save(move || {
        let token = c
            .with_hub(|h| {
                let t = h.get_model_token().to_string();
                h.set_model_token(SharedString::new());
                t
            })
            .unwrap_or_default();
        let token = (!token.is_empty()).then_some(token);
        c.hub_post_said(
            "/api/checker/token",
            json!({ "token": token }),
            "model",
            |_| "The model server's token is saved.".into(),
        );
    });
    let c = ctl.clone();
    h.on_caps_machine(move |i| c.hub_caps_machine(i));
    let c = ctl.clone();
    h.on_cap_add(move || {
        c.with_hub(|h| {
            h.set_cap_name(SharedString::new());
            h.set_cap_kind(1);
            h.set_cap_command(SharedString::new());
            h.set_cap_summary(SharedString::new());
            h.set_cap_error(SharedString::new());
            h.set_cap_form(true);
        });
    });
    let c = ctl.clone();
    h.on_cap_save(move || c.hub_cap_save());
    let c = ctl.clone();
    h.on_cap_remove(move |name| {
        let id = c.hub.cap_node.borrow().clone();
        c.hub_post_said(
            "/api/caps/remove",
            json!({"id": id, "name": name.as_str()}),
            &name,
            |_| "The capability is removed.".into(),
        );
    });
    let c = ctl.clone();
    h.on_stats_picked(move |i| c.hub_stats_pick(i));
    let c = ctl.clone();
    h.on_audit_filtered(move || c.hub_audit_shown());
    let c = ctl.clone();
    h.on_audit_rule(move |i, list, wildcard, pin| {
        c.hub_audit_rule(i.max(0) as usize, &list, wildcard, pin)
    });
    let c = ctl.clone();
    h.on_audit_trust(move |i, wildcard, pin| c.hub_audit_trust(i.max(0) as usize, wildcard, pin));
    let c = ctl.clone();
    h.on_log_filtered(move || c.hub_load(HubPage::Log));
    let c = ctl.clone();
    h.on_log_download(move || {
        let Some(client) = c.hub.client.borrow().clone() else {
            return;
        };
        let chooser = c.chooser.borrow().clone();
        c.with_hub(|h| h.set_busy("log-download".into()));
        c.job(
            move |_| -> Result<Option<PathBuf>, String> {
                let bytes = client.log_file().map_err(|e| e.text())?;
                let Some(path) = chooser(Choose::SaveLog)? else {
                    return Ok(None);
                };
                std::fs::write(&path, bytes).map_err(|e| format!("{}: {e}", path.display()))?;
                Ok(Some(path))
            },
            |c, r| {
                c.with_hub(|h| h.set_busy(SharedString::new()));
                match r {
                    Ok(Some(p)) => c.toast(format!("Saved the log to {}.", p.display()), Tone::Ok),
                    Ok(None) => {}
                    Err(e) => c.toast(e, Tone::Danger),
                }
            },
        );
    });
    let c = ctl.clone();
    h.on_settings_save(move || c.hub_settings_save());
    let c = ctl.clone();
    h.on_token_show(move || c.hub_owner_token(false));
    let c = ctl.clone();
    h.on_token_new(move || c.hub_owner_token(true));
    let c = ctl.clone();
    h.on_keep_login_set(move |on| c.hub_keep_login(on));
    let c = ctl.clone();
    h.on_key_rotate(move || {
        c.hub_post_said("/api/center/key/rotate", json!({}), "key", |_| {
            "A new center key: the machines take it at their next link.".into()
        });
    });
    let c = ctl.clone();
    h.on_key_finish(move || {
        c.hub_post_said("/api/center/key/finish", json!({}), "key", |_| {
            "The old key no longer counts.".into()
        });
    });
    let c = ctl.clone();
    h.on_backup_choose(move || c.hub_backup_choose(false));
    let c = ctl.clone();
    h.on_restore_choose(move || c.hub_backup_choose(true));
    let c = ctl.clone();
    h.on_backup(move || c.hub_backup());
    let c = ctl.clone();
    h.on_restore(move || c.hub_restore());
}
