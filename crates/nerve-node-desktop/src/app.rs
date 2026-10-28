//! The app's actions: each one runs a `nerve-node` command ([`Runner`]) off
//! the window's thread and shows its answer ([`crate::view`]). A change is
//! shown once the node made it, never before.

use std::cell::{Cell, RefCell};
use std::path::PathBuf;
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, AtomicU64};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::Value;
use slint::{ComponentHandle, ModelRc, SharedString, VecModel};

use crate::broker::Launch;
use crate::runner::{Follow, Runner};
use crate::{AppWindow, Install, Load, Manual, Motion, Page, Perm, Prefs, Store, Tone, Type, view};

mod caps;
mod install;
mod live;
mod node;
mod perm;
mod prefs;

pub use perm::PermAnswers;

/// Where the commands run: on threads of their own, answering on the
/// window's event loop; or at once, for tests and the screenshots, which
/// have no event loop.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Exec {
    Threads,
    Inline,
}

/// How the app asks the desktop whether it is dark (crate::scheme): none
/// when it does not say.
pub type SchemeSource = fn() -> Option<bool>;

/// How the app asks the desktop whether it wants less motion
/// (crate::motion): none when it does not say.
pub type MotionSource = fn() -> Option<bool>;

/// What the owner picks in one of the system's file dialogs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Choose {
    /// A folder a center may use.
    Folder,
    /// Where a new backup goes.
    SaveBackup,
    /// The backup to restore.
    OpenBackup,
    /// The program an update takes.
    Program,
    /// A program to allow as a provider.
    Provider,
}

/// Shows the system's dialog for a [`Choose`]; tests answer for it.
/// What the owner picked, `None` when they closed the dialog; an error
/// when no dialog can open (crate::deps::portal).
pub type Chooser = Arc<dyn Fn(Choose) -> Result<Option<PathBuf>, String> + Send + Sync>;

/// Starts the installed app, as the menu entry does; tests answer for it.
pub type Launcher = Arc<dyn Fn(&std::path::Path) -> Result<(), String> + Send + Sync>;

/// The system's own dialogs: the desktop portal on Linux, so they work on
/// Wayland and look like the desktop's.
fn system_chooser() -> Chooser {
    // The app on Linux is closed to /proc once it has the rights
    // (crate::broker), and the portal then refuses it: a dialog asked by a
    // process of its own, started fresh, is the portal's to show.
    #[cfg(target_os = "linux")]
    return Arc::new(|c| crate::dialog::apart(std::path::Path::new("/proc/self/exe"), c));
    #[cfg(not(target_os = "linux"))]
    Arc::new(crate::dialog::show)
}

/// Under a key or token shown once.
const KEY_NOTE: &str = "It is shown only now: copy it to the other node.";

/// The change that waits for the owner's yes in the confirm dialog.
enum Pending {
    Unpair(String),
    RotateKey(String),
    Accept,
    /// `audit clear`, or with `true` `log clear`.
    Clear(bool),
    /// `cap rm` of a capability of node.toml.
    CapRemove(String),
}

/// What a command that keeps answering gave, until the window takes it.
type Queue = Arc<Mutex<Vec<(u64, Result<Value, String>)>>>;

pub struct Ctl {
    runner: RefCell<Runner>,
    exec: Exec,
    window: slint::Weak<AppWindow>,
    chooser: RefCell<Chooser>,
    /// The audit entries read, newest first: what a button's index names.
    audit: RefCell<Vec<Value>>,
    /// What the Audit page shows of them, and the centers and actions its
    /// pickers offer (after "every").
    audit_filter: RefCell<view::AuditFilter>,
    audit_options: RefCell<(Vec<String>, Vec<String>)>,
    /// The log lines shown, newest first.
    log: RefCell<Vec<Value>>,
    /// The names of the paired centers, and the status, as the node said
    /// them last.
    centers: RefCell<Vec<String>>,
    status: RefCell<Value>,
    pending: RefCell<Option<Pending>>,
    asking_status: Cell<bool>,
    timer: slint::Timer,
    /// The page's command that keeps answering (`audit --follow`), what it
    /// gave, and which start of it that was.
    follow: RefCell<Option<Follow>>,
    queue: Queue,
    feed: Arc<AtomicU64>,
    pumping: Arc<AtomicBool>,
    settle: slint::Timer,
    /// Whether the node is the installed service's, whose state the app
    /// asks for, and whether it is asking now.
    service: Cell<bool>,
    asking_service: Cell<bool>,
    /// Starts the installed app (src/app/install.rs), which is there.
    launcher: RefCell<Launcher>,
    program: RefCell<PathBuf>,
    /// The app's own settings file (crate::settings), when it keeps one.
    settings: RefCell<Option<PathBuf>>,
    /// This window's claim as the user's one window (crate::instance).
    instance: RefCell<Option<crate::instance::Instance>>,
    /// How the broker starts when the node is installed as a service: for
    /// one command that needs an administrator (`nerve_node::owner`), or,
    /// with `session_rights`, for every command of the session.
    elevate: Cell<Option<Launch>>,
    /// Whether every command needs the broker: the app's user is no owner
    /// of the installed node.
    session_rights: Cell<bool>,
    /// A `nerve://` link the app was opened with, paired once it can be.
    link: RefCell<Option<String>>,
    /// Open the first-run steps when nothing is paired yet.
    first_run: Cell<bool>,
    /// Which reading of the Permissions page is the latest: an answer for
    /// an earlier one (another center picked meanwhile) is dropped.
    perm_asked: Cell<u64>,
    /// The same for the Capabilities page, and what `cap ls` said last:
    /// the entries of node.toml its dialog edits.
    caps_asked: Cell<u64>,
    /// The node's `limits.max_timeout_secs` as the page last read it: the
    /// most a capability's time limit may be.
    caps_max_timeout: Cell<u64>,
    /// The capability dialog that is open, or was last: a count, so an
    /// answer of a save that comes later knows whether it is still its own.
    cap_dialogs: Cell<u64>,
    caps_listing: RefCell<Value>,
    /// Restarts the service a moment after a change it takes only then.
    restart_timer: slint::Timer,
    /// A restart the app said would come and that has not run yet; the
    /// app's end runs it ([`Ctl::end`]).
    restart_waits: Cell<bool>,
    /// Asks the desktop now and then whether it is dark, while the app
    /// follows it (crate::scheme).
    scheme_timer: slint::Timer,
    /// What the desktop said last of its light or dark: not asked yet, it
    /// did not say (`Some(None)`), or whether it is dark.
    desktop_dark: Cell<Option<Option<bool>>>,
    /// How the desktop is asked (crate::scheme::dark_here); none in tests
    /// and screenshots, which set the look themselves.
    scheme_source: Cell<Option<SchemeSource>>,
    /// Asks the desktop now and then whether it wants less motion
    /// (crate::motion).
    motion_timer: slint::Timer,
    /// How the desktop is asked (crate::motion::reduced_here); none in tests
    /// and screenshots, which draw without motion.
    motion_source: Cell<Option<MotionSource>>,
    /// Every command of the CLI, for the Help page's reference.
    reference: Vec<crate::reference::Command>,
    /// The commands and topics of the reference the owner opened or closed.
    ref_opened: RefCell<crate::reference::Opened>,
    /// Where a new relay link says this machine is, as `relay ls` guessed.
    relay_address: RefCell<String>,
}

thread_local! {
    // The controller of the window on this thread, for answers that come
    // back from a command's thread.
    static CURRENT: RefCell<Option<Rc<Ctl>>> = const { RefCell::new(None) };
}

/// The system's monospace font. Slint takes one family by its name, and
/// does not resolve a generic one; fontconfig knows which one Linux uses.
fn mono_font() -> String {
    if cfg!(windows) {
        return "Consolas".into();
    }
    std::process::Command::new("fc-match")
        .args(["-f", "%{family[0]}", "monospace"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|f| f.trim().to_string())
        .filter(|f| !f.is_empty())
        .unwrap_or_else(|| "DejaVu Sans Mono".into())
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or_default()
}

/// The account the app runs as, by name.
pub fn app_user() -> String {
    std::env::var("USERNAME")
        .or_else(|_| std::env::var("USER"))
        .unwrap_or_default()
}

/// Whether the command `args` needs an administrator even for an owner of
/// the installed node (nerve_node::owner::needs_admin).
pub fn needs_admin(args: &[String]) -> bool {
    nerve_node::owner::args_need_admin(args)
}

fn strings(args: &[String]) -> Vec<&str> {
    args.iter().map(String::as_str).collect()
}

fn lines(v: &Value) -> impl Iterator<Item = &str> {
    v["messages"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
}

/// Whether the node takes what a change made only at its next start: the
/// installed node on Windows takes nothing but folder changes while it
/// runs, and a node that does not run takes everything when it starts
/// (`"next_start"` of nerve-node's `--json`).
fn waits_for_start(v: &Value) -> bool {
    v["next_start"] == true
}

/// What a change said, without the line about the next start, which
/// [`Ctl::done`] says in words of its own.
fn said_of(v: &Value) -> String {
    lines(v)
        .filter(|l| !nerve_node::cli::takes_at_next_start(l))
        .collect::<Vec<_>>()
        .join("\n")
}

/// `said`, then `then` on a line of its own.
fn and_then(said: String, then: &str) -> String {
    if said.is_empty() {
        then.to_string()
    } else {
        format!("{said}\n{then}")
    }
}

/// What the app does about a change the node takes only at its next start.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Restart {
    /// The node took it, or it changed nothing.
    No,
    /// The service runs: the app restarts it in a moment.
    Soon,
    /// The service runs, and the first-run steps restart it at their end.
    AtEnd,
    /// The node does not run, and takes it when it starts.
    AtStart,
}

impl Ctl {
    /// Wires `window`'s actions to the CLI that `runner` starts.
    pub fn attach(window: &AppWindow, runner: Runner, exec: Exec) -> Rc<Ctl> {
        let ctl = Rc::new(Ctl {
            runner: RefCell::new(runner),
            exec,
            window: window.as_weak(),
            chooser: RefCell::new(system_chooser()),
            audit: RefCell::new(Vec::new()),
            audit_filter: RefCell::default(),
            audit_options: RefCell::default(),
            log: RefCell::new(Vec::new()),
            centers: RefCell::new(Vec::new()),
            status: RefCell::new(Value::Null),
            pending: RefCell::new(None),
            asking_status: Cell::new(false),
            timer: slint::Timer::default(),
            follow: RefCell::new(None),
            queue: Arc::default(),
            feed: Arc::default(),
            pumping: Arc::default(),
            settle: slint::Timer::default(),
            service: Cell::new(false),
            asking_service: Cell::new(false),
            launcher: RefCell::new(install::system_launcher()),
            program: RefCell::new(PathBuf::new()),
            settings: RefCell::new(None),
            instance: RefCell::new(None),
            elevate: Cell::new(None),
            session_rights: Cell::new(false),
            link: RefCell::new(None),
            first_run: Cell::new(false),
            perm_asked: Cell::new(0),
            caps_asked: Cell::new(0),
            caps_max_timeout: Cell::new(nerve_policy::config::Limits::default().max_timeout_secs),
            cap_dialogs: Cell::new(0),
            caps_listing: RefCell::new(Value::Null),
            restart_timer: slint::Timer::default(),
            restart_waits: Cell::new(false),
            scheme_timer: slint::Timer::default(),
            desktop_dark: Cell::new(None),
            scheme_source: Cell::new(
                (exec == Exec::Threads).then_some(crate::scheme::dark_here as SchemeSource),
            ),
            motion_timer: slint::Timer::default(),
            motion_source: Cell::new(
                (exec == Exec::Threads).then_some(crate::motion::reduced_here as MotionSource),
            ),
            reference: crate::reference::commands(&nerve_node::cli::help()),
            ref_opened: RefCell::default(),
            relay_address: RefCell::new(String::new()),
        });
        CURRENT.with(|c| *c.borrow_mut() = Some(ctl.clone()));
        window.global::<Type>().set_mono(mono_font().into());
        ctl.reference_shown();
        let manual = window.global::<Manual>();
        let c = ctl.clone();
        manual.on_ref_update(move || c.reference_shown());
        let c = ctl.clone();
        manual.on_ref_toggle(move |name| {
            if let Some(w) = c.window.upgrade() {
                let shown = w.global::<Manual>().get_ref_groups();
                c.ref_opened.borrow_mut().toggle_command(&shown, &name);
            }
        });
        let c = ctl.clone();
        manual.on_ref_group_toggle(move |name| {
            if let Some(w) = c.window.upgrade() {
                let shown = w.global::<Manual>().get_ref_groups();
                c.ref_opened.borrow_mut().toggle_topic(&shown, &name);
            }
        });
        let c = ctl.clone();
        manual.on_ref_go(move |page, tab| {
            if tab >= 0 {
                c.with_prefs(|p| p.set_tab(tab));
            }
            c.show(page);
        });
        let store = window.global::<Store>();
        store.set_version(env!("CARGO_PKG_VERSION").into());
        let install = window.global::<Install>();
        install.set_version(env!("CARGO_PKG_VERSION").into());
        install.set_windows(cfg!(windows));
        // The account install takes for the commands, when none is chosen
        // yet: the user of the app.
        install.set_account(
            std::env::var("USERNAME")
                .or_else(|_| std::env::var("USER"))
                .unwrap_or_default()
                .into(),
        );

        let c = ctl.clone();
        store.on_show(move |page| c.show(page));
        let c = ctl.clone();
        store.on_reload(move || c.reload());
        let c = ctl.clone();
        store.on_refresh(move || c.refresh_status());
        let c = ctl.clone();
        store.on_refresh_audit(move || c.follow_audit());
        let c = ctl.clone();
        store.on_audit_filtered(move || c.show_audit());
        let c = ctl.clone();
        store.on_audit_rule(move |i, list, wildcard| c.audit_rule(i as usize, &list, wildcard));
        let c = ctl.clone();
        store.on_pair_start(move || c.pair_start());
        let c = ctl.clone();
        store.on_pair_check(move |link, name| c.pair(&link, &name, false));
        let c = ctl.clone();
        store.on_pair_confirm(move || {
            let (link, name) = c
                .with_store(|s| (s.get_pair_link(), s.get_pair_name()))
                .unwrap_or_default();
            c.pair(&link, &name, true)
        });
        let c = ctl.clone();
        store.on_center_pause(move |name, pause| c.center_pause(&name, pause));
        let c = ctl.clone();
        store.on_center_grant(move |name, on| c.center_grant(&name, on));
        let c = ctl.clone();
        store.on_center_unpair(move |name| c.ask_unpair(&name));
        let c = ctl.clone();
        store.on_center_rotate(move |name| c.ask_rotate(&name));
        let c = ctl.clone();
        store.on_confirm_accepted(move || c.confirmed());
        let c = ctl.clone();
        store.on_panic(move || c.lock(true));
        let c = ctl.clone();
        store.on_unlock(move || c.lock(false));
        let c = ctl.clone();
        store.on_set_appearance(move |i| c.set_appearance(i));
        node::wire(&ctl, window);
        perm::wire(&ctl, window);
        caps::wire(&ctl, window);
        prefs::wire(&ctl, window);
        live::wire(&ctl, window);
        install::wire(&ctl, window);
        ctl
    }

    /// Answers the file dialogs with `chooser` instead of the system's.
    pub fn set_chooser(&self, chooser: Chooser) {
        *self.chooser.borrow_mut() = chooser;
    }

    /// The node is installed as a service, and its owners change it without
    /// a question: `how` asks for an administrator only for a command that
    /// needs one ([`nerve_node::owner::needs_admin`]), each time, and the
    /// broker ends with that command.
    pub fn admin_rights(&self, how: Launch) {
        self.elevate.set(Some(how));
    }

    /// The node is installed as a service and the app's user is no owner:
    /// the app needs the rights to read it, says why, and asks with `how`
    /// when the owner goes on.
    pub fn needs_rights(&self, how: Launch) {
        self.elevate.set(Some(how));
        self.session_rights.set(true);
        self.with_store(|s| {
            s.set_elevate_needed(true);
            s.set_elevate_open(true);
            s.set_installed(true);
        });
    }

    /// Opens with `link`: straight to its pairing once the node answers.
    pub fn open_link(self: &Rc<Self>, link: String) {
        *self.link.borrow_mut() = Some(link);
        self.take_link();
    }

    /// Opens the first-run steps when the node turns out to have no center.
    pub fn offer_setup(&self) {
        self.first_run.set(true);
    }

    /// Asks for the status now and then every few seconds, so the window
    /// follows the node while it is open.
    pub fn watch(self: &Rc<Self>) {
        self.refresh_status();
        let c = Rc::downgrade(self);
        self.timer.start(
            slint::TimerMode::Repeated,
            Duration::from_secs(3),
            move || {
                if let Some(c) = c.upgrade() {
                    c.refresh_status();
                    c.refresh_times(now_ms());
                }
            },
        );
    }

    fn with_store<R>(&self, f: impl FnOnce(&Store<'_>) -> R) -> Option<R> {
        let w = self.window.upgrade()?;
        let store = w.global::<Store>();
        Some(f(&store))
    }

    fn with_perm<R>(&self, f: impl FnOnce(&Perm<'_>) -> R) -> Option<R> {
        let w = self.window.upgrade()?;
        let p = w.global::<Perm>();
        Some(f(&p))
    }

    fn with_install<R>(&self, f: impl FnOnce(&Install<'_>) -> R) -> Option<R> {
        let w = self.window.upgrade()?;
        let i = w.global::<Install>();
        Some(f(&i))
    }

    fn with_prefs<R>(&self, f: impl FnOnce(&Prefs<'_>) -> R) -> Option<R> {
        let w = self.window.upgrade()?;
        let p = w.global::<Prefs>();
        Some(f(&p))
    }

    fn runner(&self) -> Runner {
        self.runner.borrow().clone()
    }

    /// Whether the commands cannot run yet: the node is the system's and the
    /// app has no rights for it.
    fn waiting_for_rights(&self) -> bool {
        self.session_rights.get() && !self.runner.borrow().elevated()
    }

    /// How to ask for an administrator for `args` alone: when the command
    /// needs one and the commands do not have the rights already.
    fn admin_for(&self, args: &[String]) -> Option<Launch> {
        let how = self.elevate.get()?;
        if self.runner.borrow().elevated() || !needs_admin(args) {
            return None;
        }
        Some(how)
    }

    /// Runs `work` with the runner, then `done` with its result on the
    /// window's thread.
    fn job<R: Send + 'static>(
        self: &Rc<Self>,
        work: impl FnOnce(&Runner) -> R + Send + 'static,
        done: impl FnOnce(&Rc<Ctl>, R) + Send + 'static,
    ) {
        self.job_on(self.runner(), work, done);
    }

    /// [`Ctl::job`] with `runner` instead of the app's.
    fn job_on<R: Send + 'static>(
        self: &Rc<Self>,
        runner: Runner,
        work: impl FnOnce(&Runner) -> R + Send + 'static,
        done: impl FnOnce(&Rc<Ctl>, R) + Send + 'static,
    ) {
        match self.exec {
            Exec::Inline => {
                let r = work(&runner);
                done(self, r);
            }
            Exec::Threads => {
                std::thread::spawn(move || {
                    let r = work(&runner);
                    let _ = slint::invoke_from_event_loop(move || {
                        if let Some(c) = CURRENT.with(|c| c.borrow().clone()) {
                            done(&c, r);
                        }
                    });
                });
            }
        }
    }

    /// Runs one command, then `done` with its answer. An answer that says
    /// the broker is gone asks for the rights again.
    fn command(
        self: &Rc<Self>,
        args: Vec<String>,
        input: Option<String>,
        done: impl FnOnce(&Rc<Ctl>, Result<Value, String>) + Send + 'static,
    ) {
        let how = self.admin_for(&args);
        self.command_through(how, args, input, done);
    }

    /// [`Ctl::command`] with an administrator's rights asked for this once,
    /// whatever the command: an owner's restore that changes the account
    /// commands run as.
    fn command_with_rights(
        self: &Rc<Self>,
        args: Vec<String>,
        input: Option<String>,
        done: impl FnOnce(&Rc<Ctl>, Result<Value, String>) + Send + 'static,
    ) {
        let how = self
            .elevate
            .get()
            .filter(|_| !self.runner.borrow().elevated());
        self.command_through(how, args, input, done);
    }

    /// Whether this is an owner of the installed node, whose commands go to
    /// the node without the administrator's rights (nerve_node::owner).
    fn owner_path(&self) -> bool {
        self.elevate.get().is_some() && !self.runner.borrow().elevated()
    }

    /// Runs `args`, through a broker for this one command when `how` says
    /// how to start one.
    fn command_through(
        self: &Rc<Self>,
        how: Option<Launch>,
        args: Vec<String>,
        input: Option<String>,
        done: impl FnOnce(&Rc<Ctl>, Result<Value, String>) + Send + 'static,
    ) {
        // What only an administrator may do asks for the rights this once:
        // the broker ends with the command.
        if let Some(how) = how {
            let exe = self.runner().exe().clone();
            self.job(
                move |r| {
                    let broker = crate::broker::launch(&exe, how)?;
                    r.through(broker)
                        .run_with(&strings(&args), input.as_deref())
                },
                done,
            );
            return;
        }
        self.job(
            move |r| r.run_with(&strings(&args), input.as_deref()),
            move |c, answer| {
                if answer.as_ref().is_err_and(|e| e == crate::broker::GONE) {
                    c.rights_gone();
                }
                done(c, answer)
            },
        );
    }

    /// Says that a change is made: `said`, or what the command said when
    /// `said` is empty. When the node takes the change only at its next
    /// start, the app restarts the running service for it (a person who
    /// changed a setting expects it to count), and says so; a node that
    /// does not run takes it when it starts.
    fn done(self: &Rc<Self>, v: &Value, said: impl Into<String>) {
        let mut said = said.into();
        if said.is_empty() {
            said = said_of(v);
        }
        // A warning that came with it, such as folder mode running no
        // command once the keys are in the keyring, is no plain "done".
        let warned = lines(v)
            .any(|l| l.starts_with("Warning") || l.starts_with("folder mode runs no command"));
        let tone = if warned { Tone::Warn } else { Tone::Ok };
        match self.restart_for(v) {
            Restart::No | Restart::AtEnd => self.toast(said, tone),
            Restart::Soon => {
                self.toast(
                    and_then(said, "The node restarts in a moment to take it."),
                    tone,
                );
                self.restart_soon();
            }
            Restart::AtStart => self.toast(
                and_then(said, "The node takes it when it starts."),
                Tone::Warn,
            ),
        }
    }

    /// What a change's answer `v` asks of the running service: when the
    /// node takes it only at its next start, a restart, [`Ctl::restart_soon`]
    /// after the change is said, or at the end of the first-run steps while
    /// they are open. Until it restarts, the Overview says that changes wait
    /// for it.
    fn restart_for(&self, v: &Value) -> Restart {
        if !waits_for_start(v) {
            return Restart::No;
        }
        let Some((running, steps)) =
            self.with_store(|s| (s.get_service_state() == "running", s.get_setup_open()))
        else {
            return Restart::No;
        };
        if !running {
            return Restart::AtStart;
        }
        self.with_store(|s| s.set_restart_due(true));
        if steps {
            return Restart::AtEnd;
        }
        Restart::Soon
    }

    /// Restarts the service a moment after the last change that needs it,
    /// so that a few changes in a row restart it once. Should the app end
    /// before, its end runs it ([`Ctl::end`]).
    fn restart_soon(self: &Rc<Self>) {
        self.restart_waits.set(true);
        // No timers without the event loop: tests call [`Ctl::tick`].
        if self.exec == Exec::Threads {
            let c = Rc::downgrade(self);
            self.restart_timer.start(
                slint::TimerMode::SingleShot,
                Duration::from_secs(2),
                move || {
                    if let Some(c) = c.upgrade() {
                        c.restart_service();
                    }
                },
            );
        }
    }

    /// What the timers do when their moment comes, for tests, which have no
    /// event loop: the restart that waits.
    pub fn tick(self: &Rc<Self>) {
        if self.restart_waits.get() {
            self.restart_service();
        }
    }

    /// Whether the keys may go into the system keyring here, from what
    /// `config get machine.secret_storage` said, in the app's words when
    /// they may not; both the first-run steps and Settings offer it.
    fn keyring_state(&self, said: &Value) {
        let k = &said["keyring"];
        let usable = k["usable"] == true;
        let why = view::no_keyring(k["reason"].as_str().unwrap_or_default());
        self.with_store(|s| {
            s.set_keyring_usable(usable);
            s.set_keyring_why(if usable { "" } else { why }.into());
        });
    }

    fn toast(&self, text: impl Into<SharedString>, tone: Tone) {
        let text = text.into();
        self.with_store(|s| {
            // Hidden first, so the timer that hides it starts again.
            s.set_toast_shown(false);
            s.set_toast(text);
            s.set_toast_tone(tone);
            s.set_toast_shown(true);
        });
    }

    /// Opens `page` and reads what it shows. The page that is open stays
    /// as it is: a click on its tab reads nothing again, only Refresh does
    /// ([`Ctl::reload`]).
    pub(super) fn show(self: &Rc<Self>, page: Page) {
        if self.with_store(|s| s.get_page()) == Some(page) {
            return;
        }
        self.with_store(|s| s.set_page(page));
        // Only the page that shows it keeps a command running.
        if !matches!(page, Page::Audit | Page::Log) {
            self.stop_follow();
        }
        self.load(page);
    }

    /// Reads the open page again: its Refresh button, Ctrl+R and F5.
    pub(super) fn reload(self: &Rc<Self>) {
        if let Some(page) = self.with_store(|s| s.get_page()) {
            self.load(page);
        }
    }

    fn load(self: &Rc<Self>, page: Page) {
        match page {
            Page::Audit => self.follow_audit(),
            Page::Log => self.follow_log(),
            Page::Policy => {
                self.refresh_status();
                self.perm_load();
            }
            Page::Capabilities => {
                self.refresh_status();
                self.caps_load();
            }
            // The relay's state is read with the settings it shares.
            Page::Settings | Page::Relay => {
                self.refresh_status();
                self.prefs_load();
            }
            _ => self.refresh_status(),
        }
    }

    /// The command reference as the Help page's filter and order ask.
    fn reference_shown(&self) {
        let Some(w) = self.window.upgrade() else {
            return;
        };
        let m = w.global::<Manual>();
        let groups = crate::reference::groups(
            &self.reference,
            &m.get_ref_filter(),
            m.get_ref_by_name(),
            &self.ref_opened.borrow(),
        );
        m.set_ref_groups(ModelRc::new(VecModel::from(groups)));
    }

    pub fn refresh_status(self: &Rc<Self>) {
        self.refresh_service();
        if self.waiting_for_rights() {
            self.with_store(|s| {
                s.set_status_load(Load::Failed);
                s.set_status_error(
                    "The node is installed as a service: the app needs administrator rights to read it."
                        .into(),
                );
            });
            return;
        }
        // One question at a time: a slow node is not asked again meanwhile.
        if self.asking_status.replace(true) {
            return;
        }
        self.command(vec!["status".into()], None, |c, answer| {
            c.asking_status.set(false);
            c.show_status(answer);
        });
    }

    /// Shows the node's answer to `status`: the pages that follow it too
    /// (Permissions' mode and account).
    pub fn show_status(self: &Rc<Self>, answer: Result<Value, String>) {
        match answer {
            Ok(v) => {
                let (status, centers) = view::status(&v, now_ms());
                let names: Vec<String> = centers.iter().map(|c| c.name.to_string()).collect();
                let first = self.status.borrow().is_null();
                *self.centers.borrow_mut() = names.clone();
                *self.status.borrow_mut() = v;
                self.with_store(|s| {
                    s.set_status(status);
                    s.set_centers(ModelRc::new(VecModel::from(centers)));
                    s.set_status_load(Load::Ready);
                    s.set_status_error(SharedString::new());
                });
                self.perm_centers(&names);
                self.caps_centers(&names);
                if first {
                    self.after_first_status(names.is_empty());
                }
            }
            Err(e) => {
                self.with_store(|s| {
                    s.set_status_load(Load::Failed);
                    s.set_status_error(e.into());
                });
            }
        }
    }

    /// The first answer of the node: a link the app was opened with goes to
    /// its pairing now, and a node without a center gets the first-run steps.
    fn after_first_status(self: &Rc<Self>, no_center: bool) {
        if self.link.borrow().is_some() {
            self.take_link();
        } else if no_center && self.first_run.get() {
            self.setup_start();
        }
    }

    fn take_link(self: &Rc<Self>) {
        if self.waiting_for_rights() {
            return;
        }
        let Some(link) = self.link.borrow_mut().take() else {
            return;
        };
        // A relay's link: this node through that relay.
        if nerve_proto::link::strip_prefix_ci(link.trim(), "nerve://relay").is_some() {
            self.show(Page::Relay);
            self.connect_start();
            self.with_prefs(|p| p.set_connect_link(link.as_str().into()));
            self.connect_read(&link);
            return;
        }
        self.pair_start();
        self.with_store(|s| s.set_pair_link(link.as_str().into()));
        self.pair(&link, "", false);
    }

    /// One of the four buttons on an audit entry.
    fn audit_rule(self: &Rc<Self>, index: usize, list: &str, wildcard: bool) {
        let Some(entry) = self.audit.borrow().get(index).cloned() else {
            return;
        };
        let args = view::rule_args(&entry, list, wildcard);
        let list = view::rule_list(&entry, list);
        let center = entry["center"].as_str().unwrap_or_default().to_string();
        self.with_store(|s| s.set_busy(format!("audit-{index}").into()));
        self.command(args, None, move |c, answer| {
            c.with_store(|s| s.set_busy(SharedString::new()));
            match answer {
                Ok(v) => {
                    let list = match list {
                        "sudo" => "sudo allow list",
                        "deny" => "deny list",
                        _ => "allow list",
                    };
                    c.done(&v, format!("Added to the {list} of {center}."));
                }
                Err(e) => c.toast(e, Tone::Danger),
            }
        });
    }

    fn pair_start(&self) {
        self.with_store(|s| {
            s.set_pair_step(0);
            s.set_pair_link(SharedString::new());
            s.set_pair_name(SharedString::new());
            s.set_pair_error(SharedString::new());
            s.set_pair_busy(false);
            s.set_pair_open(true);
        });
    }

    /// `center add`: without `yes` the preview the owner confirms, with it
    /// the pairing. In the first-run steps the steps go on after it.
    fn pair(self: &Rc<Self>, link: &str, name: &str, yes: bool) {
        let mut args = vec!["center".to_string(), "add".into(), link.trim().to_string()];
        if !name.trim().is_empty() {
            args.push(format!("--name={}", name.trim()));
        }
        if yes {
            args.push("--yes".into());
        }
        self.with_store(|s| {
            s.set_pair_busy(true);
            s.set_pair_error(SharedString::new());
        });
        self.command(args, None, move |c, answer| {
            c.with_store(|s| s.set_pair_busy(false));
            match answer {
                Ok(v) if !yes => {
                    let preview = view::pair_preview(&v);
                    c.with_store(|s| {
                        s.set_pair_preview(preview);
                        s.set_pair_step(1);
                    });
                }
                Ok(v) => {
                    let name = v["name"].as_str().unwrap_or_default().to_string();
                    let steps = c.with_store(|s| s.get_setup_open()).unwrap_or(false);
                    c.with_store(|s| s.set_pair_open(false));
                    if steps {
                        // The service links to it when the steps end.
                        c.restart_for(&v);
                        c.setup_paired(&name);
                    } else {
                        c.done(
                            &v,
                            format!("Paired with {name}. It may do nothing until you allow it."),
                        );
                    }
                    c.refresh_status();
                }
                Err(e) => {
                    c.with_store(|s| s.set_pair_error(e.into()));
                }
            }
        });
    }

    /// Runs a change about `key` (a center's name, "node"), whose buttons
    /// wait meanwhile, and says `said` once the node made it.
    fn change(self: &Rc<Self>, key: &str, args: Vec<String>, said: String) {
        self.with_store(|s| s.set_busy(key.into()));
        self.command(args, None, move |c, answer| {
            c.with_store(|s| s.set_busy(SharedString::new()));
            match answer {
                Ok(v) => c.done(&v, said),
                Err(e) => c.toast(e, Tone::Danger),
            }
            c.refresh_status();
        });
    }

    fn center_pause(self: &Rc<Self>, name: &str, pause: bool) {
        let verb = if pause { "pause" } else { "resume" };
        let said = if pause {
            format!("{name} is paused: its link ends until you resume it.")
        } else {
            format!("{name} is resumed.")
        };
        let args = vec!["center".into(), verb.into(), format!("--center={name}")];
        self.change(name, args, said);
    }

    fn center_grant(self: &Rc<Self>, name: &str, on: bool) {
        let root = self.with_perm(|p| p.get_owner_is_root()).unwrap_or(false);
        let said = view::settings_grant_said(name, on, root);
        let value = if on { "write" } else { "off" };
        let args = vec![
            "center".into(),
            "grant".into(),
            "settings".into(),
            value.into(),
            format!("--center={name}"),
        ];
        self.change(name, args, said);
    }

    fn confirm(&self, pending: Pending, title: String, text: String, button: &str) {
        *self.pending.borrow_mut() = Some(pending);
        self.with_store(|s| {
            s.set_confirm_title(title.into());
            s.set_confirm_text(text.into());
            s.set_confirm_button(button.into());
            s.set_confirm_option(SharedString::new());
            s.set_confirm_option_detail(SharedString::new());
            s.set_confirm_option_on(false);
            s.set_confirm_open(true);
        });
    }

    fn ask_unpair(&self, name: &str) {
        self.confirm(
            Pending::Unpair(name.to_string()),
            format!("Unpair {name}?"),
            format!(
                "{name} loses its link and its key here, and its rules go. Pair again to use it."
            ),
            "Unpair",
        );
    }

    /// Asks before the audit log (or with `log` the log) is cleared, and
    /// says what stays.
    pub(crate) fn ask_clear(&self, log: bool) {
        if log {
            self.confirm(
                Pending::Clear(true),
                "Clear the log?".into(),
                "Every line goes, the older file's too. The new log starts with a line that you cleared it.".into(),
                "Clear",
            );
        } else {
            self.confirm(
                Pending::Clear(false),
                "Clear the audit log?".into(),
                format!(
                    "The page starts empty, with \"audit cleared by {}\". The entries so far stay in the file audit.jsonl.1, in place of the older copy, until the log moves aside again.",
                    app_user()
                ),
                "Clear",
            );
        }
    }

    fn ask_rotate(&self, name: &str) {
        self.confirm(
            Pending::RotateKey(name.to_string()),
            format!("A new key for {name}?"),
            format!("Made here and sent to {name} over the link, which must be up. {name} still takes the old key for 7 days."),
            "Make a new key",
        );
        self.with_store(|s| {
            s.set_confirm_option("End the old key's 7 days now".into());
            s.set_confirm_option_detail("For a key that may have leaked.".into());
        });
    }

    fn confirmed(self: &Rc<Self>) {
        let Some(p) = self.pending.borrow_mut().take() else {
            return;
        };
        match p {
            Pending::Unpair(name) => {
                let args = vec!["center".into(), "rm".into(), format!("--center={name}")];
                self.change(&name, args, format!("Unpaired {name}."));
            }
            Pending::RotateKey(name) => {
                let at_once = self
                    .with_store(|s| s.get_confirm_option_on())
                    .unwrap_or(false);
                let args = |end: bool| {
                    let mut a = vec!["center".into(), "rotate-key".into()];
                    if end {
                        a.push("--end-grace".into());
                    }
                    a.push(format!("--center={name}"));
                    a
                };
                let end_grace = args(true);
                self.with_store(|s| s.set_busy(name.as_str().into()));
                self.command(args(false), None, move |c, answer| {
                    let title = format!("New key for {name}");
                    match answer {
                        Ok(v) if at_once => c.command(end_grace, None, move |c, answer| {
                            c.with_store(|s| s.set_busy(SharedString::new()));
                            let (text, key) = view::new_key(&name, &v, Some(answer));
                            c.show_once(&title, "", &text, &key);
                        }),
                        Ok(v) => {
                            c.with_store(|s| s.set_busy(SharedString::new()));
                            let (text, key) = view::new_key(&name, &v, None);
                            c.show_once(&title, "", &text, &key);
                        }
                        Err(e) => {
                            c.with_store(|s| s.set_busy(SharedString::new()));
                            c.toast(e, Tone::Danger);
                        }
                    }
                });
            }
            Pending::Clear(log) => {
                let (what, said) = if log {
                    ("log", "The log is cleared.")
                } else {
                    (
                        "audit",
                        "The audit log is cleared. Its entries so far are in audit.jsonl.1.",
                    )
                };
                self.with_store(|s| s.set_busy(format!("{what}-clear").into()));
                self.command(vec![what.into(), "clear".into()], None, move |c, answer| {
                    c.with_store(|s| s.set_busy(SharedString::new()));
                    match answer {
                        Ok(v) => c.done(&v, said),
                        Err(e) => c.toast(e, Tone::Danger),
                    }
                    // The owner may have gone to another page meanwhile:
                    // only the cleared page, still open, follows again.
                    match c.with_store(|s| s.get_page()) {
                        Some(Page::Log) if log => c.follow_log(),
                        Some(Page::Audit) if !log => c.follow_audit(),
                        _ => {}
                    }
                });
            }
            Pending::CapRemove(name) => self.cap_remove(&name),
            Pending::Accept => {
                self.command(vec!["config".into(), "accept".into()], None, |c, answer| {
                    match answer {
                        Ok(v) => c.done(&v, ""),
                        Err(e) => c.toast(e, Tone::Danger),
                    }
                    c.refresh_status();
                });
            }
        }
    }

    /// Shows what a command said once, such as a token, to copy.
    /// No file dialog could open: why, and what to install.
    fn no_chooser(&self, e: String) {
        self.with_store(|s| {
            s.set_missing_title("No file dialog".into());
            s.set_missing_text(e.into());
            s.set_missing_open(true);
        });
    }

    /// `note` under the title, `text` to read and `copy` to copy, each
    /// left out when empty.
    fn show_once(&self, title: &str, note: &str, text: &str, copy: &str) {
        self.with_prefs(|p| {
            p.set_once_title(title.into());
            p.set_once_note(note.into());
            p.set_once_text(text.into());
            p.set_once_copy(copy.into());
            p.set_once_open(true);
        });
    }

    fn lock(self: &Rc<Self>, lock: bool) {
        let (args, said) = if lock {
            (
                "panic",
                "Locked: every link ended, and nothing runs until you unlock.",
            )
        } else {
            ("unlock", "Unlocked: the node links and works again.")
        };
        self.change("node", vec![args.into()], said.into());
    }

    /// Makes this window the user's one window: what a later start asks
    /// comes here.
    pub fn take_starts(&self, instance: crate::instance::Instance) {
        if let Some(note) = instance.note() {
            self.toast(note, Tone::Warn);
        }
        instance.listen(|asked| {
            let _ = slint::invoke_from_event_loop(move || {
                if let Some(c) = CURRENT.with(|c| c.borrow().clone()) {
                    c.started_again(asked);
                }
            });
        });
        *self.instance.borrow_mut() = Some(instance);
    }

    /// Another start of the app: this window comes to the front, and the
    /// app opens the link it was given, or its uninstall.
    pub fn started_again(self: &Rc<Self>, asked: crate::instance::Asked) {
        if let Some(w) = self.window.upgrade() {
            bring_up(&w);
        }
        let installer = self.with_install(|i| i.get_shown()).unwrap_or(false);
        if installer {
            return;
        }
        if let Some(link) = asked.link {
            self.open_link(link);
        } else if asked.uninstall {
            self.ask_uninstall();
        } else if let Some(program) = asked.program {
            self.offer_other(program.into());
        }
    }

    /// Keeps the app's settings in `file`, and takes the appearance saved
    /// there.
    pub fn keep_settings(self: &Rc<Self>, file: PathBuf) {
        let appearance = crate::settings::appearance(&file);
        *self.settings.borrow_mut() = Some(file);
        self.show_appearance(appearance);
    }

    fn set_appearance(self: &Rc<Self>, i: i32) {
        self.show_appearance(i);
        if let Some(file) = self.settings.borrow().as_ref()
            && let Err(e) = crate::settings::save_appearance(file, i)
        {
            self.toast(format!("The appearance is not saved: {e}"), Tone::Danger);
        }
    }

    /// Shows the app light, dark, or (0) as the desktop is. Each change is
    /// one step: choosing the desktop's look takes what the desktop said
    /// last, and before it said anything the look stays as it is until it
    /// does, never Slint's own reading in between, which may be light on a
    /// dark desktop (a white flash).
    fn show_appearance(self: &Rc<Self>, i: i32) {
        let Some(w) = self.window.upgrade() else {
            return;
        };
        w.global::<Store>().set_appearance(i);
        match i {
            1 => w.invoke_set_dark(false),
            2 => w.invoke_set_dark(true),
            _ => {
                match self.desktop_dark.get() {
                    Some(Some(dark)) => w.invoke_set_dark(dark),
                    Some(None) => w.invoke_follow_system(),
                    None => {}
                }
                self.follow_desktop();
            }
        }
        if i != 0 {
            self.scheme_timer.stop();
        }
    }

    /// Asks the desktop how it asks it ([`Ctl::set_scheme_source`]).
    pub fn set_scheme_source(&self, source: Option<SchemeSource>) {
        self.scheme_source.set(source);
    }

    /// What the desktop said of its look (none: it did not say), kept for
    /// the next choice of the desktop's look, and shown while that is the
    /// choice: dark or light at once, or Slint's own reading when the
    /// desktop did not say.
    pub fn desktop_said(&self, dark: Option<bool>) {
        self.desktop_dark.set(Some(dark));
        let Some(w) = self.window.upgrade() else {
            return;
        };
        if w.global::<Store>().get_appearance() != 0 {
            return;
        }
        match dark {
            Some(dark) => w.invoke_set_dark(dark),
            None => w.invoke_follow_system(),
        }
    }

    /// Follows the desktop's light or dark as the desktop keeps it
    /// (crate::scheme), now and, with an event loop, every few seconds, so
    /// a switch there shows here too.
    fn follow_desktop(self: &Rc<Self>) {
        let Some(source) = self.scheme_source.get() else {
            return;
        };
        let ask = move |c: &Rc<Ctl>| c.job(move |_| source(), |c, dark| c.desktop_said(dark));
        ask(self);
        // No event loop, no timers.
        if self.exec != Exec::Threads {
            return;
        }
        let c = Rc::downgrade(self);
        self.scheme_timer.start(
            slint::TimerMode::Repeated,
            Duration::from_secs(5),
            move || {
                if let Some(c) = c.upgrade() {
                    ask(&c);
                }
            },
        );
    }

    /// Asks the desktop how it asks it ([`Ctl::follow_motion`]).
    pub fn set_motion_source(&self, source: Option<MotionSource>) {
        self.motion_source.set(source);
    }

    /// Moves, or not, as the desktop said (none: it did not say, and the
    /// app moves).
    pub fn desktop_motion(&self, reduced: Option<bool>) {
        if let Some(w) = self.window.upgrade() {
            w.global::<Motion>().set_on(reduced != Some(true));
        }
    }

    /// Follows whether the desktop wants less motion (crate::motion), now
    /// and, with an event loop, every few seconds, so a change there shows
    /// here too. Until it answered nothing moves.
    pub fn follow_motion(self: &Rc<Self>) {
        let Some(source) = self.motion_source.get() else {
            return;
        };
        let ask = move |c: &Rc<Ctl>| c.job(move |_| source(), |c, r| c.desktop_motion(r));
        ask(self);
        // No event loop, no timers.
        if self.exec != Exec::Threads {
            return;
        }
        let c = Rc::downgrade(self);
        self.motion_timer.start(
            slint::TimerMode::Repeated,
            Duration::from_secs(5),
            move || {
                if let Some(c) = c.upgrade() {
                    ask(&c);
                }
            },
        );
    }
}

/// Opens the window and runs until it is closed. The installed program
/// opens the app, at what `start` asks (the pairing of a `nerve://` link,
/// or the uninstall); any other copy of it, such as the file just
/// downloaded, the installer.
pub fn run(start: crate::instance::Asked) -> Result<(), Failed> {
    // Said before anything else: without a display nothing below can be
    // shown (crate::deps).
    if let Some(e) = crate::deps::no_display_here() {
        return Err(Failed::NoDisplay(e));
    }
    let layout = nerve_node::service::Layout::system();
    let here = std::env::current_exe().and_then(std::fs::canonicalize).ok();
    let installed = std::fs::canonicalize(&layout.bin).ok();
    // A window of this user's is open already: it takes this start. A
    // program that is not the installed one, such as the file just
    // downloaded, says where it is, so the open app offers what the
    // installer would.
    let mut start = start;
    if here != installed {
        start.program = here.as_ref().map(|p| p.display().to_string());
    }
    // The desktop's look is asked at once, so the window opens in it and
    // not light first on a dark desktop; it may take a moment, and is not
    // waited for long.
    let (said, look) = std::sync::mpsc::channel();
    std::thread::spawn(move || said.send(crate::scheme::dark_here()));
    let instance = match crate::instance::claim(&start) {
        crate::instance::Claimed::Forwarded => return Ok(()),
        crate::instance::Claimed::First(i) => i,
    };
    let runner = Runner::this_program().map_err(Failed::Other)?;
    let window = new_window().map_err(Failed::Window)?;
    let ctl = Ctl::attach(&window, runner, Exec::Threads);
    ctl.follow_motion();
    if let Some(file) = crate::settings::file() {
        ctl.keep_settings(file);
    }
    ctl.take_starts(instance);
    if here.is_none() || here != installed {
        ctl.installer(Launch::Elevated, &layout.bin);
    } else {
        // The node's default folders: the service's when it is installed.
        let paths = nerve_node::NodePaths::from_args(None, None);
        window
            .global::<Store>()
            .set_installed(layout.installed() && paths == layout.paths);
        ctl.watch_service(paths == layout.paths, &layout.bin);
        // An owner changes the installed node without a question, and is
        // asked only for what needs an administrator; anyone else for the
        // whole session (nerve_node::owner).
        if paths == layout.paths && layout.installed() {
            ctl.admin_rights(Launch::Elevated);
        }
        if nerve_node::service::check_access(&paths).is_err() && !nerve_node::owner::is_owner_here()
        {
            ctl.needs_rights(Launch::Elevated);
        }
        match start.link {
            Some(link) => ctl.open_link(link),
            None if start.uninstall => ctl.ask_uninstall(),
            None => ctl.offer_setup(),
        }
        ctl.watch();
    }
    if let Ok(dark) = look.recv_timeout(Duration::from_millis(400)) {
        ctl.desktop_said(dark);
    }
    let r = window
        .show()
        .and_then(|()| {
            dress(&window);
            slint::run_event_loop()
        })
        .and_then(|()| window.hide())
        .map_err(|e| Failed::Window(e.to_string()));
    if let Some(Err(e)) = ctl.end() {
        eprintln!("The node did not restart for the last change: {e}");
    }
    // A start in software (crate::deps) is the user's one window then.
    ctl.instance.borrow_mut().take();
    r
}

/// Makes the app's window, named for the desktop: on Wayland and X11 its
/// name is the menu entry's (crate::parts), by which the dock and the task
/// manager show the entry's icon. Slint takes the name only once its
/// platform is there, which making the first window starts; asked before,
/// it was lost.
pub fn new_window() -> Result<AppWindow, String> {
    let window = AppWindow::new().map_err(|e| e.to_string())?;
    slint::set_xdg_app_id(crate::parts::PROGRAM)
        .map_err(|e| format!("the window's name for the desktop: {e}"))?;
    Ok(window)
}

/// What the window needs from the system once it is shown: on Windows the
/// program's icon on the taskbar, which Slint does not set (it sets the
/// small icon of the title bar only).
fn dress(window: &AppWindow) {
    #[cfg(windows)]
    {
        use slint::winit_030::WinitWindowAccessor;
        use slint::winit_030::winit::platform::windows::{IconExtWindows, WindowExtWindows};
        use slint::winit_030::winit::window::Icon;
        window.window().with_winit_window(|w| {
            // The program's icon group (build.rs).
            if let Ok(icon) = Icon::from_resource(1, None) {
                w.set_taskbar_icon(Some(icon));
            }
            if let Ok(icon) = Icon::from_resource(1, None) {
                w.set_window_icon(Some(icon));
            }
        });
    }
    #[cfg(not(windows))]
    let _ = window;
}

/// Brings `window` to the front: a later start of the app asked for it.
/// Wayland lets no program raise itself, so there the desktop says that
/// Nerve wants attention instead.
fn bring_up(window: &AppWindow) {
    use slint::winit_030::WinitWindowAccessor;
    use slint::winit_030::winit::window::UserAttentionType;
    let _ = window.show();
    window.window().set_minimized(false);
    window.window().with_winit_window(|w| {
        w.set_minimized(false);
        w.focus_window();
        if !w.has_focus() {
            w.request_user_attention(Some(UserAttentionType::Critical));
        }
    });
}

/// Why [`run`] ended without its window.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Failed {
    /// No display to open it on (crate::deps::no_display).
    NoDisplay(String),
    /// The window did not open, or ended with an error.
    Window(String),
    Other(String),
}
