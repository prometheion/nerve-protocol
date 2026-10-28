//! Screenshots of every page of the app, light and dark, drawn without a
//! screen by Slint's software renderer, for judging the look: a node of its
//! own under a temporary folder, set up and paired with fake centers through
//! the app, its daemon running, and the app asking it as it does on a
//! desktop. The software renderer draws no shadows; the app on a desktop
//! does. Long pages also come whole, as `<page>-full`.
//!
//! `NERVE_DESKTOP_SHOTS=<folder> cargo test -p nerve-node-desktop --test shots -- --ignored`

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use nerve_conformance::fake_center::FakeCenter;
use nerve_node::{Daemon, NodeOptions, NodePaths};
use nerve_node_desktop::app::{Choose, Ctl, Exec};
use nerve_node_desktop::broker::Launch;
use nerve_node_desktop::headless::Screen;
use nerve_node_desktop::runner::Runner;
use nerve_node_desktop::{
    AppWindow, Caps, Install, Load, Logs, NodeStatus, Page, Perm, Prefs, Store,
};
use slint::{ComponentHandle, Model};

const WIDTH: u32 = 1180;
const HEIGHT: u32 = 700;
const SCALE: f32 = 2.0;
/// The installer's window.
const INSTALLER: (u32, u32) = (760, 700);
/// A small screen, which the installer and the dialogs fit, the window
/// filling it.
const SMALL: (u32, u32) = (1280, 800);
/// The shots also taken on [`SMALL`], as `<name>-1280x800`: the installer's
/// steps and the dialogs.
const ALSO_SMALL: [&str; 25] = [
    "capabilities-add",
    "capabilities-edit",
    "capabilities-remove",
    "setup-",
    "pair-",
    "centers-unpair",
    "permissions-mode",
    "permissions-folder",
    "permissions-sudo",
    "settings-proxy",
    "relay-add",
    "relay-new-link",
    "relay-link",
    "relay-connect",
    "relay-node",
    "settings-backup",
    "settings-restore",
    "centers-new-key",
    "settings-no-file-dialog",
    "settings-update",
    "settings-uninstall",
    "about",
    "elevate",
    "installer-",
    "other-copy",
];
/// Long values, so the shots show how they fit.
const OFFICE: &str = "office-workstation-second-floor";
const LAB_URL: &str =
    "https://nerve-center.platform-engineering.internal.example.com:8443/teams/nerve";
const DEEP: &str =
    "alex/projects/clients/northwind/infrastructure/terraform/modules/networking/vpc-peering";
const LONG_RULE: &str = "docker compose -f deploy/docker-compose.production.yml --project-name northwind-platform up -d --remove-orphans";

struct Shots<'a> {
    screen: Screen,
    window: &'a AppWindow,
    out: PathBuf,
    /// The window's size in logical pixels.
    size: std::cell::Cell<(u32, u32)>,
}

impl Shots<'_> {
    /// Makes the window `width` by `height` logical pixels.
    fn resize(&self, (width, height): (u32, u32)) {
        self.size.set((width, height));
        self.screen.resize(
            (width as f32 * SCALE) as u32,
            (height as f32 * SCALE) as u32,
        );
    }

    /// Saves the window as `<name>-light.png` and `<name>-dark.png`, and
    /// the installer and the dialogs on [`SMALL`] too.
    fn take(&self, name: &str) {
        self.window.global::<Store>().set_toast_shown(false);
        self.take_as_is(name);
        if ALSO_SMALL.iter().any(|s| name.starts_with(s)) {
            let size = self.size.get();
            self.resize(SMALL);
            self.take_as_is(&format!("{name}-1280x800"));
            self.resize(size);
        }
    }

    /// [`Shots::take`] with the note in the corner, if one shows.
    fn take_as_is(&self, name: &str) {
        for (dark, scheme) in [(false, "light"), (true, "dark")] {
            self.window.invoke_set_dark(dark);
            let pixels = self.screen.draw();
            let path = self.out.join(format!("{name}-{scheme}.png"));
            let file = std::fs::File::create(&path).unwrap();
            let mut png = png::Encoder::new(file, pixels.width(), pixels.height());
            png.set_color(png::ColorType::Rgba);
            png.set_depth(png::BitDepth::Eight);
            let mut w = png.write_header().unwrap();
            w.write_image_data(pixels.as_bytes()).unwrap();
            eprintln!("wrote {}", path.display());
        }
    }

    /// The page `height` logical pixels high, as `<name>-full`.
    fn take_full(&self, name: &str, height: u32) {
        self.resize((WIDTH, height));
        self.take(&format!("{name}-full"));
        self.resize((WIDTH, HEIGHT));
    }
}

fn decided(
    paths: &NodePaths,
    ago_ms: u64,
    center: &str,
    (cap, action): (&str, &str),
    target: &str,
    reason: Option<&str>,
) {
    let now = nerve_node::now_ms();
    nerve_policy::audit::AuditLog::new(paths.audit_log())
        .decision(&nerve_policy::audit::Entry {
            ts: now - ago_ms,
            center: center.into(),
            cap: cap.into(),
            action: action.into(),
            target: target.into(),
            decision: if reason.is_some() {
                "forbidden"
            } else {
                "allowed"
            }
            .into(),
            code: None,
            session: None,
            reason: reason.map(str::to_string),
            command: None,
        })
        .unwrap();
}

/// Waits for a command that keeps answering to bring what `done` looks for.
fn until(ctl: &Ctl, done: impl Fn() -> bool) {
    for _ in 0..80 {
        ctl.pump();
        if done() {
            return;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

#[test]
#[ignore = "writes screenshots; NERVE_DESKTOP_SHOTS names the folder"]
fn every_page_light_and_dark() {
    let Some(out) = std::env::var_os("NERVE_DESKTOP_SHOTS").map(PathBuf::from) else {
        eprintln!("NERVE_DESKTOP_SHOTS is not set");
        return;
    };
    std::fs::create_dir_all(&out).unwrap();
    let screen = Screen::install(
        (WIDTH as f32 * SCALE) as u32,
        (HEIGHT as f32 * SCALE) as u32,
        SCALE,
    )
    .unwrap();
    let dir = tempfile::tempdir().unwrap();
    let root: &Path = dir.path();
    let paths = NodePaths::new(root.join("config"), root.join("state"));
    let runner = Runner::new(
        env!("CARGO_BIN_EXE_nerve-node-desktop").into(),
        Some(paths.config_dir.clone()),
        Some(paths.state_dir.clone()),
    );
    let cli = runner.clone();
    let run = move |args: &[&str]| cli.run(args).unwrap();
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();

    let window = AppWindow::new().unwrap();
    window.show().unwrap();
    let ctl = Ctl::attach(&window, runner, Exec::Inline);
    let store = window.global::<Store>();
    let perm = window.global::<Perm>();
    let prefs = window.global::<Prefs>();
    let shots = Shots {
        screen,
        window: &window,
        out,
        size: std::cell::Cell::new((WIDTH, HEIGHT)),
    };

    // Asking: the first moment of the app.
    store.set_status(NodeStatus::default());
    store.set_status_load(Load::Loading);
    shots.take("overview-loading");

    // A new node: its service stopped, nothing paired.
    store.set_service_state("stopped".into());
    store.set_service_enabled(true);
    ctl.refresh_status();
    shots.take("overview-new");
    store.invoke_show(Page::Centers);
    shots.take("centers-empty");

    // The first-run steps, as the app opens them on a new node.
    let home = rt.block_on(FakeCenter::start(true)).unwrap();
    store.invoke_setup_start();
    store.set_setup_name("build-server-basement-rack3-left".into());
    shots.take("setup-name");
    // A name the node refuses: the step says why.
    store.set_setup_name("build-server-in-the-basement-rack-3-left-side".into());
    store.invoke_setup_next();
    shots.take("setup-name-refused");
    store.set_setup_name("build-server-basement-rack3-left".into());
    store.invoke_setup_next();
    shots.take("setup-keys");
    // Where no keyring can hold the keys, the tile says why.
    let usable = store.get_keyring_usable();
    store.set_keyring_usable(false);
    store.set_keyring_why(nerve_node_desktop::view::no_keyring("no-answer").into());
    shots.take("setup-keys-no-keyring");
    store.set_keyring_usable(usable);
    store.invoke_setup_next();
    store.set_pair_link(home.link().render().into());
    store.set_pair_name("home".into());
    shots.take("setup-center");
    store.invoke_setup_next();
    shots.take("setup-confirm");
    store.invoke_setup_next();
    store.set_setup_mode("folder".into());
    shots.take("setup-mode");
    // Back from the mode: the center is paired already.
    store.invoke_setup_back();
    shots.take("setup-back-paired");
    store.invoke_setup_next();
    store.invoke_setup_next();
    shots.take("setup-done");
    store.set_setup_open(false);

    // Pairing from the Centers page.
    let lab = rt.block_on(FakeCenter::start(false)).unwrap();
    let office = rt.block_on(FakeCenter::start(false)).unwrap();
    store.invoke_pair_start();
    let link = lab.link().render();
    store.set_pair_link(link.clone().into());
    store.set_pair_name("lab".into());
    shots.take("pair-link");
    store.invoke_pair_check(link.clone().into(), "lab".into());
    shots.take("pair-confirm");
    store.invoke_pair_confirm();
    // The same link again: its code is used, so no Pair.
    store.invoke_pair_start();
    store.set_pair_link(link.clone().into());
    store.invoke_pair_check(link.into(), "".into());
    shots.take("pair-cannot");
    store.set_pair_open(false);
    run(&[
        "center",
        "add",
        &office.link().render(),
        "--name",
        OFFICE,
        "--yes",
    ]);
    run(&["center", "grant", "settings", "write", "--center", "home"]);
    run(&["mode", "set", "user", "--for", "8", "--center", "lab"]);
    run(&["center", "pause", "--center", OFFICE]);
    // lab's center is far away, and cannot be reached.
    run(&["config", "set", "center.lab.url", LAB_URL]);
    drop(lab);
    // home's folders and rules.
    for (folder, rights) in [
        ("alex/projects/site", vec!["+r", "+w", "+x"]),
        ("alex/Documents", vec!["+r"]),
        ("alex/scratch", vec!["+r", "+w"]),
        (DEEP, vec!["+r", "+x"]),
    ] {
        let p = root.join(folder);
        std::fs::create_dir_all(&p).unwrap();
        let p = p.display().to_string();
        let mut args = vec!["folder", "add", &p];
        args.extend(rights);
        args.extend(["--center", "home"]);
        run(&args);
    }
    for (list, rule) in [
        ("allow", "git status"),
        ("allow", "cargo test --workspace"),
        ("allow", LONG_RULE),
        ("deny", "git push --force origin main"),
        ("deny", "rm -rf /"),
        ("sudo", "sudo systemctl restart nginx"),
    ] {
        run(&["rule", "add", list, rule, "--center", "home"]);
    }
    run(&["cap", "set", "exec.signal", "off", "--center", "home"]);
    // Capabilities of node.toml, one for another platform, and a program
    // allowed as a provider that is not attached.
    let sensors = r#"{"type": "object", "properties": {"chip": {"type": "string", "description": "One chip, like coretemp-isa-0000."}}}"#;
    for args in [
        vec![
            "cap",
            "add",
            "sensors.read",
            "--effect",
            "sense",
            "--summary",
            "The machine's temperatures and fans, as JSON.",
            "--params",
            sensors,
            "--result",
            r#"{"type": "object"}"#,
            "--timeout",
            "10",
            "--",
            "sensors",
            "-j",
            "--",
            "{chip}",
        ],
        vec![
            "cap",
            "add",
            "disk.free",
            "--effect",
            "read",
            "--summary",
            "Free space of each mounted file system.",
            "--",
            "df",
            "-h",
            "--output=source,size,avail,target",
        ],
        vec![
            "cap",
            "add",
            "lamp.on",
            "--effect",
            "actuate",
            "--platform",
            "windows",
            "--summary",
            "The desk lamp on.",
            "--",
            "C:\\Tools\\lamp.exe",
            "on",
        ],
    ] {
        run(&args);
    }
    run(&["cap", "set", "sensors.read", "on", "--center", "home"]);
    run(&[
        "cap",
        "provider",
        "allow",
        "desk",
        "/usr/lib/nerve-desk/nerve-desk",
    ]);
    run(&["relay", "add", "laptop-2"]);

    // Calls the centers made, as the node records them.
    let alex = root.join("alex").display().to_string();
    decided(
        &paths,
        3 * 86_400_000,
        "lab",
        ("exec", "run"),
        "make release",
        None,
    );
    decided(
        &paths,
        26 * 3_600_000,
        OFFICE,
        ("fs", "list"),
        &format!("{alex}/Documents"),
        Some(&format!("no allow rule matches {alex}/Documents")),
    );
    decided(
        &paths,
        3 * 3_600_000,
        "home",
        ("fs", "read"),
        &format!("{alex}/projects/site/README.md"),
        None,
    );
    decided(
        &paths,
        52 * 60_000,
        "home",
        ("exec", "run"),
        "git push --force origin main",
        Some(
            "the command \"git push --force origin main\" is denied (exec.run:git push --force origin main)",
        ),
    );
    decided(
        &paths,
        14 * 60_000,
        "home",
        ("exec", "run"),
        "sudo systemctl restart nginx",
        Some("no sudo allow entry matches the command \"sudo systemctl restart nginx\""),
    );
    decided(
        &paths,
        11 * 60_000,
        "home",
        ("fs", "read"),
        &format!("{}/{DEEP}/main.tf", root.display()),
        None,
    );
    decided(
        &paths,
        8 * 60_000,
        "home",
        ("exec", "run"),
        &format!(
            "{LONG_RULE} && docker compose -f deploy/docker-compose.production.yml logs --tail 200 --follow api worker scheduler"
        ),
        Some(
            "no allow rule matches the command: it chains commands or holds an expression (; & | $ ` ( ) < > @ { } % ' \" # , \\, a line break, or a word such as powershell, cmd, iex or -Command); only an allow rule that names it exactly covers that",
        ),
    );
    decided(
        &paths,
        5 * 60_000,
        "home",
        ("fs", "write"),
        &format!("{alex}/projects/site/dist/index.html"),
        None,
    );
    decided(
        &paths,
        2 * 60_000,
        "home",
        ("exec", "run"),
        "npm run build",
        Some("no allow rule matches the command \"npm run build\""),
    );

    // The node runs, and links to home; lab cannot be reached, office waits.
    // The node writes its log, which the Log page shows.
    nerve_transport::log::install(nerve_transport::log::Level::Info, false);
    let mut opts = NodeOptions::new(paths.clone());
    opts.home = root.to_path_buf();
    opts.full_rights = Some(false);
    opts.exe = Some(env!("CARGO_BIN_EXE_nerve-node-desktop").into());
    // It offers the capabilities of node.toml as the installed node does.
    opts.config_caps_by_hand = true;
    opts.cgroups = Some(Err(
        "the node runs outside a cgroup it may manage; start it as the installed service, or under systemd-run --user --scope -p Delegate=yes".into(),
    ));
    let node = rt.block_on(Daemon::start(opts)).unwrap();
    for _ in 0..100 {
        let s = run(&["status"]);
        let up = |n: &str| {
            s["centers"].as_array().unwrap().iter().any(|c| {
                c["name"] == n
                    && c["status"]
                        .as_str()
                        .is_some_and(|t| t != "connecting" && t != "not connected")
            })
        };
        if up("home") && up("lab") {
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }

    store.invoke_show(Page::Overview);
    store.set_service_state("running".into());
    shots.take("overview");
    // Many centers: their list scrolls in its own box.
    let paired = store.get_centers();
    let first = paired.row_data(0).unwrap();
    let crowd: Vec<_> = (0..14)
        .map(|i| {
            let mut c = first.clone();
            c.name = format!("center-{i:02}").into();
            c
        })
        .collect();
    store.set_centers(slint::ModelRc::new(slint::VecModel::from(crowd)));
    shots.take_full("overview-long", 1700);
    store.set_centers(paired);
    store.set_busy("service-restart".into());
    shots.take("overview-service-restarting");
    store.set_busy("".into());
    // A change the running service takes only when it starts again.
    store.set_restart_due(true);
    shots.take("overview-restart-due");
    // A change the app restarts the service for.
    store.set_toast("home is paused: its link ends until you resume it.\nThe node restarts in a moment to take it.".into());
    store.set_toast_tone(nerve_node_desktop::Tone::Ok);
    store.set_toast_shown(true);
    shots.take_as_is("overview-restart-soon");
    store.set_toast_shown(false);
    store.set_restart_due(false);
    // Commands without their limits: one line, and the restart.
    let st = store.get_status();
    let mut off = st.clone();
    off.limits_off =
        "The service has no cgroup of its own for them. Restart it; the Log says why if it stays."
            .into();
    off.limits_restart = true;
    store.set_status(off);
    shots.take("overview-limits-off");
    store.set_status(st);
    store.invoke_show(Page::Centers);
    shots.take("centers");
    store.invoke_center_unpair(OFFICE.into());
    shots.take("centers-unpair");
    store.set_confirm_open(false);
    store.invoke_center_rotate(OFFICE.into());
    store.set_confirm_option_on(true);
    shots.take("centers-new-key");
    store.set_confirm_open(false);

    store.invoke_show(Page::Audit);
    until(&ctl, || store.get_audit().row_count() >= 7);
    shots.take("audit");
    shots.take_full("audit", 2300);
    let rows = store.get_audit();
    let build = (0..rows.row_count())
        .find(|i| rows.row_data(*i).unwrap().target == "npm run build")
        .unwrap();
    store.invoke_audit_rule(build as i32, "allow".into(), true);
    until(&ctl, || {
        store
            .get_audit()
            .row_data(0)
            .is_some_and(|r| r.kind == "settings")
    });
    shots.take_as_is("audit-rule-added");
    // The filters: refused; a center, an action and words; nothing left.
    store.set_audit_decision(2);
    store.invoke_audit_filtered();
    shots.take("audit-refused");
    store.set_audit_decision(0);
    store.set_audit_center(1);
    store.set_audit_action(1);
    store.set_audit_text("npm".into());
    store.set_audit_oldest(true);
    store.invoke_audit_filtered();
    shots.take("audit-filtered");
    store.set_audit_text("no such words".into());
    store.invoke_audit_filtered();
    shots.take("audit-no-match");
    store.set_audit_center(0);
    store.set_audit_action(0);
    store.set_audit_text("".into());
    store.set_audit_oldest(false);
    // The first few, and the button for more.
    store.set_audit_limit(4);
    store.invoke_audit_filtered();
    shots.take_full("audit-more", 1500);
    store.set_audit_limit(200);
    store.invoke_audit_filtered();
    store.invoke_audit_clear();
    shots.take("audit-clear");
    store.set_confirm_open(false);

    store.invoke_panic();
    store.invoke_show(Page::Overview);
    shots.take("overview-locked");
    store.invoke_unlock();

    // Permissions of home.
    store.invoke_show(Page::Policy);
    perm.invoke_pick(0);
    shots.take("permissions");
    shots.take_full("permissions", 2150);
    // A rule edited in place.
    perm.set_edit_text(perm.get_deny().row_data(0).unwrap());
    perm.set_edit_index(0);
    perm.set_edit_list(1);
    shots.take_full("permissions-edit", 2150);
    perm.set_edit_list(-1);
    // The installed Linux node: folder mode runs as nerve-run, with the
    // folders it always has; allowlist mode as nerve-run or as the owner; a
    // folder grant that failed (issue #142).
    perm.set_separate(true);
    perm.set_account("nerve-run".into());
    perm.set_built_in("/tmp, /var/tmp and its home /var/lib/nerve-run".into());
    perm.set_mode("folder".into());
    shots.take_full("permissions-nerve-run", 2150);
    perm.set_grant_errors("/home/alex/usb-stick: its file system does not support POSIX ACLs, so nerve-run cannot be given it; give a folder on another file system (ext4, xfs, btrfs and tmpfs have them)".into());
    shots.take("permissions-grant-errors");
    perm.set_grant_errors("".into());
    // Access nerve-run should have lost: none of its commands runs.
    perm.set_stale("/home/alex/old-project/build: Permission denied (os error 13)".into());
    shots.take("permissions-stale-grants");
    perm.set_stale("".into());
    // A kernel without Landlock, a folder given in the owner's home.
    perm.set_landlock(false);
    perm.set_home_warning("Without Landlock, nerve-run can read every file in your home /home/alex that other accounts may read, not only the folders you give it, as it passes through your home to /home/alex/project. This warning stays while you give it a folder in your home: umask 027 and `chmod -R o-rwx` narrow what it can read there, and only folders outside your home or a kernel with Landlock end it.".into());
    shots.take_full("permissions-nerve-run-without-landlock", 2150);
    perm.set_landlock(true);
    perm.set_home_warning("".into());
    perm.set_mode("allowlist".into());
    perm.set_as_owner(true);
    shots.take("permissions-allowlist-as-owner");
    // Root as the owner (issue #151): what runs as the owner runs as root.
    perm.set_owner_is_root(true);
    perm.set_account("root".into());
    shots.take("permissions-allowlist-as-root");
    perm.set_mode("user".into());
    shots.take("permissions-user-as-root");
    perm.set_owner_is_root(false);
    perm.set_account("nerve-run".into());
    perm.set_mode("allowlist".into());
    perm.set_mode_choice("folder".into());
    perm.set_mode_open(true);
    shots.take("permissions-mode-folder-nerve-run");
    perm.set_mode_open(false);
    perm.set_as_owner(false);
    perm.set_separate(false);
    perm.set_account("".into());
    perm.set_built_in("".into());
    perm.invoke_pick(0);
    // Allowlist mode: the allow list, the deny rules as its exceptions.
    let office = perm.get_centers().iter().position(|c| c == OFFICE).unwrap();
    for (list, rule) in [
        ("allow", "git status"),
        ("allow", "npm test"),
        ("deny", "npm publish"),
    ] {
        run(&["rule", "add", list, rule, "--center", OFFICE]);
    }
    perm.invoke_pick(office as i32);
    shots.take_full("permissions-allowlist", 1600);
    perm.set_except_open(true);
    shots.take_full("permissions-allowlist-exceptions", 2050);
    perm.set_except_open(false);
    // Long lists: each scrolls in its own box, and the page stays short.
    for i in 0..18 {
        run(&[
            "rule",
            "add",
            "allow",
            &format!("make target-{i}"),
            "--center",
            OFFICE,
        ]);
    }
    for i in 0..14 {
        let p = root.join(format!("alex/clients/client-{i:02}/repository"));
        std::fs::create_dir_all(&p).unwrap();
        let p = p.display().to_string();
        run(&["folder", "add", &p, "+r", "+w", "--center", OFFICE]);
    }
    perm.invoke_pick(office as i32);
    shots.take("permissions-long");
    shots.take_full("permissions-long", 2350);
    perm.invoke_pick(0);
    perm.invoke_mode_pick("user".into());
    perm.set_mode_timed(true);
    shots.take("permissions-mode");
    perm.set_mode_open(false);
    let picked = root.join("alex/projects/api");
    std::fs::create_dir_all(&picked).unwrap();
    ctl.set_chooser(Arc::new(move |c| {
        Ok((c == Choose::Folder).then(|| picked.clone()))
    }));
    perm.invoke_folder_choose();
    perm.set_folder_write(true);
    shots.take("permissions-folder");
    perm.set_folder_open(false);
    perm.invoke_sudo_ask();
    perm.set_sudo_password("hunter2hunter2".into());
    shots.take("permissions-sudo");
    perm.set_sudo_open(false);
    // Many centers: a list that names each in full.
    let centers = perm.get_centers();
    let many: Vec<slint::SharedString> = [
        "home",
        "lab",
        OFFICE,
        "build-farm-eu-west",
        "staging-cluster",
        "personal-laptop",
        "ci-runner-pool",
        "backup-vault",
        "media-server",
        "kids-pc",
    ]
    .map(Into::into)
    .to_vec();
    perm.set_centers(slint::ModelRc::new(slint::VecModel::from(many)));
    perm.set_current(0);
    shots.take("permissions-many-centers");
    perm.set_centers(centers);
    perm.invoke_pick(0);

    // Capabilities: what the node offers, home's switches, the commands of
    // node.toml and the programs, as on the installed node.
    let caps = window.global::<Caps>();
    store.set_installed(true);
    store.invoke_show(Page::Capabilities);
    caps.invoke_pick(0);
    shots.take("capabilities");
    shots.take_full("capabilities", 2300);
    caps.invoke_add();
    shots.take("capabilities-add");
    caps.set_edit_name("board.feed".into());
    caps.set_edit_command("feed --chip {chip}".into());
    caps.set_edit_params(r#"{"type": "object", "properties": {"chip": {"oneOf": [{"type": "string"}, {"type": "integer"}]}}}"#.into());
    caps.invoke_edit_check();
    shots.take("capabilities-add-broken");
    caps.set_edit_open(false);
    caps.invoke_edit("sensors.read".into());
    shots.take("capabilities-edit");
    caps.set_edit_timeout("7200".into());
    caps.invoke_edit_save();
    shots.take("capabilities-edit-refused");
    caps.set_edit_open(false);
    caps.invoke_remove("disk.free".into());
    shots.take("capabilities-remove");
    store.set_confirm_open(false);
    caps.set_program_name("pad".into());
    caps.set_program_exe("pad".into());
    caps.invoke_program_allow();
    shots.take("capabilities-program-refused");
    caps.set_program_error("".into());
    // A node by hand, and Windows: why their commands, or their programs
    // too, are not offered there.
    store.set_installed(false);
    caps.invoke_refresh();
    shots.take("capabilities-by-hand");
    let (programs, config) = nerve_node_desktop::view::caps_notes(true, true);
    caps.set_windows(true);
    caps.set_programs_note(programs.into());
    caps.set_config_note(config.into());
    shots.take_full("capabilities-windows", 2300);
    caps.set_windows(false);
    store.set_installed(true);

    // The log the running node wrote.
    store.invoke_show(Page::Log);
    until(&ctl, || window.global::<Logs>().get_rows().row_count() >= 3);
    ctl.feed_ready();
    shots.take("log");
    window.global::<Logs>().invoke_clear();
    shots.take("log-clear");
    store.set_confirm_open(false);

    window
        .global::<Install>()
        .set_program("/usr/local/bin/nerve-node-desktop".into());
    store.invoke_show(Page::Settings);
    // Each tab of Settings.
    for (i, tab) in [
        "general", "keys", "network", "limits", "backup", "app", "advanced",
    ]
    .iter()
    .enumerate()
    {
        prefs.set_tab(i as i32);
        shots.take(&format!("settings-{tab}"));
    }
    prefs.set_tab(3);
    shots.take_full("settings-limits", 1150);
    prefs.set_tab(0);
    shots.take_full("settings-general", 1000);
    // Where no keyring can hold the keys, a limit being saved and one
    // refused, and a setting by its name.
    store.set_keyring_usable(false);
    store.set_keyring_why(nerve_node_desktop::view::no_keyring("windows-service").into());
    prefs.set_tab(1);
    shots.take("settings-keys-no-keyring");
    prefs.set_tab(3);
    prefs.invoke_limit_edit("command".into(), 0, "8192".into());
    prefs.set_limits_busy("command".into());
    shots.take("settings-limits-saving");
    prefs.set_limits_busy("".into());
    prefs.invoke_limit_edit("time".into(), 1, "a day".into());
    prefs.invoke_limits_save("time".into());
    shots.take("settings-limits-refused");
    prefs.set_limits_error("".into());
    prefs.set_tab(6);
    prefs.set_raw_key("center.home.policy.allow".into());
    prefs.set_raw_value("fs.read:~/notes/*".into());
    shots.take("settings-advanced-filled");
    prefs.set_tab(2);
    store.set_keyring_usable(usable);
    prefs.set_raw_key("".into());
    prefs.set_raw_value("".into());
    // The limits as they were: the edits above were only shown.
    prefs.invoke_limit_edit("command".into(), 0, "4096".into());
    prefs.invoke_limit_edit("time".into(), 1, "60".into());
    prefs.invoke_proxy_edit();
    prefs.set_proxy_new_url("http://proxy.example:3128".into());
    prefs.set_proxy_new_headers("Proxy-Authorization: Bearer …".into());
    prefs.set_proxy_new_password("correct horse".into());
    shots.take("settings-proxy");
    prefs.set_proxy_open(false);
    // The Relay page: this node direct, the relay off with one node.
    store.invoke_show(Page::Relay);
    shots.take("relay");
    prefs.invoke_relay_add();
    prefs.set_relay_add_name("build-agent-7".into());
    shots.take("relay-add");
    prefs.invoke_relay_add_confirm();
    shots.take("relay-link");
    prefs.set_once_open(false);
    prefs.invoke_relay_token("laptop-2".into());
    shots.take("relay-new-link");
    prefs.set_relay_add_open(false);
    prefs.invoke_relay_edit(0);
    prefs.invoke_relay_edit_pick(0, true);
    prefs.set_relay_edit_own(true);
    shots.take("relay-node");
    prefs.set_relay_edit_open(false);
    // On, carrying tunnels now (as `relay ls` of a running relay says).
    prefs.set_relay_listen("0.0.0.0:7490".into());
    prefs.set_relay_status("listening on 0.0.0.0:7490".into());
    let relay = serde_json::json!({
        "nodes": [
            {"name": "laptop-2", "centers": [], "max_links": 4, "max_opens_per_minute": 30, "own_limits": false},
            {"name": "build-agent-7", "centers": ["home"], "max_links": 12, "max_opens_per_minute": 300, "own_limits": true},
        ],
        "tunnels": [
            {"node": "laptop-2", "from": "192.168.1.23:51544", "center": "home", "since_ms": nerve_node::now_ms() - 7_500_000},
            {"node": "laptop-2", "from": "192.168.1.23:51562", "center": "lab", "since_ms": nerve_node::now_ms() - 420_000},
        ],
    });
    prefs.set_relay_nodes(slint::ModelRc::new(slint::VecModel::from(
        nerve_node_desktop::view::relay_nodes(&relay),
    )));
    prefs.set_tunnels(slint::ModelRc::new(slint::VecModel::from(
        nerve_node_desktop::view::tunnels(&relay, nerve_node::now_ms()),
    )));
    shots.take("relay-on");
    shots.take_full("relay-on", 1250);
    // Many nodes and tunnels: each list in its own box.
    let many: Vec<serde_json::Value> = (0..16)
        .map(|i| serde_json::json!({"name": format!("build-agent-{i:02}"), "centers": [], "max_links": 4, "max_opens_per_minute": 30, "own_limits": false}))
        .collect();
    let tunnels: Vec<serde_json::Value> = (0..14)
        .map(|i| serde_json::json!({"node": format!("build-agent-{i:02}"), "from": format!("10.0.4.{}:5154{}", 20 + i, i % 10), "center": "home", "since_ms": nerve_node::now_ms() - 60_000 * (i + 1)}))
        .collect();
    let crowd = serde_json::json!({"nodes": many, "tunnels": tunnels});
    prefs.set_relay_nodes(slint::ModelRc::new(slint::VecModel::from(
        nerve_node_desktop::view::relay_nodes(&crowd),
    )));
    prefs.set_tunnels(slint::ModelRc::new(slint::VecModel::from(
        nerve_node_desktop::view::tunnels(&crowd, nerve_node::now_ms()),
    )));
    shots.take_full("relay-on-long", 1500);
    prefs.set_relay_nodes(slint::ModelRc::new(slint::VecModel::from(
        nerve_node_desktop::view::relay_nodes(&relay),
    )));
    prefs.set_tunnels(slint::ModelRc::new(slint::VecModel::from(
        nerve_node_desktop::view::tunnels(&relay, nerve_node::now_ms()),
    )));
    // This node through a relay, and the dialog that takes the link.
    prefs.set_via_relay(true);
    prefs.set_via_address("relay.lab.example:7490".into());
    prefs.set_via_node("laptop-2".into());
    prefs.set_via_state("2 of 3 centers linked through it.".into());
    prefs.set_via_tone(nerve_node_desktop::Tone::Warn);
    shots.take("relay-via");
    prefs.set_via_relay(false);
    prefs.invoke_connect_start();
    let pasted = "nerve://relay?address=relay.lab.example%3A7490&node=laptop-2&token=0123456789abcdefghijklmnopqrstuvwxyz0123456&pin=q1Q3tvgEmVkvsjsZTEOBtG9Rb12pM9iyCOVCTVwjz4A";
    prefs.set_connect_link(pasted.into());
    prefs.invoke_connect_read(pasted.into());
    shots.take("relay-connect");
    prefs.set_connect_apart(true);
    prefs.set_connect_address("relay.lab.example:7490".into());
    prefs.set_connect_node("laptop-2".into());
    prefs.set_connect_token("0123456789abcdefghijklmnopqrstuvwxyz0123456".into());
    shots.take("relay-connect-apart");
    prefs.set_connect_open(false);
    store.invoke_show(Page::Settings);
    prefs.set_tab(2);
    let backup = root.join("nerve-node.backup");
    ctl.set_chooser(Arc::new(move |_| Ok(Some(backup.clone()))));
    prefs.invoke_backup_choose();
    prefs.set_backup_pass("correct horse battery".into());
    prefs.set_backup_pass2("correct horse".into());
    shots.take("settings-backup");
    let no_portal = nerve_node_desktop::deps::portal(Some((false, ""))).unwrap_err();
    prefs.set_backup_open(false);
    let e = no_portal.clone();
    ctl.set_chooser(Arc::new(move |_| Err(e.clone())));
    prefs.invoke_backup_choose();
    shots.take("settings-no-file-dialog");
    store.set_missing_open(false);
    prefs.set_backup_open(false);
    let backup = root.join("nerve-node.backup");
    ctl.set_chooser(Arc::new(move |_| Ok(Some(backup.clone()))));
    prefs.invoke_restore_choose();
    prefs.set_restore_pass("correct horse battery".into());
    prefs.set_restore_in_files(true);
    shots.take("settings-restore");
    prefs.set_restore_open(false);
    // What a restore did, in the app's words.
    let restored = serde_json::json!({"restored": {
        "centers": ["home", "lab"], "kept": [], "no_key": ["lab"],
        "notes": [
            {"text": "", "fix": "sudo", "center": null},
            {"text": "", "fix": "proxy", "center": null},
            {"text": "the node key for home was rotated after the backup was made: the restore keeps the rotated key here, which the center holds, not the backup's older one", "fix": null, "center": null},
        ],
    }});
    prefs.set_once_title("The backup is restored".into());
    prefs.set_once_note("".into());
    prefs.set_once_copy("".into());
    prefs.set_once_text(
        nerve_node_desktop::view::restored(
            &restored,
            "The node started again, with what is restored.",
        )
        .into(),
    );
    prefs.set_once_open(true);
    shots.take("settings-restored");
    // What a backup wrote, in the app's words.
    let written = serde_json::json!({"backup": {
        "file": "/home/alex/nerve-node.backup", "centers": ["home", "lab"],
        "saved": ["the node key for home", "the config key"],
        "left_out": [{"what": "the node key for lab", "why": "keyring"}],
    }});
    prefs.set_once_title("The backup is written".into());
    prefs.set_once_text(nerve_node_desktop::view::backup_written(&written).into());
    shots.take("settings-backup-written");
    // A new key: the center has it; the key apart, to compare.
    let rotated = serde_json::json!({"public_key": "9f2c4be81d07a3c56e0b1f48d2a97c3e5b60f1a2d8c4e7b9031f6a5d2c8e4b17"});
    let (text, key) = nerve_node_desktop::view::new_key(OFFICE, &rotated, None);
    prefs.set_once_title(format!("New key for {OFFICE}").into());
    prefs.set_once_text(text.into());
    prefs.set_once_copy(key.into());
    shots.take("centers-new-key-done");
    prefs.set_once_copy("".into());
    prefs.set_once_open(false);
    // Windows, no account yet (a password mistyped at install): the card
    // takes the password of the app's user.
    let install = window.global::<Install>();
    let account = prefs.get_account();
    install.set_windows(true);
    install.set_account("alex".into());
    prefs.set_account("".into());
    prefs.set_tab(0);
    shots.take("settings-account-windows");
    install.set_windows(true);
    prefs.set_tab(3);
    shots.take("settings-limits-windows");
    prefs.set_account(account);
    install.set_windows(false);

    // Settings' update and uninstall.
    let install = window.global::<Install>();
    install.set_program("/usr/local/bin/nerve-node-desktop".into());
    install.invoke_ask_update();
    shots.take("settings-update");
    let new = root.join("Downloads/nerve-node-desktop-x86_64-linux");
    std::fs::create_dir_all(new.parent().unwrap()).unwrap();
    ctl.set_chooser(Arc::new(move |_| Ok(Some(new.clone()))));
    install.invoke_choose_file();
    shots.take("settings-update-file");
    let e = no_portal.clone();
    ctl.set_chooser(Arc::new(move |_| Err(e.clone())));
    install.invoke_choose_file();
    shots.take("settings-update-no-file-dialog");
    install.set_error("".into());
    install.set_error_title("".into());
    install.set_step("working".into());
    shots.take("settings-update-working");
    install.set_step("done".into());
    install.set_installed_version("0.0.6".into());
    install.set_did(lines(&[
        "read the new program from /home/alex/Downloads/nerve-node-desktop-x86_64-linux",
        "replaced nerve-node-desktop 0.0.5 with 0.0.6",
        "restarted the service nerve-node.service",
        "put Nerve in the application menu (/usr/local/share/applications/nerve-node-desktop.desktop), with its icon",
        "nerve:// links open in Nerve (the default in /etc/xdg/mimeapps.list)",
    ]));
    shots.take("settings-update-done");
    install.set_update_open(false);
    install.set_did(lines(&[]));
    install.invoke_ask_uninstall();
    shots.take("settings-uninstall");
    install.set_purge(true);
    install.set_error("uninstall needs root: run `sudo nerve-node uninstall`".into());
    shots.take("settings-uninstall-failed");
    install.set_error("".into());
    install.set_step("done".into());
    install.set_did(lines(&[
        "stopped the service nerve-node.service",
        "removed the service unit /etc/systemd/system/nerve-node.service",
        "deleted /etc/nerve",
        "deleted /var/lib/nerve",
        "removed the user nerve",
        "removed Nerve from the application menu",
        "nerve:// links no longer open in Nerve",
        "removed the program /usr/local/bin/nerve-node-desktop",
    ]));
    shots.take("settings-uninstall-done");
    install.set_did(lines(&[
        "stopped and removed the service nerve-node",
        "took the folder grants of the commands off: none were left",
        "removed the source nerve-node from the Windows Event Log; its entries stay",
        "deleted C:\\ProgramData\\Nerve\\config",
        "deleted C:\\ProgramData\\Nerve",
        "deleted C:\\ProgramData\\Nerve\\state",
        "removed the user nerve and its profile",
        "removed Nerve from the Start menu",
        "nerve:// links no longer open in Nerve",
        "removed Nerve from Apps & features",
        "removed the program C:\\Program Files\\Nerve\\nerve-node-desktop.exe; Windows holds it (this command runs from it, or the Event Log reads it), so Windows deletes the file at its next start",
    ]));
    shots.take("settings-uninstall-done-windows");
    install.set_uninstall_open(false);
    install.set_purge(false);

    store.invoke_show(Page::Help);
    shots.take("help");
    let manual = window.global::<nerve_node_desktop::Manual>();
    manual.set_keys_open(true);
    shots.take_full("help-keys", 1000);
    // The command reference beside the keys: by topic, two commands open,
    // a topic closed, filtered, A to Z.
    manual.set_commands_open(true);
    shots.take("help-both");
    shots.take_full("help-commands", 3600);
    manual.invoke_ref_toggle("center add".into());
    manual.invoke_ref_toggle("relay add".into());
    manual.invoke_ref_group_toggle("Install".into());
    shots.take_full("help-commands-open", 4400);
    manual.set_ref_filter("relay".into());
    manual.invoke_ref_update();
    shots.take_full("help-commands-filter", 2200);
    manual.set_ref_filter("".into());
    manual.set_ref_by_name(true);
    manual.invoke_ref_update();
    shots.take_full("help-commands-az", 4200);
    manual.set_ref_by_name(false);
    manual.invoke_ref_toggle("center add".into());
    manual.invoke_ref_toggle("relay add".into());
    manual.invoke_ref_group_toggle("Install".into());
    manual.invoke_ref_update();
    manual.set_keys_open(false);
    manual.set_commands_open(false);
    store.invoke_show(Page::Overview);
    store.set_about_open(true);
    shots.take("about");
    store.set_about_open(false);
    // The downloaded file opened while the app is open: a newer one, and
    // the same version.
    let install = window.global::<Install>();
    install.set_other_file("/home/alex/Downloads/nerve-node-desktop-x86_64-linux".into());
    install.set_other_version("0.0.7".into());
    install.set_other_newer(true);
    install.set_other_open(true);
    shots.take("other-copy-newer");
    install.set_other_version(install.get_version());
    install.set_other_newer(false);
    shots.take("other-copy-same");
    install.set_other_open(false);

    // An installed node: why the app asks for administrator rights.
    ctl.needs_rights(Launch::Plain);
    shots.take("elevate");
    // Without a polkit agent to ask (crate::deps), the dialog says what to
    // install instead of asking.
    let no_agent = nerve_node_desktop::deps::no_agent();
    store.set_elevate_error(no_agent.clone().into());
    shots.take("elevate-no-polkit-agent");
    store.set_elevate_error("".into());
    store.invoke_elevate_allow();

    // A node.toml changed by hand: the CLI refuses it, and the app says so.
    ctl.end();
    rt.block_on(node.stop());
    let file = paths.config_file();
    let text = std::fs::read_to_string(&file).unwrap();
    std::fs::write(&file, text.replace("mode = \"folder\"", "mode = \"user\"")).unwrap();
    store.invoke_show(Page::Centers);
    shots.take("centers-error");

    // The installer, as the downloaded file shows it, in its own size.
    shots.resize(INSTALLER);
    let install = window.global::<Install>();
    let bin = root.join("usr/local/bin/nerve-node-desktop");
    ctl.installer(Launch::Plain, &bin);
    install.set_program("/usr/local/bin/nerve-node-desktop".into());
    install.set_step("welcome".into());
    install.set_node_only(false);
    shots.take("installer-welcome");
    // The system refuses (here: no root); the step says why. With the
    // rights, Install would install this build on the machine (tests/app.rs).
    if nerve_node::rights::full_rights() {
        eprintln!("installer-failed left out: this run has the rights to install");
    } else {
        install.invoke_install();
        shots.take("installer-failed");
    }
    install.set_error(no_agent.into());
    shots.take("installer-no-polkit-agent");
    install.set_error("".into());
    install.set_windows(true);
    install.set_account("alex".into());
    install.set_program("C:\\Program Files\\Nerve\\nerve-node-desktop.exe".into());
    install.set_password("hunter2hunter2".into());
    shots.take("installer-welcome-windows");
    // Longer than the window: it scrolls.
    install.set_error("the service nerve-node did not start: the node did not answer on its control pipe within 30 seconds; the Windows Event Log (Application, source nerve-node) and C:\\ProgramData\\Nerve\\state\\log.jsonl say why".into());
    shots.take("installer-welcome-windows-failed");
    install.set_error("".into());
    install.set_node_only(true);
    shots.take("installer-node-only-windows");
    install.set_windows(false);
    install.set_program("/usr/local/bin/nerve-node-desktop".into());
    shots.take("installer-node-only");
    install.set_action("install".into());
    install.set_step("done".into());
    install.set_did(lines(&[
        "the user nerve is there already",
        "put the program at /usr/local/bin/nerve-node-desktop",
        "put Nerve in the application menu (/usr/local/share/applications/nerve-node-desktop.desktop), with its icon",
        "nerve:// links open in Nerve (the default in /etc/xdg/mimeapps.list)",
        "/usr/local/bin/nerve-node is a link to /usr/local/bin/nerve-node-desktop now, so the command nerve-node runs it",
        "the service nerve-node.service runs as nerve and starts with the machine",
    ]));
    shots.take("installer-node-only-done");
    install.set_windows(true);
    install.set_did(lines(&[
        "put the program at C:\\Program Files\\Nerve\\nerve-node-desktop.exe",
        "put Nerve in the Start menu (C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Nerve.lnk)",
        "nerve:// links open in Nerve (HKEY_LOCAL_MACHINE\\Software\\Classes\\nerve)",
        "put Nerve in Apps & features, where Uninstall removes it",
        "registered the service nerve-node, which runs as nerve and starts with the machine",
        "registered the source nerve-node in the Windows Event Log (Application): the service's start, stop and failures go there as well as to C:\\ProgramData\\Nerve\\state\\log.jsonl",
        "removed C:\\Program Files\\Nerve\\nerve-node.exe, the node installed alone: C:\\Program Files\\Nerve\\nerve-node-desktop.exe is the node now (Windows holds the old file, as when the Event Log read it or it runs; Windows deletes it at its next start). For a terminal, download the CLI edition nerve-node.exe on its own",
        "the service nerve-node runs",
    ]));
    shots.take("installer-node-only-done-windows");
    install.set_windows(false);
    install.set_did(lines(&[]));
    install.set_node_only(false);
    install.set_action("install".into());
    install.set_step("working".into());
    install.set_asking(true);
    shots.take("installer-asking");
    install.set_asking(false);
    shots.take("installer-working");
    install.set_step("done".into());
    install.set_did(lines(&[
        "made the user nerve (uid 991)",
        "/etc/nerve and /var/lib/nerve/state belong to nerve",
        "commands run as alex, who ran install",
        "put the program at /usr/local/bin/nerve-node-desktop",
        "put Nerve in the application menu (/usr/local/share/applications/nerve-node-desktop.desktop), with its icon",
        "nerve:// links open in Nerve (the default in /etc/xdg/mimeapps.list)",
        "wrote the service unit /etc/systemd/system/nerve-node.service",
        "the service nerve-node.service runs as nerve and starts with the machine",
    ]));
    install.set_warnings(lines(&[
        "Warning: alex is your own account, the one you log in as: a command from a center can do what you can.",
        "An account only the node uses is the boundary: Settings, General, Account for commands, makes one and runs commands as it.",
    ]));
    shots.take("installer-done");
    install.set_warnings(lines(&[
        "Warning: update-desktop-database is not on this machine, so the desktop may not know yet that Nerve opens nerve:// links. Install desktop-file-utils, or log out and in.",
    ]));
    shots.take("installer-done-no-desktop-database");
    install.set_warnings(lines(&[]));
    install.set_step("installed".into());
    install.set_installed_version("0.0.4".into());
    install.set_newer(true);
    shots.take("installer-installed");
    install.set_installed_version(install.get_version());
    install.set_newer(false);
    shots.take("installer-installed-same");
    install.invoke_ask_uninstall();
    shots.take("installer-uninstall");
    install.set_purge(true);
    shots.take("installer-uninstall-purge");
    install.set_step("done".into());
    install.set_did(lines(&[
        "stopped the service nerve-node.service",
        "removed the service unit /etc/systemd/system/nerve-node.service",
        "deleted /etc/nerve",
        "removed the user nerve",
        "removed the link /usr/local/bin/nerve-node",
        "removed Nerve from the application menu",
        "removed the program /usr/local/bin/nerve-node-desktop",
    ]));
    shots.take("installer-removed");
    // What an uninstall on Windows says, more than fits: the steps scroll.
    install.set_windows(true);
    install.set_did(lines(&[
        "stopped and removed the service nerve-node",
        "took the folder grants of the commands off: none were left",
        "removed the source nerve-node from the Windows Event Log; its entries stay",
        "deleted C:\\ProgramData\\Nerve\\config",
        "deleted C:\\ProgramData\\Nerve",
        "deleted C:\\ProgramData\\Nerve\\state",
        "removed the user nerve and its profile",
        "removed Nerve from the Start menu",
        "nerve:// links no longer open in Nerve",
        "removed Nerve from Apps & features",
        "removed the program C:\\Program Files\\Nerve\\nerve-node-desktop.exe; Windows holds it (this command runs from it, or the Event Log reads it), so Windows deletes the file at its next start",
    ]));
    shots.take("installer-removed-windows");
    install.set_windows(false);
    install.set_action("update".into());
    install.set_installed_version("0.0.6".into());
    install.set_did(lines(&[
        "replaced nerve-node-desktop 0.0.5 with 0.0.6",
        "restarted the service nerve-node.service",
    ]));
    shots.take("installer-updated");
    drop((home, office));
}

fn lines(l: &[&str]) -> slint::ModelRc<slint::SharedString> {
    slint::ModelRc::new(slint::VecModel::from(
        l.iter()
            .map(|s| slint::SharedString::from(*s))
            .collect::<Vec<_>>(),
    ))
}
