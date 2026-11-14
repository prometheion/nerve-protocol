//! The app fits a screen of 1280x800: its windows open no larger than such a
//! screen leaves them, what an install, update or uninstall did fits the
//! installer and the dialogs without scrolling, and a longer step or dialog
//! scrolls inside the window. The sidebar holds all its items at the
//! window's least height.

use nerve_node_desktop::headless::Screen;
use nerve_node_desktop::{
    AppWindow, Caps, Install, Load, Page, PairPreview, Perm, Pick, Prefs, Store,
};
use slint::{ComponentHandle, ModelRc, Rgba8Pixel, SharedPixelBuffer, SharedString, VecModel};

/// What a screen of 1280x800 leaves a window's content: less a panel (the
/// taskbar of Windows is 48 pixels high) and the window's title bar.
const ROOM: (f32, f32) = (1280.0, 720.0);
/// The app's window, as it opens, and as small as it gets (ui/app.slint).
const APP: (u32, u32) = (1180, 700);
const LEAST: (u32, u32) = (900, 580);

fn lines(n: usize, text: &str) -> ModelRc<SharedString> {
    ModelRc::new(VecModel::from(
        (0..n)
            .map(|i| SharedString::from(format!("{text} ({i})")))
            .collect::<Vec<_>>(),
    ))
}

/// The installer's window, as it opens.
const INSTALLER: (u32, u32) = (760, 700);

/// The bottom `rows` of the window. A dialog's card ends 24 pixels above
/// the window's foot when its content scrolls, and higher when it fits.
fn bottom(pixels: &SharedPixelBuffer<Rgba8Pixel>, rows: usize) -> Vec<Rgba8Pixel> {
    let (w, h) = (pixels.width() as usize, pixels.height() as usize);
    pixels.as_slice()[(h - rows) * w..].to_vec()
}

/// Whether the bottom rows of the installer show its background only, left
/// of where a scroll bar may be: the step ends above them.
fn foot_is_background(pixels: &SharedPixelBuffer<Rgba8Pixel>) -> bool {
    let w = pixels.width() as usize;
    let background = pixels.as_slice()[0];
    bottom(pixels, 20)
        .chunks(w)
        .all(|row| row[..w - 24].iter().all(|p| *p == background))
}

/// The window once nothing moves in it any more: a page that just opened
/// fades its parts in.
fn settled(screen: &Screen) -> SharedPixelBuffer<Rgba8Pixel> {
    let mut last = screen.draw();
    for _ in 0..60 {
        std::thread::sleep(std::time::Duration::from_millis(50));
        let now = screen.draw();
        if now.as_slice() == last.as_slice() {
            return now;
        }
        last = now;
    }
    panic!("the window keeps moving");
}

#[test]
fn every_installer_step_and_dialog_fits_a_small_screen() {
    let screen = Screen::install(APP.0, APP.1, 1.0).unwrap();
    let window = AppWindow::new().unwrap();
    window.show().unwrap();
    let fits = |what: &str| {
        let (min, preferred) = screen.wants();
        assert!(
            min.width <= ROOM.0 && min.height <= ROOM.1,
            "{what}: the window cannot be smaller than {min:?}"
        );
        assert!(
            preferred.width <= ROOM.0 && preferred.height <= ROOM.1,
            "{what}: the window opens at {preferred:?}"
        );
    };
    fits("the app");

    // The installer opens smaller still.
    let install = window.global::<Install>();
    install.set_shown(true);
    fits("the installer");

    // A step longer than the installer's window scrolls to its end: the
    // welcome on Windows, with its password field, after a long error.
    screen.resize(INSTALLER.0, INSTALLER.1);
    install.set_windows(true);
    install.set_program("C:\\Program Files\\Nerve\\nerve-node-desktop.exe".into());
    install.set_step("welcome".into());
    install.set_action("install".into());
    install.set_error(
        "the service did not start: a long reason from the system, which goes on for a while so that it wraps over more than one line of the step, and then some more, as Windows says it. ".repeat(3)
            .trim_end()
            .into(),
    );
    assert!(
        !foot_is_background(&screen.draw()),
        "the step is not longer than the window"
    );
    window
        .window()
        .dispatch_event(slint::platform::WindowEvent::PointerScrolled {
            position: slint::LogicalPosition::new(380.0, 320.0),
            delta_x: 0.0,
            delta_y: -5000.0,
        });
    assert!(
        foot_is_background(&screen.draw()),
        "a long step of the installer does not scroll to its end"
    );

    // What an install, update or uninstall did fits the installer's window
    // without scrolling, the buttons below it: its foot is the window's
    // background.
    install.set_error("".into());
    install.set_warnings(lines(1, "Warning: update-desktop-database is not on this machine, so the desktop may not know yet that Nerve opens nerve:// links"));
    install.set_did(lines(
        12,
        "removed Nerve from the application menu and the link handler of nerve:// links",
    ));
    for action in ["install", "update", "uninstall"] {
        install.set_step("done".into());
        install.set_action(action.into());
        assert!(
            foot_is_background(&screen.draw()),
            "the installer's last step of {action} does not fit its window"
        );
    }
    install.set_shown(false);
    fits("the app after the installer");

    // The dialogs in the app's window: a short one ends well above the
    // window's foot, so does the last step of an update or uninstall, and a
    // dialog longer than the window scrolls inside it.
    screen.resize(APP.0, APP.1);
    install.set_did(lines(
        16,
        "removed Nerve from the application menu and the link handler of nerve:// links",
    ));
    let store = window.global::<Store>();
    store.set_elevate_open(true);
    let foot = bottom(&screen.draw(), 26);
    store.set_elevate_open(false);
    install.set_action("uninstall".into());
    install.set_uninstall_open(true);
    assert!(
        bottom(&screen.draw(), 26) == foot,
        "the uninstall's last step does not fit the window"
    );
    install.set_uninstall_open(false);
    install.set_action("update".into());
    install.set_update_open(true);
    assert!(
        bottom(&screen.draw(), 26) == foot,
        "the update's last step does not fit the window"
    );
    install.set_update_open(false);
    let prefs = window.global::<Prefs>();
    prefs.set_relay_edit_name("laptop-2".into());
    prefs.set_relay_edit_centers(ModelRc::new(VecModel::from(
        (0..30)
            .map(|i| Pick {
                name: format!("center-{i}").into(),
                on: i % 2 == 0,
            })
            .collect::<Vec<_>>(),
    )));
    prefs.set_relay_edit_own(true);
    prefs.set_relay_edit_open(true);
    assert!(
        bottom(&screen.draw(), 20) == foot[foot.len() - 20 * APP.0 as usize..],
        "a dialog longer than the window runs out of it"
    );
    prefs.set_relay_edit_open(false);
    // The dialogs that are new with the relay's page and the pairing's
    // check end above the window's foot too, with every part shown.
    prefs.set_connect_apart(true);
    prefs.set_proxy("http://proxy.example:3128".into());
    prefs.set_connect_error("the relay link's address is not host:port".into());
    prefs.set_connect_open(true);
    assert!(
        bottom(&screen.draw(), 26) == foot,
        "the relay link's dialog does not fit the window"
    );
    prefs.set_connect_open(false);
    store.set_pair_preview(PairPreview {
        center: "http://127.0.0.1:7480".into(),
        tls: false,
        pin: "".into(),
        name: "home-lab".into(),
        ready: false,
        check: "A machine paired with this code already. Make a new link in the center's web UI."
            .into(),
    });
    store.set_pair_step(1);
    store.set_pair_open(true);
    assert!(
        bottom(&screen.draw(), 26) == foot,
        "the pairing's confirmation does not fit the window"
    );
    store.set_pair_open(false);

    // Ten centers on the Permissions page: the chosen one is named in full,
    // not squeezed to an ellipsis with the others. Drawn with its name
    // spelled two ways, the window differs only if the name is drawn.
    let perm = window.global::<Perm>();
    let names = |first: &str| {
        let mut names = vec![SharedString::from(first)];
        names.extend(
            [
                "lab",
                "office-workstation-second-floor",
                "build-farm-eu-west",
                "staging-cluster",
                "personal-laptop",
                "ci-runner-pool",
                "backup-vault",
                "media-server",
                "kids-pc",
            ]
            .map(SharedString::from),
        );
        ModelRc::new(VecModel::from(names))
    };
    store.set_page(Page::Policy);
    // Nothing that moves: the page's loading dots would differ anyway.
    perm.set_load(Load::Failed);
    store.set_status_load(Load::Failed);
    perm.set_current(0);
    perm.set_centers(names("home"));
    let one = screen.draw();
    perm.set_centers(names("hxme"));
    assert!(
        screen.draw().as_slice() != one.as_slice(),
        "the chosen center's name is not drawn among ten centers"
    );

    // Windows, no account chosen yet (a password mistyped at install): the
    // card has the password field all the same, for the app's user. Drawn
    // with a password typed and without, the window differs only if the
    // field is there.
    // Set before the page is made, as the app sets them at its start.
    screen.resize(APP.0, 3000);
    let install = window.global::<Install>();
    install.set_windows(true);
    install.set_account("alice".into());
    store.set_page(Page::Overview);
    screen.draw();
    store.set_page(Page::Settings);
    prefs.set_load(Load::Ready);
    prefs.set_account("".into());
    prefs.set_account_password("".into());
    let empty = settled(&screen);
    prefs.set_account_password("s3cret".into());
    assert!(
        settled(&screen).as_slice() != empty.as_slice(),
        "no password field for the account on Windows"
    );

    // The form of a capability in the details pane, on a screen of
    // 1280x800, with what is wrong shown at every field: taller than the
    // window, it scrolls on its own to its buttons, whose main one saves.
    screen.resize(ROOM.0 as u32, ROOM.1 as u32);
    store.set_page(Page::Capabilities);
    let caps = window.global::<Caps>();
    caps.set_read(true);
    caps.set_load(Load::Ready);
    let saved = std::rc::Rc::new(std::cell::Cell::new(false));
    let s = saved.clone();
    caps.on_edit_save(move || s.set(true));
    let long = "the schema's /properties/chip/oneOf: alternatives are not supported here; give one type, or an enum of plain values for a choice";
    caps.set_edit_new(true);
    caps.set_edit_name("sensors.read".into());
    caps.set_edit_effect(3);
    let schema: Vec<String> = (0..8).map(|i| format!("  \"line-{i}\": {{}},")).collect();
    caps.set_edit_params(schema.join("\n").into());
    for set in [
        Caps::set_name_error,
        Caps::set_summary_error,
        Caps::set_command_error,
        Caps::set_params_error,
        Caps::set_result_error,
        Caps::set_timeout_error,
        Caps::set_edit_error,
    ] {
        set(&caps, long.into());
    }
    // Add is there with the fields not ready: a click shows what is missing.
    caps.set_edit_ready(false);
    // The details pane: right of the list, its 400 px before the margin.
    let pane = (ROOM.0 - 32.0 - 400.0, ROOM.0 - 32.0);
    // The page to its end, with the pane in view at its top, then the
    // form to its end.
    let to_the_end = || {
        caps.set_edit_open(true);
        screen.draw();
        for x in [400.0, (pane.0 + pane.1) / 2.0] {
            window
                .window()
                .dispatch_event(slint::platform::WindowEvent::PointerScrolled {
                    position: slint::LogicalPosition::new(x, 360.0),
                    delta_x: 0.0,
                    delta_y: -5000.0,
                });
            screen.draw();
        }
    };
    to_the_end();
    // Add, the last button: the right-most one low in the pane; a click
    // that closed the form (Cancel) opens it again.
    'add: for y in (ROOM.1 as i32 - 120..ROOM.1 as i32).rev().step_by(4) {
        for x in (pane.0 as i32..pane.1 as i32).rev().step_by(8) {
            if !caps.get_edit_open() {
                to_the_end();
            }
            let at = slint::LogicalPosition::new(x as f32, y as f32);
            for event in [
                slint::platform::WindowEvent::PointerMoved { position: at },
                slint::platform::WindowEvent::PointerPressed {
                    position: at,
                    button: slint::platform::PointerEventButton::Left,
                },
                slint::platform::WindowEvent::PointerReleased {
                    position: at,
                    button: slint::platform::PointerEventButton::Left,
                },
            ] {
                window.window().dispatch_event(event);
            }
            if saved.get() {
                break 'add;
            }
        }
    }
    assert!(
        saved.get(),
        "the form's Add is not at the end of its scroll"
    );
    caps.set_edit_open(true);

    // The Arguments box holds more lines than it shows, and a TextInput
    // does not scroll itself: the wheel over the box moves its text, and
    // the cursor sent to the end brings the last line into view. The window
    // is tall for this, so the form's pane has nothing to scroll and
    // only the box takes the wheel; the box is found by where it does.
    screen.resize(ROOM.0 as u32, 1600);
    caps.set_params_scrolled(0.0);
    screen.draw();
    // A probe needs no picture: the event finds its item by the layout, and
    // the timers move what it starts. A full software render after each of
    // up to 1600 probes made this the slowest test of the workspace.
    let probe = |x: f32, y: f32, delta_y: f32| {
        window
            .window()
            .dispatch_event(slint::platform::WindowEvent::PointerScrolled {
                position: slint::LogicalPosition::new(x, y),
                delta_x: 0.0,
                delta_y,
            });
        slint::platform::update_timers_and_animations();
    };
    let wheel = |x: f32, y: f32, delta_y: f32| {
        probe(x, y, delta_y);
        screen.draw();
    };
    let mut over = None;
    'find: for y in (0..1600).step_by(8) {
        for x in [870.0, 930.0, 990.0, 1050.0, 1110.0, 1170.0, 1230.0] {
            probe(x, y as f32, -20.0);
            if caps.get_params_scrolled() < 0.0 {
                over = Some((x, y as f32));
                break 'find;
            }
        }
    }
    let (x, y) = over.expect("the wheel does not scroll the Arguments box");
    wheel(x, y, -5000.0);
    let end = caps.get_params_scrolled();
    assert!(end < -20.0, "the box scrolls {end} pixels at most");
    wheel(x, y, 5000.0);
    assert_eq!(caps.get_params_scrolled(), 0.0);
    // A drag up inside the box selects text and leaves the box where it is;
    // it is the wheel that scrolls. The drag starts high in the box: a press
    // on a line that is cut off at the bottom brings that line into view, and
    // how many lines fit depends on the platform's font.
    let at = |dy: f32| slint::LogicalPosition::new(x, y + dy);
    window
        .window()
        .dispatch_event(slint::platform::WindowEvent::PointerMoved { position: at(50.0) });
    window
        .window()
        .dispatch_event(slint::platform::WindowEvent::PointerPressed {
            position: at(50.0),
            button: slint::platform::PointerEventButton::Left,
        });
    for dy in [44.0, 38.0, 32.0, 26.0, 20.0, 14.0] {
        window
            .window()
            .dispatch_event(slint::platform::WindowEvent::PointerMoved { position: at(dy) });
        screen.draw();
    }
    window
        .window()
        .dispatch_event(slint::platform::WindowEvent::PointerReleased {
            position: at(14.0),
            button: slint::platform::PointerEventButton::Left,
        });
    screen.draw();
    assert_eq!(
        caps.get_params_scrolled(),
        0.0,
        "a drag in the Arguments box scrolls it and does not select"
    );
    // Focused by a click, Ctrl+End puts the cursor after the last line.
    for event in [
        slint::platform::WindowEvent::PointerMoved {
            position: slint::LogicalPosition::new(x, y),
        },
        slint::platform::WindowEvent::PointerPressed {
            position: slint::LogicalPosition::new(x, y),
            button: slint::platform::PointerEventButton::Left,
        },
        slint::platform::WindowEvent::PointerReleased {
            position: slint::LogicalPosition::new(x, y),
            button: slint::platform::PointerEventButton::Left,
        },
    ] {
        window.window().dispatch_event(event);
    }
    let control: SharedString = slint::platform::Key::Control.into();
    let w = window.window();
    w.dispatch_event(slint::platform::WindowEvent::KeyPressed {
        text: control.clone(),
    });
    let key: SharedString = slint::platform::Key::End.into();
    w.dispatch_event(slint::platform::WindowEvent::KeyPressed { text: key.clone() });
    w.dispatch_event(slint::platform::WindowEvent::KeyReleased { text: key });
    w.dispatch_event(slint::platform::WindowEvent::KeyReleased {
        text: control.clone(),
    });
    screen.draw();
    let followed = caps.get_params_scrolled();
    assert!(
        followed < end / 2.0,
        "the box did not follow the cursor to the last line: {followed} of {end}"
    );
    // And back to the first line with Ctrl+Home.
    let key: SharedString = slint::platform::Key::Home.into();
    w.dispatch_event(slint::platform::WindowEvent::KeyPressed {
        text: control.clone(),
    });
    w.dispatch_event(slint::platform::WindowEvent::KeyPressed { text: key.clone() });
    w.dispatch_event(slint::platform::WindowEvent::KeyReleased { text: key });
    w.dispatch_event(slint::platform::WindowEvent::KeyReleased { text: control });
    screen.draw();
    assert_eq!(
        caps.get_params_scrolled(),
        0.0,
        "the box did not follow the cursor back to the first line"
    );
    // Enter in a one-line field saves, as it does with no field focused:
    // the TextField takes the key for its own `accepted`, so the form's
    // `enter` never sees it. Each field is found by a click that a typed
    // letter then lands in.
    let tap = |x: f32, y: f32| {
        let position = slint::LogicalPosition::new(x, y);
        let w = window.window();
        w.dispatch_event(slint::platform::WindowEvent::PointerMoved { position });
        w.dispatch_event(slint::platform::WindowEvent::PointerPressed {
            position,
            button: slint::platform::PointerEventButton::Left,
        });
        w.dispatch_event(slint::platform::WindowEvent::PointerReleased {
            position,
            button: slint::platform::PointerEventButton::Left,
        });
    };
    let key = |text: SharedString| {
        w.dispatch_event(slint::platform::WindowEvent::KeyPressed { text: text.clone() });
        w.dispatch_event(slint::platform::WindowEvent::KeyReleased { text });
    };
    let fields = |c: &Caps| {
        [
            c.get_edit_name(),
            c.get_edit_timeout(),
            c.get_edit_summary(),
            c.get_edit_command(),
        ]
    };
    let mut entered = [false; 4];
    for y in (0..1600).step_by(6) {
        for x in [880.0, 1000.0, 1120.0, 1230.0] {
            if !caps.get_edit_open() {
                caps.set_edit_open(true);
                screen.draw();
            }
            let before = fields(&caps);
            tap(x, y as f32);
            key("x".into());
            let after = fields(&caps);
            let Some(i) = (0..4).find(|&i| before[i] != after[i]) else {
                continue;
            };
            if entered[i] {
                continue;
            }
            saved.set(false);
            key(slint::platform::Key::Return.into());
            assert!(
                saved.get(),
                "Enter in the form's field {i} (name, time limit, summary, command) does not save"
            );
            entered[i] = true;
        }
        if entered == [true; 4] {
            break;
        }
    }
    assert_eq!(entered, [true; 4], "a field of the form was not found");
    caps.set_edit_open(false);
    screen.resize(ROOM.0 as u32, ROOM.1 as u32);
    screen.draw();

    // The sidebar at the window's least height: each page's item, About,
    // and the look's switch at its foot are all in the window, in their
    // order. A click every few pixels down the sidebar opens them one
    // after the other; an item pushed below the window's foot opens none.
    screen.resize(LEAST.0, LEAST.1);
    install.set_windows(false);
    store.set_page(Page::Overview);
    let w = window.as_weak();
    store.on_show(move |page| w.unwrap().global::<Store>().set_page(page));
    let w = window.as_weak();
    store.on_set_appearance(move |i| w.unwrap().global::<Store>().set_appearance(i));
    // As above, a click finds its item by the layout, so the scan draws
    // only after a change of the page, whose sidebar marks the new item.
    screen.draw();
    let click = |x: f32, y: f32| {
        let position = slint::LogicalPosition::new(x, y);
        let w = window.window();
        w.dispatch_event(slint::platform::WindowEvent::PointerMoved { position });
        w.dispatch_event(slint::platform::WindowEvent::PointerPressed {
            position,
            button: slint::platform::PointerEventButton::Left,
        });
        w.dispatch_event(slint::platform::WindowEvent::PointerReleased {
            position,
            button: slint::platform::PointerEventButton::Left,
        });
        slint::platform::update_timers_and_animations();
    };
    let mut opened = vec![Page::Overview];
    let mut about = false;
    for y in (40..LEAST.1 as i32).step_by(6) {
        click(118.0, y as f32);
        if store.get_about_open() {
            about = opened.len() == 9;
            store.set_about_open(false);
            screen.draw();
        }
        let page = store.get_page();
        if opened.last() != Some(&page) {
            opened.push(page);
            screen.draw();
        }
    }
    assert_eq!(
        opened,
        [
            Page::Overview,
            Page::Centers,
            Page::Relay,
            Page::Policy,
            Page::Capabilities,
            Page::Audit,
            Page::Log,
            Page::Settings,
            Page::Help,
        ],
        "the sidebar's items at the least height"
    );
    assert!(about, "About is not below Help in the window");
    // Dark, the last third of the switch, 27 pixels above the foot.
    click(12.0 + 211.0 * 5.0 / 6.0, LEAST.1 as f32 - 27.0);
    screen.draw();
    assert_eq!(
        store.get_appearance(),
        2,
        "the look's switch is not at the foot"
    );

    // Every page at the window's four sizes, the least, a small one, a
    // middle and a large one, its list and its details: nothing runs into
    // the page's right margin, however long a name, a path or a rule is.
    // Light only: the layout is the same in dark.
    store.on_show(|_| {});
    made_up(&window);
    for (width, height) in SIZES {
        screen.resize(width, height);
        // The margin right of the page, left of its scroll bar.
        let margin = if width >= 1100 { 32 } else { 24 };
        let (from, to) = (width as usize - margin + 2, width as usize - 18);
        for page in [
            Page::Overview,
            Page::Centers,
            Page::Relay,
            Page::Policy,
            Page::Capabilities,
            Page::Audit,
            Page::Log,
            Page::Settings,
            Page::Help,
        ] {
            store.set_page(page);
            for open in [false, true] {
                store.set_details_open(open);
                let shot = settled(&screen);
                let w = shot.width() as usize;
                let px = shot.as_slice();
                let background = px[(shot.height() as usize - 1) * w + from];
                let overrun = (0..shot.height() as usize)
                    .find(|y| px[y * w + from..y * w + to].iter().any(|p| *p != background));
                assert_eq!(
                    overrun, None,
                    "{page:?} at {width}x{height} (details open: {open}) runs into the margin"
                );
            }
        }
    }
}

/// The window's sizes the pages fit: the least, a small window, a middle
/// one and a large one (the breakpoints are 1100 and 1800 px).
const SIZES: [(u32, u32); 4] = [(900, 580), (1024, 700), (1440, 900), (2200, 1200)];

/// Made-up rows for every page, with long names, paths and rules.
fn made_up(window: &AppWindow) {
    use nerve_node_desktop::{
        AuditRow, CapRow, CenterRow, DeclaredRow, FolderRow, LogRow, NodeStatus, ProgramRow,
        RelayNodeRow, Tone, TunnelRow,
    };
    let long_path = "/home/alex/projects/clients/northwind/infrastructure/terraform/modules/networking/vpc-peering";
    let long_rule = "exec.run:docker compose -f deploy/docker-compose.production.yml --project-name northwind-platform up -d --remove-orphans";
    let store = window.global::<Store>();
    store.set_status_load(Load::Ready);
    store.set_status(NodeStatus {
        state: "running".into(),
        title: "Running".into(),
        detail: "Each call of a center is checked against your rules.".into(),
        tone: Tone::Ok,
        confinement: "landlock v10".into(),
        centers: 2,
        connected: 1,
        limits: "4096 MiB · 200 % · 1024".into(),
        limits_off: "The service has no cgroup of its own for them.".into(),
        ..Default::default()
    });
    store.set_service_state("running".into());
    let center = |name: &str| CenterRow {
        name: name.into(),
        url: "https://nerve-center.platform-engineering.internal.example.com:8443/teams/nerve".into(),
        link: "Connected".into(),
        link_tone: Tone::Ok,
        mode: "Folder mode".into(),
        mode_detail: "What each of its folders allows.".into(),
        note: "The center no longer takes this machine: pair it again.".into(),
        note_tone: Tone::Warn,
        ..Default::default()
    };
    store.set_centers(ModelRc::new(VecModel::from(vec![
        center("home"),
        center("office-workstation-second-floor"),
    ])));
    store.set_audit_read(1);
    store.set_audit_load(Load::Ready);
    store.set_audit(ModelRc::new(VecModel::from(vec![AuditRow {
        kind: "call".into(),
        tone: Tone::Danger,
        title: "exec.run".into(),
        badge: "Refused".into(),
        center: "office-workstation-second-floor".into(),
        target: long_rule.into(),
        detail: "No allow rule matches the command.".into(),
        when: "2 min ago".into(),
        rules: true,
        ..Default::default()
    }])));
    let logs = window.global::<nerve_node_desktop::Logs>();
    logs.set_load(Load::Ready);
    logs.set_rows(ModelRc::new(VecModel::from(vec![LogRow {
        tone: Tone::Danger,
        level: "Error".into(),
        msg: format!("center lab: cannot resolve {long_path}, and the link waits for the next try in 30 s").into(),
        when: "2 min ago".into(),
        when_exact: "2026-11-14 18:02:05 UTC".into(),
    }])));
    let perm = window.global::<Perm>();
    perm.set_centers(ModelRc::new(VecModel::from(vec![
        SharedString::from("home"),
        SharedString::from("office-workstation-second-floor"),
    ])));
    perm.set_center("home".into());
    perm.set_read(true);
    perm.set_load(Load::Ready);
    perm.set_mode("folder".into());
    perm.set_folders(ModelRc::new(VecModel::from(vec![FolderRow {
        path: long_path.into(),
        read: true,
        write: true,
        execute: true,
    }])));
    perm.set_deny(ModelRc::new(VecModel::from(vec![SharedString::from(long_rule)])));
    perm.set_deny_unfit(ModelRc::new(VecModel::from(vec![SharedString::new()])));
    let caps = window.global::<Caps>();
    caps.set_centers(perm.get_centers());
    caps.set_center("home".into());
    caps.set_read(true);
    caps.set_running(true);
    caps.set_edit_open(false);
    let unit = |name: &str, action: bool| CapRow {
        name: name.into(),
        action,
        effect: if action { "execute".into() } else { "".into() },
        tone: Tone::Accent,
        source: "built-in".into(),
        summary: "Runs a command with /bin/sh -c. A command is killed after timeout_ms, after 10 min when you give none, and never runs longer than 1 h.".into(),
        switchable: true,
        setting: 1,
        now: "on".into(),
        command: long_rule.into(),
        units: if action { 0 } else { 1 },
        ..Default::default()
    };
    caps.set_rows(ModelRc::new(VecModel::from(vec![
        unit("exec", false),
        unit("exec.run-a-long-name-of-a-unit", true),
    ])));
    caps.set_pick_kind(0);
    caps.set_pick_at(1);
    caps.set_declared(ModelRc::new(VecModel::from(vec![DeclaredRow {
        name: "sensors.read".into(),
        effect: "sense".into(),
        command: long_rule.into(),
        detail: "takes arguments, returns JSON".into(),
        ..Default::default()
    }])));
    caps.set_programs(ModelRc::new(VecModel::from(vec![ProgramRow {
        name: "desk".into(),
        exe: long_path.into(),
        attached: "attached".into(),
    }])));
    let prefs = window.global::<Prefs>();
    prefs.set_load(Load::Ready);
    prefs.set_relay_listen("0.0.0.0:7490".into());
    prefs.set_relay_pin("Q3hT7c1Lm9VwX2bN8kPz4RsYd6FgJ0uA5eHiKoWq1ZcQ3hT7c1Lm9VwX2bN8kPz4R".into());
    prefs.set_relay_nodes(ModelRc::new(VecModel::from(vec![RelayNodeRow {
        name: "build-agent-with-a-long-name-7".into(),
        reach: "May reach every https center of this node.".into(),
        live: "2 links".into(),
        ..Default::default()
    }])));
    prefs.set_tunnels(ModelRc::new(VecModel::from(vec![TunnelRow {
        node: "build-agent-with-a-long-name-7".into(),
        center: "office-workstation-second-floor".into(),
        from: "192.0.2.14:51234".into(),
        since: "2 h 5 min".into(),
    }])));
    prefs.set_relay_pick(3);
    prefs.set_relay_pick_at(0);
}
