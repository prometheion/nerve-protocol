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
    prefs.set_relay_add_error(
        "the relay knows a node laptop-2 already; take its link away first".into(),
    );
    prefs.set_relay_add_open(true);
    assert!(
        bottom(&screen.draw(), 26) == foot,
        "the dialog of a node's link does not fit the window"
    );
    prefs.set_relay_add_open(false);
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

    // The dialog of a capability on a screen of 1280x800, with what is
    // wrong shown at every field: its card stays in the window, and
    // scrolls to its buttons, whose main one saves.
    screen.resize(ROOM.0 as u32, ROOM.1 as u32);
    store.set_page(Page::Capabilities);
    store.set_elevate_open(true);
    let foot = bottom(&screen.draw(), 20);
    store.set_elevate_open(false);
    let caps = window.global::<Caps>();
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
    caps.set_edit_open(true);
    assert!(
        bottom(&screen.draw(), 20) == foot,
        "the capability's dialog runs out of the window"
    );
    window
        .window()
        .dispatch_event(slint::platform::WindowEvent::PointerScrolled {
            position: slint::LogicalPosition::new(640.0, 360.0),
            delta_x: 0.0,
            delta_y: -5000.0,
        });
    screen.draw();
    // Add, the last button: right in the card of 640, above its padding.
    let at = slint::LogicalPosition::new(
        (ROOM.0 + 640.0) / 2.0 - 24.0 - 24.0,
        ROOM.1 - 24.0 - 24.0 - 17.0,
    );
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
    assert!(
        saved.get(),
        "the dialog's Add is not at the end of its scroll"
    );

    // The Arguments box holds more lines than it shows, and a TextInput
    // does not scroll itself: the wheel over the box moves its text, and
    // the cursor sent to the end brings the last line into view. The window
    // is tall for this, so the dialog's own body has nothing to scroll and
    // only the box takes the wheel; the box is found by where it does.
    screen.resize(ROOM.0 as u32, 1600);
    caps.set_params_scrolled(0.0);
    screen.draw();
    let wheel = |x: f32, y: f32, delta_y: f32| {
        window
            .window()
            .dispatch_event(slint::platform::WindowEvent::PointerScrolled {
                position: slint::LogicalPosition::new(x, y),
                delta_x: 0.0,
                delta_y,
            });
        screen.draw();
    };
    let mut over = None;
    'find: for y in (0..1600).step_by(8) {
        for x in [380.0, 450.0, 520.0, 600.0, 680.0, 760.0, 840.0, 900.0] {
            wheel(x, y as f32, -20.0);
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
    // it is the wheel that scrolls.
    let at = |dy: f32| slint::LogicalPosition::new(x, y + dy);
    window
        .window()
        .dispatch_event(slint::platform::WindowEvent::PointerMoved { position: at(70.0) });
    window
        .window()
        .dispatch_event(slint::platform::WindowEvent::PointerPressed {
            position: at(70.0),
            button: slint::platform::PointerEventButton::Left,
        });
    for dy in [62.0, 54.0, 46.0, 38.0, 30.0, 22.0] {
        window
            .window()
            .dispatch_event(slint::platform::WindowEvent::PointerMoved { position: at(dy) });
        screen.draw();
    }
    window
        .window()
        .dispatch_event(slint::platform::WindowEvent::PointerReleased {
            position: at(22.0),
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
    // the TextField takes the key for its own `accepted`, so the dialog's
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
        for x in [400.0, 640.0, 900.0] {
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
                "Enter in the dialog's field {i} (name, time limit, summary, command) does not save"
            );
            entered[i] = true;
        }
        if entered == [true; 4] {
            break;
        }
    }
    assert_eq!(entered, [true; 4], "a field of the dialog was not found");
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
        screen.draw();
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
    assert_eq!(
        store.get_appearance(),
        2,
        "the look's switch is not at the foot"
    );
}
