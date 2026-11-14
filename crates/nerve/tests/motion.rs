//! The animations: a page, a dialog, a toast and a section that opens move
//! for no longer than their time in `Motion` (ui/theme.slint) and end where
//! they would stand without motion; nothing moves while motion is off, as it
//! is until the desktop allows it; a dialog takes keys and the page takes
//! clicks while either still moves; and the switch from dark to the
//! desktop's dark shows no light frame. Drawn with the clock stopped, so
//! each frame is the moment the test chose. One test: Slint takes one
//! platform per process.

use std::time::Duration;

use nerve::app::{Ctl, Exec};
use nerve::headless::Screen;
use nerve::runner::Runner;
use nerve::{AppWindow, Load, Manual, Motion, Page, Store, Tone};
use slint::platform::{Key, PointerEventButton, WindowEvent};
use slint::{ComponentHandle, LogicalPosition, Rgba8Pixel, SharedPixelBuffer};

const SIZE: (u32, u32) = (1180, 700);
/// The times of `Motion` with motion on: a page or a dialog coming in, a
/// switch, a section or a toast, and a dialog's veil or a toast going.
const ENTER: Duration = Duration::from_millis(200);
const BASE: Duration = Duration::from_millis(150);
const LEAVE: Duration = Duration::from_millis(120);
/// Long past every animation. An animation starts when the window is next
/// drawn after the change, as a window on a desktop is at once: each change
/// here is drawn before the clock moves.
const LATER: Duration = Duration::from_secs(1);

type Shot = SharedPixelBuffer<Rgba8Pixel>;

fn same(a: &Shot, b: &Shot) -> bool {
    a.as_slice() == b.as_slice()
}

#[test]
fn animations_are_short_end_in_place_and_wait_for_nothing() {
    let screen = Screen::install(SIZE.0, SIZE.1, 1.0).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let runner = Runner::new(
        env!("CARGO_BIN_EXE_nerve").into(),
        Some(dir.path().join("config")),
        Some(dir.path().join("state")),
    );
    let window = AppWindow::new().unwrap();
    let ctl = Ctl::attach(&window, runner, Exec::Inline);
    window.show().unwrap();
    let store = window.global::<Store>();
    let motion = window.global::<Motion>();
    // Nothing on the pages that moves of its own: no loading dots.
    store.set_status_load(Load::Failed);
    screen.stop_clock();
    let at = |by: Duration| {
        screen.advance(by);
        screen.draw()
    };
    // Opens `p` anew, and draws its first frame.
    let page = |p: Page| {
        store.set_page(Page::Overview);
        at(LATER);
        store.set_page(p);
        screen.draw()
    };

    // Off until the desktop said: a page opens at once.
    assert!(!motion.get_on(), "motion is on before the desktop said");
    let centers = page(Page::Centers);
    assert!(same(&centers, &at(LATER)), "a page moves with motion off");

    // What the desktop says turns it on or off; when it says nothing, the
    // app moves.
    ctl.desktop_motion(Some(true));
    assert!(!motion.get_on());
    ctl.desktop_motion(None);
    assert!(motion.get_on());
    ctl.desktop_motion(Some(true));
    ctl.set_motion_source(Some(|| Some(false)));
    ctl.follow_motion();
    assert!(motion.get_on(), "the desktop's answer is not taken");
    ctl.set_motion_source(Some(|| Some(true)));
    ctl.follow_motion();
    assert!(!motion.get_on(), "less motion is not taken");
    motion.set_on(true);

    // A page comes in, and at its time stands where it stands without
    // motion.
    let start = page(Page::Centers);
    let mid = at(ENTER / 2);
    assert!(!same(&start, &centers) && !same(&mid, &centers));
    assert!(!same(&start, &mid), "the page does not move");
    assert!(
        same(&at(ENTER / 2), &centers),
        "a page takes longer than ENTER"
    );
    assert!(same(&at(LATER), &centers), "the page keeps moving");

    // A dialog comes in in its time, and takes Escape at once.
    store.set_about_open(true);
    let start = screen.draw();
    let about = at(LATER);
    assert!(!same(&start, &about), "the dialog does not come in");
    store.set_about_open(false);
    at(LATER);
    store.set_about_open(true);
    screen.draw();
    at(ENTER - Duration::from_millis(40));
    assert!(same(&at(Duration::from_millis(40)), &about));
    store.set_about_open(false);
    at(LATER);
    store.set_about_open(true);
    screen.draw();
    window.window().dispatch_event(WindowEvent::KeyPressed {
        text: Key::Escape.into(),
    });
    assert!(
        !store.get_about_open(),
        "a dialog that comes in does not take Escape"
    );
    at(LATER);

    // It goes at once; its veil lifts in its time, and the page takes a
    // click while it does: Overview, the first page in the sidebar.
    store.set_about_open(true);
    at(LATER);
    store.set_about_open(false);
    let lifting = screen.draw();
    assert!(!same(&lifting, &centers), "the veil does not lift");
    assert!(
        same(&at(LEAVE), &centers),
        "the veil takes longer than LEAVE"
    );
    store.set_about_open(true);
    at(LATER);
    store.set_about_open(false);
    screen.draw();
    let position = LogicalPosition::new(100.0, 90.0);
    for event in [
        WindowEvent::PointerMoved { position },
        WindowEvent::PointerPressed {
            position,
            button: PointerEventButton::Left,
        },
        WindowEvent::PointerReleased {
            position,
            button: PointerEventButton::Left,
        },
    ] {
        window.window().dispatch_event(event);
    }
    assert_eq!(
        store.get_page(),
        Page::Overview,
        "the page takes no click while the veil lifts"
    );
    // The page asked the node meanwhile, which may have changed its state.
    page(Page::Centers);
    let centers = at(LATER);

    // A toast rises in its time, and fades out in its time when it goes.
    store.set_toast("Paired with home".into());
    store.set_toast_tone(Tone::Ok);
    store.set_toast_shown(true);
    let start = screen.draw();
    let toast = at(LATER);
    assert!(!same(&start, &toast) && !same(&toast, &centers));
    store.set_toast_shown(false);
    at(LATER);
    store.set_toast_shown(true);
    screen.draw();
    at(BASE - Duration::from_millis(30));
    assert!(same(&at(Duration::from_millis(30)), &toast));
    store.set_toast_shown(false);
    let going = screen.draw();
    assert!(!same(&going, &centers), "the toast does not fade out");
    assert!(
        same(&at(LEAVE), &centers),
        "a toast takes longer than LEAVE"
    );

    // A section opens and closes in its time.
    page(Page::Help);
    at(LATER);
    let manual = window.global::<Manual>();
    let closed = screen.draw();
    manual.set_keys_open(true);
    let start = screen.draw();
    let open = at(LATER);
    assert!(!same(&open, &closed));
    manual.set_keys_open(false);
    at(LATER);
    manual.set_keys_open(true);
    screen.draw();
    let mid = at(BASE / 2);
    assert!(
        !same(&mid, &start) && !same(&mid, &open),
        "the section jumps"
    );
    assert!(
        same(&at(BASE / 2), &open),
        "a section takes longer than BASE"
    );
    manual.set_keys_open(false);
    screen.draw();
    assert!(!same(&at(BASE / 2), &closed), "the section closes at once");
    assert!(
        same(&at(BASE / 2), &closed),
        "a section takes longer than BASE"
    );

    // The loading dots pulse with motion, and stand still without it.
    page(Page::Overview);
    store.set_status_load(Load::Loading);
    store.set_status(Default::default());
    at(LATER);
    let one = screen.draw();
    assert!(
        !same(&one, &at(Duration::from_millis(300))),
        "the dots stand"
    );
    motion.set_on(false);
    let one = at(LATER);
    assert!(same(&one, &at(Duration::from_millis(300))), "the dots move");
    motion.set_on(true);
    store.set_status_load(Load::Failed);

    // Dark, then the desktop's look while the desktop is dark: no frame
    // shows the light window in between.
    page(Page::Centers);
    ctl.desktop_said(Some(true));
    store.invoke_set_appearance(2);
    let dark = at(LATER);
    let window_px = |s: &Shot| s.as_slice()[(SIZE.1 as usize - 4) * SIZE.0 as usize + 700];
    store.invoke_set_appearance(0);
    for _ in 0..12 {
        assert_eq!(
            window_px(&at(Duration::from_millis(20))),
            window_px(&dark),
            "a light frame on the way to the desktop's dark"
        );
    }
}
