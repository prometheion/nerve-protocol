//! A change of the look is one step: from Dark to the desktop's look the
//! window stays dark on a dark desktop, never light in between (a white
//! flash), also before the desktop said anything. One test: Slint takes one
//! platform per process.

use nerve::app::{Ctl, Exec};
use nerve::headless::Screen;
use nerve::runner::Runner;
use nerve::{AppWindow, Store};
use slint::ComponentHandle;

const SIZE: (u32, u32) = (1180, 700);

#[test]
fn a_change_of_the_look_never_shows_light_in_between() {
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
    // The window's background at the foot of the page, dark or light.
    let dark = || {
        let shot = screen.draw();
        let p = shot.as_slice()[(SIZE.1 as usize - 4) * SIZE.0 as usize + SIZE.0 as usize - 4];
        (u32::from(p.r) + u32::from(p.g) + u32::from(p.b)) < 3 * 128
    };
    // Headless, Slint's own reading of the system is light.
    assert!(!dark());
    store.invoke_set_appearance(2);
    assert!(dark());
    // The desktop has not said yet: the look stays until it does.
    store.invoke_set_appearance(0);
    assert!(dark(), "light before the desktop said anything");
    ctl.desktop_said(Some(true));
    assert!(dark());
    // Said once, it is taken at once the next time.
    store.invoke_set_appearance(1);
    assert!(!dark());
    store.invoke_set_appearance(2);
    store.invoke_set_appearance(0);
    assert!(dark(), "light on the way from Dark to a dark desktop");
    store.invoke_set_appearance(1);
    store.invoke_set_appearance(0);
    assert!(dark(), "not dark at once from Light to a dark desktop");
    // A desktop that turns light, and one that does not say: Slint's
    // reading then.
    ctl.desktop_said(Some(false));
    assert!(!dark());
    store.invoke_set_appearance(2);
    ctl.desktop_said(None);
    assert!(dark(), "the desktop's word changed the chosen look");
    store.invoke_set_appearance(0);
    assert!(!dark());
    // The desktop asked as the choice is made.
    ctl.set_scheme_source(Some(|| Some(true)));
    store.invoke_set_appearance(1);
    store.invoke_set_appearance(0);
    assert!(dark(), "the desktop was not asked");
}
