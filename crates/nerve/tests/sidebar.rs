//! Light, dark or the system's look is chosen at the foot of the sidebar,
//! on every page, with a click. One test: Slint takes one platform per
//! process.

use nerve::app::{Ctl, Exec};
use nerve::headless::Screen;
use nerve::runner::Runner;
use nerve::{AppWindow, Page, Store};
use slint::platform::{PointerEventButton, WindowEvent};
use slint::{ComponentHandle, LogicalPosition};

const SIZE: (u32, u32) = (1180, 700);

#[test]
fn the_look_is_chosen_at_the_foot_of_the_sidebar() {
    let screen = Screen::install(SIZE.0, SIZE.1, 1.0).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let runner = Runner::new(
        env!("CARGO_BIN_EXE_nerve").into(),
        Some(dir.path().join("config")),
        Some(dir.path().join("state")),
    );
    let window = AppWindow::new().unwrap();
    let _ctl = Ctl::attach(&window, runner, Exec::Inline);
    window.show().unwrap();
    let store = window.global::<Store>();
    let click = |x: f32, y: f32| {
        let position = LogicalPosition::new(x, y);
        let w = window.window();
        w.dispatch_event(WindowEvent::PointerMoved { position });
        w.dispatch_event(WindowEvent::PointerPressed {
            position,
            button: PointerEventButton::Left,
        });
        w.dispatch_event(WindowEvent::PointerReleased {
            position,
            button: PointerEventButton::Left,
        });
    };
    // The switch fills the sidebar's width (236 less its padding of 12 and
    // 13) in its last 30 pixels above the padding of 12: System, Light and
    // Dark, a third each.
    let (left, width) = (12.0, 211.0);
    let y = SIZE.1 as f32 - 12.0 - 15.0;
    let third = |i: f32| left + width * (2.0 * i + 1.0) / 6.0;
    for page in [Page::Overview, Page::Settings] {
        store.invoke_show(page);
        screen.draw();
        assert_eq!(store.get_appearance(), 0);
        click(third(2.0), y);
        assert_eq!(store.get_appearance(), 2, "Dark on {page:?}");
        click(third(1.0), y);
        assert_eq!(store.get_appearance(), 1, "Light on {page:?}");
        click(third(0.0), y);
        assert_eq!(store.get_appearance(), 0, "System on {page:?}");
    }
}
