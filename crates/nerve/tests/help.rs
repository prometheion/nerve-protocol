//! Help's sections come from a list beside them, and the task map's
//! groups open each on their own; on Windows the reference is there too.
//! One test: Slint takes one platform per process.

use nerve::app::{Ctl, Exec};
use nerve::headless::Screen;
use nerve::runner::Runner;
use nerve::{AppWindow, Install, Manual, Page, Store};
use slint::platform::{PointerEventButton, WindowEvent};
use slint::{ComponentHandle, LogicalPosition, Model};

// Tall enough for the task map with two groups open.
const SIZE: (u32, u32) = (1180, 1200);

#[test]
fn the_sections_come_from_the_list_and_the_groups_open_on_their_own() {
    let screen = Screen::install(SIZE.0, SIZE.1, 1.0).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let runner = Runner::new(
        env!("CARGO_BIN_EXE_nerve").into(),
        Some(dir.path().join("config")),
        Some(dir.path().join("state")),
    );
    let window = AppWindow::new().unwrap();
    let _ctl = Ctl::attach(&window, runner, Exec::Inline);
    // Linux's page first, wherever the test runs.
    window.global::<Install>().set_windows(false);
    window.show().unwrap();
    window.global::<Store>().invoke_show(Page::Help);
    screen.draw();
    let manual = window.global::<Manual>();
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
        screen.draw();
    };
    let open = |i: usize| manual.get_tasks_open().row_data(i).unwrap_or(false);

    // Down the list of sections, a click every few pixels picks the keys,
    // then the commands, in the list's order.
    let mut picked = vec![manual.get_section()];
    let mut y = 90.0;
    while y < 400.0 {
        click(400.0, y);
        if picked.last() != Some(&manual.get_section()) {
            picked.push(manual.get_section());
        }
        y += 6.0;
    }
    assert_eq!(picked, [0, 1, 2], "the sections in the list");

    // The task map's groups, beside the list: a click opens the first, the
    // same click closes it again; further down the next one opens, and the
    // first stays as it is.
    manual.set_section(0);
    screen.draw();
    let x = 800.0;
    let mut y = 90.0;
    while !open(0) {
        assert!(y < SIZE.1 as f32, "the task map's first group did not open");
        click(x, y);
        y += 6.0;
    }
    click(x, y - 6.0);
    assert!(!open(0), "the same click does not close the group");
    click(x, y - 6.0);
    // Past the first group's head, into its tasks.
    y += 48.0;
    while !open(1) {
        assert!(y < SIZE.1 as f32, "no second group opened");
        click(x, y);
        assert!(open(0), "a click below the first group's head closed it");
        y += 6.0;
    }
    assert!(open(0), "opening a group closed the other");

    // Windows' page: the reference is there too.
    window.global::<Install>().set_windows(true);
    manual.set_section(2);
    screen.draw();
    assert!(
        manual.get_ref_groups().row_count() > 0,
        "no reference on Windows' page"
    );
}
