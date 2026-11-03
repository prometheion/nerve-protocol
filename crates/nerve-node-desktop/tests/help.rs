//! Help's parts open each on their own: opening the command reference
//! leaves the keyboard's shortcuts open; on Windows there is no reference
//! (#176). One test: Slint takes one platform per process.

use nerve_node_desktop::app::{Ctl, Exec};
use nerve_node_desktop::headless::Screen;
use nerve_node_desktop::runner::Runner;
use nerve_node_desktop::{AppWindow, Install, Manual, Page, Store};
use slint::platform::{PointerEventButton, WindowEvent};
use slint::{ComponentHandle, LogicalPosition};

const SIZE: (u32, u32) = (1180, 700);

#[test]
fn opening_one_part_leaves_the_other_open() {
    let screen = Screen::install(SIZE.0, SIZE.1, 1.0).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let runner = Runner::new(
        env!("CARGO_BIN_EXE_nerve-node-desktop").into(),
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
    // Down the page, below its header, a click every few pixels in the
    // middle of the content until a part opens: first the keys, then,
    // further down, the commands.
    let x = 700.0;
    let mut y = 90.0;
    while !manual.get_keys_open() {
        assert!(y < SIZE.1 as f32, "no part of Help opened on a click");
        click(x, y);
        y += 6.0;
    }
    assert!(!manual.get_commands_open());
    // Past the keys' head: a click there closes them, and the next one
    // opens them again.
    while !manual.get_commands_open() {
        assert!(y < SIZE.1 as f32, "the commands did not open on a click");
        click(x, y);
        if !manual.get_keys_open() {
            click(x, y);
            assert!(manual.get_keys_open());
        }
        y += 6.0;
    }
    assert!(
        manual.get_keys_open(),
        "opening the commands closed the keys"
    );

    // Windows' page: the keys, and no reference to open anywhere on it.
    manual.set_commands_open(false);
    manual.set_keys_open(false);
    window.global::<Install>().set_windows(true);
    screen.draw();
    let mut y = 90.0;
    let mut keys = false;
    while y < SIZE.1 as f32 {
        click(x, y);
        keys |= manual.get_keys_open();
        assert!(!manual.get_commands_open(), "a reference opened at y {y}");
        y += 6.0;
    }
    assert!(keys, "the keys did not open on Windows' page");
}
