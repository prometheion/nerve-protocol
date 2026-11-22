//! The widths of a page's panes the owner dragged are kept per page in the
//! app's settings, come back when the page opens again, and a reset forgets
//! them (#213). One test: Slint takes one platform per process.

use nerve::app::{Ctl, Exec};
use nerve::headless::Screen;
use nerve::runner::Runner;
use nerve::{AppWindow, Page, Panes, Store};
use slint::ComponentHandle;

#[test]
fn the_dragged_widths_are_kept_per_page() {
    let screen = Screen::install(1600, 900, 1.0).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let runner = Runner::new(
        env!("CARGO_BIN_EXE_nerve").into(),
        Some(dir.path().join("config")),
        Some(dir.path().join("state")),
    );
    let window = AppWindow::new().unwrap();
    let ctl = Ctl::attach(&window, runner, Exec::Inline);
    let file = dir.path().join("app/settings.json");
    ctl.keep_settings(file.clone());
    window.show().unwrap();
    let store = window.global::<Store>();
    let panes = window.global::<Panes>();
    store.set_page(Page::Capabilities);
    screen.draw();
    assert_eq!(panes.get_list_share(), -1.0, "a share before any drag");
    // What a drag leaves, kept under the page.
    panes.set_list_share(0.5);
    panes.set_side_share(0.2);
    panes.invoke_save();
    assert_eq!(
        nerve::settings::pane_shares(&file, "node-capabilities"),
        (Some(0.5), Some(0.2))
    );
    // Another page has its own, the defaults here.
    store.set_page(Page::Audit);
    screen.draw();
    assert_eq!(
        panes.get_list_share(),
        -1.0,
        "the Audit page took another's"
    );
    // Back on the page, its shares come back.
    store.set_page(Page::Capabilities);
    screen.draw();
    assert_eq!(panes.get_list_share(), 0.5);
    assert_eq!(panes.get_side_share(), 0.2);
    // A reset forgets them.
    panes.invoke_reset();
    assert_eq!(
        nerve::settings::pane_shares(&file, "node-capabilities"),
        (None, None)
    );
}
