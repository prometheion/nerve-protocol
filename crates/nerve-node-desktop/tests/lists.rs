//! A long list scrolls in a box of its own: past some eight rows more rules
//! or folders leave the page as long as it was, and the list scrolls inside
//! it. One test: Slint takes one platform per process.

use nerve_node_desktop::headless::Screen;
use nerve_node_desktop::{AppWindow, FolderRow, Load, Page, Perm, Store};
use slint::platform::WindowEvent;
use slint::{
    ComponentHandle, LogicalPosition, ModelRc, Rgba8Pixel, SharedPixelBuffer, SharedString,
    VecModel,
};

/// A window as tall as no page here gets, so the page itself never scrolls.
const SIZE: (u32, u32) = (1180, 4000);

/// The window once nothing moves in it any more.
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

/// The last row of pixels of the page's content: below it, the window's
/// background only (taken at the window's foot), right of the sidebar.
fn content_end(shot: &SharedPixelBuffer<Rgba8Pixel>) -> usize {
    let w = shot.width() as usize;
    let px = shot.as_slice();
    let background = px[px.len() - 1];
    (0..shot.height() as usize)
        .rev()
        .find(|y| {
            px[y * w + 260..y * w + w - 20]
                .iter()
                .any(|p| *p != background)
        })
        .unwrap()
}

#[test]
fn long_lists_scroll_in_their_own_box() {
    let screen = Screen::install(SIZE.0, SIZE.1, 1.0).unwrap();
    let window = AppWindow::new().unwrap();
    window.show().unwrap();
    let store = window.global::<Store>();
    let perm = window.global::<Perm>();
    store.set_page(Page::Policy);
    perm.set_centers(ModelRc::new(VecModel::from(vec![SharedString::from(
        "home",
    )])));
    perm.set_center("home".into());
    perm.set_mode("allowlist".into());
    // The page shows once it read its center.
    perm.set_read(true);
    perm.set_load(Load::Ready);
    let rules = |n: usize| {
        let all: Vec<SharedString> = (0..n)
            .map(|i| format!("exec.run:make target-{i}").into())
            .collect();
        ModelRc::new(VecModel::from(all))
    };
    let folders = |n: usize| {
        let all: Vec<FolderRow> = (0..n)
            .map(|i| FolderRow {
                path: format!("/srv/project-{i}").into(),
                read: true,
                write: false,
                execute: false,
            })
            .collect();
        ModelRc::new(VecModel::from(all))
    };
    let end = |r: usize, f: usize| {
        perm.set_allow(rules(r));
        perm.set_folders(folders(f));
        content_end(&settled(&screen))
    };
    // Short lists grow the page, row by row.
    let short = end(2, 2);
    assert!(end(5, 2) > short, "three more rules took no room");
    assert!(end(2, 5) > short, "three more folders took no room");
    // Past their box, they do not.
    let long = end(12, 12);
    assert_eq!(end(60, 12), long, "more rules made the page longer");
    assert_eq!(end(12, 60), long, "more folders made the page longer");
    assert!(long < 2600, "the page is {long} pixels long");

    // A turn of the wheel over a long list scrolls it, and the page stays.
    perm.set_allow(rules(60));
    let before = settled(&screen);
    let mut moved = false;
    for y in (120..long as i32).step_by(40) {
        window
            .window()
            .dispatch_event(WindowEvent::PointerScrolled {
                position: LogicalPosition::new(700.0, y as f32),
                delta_x: 0.0,
                delta_y: -120.0,
            });
        let now = settled(&screen);
        if now.as_slice() != before.as_slice() {
            moved = true;
            assert_eq!(content_end(&now), long, "the page moved");
            break;
        }
    }
    assert!(moved, "no list scrolled");
}
