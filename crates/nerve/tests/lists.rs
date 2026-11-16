//! A long list grows with its rows (#231): one scroll per page, no list in
//! a box of its own, so more rules or folders make the page longer, each
//! row as tall as the others. One test: Slint takes one platform per
//! process.

use nerve::headless::Screen;
use nerve::{AppWindow, FolderRow, Load, Page, Perm, Store};
use slint::{ComponentHandle, ModelRc, Rgba8Pixel, SharedPixelBuffer, SharedString, VecModel};

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
fn long_lists_grow_the_page() {
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
    perm.set_allow_unfit(ModelRc::new(VecModel::from(vec![SharedString::new(); 60])));
    let end = |section: i32, r: usize, f: usize| {
        perm.set_section(section);
        perm.set_allow(rules(r));
        perm.set_folders(folders(f));
        content_end(&settled(&screen))
    };
    // Each list grows the page row by row, past any eight rows too.
    for (section, what) in [(0, "folders"), (2, "rules")] {
        let at = |n: usize| {
            if section == 0 {
                end(section, 2, n)
            } else {
                end(section, n, 2)
            }
        };
        let (two, twelve, sixty) = (at(2), at(12), at(60));
        assert!(twelve > two, "ten more {what} took no room");
        let row = at(13) - twelve;
        assert!(row > 30, "a row of {what} is {row} pixels");
        assert_eq!(
            sixty,
            twelve + 48 * row,
            "{what} past twelve grow the page by another {} pixels",
            sixty - twelve
        );
    }
}
