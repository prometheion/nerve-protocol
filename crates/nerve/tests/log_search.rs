//! The log's search finds words only in the lines the page read, so the
//! footer that reads further back stays while the search narrows the list,
//! also when no line is left. One test: Slint takes one platform per
//! process.

use nerve::headless::Screen;
use nerve::{AppWindow, Load, LogRow, Logs, Page, Store};
use slint::{ComponentHandle, ModelRc, Rgba8Pixel, SharedPixelBuffer, VecModel};

const SIZE: (u32, u32) = (1440, 1600);

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
fn a_search_can_read_further_back() {
    let screen = Screen::install(SIZE.0, SIZE.1, 1.0).unwrap();
    let window = AppWindow::new().unwrap();
    window.show().unwrap();
    window.global::<Store>().set_page(Page::Log);
    let logs = window.global::<Logs>();
    logs.set_load(Load::Ready);
    logs.set_limit(300);
    logs.set_search("words".into());
    let line = |msg: &str| LogRow {
        level: "Info".into(),
        msg: msg.into(),
        when: "2 min ago".into(),
        when_exact: "2026-11-14 18:02:05 UTC".into(),
        ..Default::default()
    };
    let end = |rows: Vec<LogRow>, read: i32| {
        logs.set_rows(ModelRc::new(VecModel::from(rows)));
        logs.set_read(read);
        content_end(&settled(&screen))
    };
    // No line matches: the empty state offers more when the page read as
    // many lines as it asked for, and not when the log has no more.
    let whole = end(vec![], 40);
    let cut = end(vec![], 300);
    assert!(cut > whole, "no way to read further back: {whole} {cut}");
    // Some lines match, fewer than were read: the same.
    let rows = || vec![line("a"), line("b"), line("c")];
    let whole = end(rows(), 40);
    let cut = end(rows(), 300);
    assert!(cut > whole, "no way to read further back: {whole} {cut}");
    // Without a search the footer shows as it did, by the lines read.
    logs.set_search("".into());
    let all = end(rows(), 300);
    assert_eq!(all, cut, "the footer changed with the search's words");
}
