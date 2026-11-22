//! The center role's pages fit the window at every 100 px from 900 to 2200
//! (#213), each with its list and its details:
//! nothing runs into the page's right margin, however long a name, a path
//! or a rule is. The sidebar names the center's pages.

mod hub_sample;

use nerve::app::{Ctl, Exec};
use nerve::headless::Screen;
use nerve::runner::Runner;
use nerve::{AppWindow, Hub, HubPage};
use slint::{ComponentHandle, Rgba8Pixel, SharedPixelBuffer};

/// Every 100 px from the least window, 900 px, to 2200 px, so that no width
/// between the points where a column folds breaks a page (#213).
fn sizes() -> impl Iterator<Item = (u32, u32)> {
    (900..=2200)
        .step_by(100)
        .map(|w| (w, if w == 900 { 580 } else { 800 }))
}

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

/// The first row of `shot` with anything but the page's background in its
/// right margin, left of the scroll bar.
fn overrun(shot: &SharedPixelBuffer<Rgba8Pixel>, width: u32) -> Option<usize> {
    let margin = if width >= 1100 { 32 } else { 24 };
    let (from, to) = (width as usize - margin + 2, width as usize - 18);
    let w = shot.width() as usize;
    let px = shot.as_slice();
    let background = px[(shot.height() as usize - 1) * w + from];
    (0..shot.height() as usize).find(|y| {
        px[y * w + from..y * w + to]
            .iter()
            .any(|p| *p != background)
    })
}

#[test]
fn every_center_page_fits_the_window() {
    let screen = Screen::install(1440, 900, 1.0).unwrap();
    let window = AppWindow::new().unwrap();
    window.show().unwrap();
    let dir = tempfile::tempdir().unwrap();
    let ctl = Ctl::attach(
        &window,
        Runner::new(env!("CARGO_BIN_EXE_nerve").into(), None, None),
        Exec::Inline,
    );
    ctl.center_role(dir.path().join("owner.sock"));
    let hub = window.global::<Hub>();
    // The sidebar says what the machine is.
    assert!(hub.get_shown());
    // The log-in, before anything else.
    for (width, height) in sizes() {
        screen.resize(width, height);
        let shot = settled(&screen);
        assert_eq!(
            overrun(&shot, width),
            None,
            "the log-in at {width}x{height} runs into the margin"
        );
    }
    hub_sample::fill(&window, true);
    let pages = [
        HubPage::Overview,
        HubPage::Nodes,
        HubPage::Harnesses,
        HubPage::Checker,
        HubPage::Caps,
        HubPage::Stats,
        HubPage::Audit,
        HubPage::Log,
        HubPage::Settings,
        HubPage::Help,
    ];
    for (width, height) in sizes() {
        screen.resize(width, height);
        for page in pages {
            hub.set_page(page);
            // Each group of a page with groups, each section of Settings.
            let views: &[i32] = match page {
                HubPage::Checker => &[0, 1, 2, 3],
                HubPage::Harnesses => &[0, 1],
                HubPage::Settings => &[0, 1, 2, 3, 4],
                HubPage::Help => &[0, 1, 2],
                _ => &[0],
            };
            for &view in views {
                match page {
                    HubPage::Checker => {
                        hub.set_chk_view(view);
                        hub.set_chk_pick(0);
                    }
                    HubPage::Harnesses => {
                        hub.set_harn_view(view);
                        hub.set_harn_pick(if view == 0 { -1 } else { 0 });
                    }
                    HubPage::Settings => hub.set_set_pick(view),
                    HubPage::Help => hub.set_help_pick(view),
                    _ => {}
                }
                for open in [false, true] {
                    hub.set_details_open(open);
                    let shot = settled(&screen);
                    assert_eq!(
                        overrun(&shot, width),
                        None,
                        "{page:?} ({view}) at {width}x{height} (details open: {open}) runs into the margin"
                    );
                }
            }
        }
        // The rule form in the details pane.
        hub.set_page(HubPage::Checker);
        hub.set_chk_view(0);
        hub.set_chk_pick(-1);
        hub.set_rule_all(false);
        hub.set_details_open(true);
        let shot = settled(&screen);
        assert_eq!(
            overrun(&shot, width),
            None,
            "the rule form at {width}x{height} runs into the margin"
        );
        hub.set_rule_all(true);
    }
}
