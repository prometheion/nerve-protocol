//! A filled button that is off looks off: Pair under "Pairing cannot work"
//! has no accent fill, in light and dark. One test: Slint takes one
//! platform per process.

use std::time::Duration;

use nerve::app::{Ctl, Exec};
use nerve::headless::Screen;
use nerve::runner::Runner;
use nerve::{AppWindow, PairPreview, Store};
use slint::ComponentHandle;

const SIZE: (u32, u32) = (1180, 700);

#[test]
fn a_primary_button_that_is_off_has_no_accent_fill() {
    let screen = Screen::install(SIZE.0, SIZE.1, 1.0).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let runner = Runner::new(
        env!("CARGO_BIN_EXE_nerve").into(),
        Some(dir.path().join("config")),
        Some(dir.path().join("state")),
    );
    let window = AppWindow::new().unwrap();
    // The app's own look, light or dark, as the owner picks it.
    let _ctl = Ctl::attach(&window, runner, Exec::Inline);
    window.show().unwrap();
    let store = window.global::<Store>();
    store.set_pair_open(true);
    store.set_pair_step(1);
    let preview = |ready: bool| PairPreview {
        center: "https://center.example:7443".into(),
        tls: true,
        pin: "sha256:AAAA".into(),
        name: "lab".into(),
        ready,
        check: if ready {
            "The center answers and the code is open.".into()
        } else {
            "The code was used already.".into()
        },
    };
    // The pixels in the accent colour, once the button's colour has moved
    // to its new state.
    let accent = |rgb: (u8, u8, u8)| {
        std::thread::sleep(Duration::from_millis(300));
        screen.draw();
        screen
            .draw()
            .as_slice()
            .iter()
            .filter(|p| (p.r, p.g, p.b) == rgb)
            .count()
    };
    for (scheme, rgb) in [(1, (0x46, 0x55, 0xd4)), (2, (0x8b, 0x96, 0xff))] {
        store.invoke_set_appearance(scheme);
        store.set_pair_preview(preview(true));
        let on = accent(rgb);
        store.set_pair_preview(preview(false));
        let off = accent(rgb);
        // The Pair button is about 90 by 36 pixels.
        assert!(
            off + 2000 < on,
            "scheme {scheme}: {off} accent pixels with Pair off, {on} with it on"
        );
    }
}
