//! The animations frame by frame, light and dark, for judging how they feel:
//! a page change, a dialog that opens and closes, a toast that comes and
//! goes, a section that opens and closes, and a step of the installer. Each
//! scene is a series of frames 1/60 s apart, drawn with the clock stopped by
//! Slint's software renderer, which draws no shadows; it also says how long
//! the software renderer took for a frame of the page change, the fallback's
//! cost.
//!
//! `NERVE_DESKTOP_FRAMES=<folder> cargo test -p nerve-node-desktop --test frames -- --ignored`

use std::path::Path;
use std::time::{Duration, Instant};

use nerve_node_desktop::app::{Ctl, Exec};
use nerve_node_desktop::headless::Screen;
use nerve_node_desktop::runner::Runner;
use nerve_node_desktop::{AppWindow, Install, Load, Manual, Motion, Page, Store, Tone};
use slint::{ComponentHandle, Rgba8Pixel, SharedPixelBuffer};

const SIZE: (u32, u32) = (1180, 700);
/// One frame of a screen of 60 Hz.
const FRAME: Duration = Duration::from_micros(16_667);
/// Frames of each scene: the change and some rest after it.
const FRAMES: usize = 24;

fn save(pixels: &SharedPixelBuffer<Rgba8Pixel>, path: &Path) {
    let file = std::fs::File::create(path).unwrap();
    let mut png = png::Encoder::new(file, pixels.width(), pixels.height());
    png.set_color(png::ColorType::Rgba);
    png.set_depth(png::BitDepth::Eight);
    let mut w = png.write_header().unwrap();
    w.write_image_data(pixels.as_bytes()).unwrap();
}

/// The task map's groups of Help, the first open or none.
fn first_group(open: bool) -> slint::ModelRc<bool> {
    slint::ModelRc::new(slint::VecModel::from(vec![open, false, false, false]))
}

#[test]
#[ignore = "writes frames for a person to look at; NERVE_DESKTOP_FRAMES=<folder>"]
fn every_animation_frame_by_frame() {
    let out = std::path::PathBuf::from(
        std::env::var_os("NERVE_DESKTOP_FRAMES").expect("NERVE_DESKTOP_FRAMES=<folder>"),
    );
    std::fs::create_dir_all(&out).unwrap();
    let screen = Screen::install(SIZE.0, SIZE.1, 1.0).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let runner = Runner::new(
        env!("CARGO_BIN_EXE_nerve-node-desktop").into(),
        Some(dir.path().join("config")),
        Some(dir.path().join("state")),
    );
    let window = AppWindow::new().unwrap();
    let _ctl = Ctl::attach(&window, runner, Exec::Inline);
    window.show().unwrap();
    let store = window.global::<Store>();
    let manual = window.global::<Manual>();
    let install = window.global::<Install>();
    store.set_status_load(Load::Failed);
    window.global::<Motion>().set_on(true);
    screen.stop_clock();
    let rest = || {
        screen.advance(Duration::from_secs(1));
        screen.draw();
    };
    // Draws the window before `change`, as `<name>-<scheme>-before.png`,
    // and the frames after it, as `<name>-<scheme>-<n>.png`; says how long
    // each of those took.
    let scene = |name: &str, scheme: &str, change: &dyn Fn()| -> Vec<Duration> {
        rest();
        save(
            &screen.draw(),
            &out.join(format!("{name}-{scheme}-before.png")),
        );
        let mut took = Vec::new();
        change();
        for n in 0..FRAMES {
            if n > 0 {
                screen.advance(FRAME);
            }
            let start = Instant::now();
            let pixels = screen.draw();
            took.push(start.elapsed());
            save(&pixels, &out.join(format!("{name}-{scheme}-{n:02}.png")));
        }
        took
    };
    for (dark, scheme) in [(false, "light"), (true, "dark")] {
        window.invoke_set_dark(dark);
        store.set_page(Page::Overview);
        let took = scene("page", scheme, &|| store.set_page(Page::Help));
        let most = took.iter().max().unwrap();
        let all: Duration = took.iter().sum();
        eprintln!(
            "{scheme}: a frame of the page change took {:?} on average, {most:?} at most",
            all / took.len() as u32
        );
        scene("dialog-open", scheme, &|| store.set_about_open(true));
        scene("dialog-close", scheme, &|| store.set_about_open(false));
        store.set_toast("Paired with office-workstation".into());
        store.set_toast_tone(Tone::Ok);
        scene("toast-in", scheme, &|| store.set_toast_shown(true));
        scene("toast-out", scheme, &|| store.set_toast_shown(false));
        store.set_page(Page::Help);
        scene("section-open", scheme, &|| {
            manual.set_tasks_open(first_group(true))
        });
        scene("section-close", scheme, &|| {
            manual.set_tasks_open(first_group(false))
        });
        install.set_shown(true);
        install.set_step("welcome".into());
        scene("installer-step", scheme, &|| {
            install.set_step("working".into())
        });
        install.set_shown(false);
    }
    eprintln!("wrote the frames to {}", out.display());
}
