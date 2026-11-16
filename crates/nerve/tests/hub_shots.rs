//! Screenshots of every page of the center role, light and dark, drawn
//! without a screen by Slint's software renderer, for comparing them with
//! the approved mockup (proposal B of #232): made-up data, as the mockup
//! has it (tests/hub_sample).
//!
//! `NERVE_DESKTOP_SHOTS_SIZE=WxH` sets the window's size (logical pixels).
//!
//! `NERVE_DESKTOP_SHOTS=<folder> cargo test -p nerve --test hub_shots -- --ignored`

mod hub_sample;

use std::path::PathBuf;

use nerve::app::{Ctl, Exec};
use nerve::headless::Screen;
use nerve::runner::Runner;
use nerve::{AppWindow, Hub, HubPage, Store};
use slint::ComponentHandle;

const SCALE: f32 = 2.0;

fn window_size() -> (u32, u32) {
    std::env::var("NERVE_DESKTOP_SHOTS_SIZE")
        .ok()
        .and_then(|v| {
            let (w, h) = v.split_once('x')?;
            Some((w.parse().ok()?, h.parse().ok()?))
        })
        .unwrap_or((1440, 900))
}

#[test]
#[ignore = "writes screenshots; NERVE_DESKTOP_SHOTS names the folder"]
fn every_center_page_light_and_dark() {
    let Some(out) = std::env::var_os("NERVE_DESKTOP_SHOTS").map(PathBuf::from) else {
        eprintln!("NERVE_DESKTOP_SHOTS is not set");
        return;
    };
    std::fs::create_dir_all(&out).unwrap();
    let (w, h) = window_size();
    let screen =
        Screen::install((w as f32 * SCALE) as u32, (h as f32 * SCALE) as u32, SCALE).unwrap();
    let window = AppWindow::new().unwrap();
    window.show().unwrap();
    let dir = tempfile::tempdir().unwrap();
    let ctl = Ctl::attach(
        &window,
        Runner::new(env!("CARGO_BIN_EXE_nerve").into(), None, None),
        Exec::Inline,
    );
    ctl.center_role(dir.path().to_path_buf());
    let hub = window.global::<Hub>();
    let take = |name: &str| {
        window.global::<Store>().set_toast_shown(false);
        for (dark, scheme) in [(false, "light"), (true, "dark")] {
            window.invoke_set_dark(dark);
            let pixels = screen.draw();
            let path = out.join(format!("{name}-{scheme}.png"));
            let file = std::fs::File::create(&path).unwrap();
            let mut png = png::Encoder::new(file, pixels.width(), pixels.height());
            png.set_color(png::ColorType::Rgba);
            png.set_depth(png::BitDepth::Eight);
            png.write_header()
                .unwrap()
                .write_image_data(pixels.as_bytes())
                .unwrap();
            eprintln!("wrote {}", path.display());
        }
    };
    let details = |name: &str| {
        hub.set_details_open(true);
        take(&format!("{name}-details"));
        hub.set_details_open(false);
    };

    // The log-in: the center is not running, then found and checked.
    take("c-login-not-running");
    hub.set_not_running(false);
    hub.set_state("running".into());
    hub.set_state_tone(nerve::Tone::Ok);
    hub.set_state_line("2 of 4 nodes online".into());
    hub.set_login_checked(true);
    hub.set_login_check("This is the center's service on 127.0.0.1:7480.".into());
    take("c-login");
    hub.set_login_error(nerve::hub::WRONG_TOKEN.into());
    take("c-login-wrong");
    hub.set_login_error("".into());

    hub_sample::fill(&window, false);
    let show = |page: HubPage| {
        hub.invoke_show(page);
    };
    show(HubPage::Overview);
    take("c-overview");
    details("c-overview");
    show(HubPage::Nodes);
    take("nodes");
    details("nodes");
    hub.invoke_pair_start();
    hub_sample::fill(&window, false);
    take("nodes-pair");
    hub.set_pair_open(false);
    hub.set_node_pick(3);
    take("nodes-disabled");
    hub.set_node_pick(0);

    show(HubPage::Harnesses);
    take("harnesses");
    hub.set_token_shown(true);
    take("harnesses-shown");
    hub.set_token_shown(false);
    details("harnesses");
    hub.set_harn_view(1);
    hub.set_harn_pick(0);
    take("harnesses-sessions");
    hub.set_harn_view(0);
    take("harnesses-token");
    hub.set_harn_pick(-1);

    show(HubPage::Checker);
    hub.set_chk_view(0);
    hub.set_chk_pick(0);
    take("checker");
    details("checker");
    hub.set_chk_pick(-1);
    hub.set_rule_text("exec.run:shutdown *".into());
    hub.set_rule_note("Turns the machine off".into());
    take("checker-add-rule");
    hub.set_rule_all(false);
    take("checker-add-rule-chosen");
    hub.set_rule_all(true);
    hub.set_chk_view(1);
    hub.set_chk_pick(0);
    take("checker-skip");
    hub.set_chk_view(2);
    take("checker-model");
    hub.set_chk_view(3);
    hub.set_chk_pick(1);
    take("checker-per-machine");
    hub.set_chk_view(0);
    hub.set_chk_pick(0);

    show(HubPage::Caps);
    take("c-caps");
    details("c-caps");
    hub.set_cap_form(true);
    hub.set_cap_name("logs.pack".into());
    hub.set_cap_command("tar czf backups/logs.tgz /var/log/site".into());
    take("c-caps-add");
    hub.set_cap_form(false);

    show(HubPage::Stats);
    hub_sample::fill(&window, false);
    take("stats");
    details("stats");
    show(HubPage::Audit);
    take("c-audit");
    details("c-audit");
    hub.set_audit_pick(3);
    take("c-audit-checker");
    hub.set_audit_pick(0);
    show(HubPage::Log);
    take("c-log");
    details("c-log");

    for (i, name) in ["center", "machine", "owner", "key", "backup"]
        .iter()
        .enumerate()
    {
        show(HubPage::Settings);
        hub_sample::fill(&window, false);
        hub.set_set_pick(i as i32);
        take(&format!("csettings-{name}"));
    }
    hub.set_set_pick(0);
    details("csettings");
    hub.set_uninstall_open(true);
    take("csettings-uninstall");
    hub.set_uninstall_open(false);
    hub.set_backup_file("/home/alex/nerve-center.backup".into());
    hub.set_backup_open(true);
    take("csettings-backup-dialog");
    hub.set_backup_open(false);

    show(HubPage::Help);
    take("c-help");
    for i in [1, 2] {
        hub.set_help_pick(i);
        take(&format!("c-help-{i}"));
    }
    hub.set_help_pick(0);
    window.global::<Store>().set_about_open(true);
    take("c-about");
    window.global::<Store>().set_about_open(false);

    // Long names, paths and rules.
    hub_sample::fill(&window, true);
    for (page, name) in [
        (HubPage::Overview, "c-overview-long"),
        (HubPage::Checker, "checker-long"),
        (HubPage::Audit, "c-audit-long"),
        (HubPage::Log, "c-log-long"),
    ] {
        show(page);
        hub_sample::fill(&window, true);
        take(name);
    }
    ctl.end();
}
