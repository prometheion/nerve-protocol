use super::*;

fn cfg_with(tokens: &[(&str, &str)], locked: bool) -> NodeConfig {
    let mut c = NodeConfig {
        locked,
        ..NodeConfig::default()
    };
    c.ui.tokens = tokens
        .iter()
        .map(|(label, hash)| nerve_policy::config::UiToken {
            label: label.to_string(),
            token_sha256: hash.to_string(),
            made: String::new(),
        })
        .collect();
    c
}

#[test]
fn a_session_ends_with_its_token_and_every_one_with_a_panic() {
    let (a, b) = ("a".repeat(64), "b".repeat(64));
    let ui = WebUi::default();
    let sa = ui.sessions.start(Some(a.clone()));
    ui.sessions.start(Some(b.clone()));
    ui.settle(&cfg_with(&[("one", &a), ("two", &b)], false));
    assert_eq!(ui.sessions.len(), 2);
    // `two` revoked: only its session ends.
    ui.settle(&cfg_with(&[("one", &a)], false));
    assert_eq!(ui.sessions.len(), 1);
    ui.sessions.start(Some(a.clone()));
    // Locked: every session ends, and a new one after it lives on while the
    // node stays locked.
    ui.settle(&cfg_with(&[("one", &a)], true));
    assert!(ui.sessions.is_empty());
    let after = ui.sessions.start(Some(a.clone()));
    ui.settle(&cfg_with(&[("one", &a)], true));
    assert_eq!(ui.sessions.len(), 1);
    ui.sessions.end(&after);
    let _ = sa;
    // A session without a token is none.
    ui.sessions.start(None);
    ui.settle(&cfg_with(&[("one", &a)], false));
    assert!(ui.sessions.is_empty());
}

#[test]
fn a_copy_of_the_config_older_than_the_last_look_is_passed_over() {
    let a = "a".repeat(64);
    let ui = WebUi::default();
    let at = |version: u64, locked: bool| NodeConfig {
        version,
        ..cfg_with(&[("one", &a)], locked)
    };
    ui.settle(&at(4, false));
    // A panic, then the unlock after it.
    ui.settle(&at(5, true));
    assert_eq!(ui.lock_count(), 1);
    ui.settle(&at(6, false));
    let s = ui.sessions.start(Some(a.clone()));
    // The panic's copy, read before the unlock and looked at only now: it
    // must neither end the session nor count a lock the node does not hold.
    ui.settle(&at(5, true));
    assert_eq!(ui.lock_count(), 1);
    assert_eq!(ui.sessions.len(), 1);
    // The next panic still ends it.
    ui.settle(&at(7, true));
    assert_eq!(ui.lock_count(), 2);
    assert!(ui.sessions.is_empty());
    let _ = s;
}

#[test]
fn a_panic_of_a_locked_node_still_ends_the_sessions_and_counts() {
    let a = "a".repeat(64);
    let ui = WebUi::default();
    let at = |version: u64| NodeConfig {
        version,
        ..cfg_with(&[("one", &a)], true)
    };
    ui.settle(&at(5));
    assert_eq!(ui.lock_count(), 1);
    // A session started in the lock, then the owner's next panic, which does
    // not change the config (same version).
    ui.sessions.start(Some(a.clone()));
    ui.settle_panic(&at(5));
    assert!(ui.sessions.is_empty());
    assert_eq!(ui.lock_count(), 2);
    // A panic that locks counts once, not twice.
    let ui = WebUi::default();
    ui.settle_panic(&at(1));
    assert_eq!(ui.lock_count(), 1);
}

#[test]
fn wrong_tokens_are_told_once_a_minute() {
    let ui = WebUi::default();
    assert_eq!(ui.wrong_token(), Some(1));
    for _ in 0..50 {
        assert_eq!(ui.wrong_token(), None);
    }
    // A minute later the count of what came meanwhile is told.
    lock(&ui.wrong).1 = Instant::now().checked_sub(Duration::from_secs(61));
    assert_eq!(ui.wrong_token(), Some(51));
}

#[test]
fn a_peer_has_sixteen_connections_at_most() {
    let ui = Arc::new(WebUi::default());
    let owner = Who::Uid(1000);
    let held: Vec<Place> = (0..PER_PEER)
        .map(|_| ui.place_for(owner).unwrap())
        .collect();
    assert!(ui.place_for(owner).is_none());
    // Another account, or another machine, has its own places.
    assert!(ui.place_for(Who::Uid(0)).is_some());
    let far = Who::remote([192, 0, 2, 1].into());
    let far_held: Vec<Place> = (0..PER_PEER).map(|_| ui.place_for(far).unwrap()).collect();
    assert!(ui.place_for(far).is_none());
    // An IPv4 address that IPv6 carries is that address; the addresses of
    // one IPv6 /64 are one machine.
    let ip = |s: &str| s.parse::<std::net::IpAddr>().unwrap();
    assert_eq!(Who::remote(ip("::ffff:192.0.2.1")), far);
    assert_eq!(
        Who::remote(ip("2001:db8:1:2::1")),
        Who::remote(ip("2001:db8:1:2::ffff"))
    );
    assert_ne!(
        Who::remote(ip("2001:db8:1:2::1")),
        Who::remote(ip("2001:db8:1:3::1"))
    );
    drop(held);
    drop(far_held);
    assert!(ui.place_for(owner).is_some());
    assert!(lock(&ui.places).is_empty());
}

/// A wrong token's answer waits; past [`LATE`] waiting, the one that waited
/// longest goes at once, so the waits hold a bounded number of connections.
#[tokio::test]
async fn a_wrong_token_waits_and_past_the_limit_the_oldest_goes_first() {
    let ui = Arc::new(WebUi::default());
    let start = Instant::now();
    ui.wait_late().await;
    assert!(start.elapsed() >= webui::WRONG_SECRET_DELAY);
    assert!(lock(&ui.late).is_empty());
    let waits: Vec<_> = (0..LATE)
        .map(|_| {
            let ui = ui.clone();
            tokio::spawn(async move { ui.wait_late().await })
        })
        .collect();
    while lock(&ui.late).len() < LATE {
        tokio::task::yield_now().await;
    }
    let extra = {
        let ui = ui.clone();
        tokio::spawn(async move { ui.wait_late().await })
    };
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(waits[0].is_finished(), "the oldest still waits");
    assert_eq!(waits.iter().filter(|w| w.is_finished()).count(), 1);
    assert_eq!(lock(&ui.late).len(), LATE);
    for w in waits {
        w.await.unwrap();
    }
    extra.await.unwrap();
    assert!(lock(&ui.late).is_empty());
}

#[test]
fn the_label_is_found_by_the_whole_hash() {
    let a = "a".repeat(64);
    let cfg = cfg_with(&[("one", &a)], false);
    assert_eq!(token_label(&cfg, &a), Some("one"));
    assert_eq!(token_label(&cfg, &a[..63]), None);
    assert_eq!(token_label(&cfg, ""), None);
}

#[test]
fn a_value_that_reads_as_an_option_is_refused() {
    assert_eq!(text(&json!({"label": "x"}), "label"), Ok("x"));
    for bad in [
        json!({"label": "-x"}),
        json!({"label": ""}),
        json!({}),
        json!({"label": 3}),
    ] {
        assert_eq!(text(&bad, "label").unwrap_err().0, 400, "{bad}");
    }
}

#[test]
fn a_command_says_its_data_or_its_error() {
    use crate::owner::Ran;
    let ran = |code, out: &str, err: &str| Ran {
        code,
        out: out.into(),
        err: err.into(),
    };
    assert_eq!(
        answer(ran(0, "{\"messages\":[\"node locked\"]}\n", "")).unwrap()["messages"][0],
        "node locked"
    );
    assert_eq!(
        answer(ran(
            1,
            "{\"error\":\"no web UI token is labelled x\"}\n",
            ""
        ))
        .unwrap_err(),
        (400, "no web UI token is labelled x".to_string())
    );
    assert_eq!(
        answer(ran(1, "", "nerve-node: broken\n")).unwrap_err().1,
        "nerve-node: broken"
    );
    assert!(
        answer(ran(2, "", ""))
            .unwrap_err()
            .1
            .contains("exit code 2")
    );
}

/// No script of the page builds HTML from text: what a center or the node
/// wrote goes into text nodes only. The page has no inline script.
#[test]
fn the_page_builds_no_html_from_text() {
    assert_eq!(webui::html_sinks(APP_JS), Vec::<&str>::new());
    for line in INDEX.lines().filter(|l| l.contains("<script")) {
        assert!(line.contains(" src=\""), "an inline script: {line}");
    }
    let handler = INDEX
        .split_whitespace()
        .find(|w| w.starts_with("on") && w.contains('='));
    assert_eq!(handler, None, "an inline handler");
}

#[test]
fn a_loopback_ui_answers_to_its_own_address_and_loopback_names_only() {
    let at = |s: &str| s.parse::<SocketAddr>().unwrap();
    let other = at("127.0.0.2:7470");
    for h in ["127.0.0.2:7470", "localhost:7470", "127.0.0.1:7470"] {
        assert!(host_allowed(Some(h), other, false), "{h}");
    }
    assert!(!host_allowed(Some("evil.example:7470"), other, false));
    assert!(!host_allowed(Some("127.0.0.3:7470"), other, false));
    assert!(!host_allowed(None, other, false));
    // Beyond loopback any name, the owner's own among them.
    assert!(host_allowed(
        Some("node.lan:7470"),
        at("192.0.2.7:7470"),
        true
    ));
    // Over TLS also at a loopback address of this machine: its own name
    // resolves to 127.0.1.1 on many systems.
    assert!(host_allowed(
        Some("box.lan:7470"),
        at("127.0.1.1:7470"),
        true
    ));
}

/// The page's script parses: a bracket missing anywhere stops every page
/// of the web UI. Checked with Node.js where it is installed, else skipped.
#[test]
fn the_pages_script_parses() {
    let Ok(dir) = tempfile::tempdir() else {
        return;
    };
    let file = dir.path().join("app.js");
    std::fs::write(&file, APP_JS).unwrap();
    match std::process::Command::new("node")
        .arg("--check")
        .arg(&file)
        .output()
    {
        Ok(o) => assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr)),
        Err(_) => eprintln!("skipped: no node here"),
    }
}
