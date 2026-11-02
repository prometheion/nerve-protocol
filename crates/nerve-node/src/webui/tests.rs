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
fn a_peer_waits_with_four_connections_at_most() {
    let ui = Arc::new(WebUi::default());
    let owner = Waiter::Uid(1000);
    let held: Vec<Waiting> = (0..WAITING_PER_PEER)
        .map(|_| ui.wait_for(owner).unwrap())
        .collect();
    assert!(ui.wait_for(owner).is_none());
    // Another account, or another machine, has its own places.
    assert!(ui.wait_for(Waiter::Uid(0)).is_some());
    let far = Waiter::Address([192, 0, 2, 1].into());
    let far_held: Vec<Waiting> = (0..WAITING_PER_PEER)
        .map(|_| ui.wait_for(far).unwrap())
        .collect();
    assert!(ui.wait_for(far).is_none());
    drop(held);
    drop(far_held);
    assert!(ui.wait_for(owner).is_some());
    assert!(lock(&ui.waiting).is_empty());
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
