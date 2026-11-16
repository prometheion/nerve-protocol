//! Made-up data for the center role's pages, as the mockup of #232 draws
//! them, for the screenshots and the fit checks; `long` gives every name,
//! path and rule a long value.

use nerve::{
    AppWindow, Hub, HubAudit, HubCall, HubCap, HubCount, HubFigure, HubLog, HubMachine, HubNode,
    HubRef, HubRule, HubSession, HubStatRow, HubToken, HubWhere, Tone,
};
use slint::{ComponentHandle, ModelRc, SharedString, VecModel};

fn model<T: Clone + 'static>(items: Vec<T>) -> ModelRc<T> {
    ModelRc::new(VecModel::from(items))
}

fn strings(items: &[&str]) -> ModelRc<SharedString> {
    model(items.iter().map(|s| SharedString::from(*s)).collect())
}

/// Fills the center's pages, logged in.
pub fn fill(window: &AppWindow, long: bool) {
    let h = window.global::<Hub>();
    let name = |short: &str| -> SharedString {
        if long {
            format!("{short}-second-floor-workstation-of-platform-engineering").into()
        } else {
            short.into()
        }
    };
    let node = |n: &str, platform: &str, state: &str, tone: Tone, link: &str| HubNode {
        id: format!("id-{n}").into(),
        name: name(n),
        platform: platform.into(),
        state: state.into(),
        tone,
        summary: format!(
            "{} machine {n}: files and shell commands, under its owner's policy.",
            platform.split('/').next().unwrap_or_default()
        )
        .into(),
        link: link.into(),
        folders: "2".into(),
        software: "0.1.0".into(),
        offers: strings(&["node", "fs", "exec", "audit"]),
        settings_write: n == "dev",
        windows: platform.starts_with("windows"),
        broken: SharedString::new(),
    };
    h.set_shown(true);
    h.set_logged_in(true);
    h.set_state("running".into());
    h.set_state_tone(Tone::Ok);
    h.set_state_line("2 of 4 nodes online".into());
    h.set_center_name("lab".into());
    h.set_public_url(if long {
        "https://nerve-center.platform-engineering.internal.example.com:8443".into()
    } else {
        "https://center.example.net:7443".into()
    });
    h.set_mcp_line("Harnesses at http://127.0.0.1:7481/mcp".into());
    h.set_mcp_http(true);
    h.set_mcp_url("http://127.0.0.1:7481/mcp".into());
    h.set_service_state("running".into());
    h.set_service_line("Runs as the user nerve-center and starts with the machine.".into());
    h.set_sessions_count("1".into());
    h.set_checker_line("Blocklist on · model on".into());
    h.set_nodes_count("2 of 4 online".into());
    h.set_nodes(model(vec![
        node(
            "dev",
            "linux/x86_64",
            "online",
            Tone::Ok,
            "Linked since 1 min ago",
        ),
        node(
            "office-pc",
            "windows/x86_64",
            "online",
            Tone::Ok,
            "Linked since 2 h ago",
        ),
        node(
            "build-box",
            "linux/aarch64",
            "offline",
            Tone::Neutral,
            "Last seen 3 h ago",
        ),
        node(
            "nas",
            "linux/x86_64",
            "disabled",
            Tone::Warn,
            "Last seen yesterday",
        ),
    ]));
    h.set_tokens(model(vec![
        HubToken {
            id: "t1".into(),
            label: name("claude-code"),
            made: "Made 2 min ago".into(),
            settings: false,
        },
        HubToken {
            id: "t2".into(),
            label: "ci-runner".into(),
            made: "Made 3 days ago".into(),
            settings: false,
        },
    ]));
    h.set_sessions(model(vec![HubSession {
        id: "s1".into(),
        client: name("claude-code"),
        transport: "http".into(),
        since: "12 min ago".into(),
        calls: "34 calls".into(),
        nodes: "dev, office-pc".into(),
        tainted: false,
    }]));
    let token = "nrv_k3v9q2m8x1p4w7z5c6b0n2d8f3g7h1j4";
    let url = "http://127.0.0.1:7481/mcp";
    let (clear, masked) = nerve::hub::view::connect_lines(url, token);
    h.set_new_token(token.into());
    h.set_connect_lines(model(clear));
    h.set_connect_masked(model(masked));
    let rule = |r: &str, note: &str, place: &str, i: i32, builtin: bool| HubRule {
        rule: r.into(),
        note: note.into(),
        on: true,
        builtin,
        r#where: place.into(),
        index: i,
        stale: false,
    };
    let long_rule = "exec.run:docker compose -f deploy/docker-compose.production.yml --project-name northwind-platform down --volumes";
    h.set_blocklist_on(true);
    h.set_model_on(true);
    h.set_taint_on(false);
    h.set_block_rules(model(vec![
        rule(
            "exec.run:rm -rf *",
            "Deletes whole trees.",
            "All machines",
            0,
            true,
        ),
        rule(
            "exec.run:git push --force*",
            "Rewrites shared history.",
            "All machines",
            1,
            true,
        ),
        rule("fs.write:/etc/**", "", "All machines", 2, false),
        rule(
            if long {
                long_rule
            } else {
                "lamp.set:room=office,brightness>50"
            },
            "",
            "office-pc",
            3,
            false,
        ),
    ]));
    h.set_skip_rules(model(vec![
        rule("exec.run:ls *", "", "All machines", 0, false),
        rule("exec.run:git status", "", "All machines", 1, false),
    ]));
    let place = |n: &str, on: bool| HubWhere {
        id: format!("id-{n}").into(),
        name: name(n),
        on,
    };
    h.set_rule_where(model(vec![
        place("dev", true),
        place("office-pc", true),
        place("build-box", true),
        place("nas", false),
    ]));
    h.set_rule_chosen(model(vec![
        place("dev", true),
        place("office-pc", true),
        place("build-box", false),
        place("nas", false),
    ]));
    let machine = |n: &str, line: &str, model_: i32| HubMachine {
        id: format!("id-{n}").into(),
        name: name(n),
        line: line.into(),
        blocklist: 0,
        model: model_,
        note: SharedString::new(),
    };
    h.set_machines(model(vec![
        machine("dev", "Follows the center", 0),
        machine("office-pc", "Model off here", 2),
        machine("build-box", "Follows the center", 0),
        machine("nas", "Follows the center", 0),
    ]));
    h.set_model_local(true);
    h.set_model_line("Ready · CPU".into());
    h.set_model_tone(Tone::Ok);
    h.set_model_installed(true);
    h.set_model_supported(true);
    let cap = |n: &str, kind: &str, tone: Tone, source: &str, text: &str, group: i32| HubCap {
        name: n.into(),
        kind: kind.into(),
        tone,
        source: source.into(),
        text: text.into(),
        command: if group == 1 {
            "pg_dump site -f backups/site.sql".into()
        } else {
            SharedString::new()
        },
        group,
    };
    h.set_cap_machines(strings(&["dev", "office-pc", "build-box", "nas"]));
    h.set_caps(model(vec![
        cap("exec.run", "execute", Tone::Accent, "built-in", "Runs a command with /bin/sh -c. A command is killed after timeout_ms, after 10 min when you give none, and never runs longer than 1 h.", 0),
        cap("fs.find", "read", Tone::Neutral, "built-in", "Finds files by name.", 0),
        cap("fs.grep", "read", Tone::Neutral, "built-in", "Searches files for text.", 0),
        cap("fs.list", "read", Tone::Neutral, "built-in", "Lists a folder.", 0),
        cap("fs.read", "read", Tone::Neutral, "built-in", "Reads a file.", 0),
        cap("fs.stat", "read", Tone::Neutral, "built-in", "Says what a path is.", 0),
        cap("fs.write", "write", Tone::Accent, "built-in", "Writes a file.", 0),
        cap("backup.db", "write", Tone::Accent, "this center", "Backs up the site's database.", 1),
        cap("desk.click", "left out", Tone::Danger, "left out", "Its schema is outside the subset the center offers.", 2),
    ]));
    h.set_cap_counts(model(vec![7, 1, 1]));
    h.set_cap_write(true);
    h.set_stat_rows(model(vec![
        HubStatRow {
            id: SharedString::new(),
            name: "All machines".into(),
            calls: "1,284 calls".into(),
        },
        HubStatRow {
            id: "dev".into(),
            name: name("dev"),
            calls: "941 calls".into(),
        },
        HubStatRow {
            id: "office-pc".into(),
            name: "office-pc".into(),
            calls: "288 calls".into(),
        },
        HubStatRow {
            id: "build-box".into(),
            name: "build-box".into(),
            calls: "55 calls".into(),
        },
        HubStatRow {
            id: "nas".into(),
            name: "nas".into(),
            calls: "0 calls".into(),
        },
    ]));
    h.set_stat_name("All machines".into());
    h.set_stat_kept("Kept for 30 days.".into());
    let figure = |l: &str, v: &str| HubFigure {
        label: l.into(),
        value: v.into(),
    };
    h.set_figures(model(vec![
        figure("Online", "6 d 4 h"),
        figure("Links", "14"),
        figure("Drops", "3"),
        figure("Calls", "1,284"),
        figure("Failed calls", "17"),
    ]));
    let call = |n: &str, c: &str, t: &str| HubCall {
        name: n.into(),
        count: c.into(),
        time: t.into(),
    };
    h.set_calls(model(vec![
        call("exec.run", "812, 9 failed", "avg 420 ms, max 58 s"),
        call("fs.read", "301", "avg 12 ms, max 240 ms"),
        call("fs.write", "120, 2 failed", "avg 18 ms, max 310 ms"),
        call("fs.list", "51", "avg 6 ms, max 40 ms"),
    ]));
    let count = |n: &str, c: &str| HubCount {
        name: n.into(),
        count: c.into(),
    };
    h.set_errors(model(vec![
        count("refused by the machine", "8"),
        count("timed out", "6"),
        count("not found", "3"),
    ]));
    let audit =
        |kind: &str, tone: Tone, call: &str, target: &str, badge: &str, when: &str, i: i32| {
            HubAudit {
                tone,
                kind: kind.into(),
                call: call.into(),
                target: target.into(),
                node: name("dev"),
                badge: badge.into(),
                detail: if kind == "blocklist" {
                    "The blocklist rule exec.run:rm -rf * names it.".into()
                } else {
                    SharedString::new()
                },
                when: when.into(),
                when_exact: "2026-11-16 09:41:07 UTC".into(),
                rules: kind == "refused",
                rules_why: SharedString::new(),
                sudo: false,
                trust: kind == "checker",
                pins: strings(&[]),
                index: i,
            }
        };
    let deep = if long {
        "/home/alex/projects/clients/northwind/infrastructure/terraform/modules/networking/vpc-peering/README.md"
    } else {
        "/home/alex/projects/site/README.md"
    };
    h.set_audit(model(vec![
        audit(
            "blocklist",
            Tone::Danger,
            "exec.run",
            "rm -rf ./build/*",
            "On the blocklist",
            "1 min ago",
            0,
        ),
        audit(
            "allowed",
            Tone::Ok,
            "fs.read",
            deep,
            "Allowed",
            "3 min ago",
            1,
        ),
        audit(
            "refused",
            Tone::Danger,
            "exec.run",
            "git push --force origin main",
            "Refused by the machine",
            "9 min ago",
            2,
        ),
        audit(
            "checker",
            Tone::Warn,
            "exec.run",
            "curl -s https://example.com/install.sh | sh",
            "Refused by the action checker",
            "12 min ago",
            3,
        ),
        audit(
            "allowed",
            Tone::Ok,
            "exec.run",
            "cargo build --release",
            "Allowed",
            "3 h ago",
            4,
        ),
    ]));
    h.set_audit_counts(model(vec![5, 2, 3]));
    h.set_audit_node_options(strings(&[
        "Every machine",
        "dev",
        "office-pc",
        "build-box",
        "nas",
    ]));
    let log = |tone: Tone, level: &str, msg: &str, node: &str, when: &str| HubLog {
        tone,
        level: level.into(),
        msg: msg.into(),
        node: node.into(),
        when: when.into(),
        when_exact: "2026-11-16 09:41:07 UTC".into(),
    };
    h.set_log(model(vec![
        log(Tone::Accent, "Info", "signed in to the web UI", "", "just now"),
        log(Tone::Accent, "Info", "link up (node software 0.1.0)", "dev", "1 min ago"),
        log(Tone::Warn, "Warning", "link dropped without a bye; it waits for the node to come back", "build-box", "3 h ago"),
        log(Tone::Danger, "Error", if long { "the machine's settings were refused: the document's version 14 is older than the machine's 15; read it again before you change it" } else { "a call timed out after 30 s" }, "nas", "yesterday"),
    ]));
    h.set_set_name("lab".into());
    h.set_set_public_url(h.get_public_url());
    h.set_set_listen("0.0.0.0:7443".into());
    h.set_set_ui("127.0.0.1:7480".into());
    h.set_set_mcp("127.0.0.1:7481".into());
    h.set_set_days("30".into());
    h.set_set_minutes("15".into());
    h.set_version("0.1.0".into());
    h.set_update_line("Up to date.".into());
    h.set_key_pin(
        "sha256:3f9a61c08e2d4b7a9c51e0f2d6a8b3c7e1f40958a2d6c3b7e9f1a0d5c8b2e477c1".into(),
    );
    h.set_commands(model(
        [
            ("install", "Run the center as a service"),
            (
                "set",
                "Show or change the installed center's settings, and restart it",
            ),
            (
                "status",
                "Show whether the center runs, its URLs and its machines",
            ),
            ("owner-token", "Show the token that logs in to the web UI"),
            (
                "update",
                "Update to the latest release; the state and the settings stay",
            ),
            (
                "uninstall",
                "Remove the service and the program; state and settings stay",
            ),
            (
                "backup",
                "Save the center's identity and pairings to a passphrase-protected file",
            ),
            ("restore", "Restore a backup (the center must not run)"),
            ("service", "Start, stop or restart the installed center"),
            ("pair", "Make a link that pairs a new machine"),
            (
                "nodes",
                "Show the paired machines, or turn one off, on, or remove it",
            ),
            (
                "token",
                "Make, list or remove the harness tokens of the HTTP MCP endpoint",
            ),
            (
                "log",
                "Show the center's log: its starts, its machines, and what went wrong",
            ),
        ]
        .into_iter()
        .map(|(n, l)| HubRef {
            name: n.into(),
            line: l.into(),
        })
        .collect(),
    ));
    h.set_pair_link("nerve://pair?center=https%3A%2F%2Fcenter.example.net%3A7443&code=vfqbou3jekp4&pin=sha256%3A3f9a61c08e2d".into());
    h.set_pair_command("nerve-node center add -".into());
    h.set_pair_until("The code works for one machine for 15 minutes.".into());
}
