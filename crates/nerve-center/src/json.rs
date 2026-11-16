//! `--json` for the administrator's commands of the center (install, set,
//! update, uninstall, service, owner-token, backup, restore and status), as
//! the node has it: the desktop app runs them through its broker and reads
//! what happened from stdout. A command prints the lines it says to people
//! as `{"messages": [...]}`, with the data a program needs beside them
//! ([`also`]: the owner token, the service's state); an error is
//! `{"error": "..."}`, on stdout too.

use std::cell::RefCell;

use serde_json::{Map, Value, json};

use crate::config::Cmd;

thread_local! {
    /// The data of the command that runs with `--json`; `None` without it.
    /// A command runs on the thread that started it (`block_on` runs its
    /// future there too).
    static ALSO: RefCell<Option<Map<String, Value>>> = const { RefCell::new(None) };
}

/// Why `--json` is refused for another command.
pub const ONLY_FOR: &str = "--json is for install, set, update, uninstall, service, owner-token, backup, restore and status";

/// Whether `cmd` answers with `--json`: the administrator's commands, and
/// `status`. The center itself (no command), and the commands that ask the
/// running center, do not.
pub fn takes(cmd: Option<&Cmd>) -> bool {
    matches!(
        cmd,
        Some(
            Cmd::Install
                | Cmd::Set { .. }
                | Cmd::Update { .. }
                | Cmd::Uninstall { .. }
                | Cmd::Service { cmd: Some(_) }
                | Cmd::OwnerToken { .. }
                | Cmd::Backup { .. }
                | Cmd::Restore { .. }
                | Cmd::Status
        )
    )
}

/// Starts the answer of a command that runs with `--json`.
pub fn start() {
    ALSO.with(|a| *a.borrow_mut() = Some(Map::new()));
}

/// Adds `key` to the `--json` answer of the command that runs; nothing
/// without `--json`.
pub fn also(key: &str, value: Value) {
    ALSO.with(|a| {
        if let Some(m) = a.borrow_mut().as_mut() {
            m.insert(key.into(), value);
        }
    });
}

/// The answer of a command that printed `text` and ended with `done`.
pub fn answer(text: &[u8], done: &Result<(), String>) -> Value {
    let fields = ALSO.with(|a| a.borrow_mut().take()).unwrap_or_default();
    if let Err(e) = done {
        return json!({ "error": e });
    }
    let text = String::from_utf8_lossy(text);
    let messages: Vec<&str> = text
        .lines()
        .map(str::trim_end)
        .filter(|l| !l.trim().is_empty())
        .collect();
    let mut v = json!({ "messages": messages });
    for (k, f) in fields {
        v[k] = f;
    }
    v
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    fn cmd(args: &[&str]) -> Option<Cmd> {
        let mut argv = vec!["nerve-center"];
        argv.extend_from_slice(args);
        crate::config::Args::try_parse_from(argv).unwrap().cmd
    }

    #[test]
    fn only_the_administrator_s_commands_and_status_take_it() {
        for args in [
            &["install"][..],
            &["set", "ui", "off"],
            &["update"],
            &["uninstall", "--purge"],
            &["service", "restart"],
            &["owner-token"],
            &["backup", "f"],
            &["restore", "f"],
            &["status"],
        ] {
            assert!(takes(cmd(args).as_ref()), "{args:?}");
        }
        for args in [&[][..], &["pair"], &["log"], &["service"], &["nodes"]] {
            assert!(!takes(cmd(args).as_ref()), "{args:?}");
        }
    }

    #[test]
    fn the_answer_is_the_lines_and_the_data_or_the_error() {
        start();
        also("token", json!("nrv_x"));
        let v = answer(b"made it\n\n  Token   nrv_x  \n", &Ok(()));
        assert_eq!(
            v,
            json!({"messages": ["made it", "  Token   nrv_x"], "token": "nrv_x"})
        );
        // Without --json nothing is kept.
        also("token", json!("nrv_y"));
        assert_eq!(answer(b"", &Ok(())), json!({"messages": []}));
        start();
        assert_eq!(answer(b"half", &Err("no".into())), json!({"error": "no"}));
    }
}
