//! `nerve-node config`: node.toml's settings by their dotted keys, and
//! `config accept` of a file edited by hand.

use super::*;

/// Why `config set machine.user` is refused on Linux.
pub const NO_ACCOUNT_TO_CHOOSE: &str = "machine.user is Windows's: on Linux commands run as nerve-run, or in user mode as the owner, the account that ran `install`";

/// `config get|set|unset|add|remove` on dotted keys. `center.<name>` picks
/// a `[[center]]` entry by its name.
pub(super) async fn config_cmd(
    paths: &NodePaths,
    c: ConfigCmd,
    out: &mut dyn Write,
) -> Result<(), String> {
    if let ConfigCmd::Accept = c {
        // It takes a hand-edited node.toml whole, with no check of what
        // changed: a terminal's job, never the web UI's.
        if crate::owner::via_web() {
            return Err(crate::owner::NOT_FROM_THE_WEB.into());
        }
        let (v, notes) = accept(paths).await?;
        let _ = writeln!(out, "accepted node.toml as version {v}");
        for note in notes {
            let _ = writeln!(out, "{note}");
        }
        return Ok(());
    }
    if let ConfigCmd::Get { key } = &c {
        let (cfg, _) = read_config(paths).await?;
        let v = setting(&cfg, key)?;
        let _ = writeln!(out, "{}", show(&v));
        return Ok(());
    }
    // The web UI's own settings change through `ui` at the CLI alone.
    if crate::owner::via_web()
        && let ConfigCmd::Set { key, .. }
        | ConfigCmd::Unset { key }
        | ConfigCmd::Add { key, .. }
        | ConfigCmd::Rm { key, .. } = &c
        && (key == "ui" || key.starts_with("ui."))
    {
        return Err(crate::owner::NOT_FROM_THE_WEB.into());
    }
    // Linux chooses no account for the commands: they run as nerve-run or
    // as the owner, the account that ran `install`.
    if !cfg!(windows)
        && let ConfigCmd::Set { key, .. }
        | ConfigCmd::Unset { key }
        | ConfigCmd::Add { key, .. }
        | ConfigCmd::Rm { key, .. } = &c
        && key == "machine.user"
    {
        return Err(NO_ACCOUNT_TO_CHOOSE.into());
    }
    // Keys into the keyring: at a terminal, where none answers, the owner
    // is offered one (as root for the node's user) before anything moves.
    if moves_keys_to_keyring(&c) && crate::owner::at_terminal() {
        let (machine, keyring) = keyring_of(paths);
        let mut input = std::io::BufReader::new(std::io::stdin());
        offer_keyring(paths, machine, &keyring, Some(&mut input), out).await?;
    }
    let before = std::cell::Cell::new(SecretStorage::File);
    let cfg = edit(paths, |cfg| {
        before.set(cfg.machine.secret_storage);
        let mut doc = toml::Value::Table(as_table(cfg)?);
        match &c {
            ConfigCmd::Get { .. } | ConfigCmd::Accept => {}
            ConfigCmd::Set { key, value } => {
                let (parent, last) = split_key(key)?;
                table_at(&mut doc, &parent, true)?.insert(last, literal(value));
            }
            ConfigCmd::Unset { key } => {
                let (parent, last) = split_key(key)?;
                table_at(&mut doc, &parent, false)?
                    .remove(&last)
                    .ok_or_else(|| format!("{key} is not set"))?;
            }
            ConfigCmd::Add { key, value } => {
                let (parent, last) = split_key(key)?;
                let t = table_at(&mut doc, &parent, true)?;
                let list = t
                    .entry(last)
                    .or_insert_with(|| toml::Value::Array(Vec::new()));
                let toml::Value::Array(a) = list else {
                    return Err(format!("{key} is not a list"));
                };
                // The text `rule` prints for a tab or line break is not
                // one: the rule would look like the listed one and not be.
                // Any other text is a rule as it stands (`C:\tools` too).
                if ["allow", "deny", "sudo_allow"]
                    .iter()
                    .any(|l| key.starts_with("center.") && key.ends_with(&format!(".policy.{l}")))
                {
                    let listed: Vec<String> = a
                        .iter()
                        .filter_map(|v| v.as_str().map(str::to_string))
                        .collect();
                    rules::check_not_a_listed_form(value, &listed)?;
                }
                a.push(literal(value));
            }
            ConfigCmd::Rm { key, value } => {
                let (parent, last) = split_key(key)?;
                let t = table_at(&mut doc, &parent, false)?;
                let Some(toml::Value::Array(a)) = t.get_mut(&last) else {
                    return Err(format!("{key} is not a list"));
                };
                let v = literal(value);
                let before = a.len();
                a.retain(|x| x != &v);
                if a.len() == before {
                    return Err(format!("{value} is not in {key}"));
                }
            }
        }
        let text = toml::to_string(&doc).map_err(|e| e.to_string())?;
        let mut new = NodeConfig::parse(&text)?;
        new.version = cfg.version;
        *cfg = new;
        Ok(())
    })
    .await?;
    let _ = writeln!(out, "saved");
    if before.get() != SecretStorage::Keyring
        && cfg.machine.secret_storage == SecretStorage::Keyring
    {
        tell_folder_commands(paths, &cfg, out).await;
    }
    Ok(())
}

/// Says, once the keys went into the keyring, that folder mode now runs no
/// command where Landlock cannot keep a command off the session bus
/// (crate::daemon::KEYRING_NOT_CONFINED). The running node knows; without one,
/// the kernel here and the account `cfg` runs commands as tell.
pub(super) async fn tell_folder_commands(paths: &NodePaths, cfg: &NodeConfig, out: &mut dyn Write) {
    #[cfg(unix)]
    match nerve_transport::ctl::call(&paths.ctl_socket(), "status", json!({})).await {
        Ok(v) => {
            if v["folder_commands_off"] == crate::daemon::KEYRING_NOT_CONFINED {
                let _ = writeln!(out, "{}", folder_commands_off());
            }
            return;
        }
        Err(e) if e == nerve_transport::ctl::NOT_RUNNING => {}
        // The node that runs knows, and was not asked.
        Err(e) => {
            let _ = writeln!(
                out,
                "the running node was not asked whether folder mode still runs commands ({e}); `nerve-node status` shows it"
            );
            return;
        }
    }
    // A node run by hand takes an old Landlock as none, as it would.
    let detected = nerve_sandbox::Confinement::detect();
    let c = match crate::service::is_service_node(paths) {
        true => detected,
        false => detected.by_hand(),
    };
    if keyring_turns_commands_off(c, || node_command_account(paths, cfg)) {
        let _ = writeln!(out, "{}", folder_commands_off());
    }
}

/// The account the node at `paths` runs commands as with `cfg`, looked up as
/// that node does (crate::account::for_commands), for a CLI that finds no
/// node to ask: the installed node runs as its own user and can switch, a
/// node run by hand as this CLI's user. `None` for the node's own user, and
/// where no command runs.
fn node_command_account(paths: &NodePaths, cfg: &NodeConfig) -> Option<crate::service::Account> {
    let me = nerve_transport::net::euid();
    let service = crate::service::is_service_node(paths);
    let own = match service {
        true => crate::account::lookup(crate::service::USER)
            .ok()
            .flatten()
            .map_or(me, |a| a.uid),
        false => me,
    };
    // Folder mode's account; the owner is the unit's on Linux, the
    // config's on Windows.
    let owner = if cfg!(windows) {
        cfg.machine.user.clone()
    } else {
        crate::service::owner_of(paths)
    };
    crate::account::for_commands(
        false,
        owner.as_deref(),
        own,
        service,
        service || crate::account::can_switch(),
        crate::account::lookup,
    )
    .ok()
    .flatten()
}

fn folder_commands_off() -> String {
    format!(
        "folder mode runs no command: {}",
        crate::daemon::KEYRING_NOT_CONFINED
    )
}

/// Whether, with the keys in the keyring, `c` leaves folder mode's commands
/// a way to the session bus: for commands that run as the node's own user or
/// root (crate::daemon::keys_kept_from_commands). `account` is asked only
/// where commands are confined at all.
fn keyring_turns_commands_off(
    c: nerve_sandbox::Confinement,
    account: impl FnOnce() -> Option<crate::service::Account>,
) -> bool {
    c.available() && !crate::daemon::keys_kept_from_commands(SecretStorage::Keyring, account)
}

/// `config accept`: the running daemon takes the file, or, when none runs,
/// the file is signed here. Also a note for each switch the daemon set to
/// `off` as it took it, each saying what to do for its kind
/// (crate::config_cap::hold_new, hold_shadowed, hold_with_own), and for
/// each a center's capability took along as the file dropped it
/// (drop_removed); a stopped node cannot tell what the file had before, so
/// it switches off and takes along none.
async fn accept(paths: &NodePaths) -> Result<(u64, Vec<String>), String> {
    // Keys already in the keyring move nowhere when the file is taken, so
    // the settings store alone would not refuse it.
    if crate::secrets::stated_storage(paths) == SecretStorage::Keyring
        && let Some(n) = crate::secrets::no_keyring(paths)
    {
        return Err(format!(
            "{} says machine.secret_storage = \"keyring\", but {}. So the file was not accepted: change it to `secret_storage = \"file\"` and accept it again, which takes keys found in the keyring into files",
            paths.config_file().display(),
            n.why()
        ));
    }
    #[cfg(unix)]
    match nerve_transport::ctl::call(
        &paths.ctl_socket(),
        "config.accept",
        json!({"user": changed_by()}),
    )
    .await
    {
        Ok(v) => {
            let of = |key: &str| -> Vec<(String, String)> {
                serde_json::from_value(v[key].clone()).unwrap_or_default()
            };
            let notes = of("held")
                .iter()
                .map(|(center, name)| held_note(center, name))
                .chain(of("shadowed").iter().map(|(c, n)| shadowed_note(c, n)))
                .chain(of("with_own").iter().map(|(c, n)| with_own_note(c, n)))
                .chain(of("dropped").iter().map(|(c, n)| dropped_note(c, n)))
                .collect();
            return Ok((v["version"].as_u64().unwrap_or_default(), notes));
        }
        Err(e) if e != nerve_transport::ctl::NOT_RUNNING => return Err(e),
        Err(_) => {}
    }
    let (_, v) = SettingsStore::open_accepting_with(
        paths.config_file(),
        Box::new(crate::secrets::NodeSecrets::for_accept(paths)),
        AuditLog::new(paths.audit_log()),
    )?;
    Ok((v, Vec::new()))
}

fn as_table(cfg: &NodeConfig) -> Result<toml::Table, String> {
    toml::from_str(&cfg.to_toml()).map_err(|e| e.to_string())
}

/// The keys of node.toml that hold the node's own state, not a setting:
/// `config get` leaves them out (each center's, and the file's own).
const STATE_KEYS: &[&str] = &["version", "locked"];
const CENTER_STATE_KEYS: &[&str] = &[
    "center_id",
    "node_id",
    "pin",
    "public_key",
    "key_rotations",
    "pin_rotations",
    "old_pin",
    "revoked",
    "unknown",
    "places",
];

/// The tables of node.toml a setting may be in, by their first word.
const SETTING_TABLES: &[&str] = &[
    "node",
    "machine",
    "limits",
    "connection",
    "relay",
    "ui",
    "log",
    "providers",
    "capability",
    "center",
];

/// node.toml without the node's own state ([`STATE_KEYS`]).
fn settings_table(cfg: &NodeConfig) -> Result<toml::Value, String> {
    let mut doc = as_table(cfg)?;
    for k in STATE_KEYS {
        doc.remove(*k);
    }
    for c in doc
        .get_mut("center")
        .and_then(toml::Value::as_array_mut)
        .into_iter()
        .flatten()
    {
        if let Some(t) = c.as_table_mut() {
            for k in CENTER_STATE_KEYS {
                t.remove(*k);
            }
        }
    }
    Ok(toml::Value::Table(doc))
}

/// `config get`: one setting, or a table of them, without the node's own
/// state. A key that is not set says whether its default applies or it is
/// no setting at all.
pub(super) fn setting(cfg: &NodeConfig, key: &str) -> Result<toml::Value, String> {
    let words = segments(key);
    if let Some(v) = lookup(&settings_table(cfg)?, &words) {
        return Ok(v);
    }
    if lookup(&toml::Value::Table(as_table(cfg)?), &words).is_some() {
        return Err(format!(
            "{key} is the node's own state, not a setting; `nerve-node status` shows the node"
        ));
    }
    match words.as_slice() {
        [c, name, ..] if c == "center" && cfg.center(name).is_none() => {
            Err(no_center_named(cfg, name))
        }
        [first, ..] if SETTING_TABLES.contains(&first.as_str()) => Err(format!(
            "{key} is not set, so its default applies (docs/dev/settings-and-config.md lists the defaults)"
        )),
        _ => Err(format!(
            "{key} is no setting of node.toml; its tables are {}",
            SETTING_TABLES.join(", ")
        )),
    }
}

fn segments(key: &str) -> Vec<String> {
    key.split('.').map(str::to_string).collect()
}

fn split_key(key: &str) -> Result<(Vec<String>, String), String> {
    let mut s = segments(key);
    let last = s.pop().filter(|l| !l.is_empty()).ok_or("empty key")?;
    Ok((s, last))
}

/// Whether `c` is `config set machine.secret_storage keyring`, which at a
/// terminal offers to install a keyring where none answers: the owner's
/// input goes to the installed node for it (crate::owner::reads_input).
pub fn moves_keys_to_keyring(c: &ConfigCmd) -> bool {
    matches!(c, ConfigCmd::Set { key, value }
        if key == "machine.secret_storage" && literal(value).as_str() == Some("keyring"))
}

/// A value as TOML reads it (`true`, `3`, `["a"]`), else as a string.
fn literal(s: &str) -> toml::Value {
    toml::from_str::<toml::Table>(&format!("v = {s}"))
        .ok()
        .and_then(|mut t| t.remove("v"))
        .unwrap_or_else(|| toml::Value::String(s.to_string()))
}

fn show(v: &toml::Value) -> String {
    match v {
        toml::Value::String(s) => s.clone(),
        toml::Value::Table(t) => toml::to_string(t).unwrap_or_default(),
        other => other.to_string(),
    }
}

fn lookup(v: &toml::Value, key: &[String]) -> Option<toml::Value> {
    let Some((first, rest)) = key.split_first() else {
        return Some(v.clone());
    };
    if first == "center" && !rest.is_empty() {
        let list = v.get("center")?.as_array()?;
        let entry = list
            .iter()
            .find(|e| e.get("name").and_then(|n| n.as_str()) == Some(rest[0].as_str()))?;
        return lookup(entry, &rest[1..]);
    }
    lookup(v.get(first.as_str())?, rest)
}

fn table_at<'a>(
    v: &'a mut toml::Value,
    key: &[String],
    create: bool,
) -> Result<&'a mut toml::Table, String> {
    let Some((first, rest)) = key.split_first() else {
        return v.as_table_mut().ok_or_else(|| "not a table".to_string());
    };
    let t = v
        .as_table_mut()
        .ok_or_else(|| format!("{first}: not a table"))?;
    if first == "center" && !rest.is_empty() {
        let list = t
            .get_mut("center")
            .and_then(toml::Value::as_array_mut)
            .ok_or(NO_CENTER_PAIRED)?;
        let entry = list
            .iter_mut()
            .find(|e| e.get("name").and_then(|n| n.as_str()) == Some(rest[0].as_str()))
            .ok_or_else(|| {
                format!(
                    "no center named {}; `nerve-node center` lists them",
                    rest[0]
                )
            })?;
        return table_at(entry, &rest[1..], create);
    }
    if !t.contains_key(first.as_str()) {
        if !create {
            return Err(format!("{first} is not set"));
        }
        t.insert(first.clone(), toml::Value::Table(toml::Table::new()));
    }
    table_at(t.get_mut(first.as_str()).expect("present"), rest, create)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::tests::{json_of, load, run, setup, setup_with};

    #[test]
    fn config_get_set_by_dotted_key() {
        let (_d, paths) = setup(&["home"]);
        run(&paths, &["config", "set", "limits.max_running", "4"]).unwrap();
        assert_eq!(load(&paths).limits.max_running, 4);
        run(&paths, &["config", "set", "center.home.policy.until", "30"]).unwrap();
        assert_eq!(
            run(&paths, &["config", "get", "center.home.policy.until"]).unwrap(),
            "30\n"
        );
        run(
            &paths,
            &["config", "add", "center.home.policy.deny", "fs:~/secret/*"],
        )
        .unwrap();
        assert_eq!(
            load(&paths).centers[0].policy.deny,
            vec!["fs:~/secret/*".to_string()]
        );
        run(
            &paths,
            &["config", "rm", "center.home.policy.deny", "fs:~/secret/*"],
        )
        .unwrap();
        assert!(load(&paths).centers[0].policy.deny.is_empty());
        // Unknown keys fail validation and change nothing.
        assert!(run(&paths, &["config", "set", "limits.bogus", "1"]).is_err());
        run(&paths, &["config", "unset", "limits.max_running"]).unwrap();
        assert_eq!(load(&paths).limits.max_running, 16);
    }

    /// `config get` shows settings, not the node's own state: a center's
    /// keys and counters are left out of its table, and asked by name they
    /// are said to be state. A key that is not set says whether its default
    /// applies or it is no setting at all.
    #[test]
    fn config_get_hides_the_nodes_own_state() {
        let (_d, paths) = setup(&["home"]);
        let table = run(&paths, &["config", "get", "center.home"]).unwrap();
        assert!(table.contains("name = \"home\""), "{table}");
        for state in ["center_id", "node_id", "public_key", "pin ="] {
            assert!(!table.contains(state), "{state}: {table}");
        }
        let whole = run(&paths, &["config", "get", "center"]).unwrap();
        assert!(!whole.contains("node_id"), "{whole}");
        let e = run(&paths, &["config", "get", "center.home.node_id"]).unwrap_err();
        assert!(e.contains("the node's own state, not a setting"), "{e}");
        let e = run(&paths, &["config", "get", "version"]).unwrap_err();
        assert!(e.contains("the node's own state"), "{e}");
        let e = run(&paths, &["config", "get", "center.home.policy.until"]).unwrap_err();
        assert!(e.contains("not set, so its default applies"), "{e}");
        let e = run(&paths, &["config", "get", "nonsense"]).unwrap_err();
        assert!(e.contains("no setting of node.toml"), "{e}");
        let e = run(&paths, &["config", "get", "center.lab.policy"]).unwrap_err();
        assert!(e.contains("paired: home"), "{e}");
        let v = json_of(&paths, &["config", "get", "center.home"]);
        assert!(v["value"].get("node_id").is_none(), "{v}");
    }

    /// No account for the commands is chosen on Linux: `config` refuses
    /// `machine.user` in every verb, and nothing changes.
    #[cfg(not(windows))]
    #[test]
    fn config_chooses_no_account_on_linux() {
        let (_d, paths) = setup(&["home"]);
        for cmd in [
            &["config", "set", "machine.user", "bob"][..],
            &["config", "unset", "machine.user"],
            &["config", "add", "machine.user", "bob"],
        ] {
            let e = run(&paths, cmd).unwrap_err();
            assert_eq!(e, NO_ACCOUNT_TO_CHOOSE, "{cmd:?}");
        }
        assert_eq!(load(&paths).machine.user, None);
    }

    /// The owner sets the run-time limits by name; a limit of 0 is refused
    /// and changes nothing, and unsetting one gives the default back.
    #[test]
    fn config_sets_the_run_time_limits() {
        let (_d, paths) = setup(&["home"]);
        assert_eq!(load(&paths).limits.default_timeout_secs, 600);
        assert_eq!(load(&paths).limits.max_timeout_secs, 3600);
        run(
            &paths,
            &["config", "set", "limits.default_timeout_secs", "30"],
        )
        .unwrap();
        run(&paths, &["config", "set", "limits.max_timeout_secs", "90"]).unwrap();
        assert_eq!(load(&paths).limits.default_timeout_secs, 30);
        assert_eq!(load(&paths).limits.max_timeout_secs, 90);
        assert_eq!(
            run(&paths, &["config", "get", "limits.max_timeout_secs"]).unwrap(),
            "90\n"
        );
        for key in ["default_timeout_secs", "max_timeout_secs"] {
            let e = run(&paths, &["config", "set", &format!("limits.{key}"), "0"]).unwrap_err();
            assert!(e.contains("must be at least 1"), "{e}");
        }
        assert_eq!(load(&paths).limits.max_timeout_secs, 90);
        run(&paths, &["config", "unset", "limits.max_timeout_secs"]).unwrap();
        assert_eq!(load(&paths).limits.max_timeout_secs, 3600);
    }

    /// Folder mode's commands are told off where they run as the node's own
    /// user or root, whatever the kernel, and `status` prints why the node
    /// says they are.
    #[test]
    fn the_keyring_turns_folder_commands_of_the_nodes_own_user_off() {
        use nerve_sandbox::Confinement;
        let abi = |v| Confinement {
            landlock_abi: v,
            appcontainer: false,
        };
        let account = |uid| crate::service::Account {
            name: "alice".into(),
            uid,
            gid: uid,
            comment: String::new(),
            home: "/home/alice".into(),
            groups: vec![uid],
        };
        let (root, alice) = (account(0), account(4242));
        assert!(keyring_turns_commands_off(abi(Some(6)), || None));
        assert!(keyring_turns_commands_off(abi(Some(6)), || Some(root)));
        // Another account than root cannot reach the bus: its commands run.
        assert!(!keyring_turns_commands_off(abi(Some(6)), || Some(
            alice.clone()
        )));
        let asked = std::cell::Cell::new(false);
        let ask = || {
            asked.set(true);
            None
        };
        assert!(keyring_turns_commands_off(abi(Some(9)), || None));
        assert!(!keyring_turns_commands_off(abi(Some(9)), || Some(alice)));
        assert!(!keyring_turns_commands_off(abi(None), ask));
        assert!(!asked.get());
        assert!(folder_commands_off().contains("machine.secret_storage file"));
    }

    /// The node's keys as setup and `config set` leave them: whether the
    /// config's key is in its file, and in the test keyring.
    fn config_key_at(paths: &NodePaths) -> (bool, bool) {
        let entry = crate::secrets::Entry::config_key(paths);
        (
            paths.config_key().exists(),
            crate::secrets::store::get(entry.account())
                .unwrap()
                .is_some(),
        )
    }

    #[test]
    fn config_set_moves_the_keys_and_center_rm_deletes_them_from_the_keyring() {
        let (_d, paths) = setup(&["home"]);
        let key = nerve_transport::keys::NodeKey::generate().unwrap();
        crate::secrets::store_center_key(&paths, SecretStorage::File, "home", &key).unwrap();
        let set = |to: &str| run(&paths, &["config", "set", "machine.secret_storage", to]);
        // Without a keyring nothing moves, and the setting stays.
        crate::secrets::store::set_unreachable(true);
        let e = set("keyring").unwrap_err();
        crate::secrets::store::set_unreachable(false);
        assert!(e.contains("nothing was changed"), "{e}");
        assert_eq!(load(&paths).machine.secret_storage, SecretStorage::File);
        assert_eq!(config_key_at(&paths), (true, false));
        assert!(paths.key_file("home").exists());
        set("keyring").unwrap();
        assert_eq!(load(&paths).machine.secret_storage, SecretStorage::Keyring);
        assert_eq!(config_key_at(&paths), (false, true));
        assert!(!paths.key_file("home").exists());
        let read = crate::secrets::center_key(&paths, SecretStorage::Keyring, "home").unwrap();
        assert_eq!(read.public_key(), key.public_key());
        run(&paths, &["center", "rm", "home"]).unwrap();
        assert!(crate::secrets::center_key(&paths, SecretStorage::Keyring, "home").is_err());
        set("file").unwrap();
        assert_eq!(config_key_at(&paths), (true, false));
        assert_eq!(
            run(&paths, &["config", "get", "machine.secret_storage"])
                .unwrap()
                .trim(),
            "file"
        );
    }

    /// The installed node on Windows keeps its keys in files: `config set`
    /// refuses the keyring and changes nothing, and setup does not ask
    /// where the keys go but takes keys left in the keyring into files.
    #[test]
    fn config_get_says_whether_the_keyring_can_hold_the_keys() {
        let (_d, paths) = setup(&["home"]);
        crate::secrets::for_tests::pretend_windows_service(&paths);
        let said = run(
            &paths,
            &["--json", "config", "get", "machine.secret_storage"],
        )
        .unwrap();
        let v: Value = serde_json::from_str(said.trim()).unwrap();
        assert_eq!(v["value"], "file");
        assert_eq!(v["keyring"]["usable"], false, "{v}");
        assert_eq!(v["keyring"]["reason"], "windows-service");
        assert!(
            v["keyring"]["why"]
                .as_str()
                .unwrap()
                .contains("Credential Manager")
        );
        // Another key says nothing of it.
        let said = run(&paths, &["--json", "config", "get", "log.level"]).unwrap();
        let v: Value = serde_json::from_str(said.trim()).unwrap();
        assert!(v.get("keyring").is_none(), "{v}");
    }

    #[test]
    fn the_installed_node_on_windows_keeps_its_keys_in_files() {
        let (_d, paths) = setup(&["home"]);
        let key = nerve_transport::keys::NodeKey::generate().unwrap();
        crate::secrets::store_center_key(&paths, SecretStorage::File, "home", &key).unwrap();
        let set = |to: &str| run(&paths, &["config", "set", "machine.secret_storage", to]);
        // Moved there before it was the installed node.
        set("keyring").unwrap();
        crate::secrets::for_tests::pretend_windows_service(&paths);
        let (r, out) = setup_with(&paths, "\n\n\n");
        r.unwrap();
        assert!(!out.contains("Where the node keeps its keys"), "{out}");
        assert!(
            out.contains("Warning: the installed node on Windows"),
            "{out}"
        );
        assert!(out.contains("the node's keys are in files now"), "{out}");
        assert_eq!(load(&paths).machine.secret_storage, SecretStorage::File);
        assert_eq!(config_key_at(&paths), (true, false));
        assert!(paths.key_file("home").exists());
        let e = set("keyring").unwrap_err();
        assert!(e.contains("cannot be \"keyring\""), "{e}");
        assert!(
            e.contains(
                "go to the Credential Manager of the account that put them there, not to that of nerve"
            ),
            "{e}"
        );
        assert!(e.contains("nothing was changed"), "{e}");
        assert_eq!(load(&paths).machine.secret_storage, SecretStorage::File);
        assert_eq!(config_key_at(&paths), (true, false));
        // Asked again, setup leaves the files as they are.
        let (r, out) = setup_with(&paths, "\n\n\n");
        r.unwrap();
        assert!(!out.contains("are in files now"), "{out}");
        assert_eq!(load(&paths).machine.secret_storage, SecretStorage::File);
    }

    /// Where no keyring answers, `config set machine.secret_storage
    /// keyring` at a terminal offers to install one: no keeps the files,
    /// yes installs it.
    #[test]
    fn config_set_offers_a_keyring_where_none_answers() {
        let (_d, paths) = setup(&[]);
        let k = crate::keyring_setup::tests::FakeKeyring::new(false);
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let offer = |answers: &str| {
            let mut out = Vec::new();
            let mut input = std::io::Cursor::new(answers.as_bytes().to_vec());
            let r = rt.block_on(offer_keyring(&paths, None, &k, Some(&mut input), &mut out));
            (r, String::from_utf8(out).unwrap())
        };
        let (r, out) = offer("n\n");
        assert!(r.unwrap_err().contains("no system keyring answers"));
        assert!(out.contains("Install it now? [y/N]"), "{out}");
        assert!(k.installed.borrow().is_empty());
        let (r, out) = offer("y\n");
        r.unwrap();
        assert_eq!(k.installed.borrow().len(), 1);
        assert!(out.contains("the system keyring answers"), "{out}");
    }
}
