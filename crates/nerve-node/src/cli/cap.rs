//! `nerve-node cap`: the capabilities the centers see, their settings, and
//! the capabilities node.toml declares.

use super::*;

/// `cap set`: a capability on, off or hidden for a center.
pub(super) async fn set_cap(
    paths: NodePaths,
    cap: String,
    setting: String,
    center: CenterArg,
    out: &mut dyn Write,
) -> Result<(), String> {
    let s = CapSetting::parse(&setting)
        .ok_or_else(|| format!("unknown setting {setting} (on, off or hidden)"))?;
    let name = edit_center(&paths, &center, |e| {
        e.policy.caps.insert(cap.clone(), s);
        Ok(())
    })
    .await?;
    w(out, format!("{name}: {cap} {setting}"));
    Ok(())
}

/// A bare `cap`: every capability with its effect and settings.
pub(super) async fn show_caps(
    paths: NodePaths,
    center: Option<String>,
    out: &mut dyn Write,
) -> Result<(), String> {
    let (cfg, _) = read_config(&paths).await?;
    if let Some(c) = &center {
        cfg.center(c).ok_or_else(|| no_center_named(&cfg, c))?;
    }
    let v = cap_listing(&paths, &cfg).await?;
    for l in cap_lines(&cfg, &v, center.as_deref()) {
        w(out, l);
    }
    Ok(())
}

/// `cap add`: declares a capability in node.toml.
pub(super) async fn add_cap(
    paths: NodePaths,
    name: String,
    spec: CapSpec,
    command: Vec<String>,
    out: &mut dyn Write,
) -> Result<(), String> {
    let effect = spec
        .effect
        .as_deref()
        .ok_or("cap add needs --effect: read, write, execute, sense or actuate")?;
    let mut c = nerve_policy::config::ConfigCapability {
        name: name.clone(),
        summary: String::new(),
        effect: parse_enum(effect, "read, write, execute, sense or actuate")?,
        command,
        params: Value::Null,
        result: Default::default(),
        timeout_secs: None,
        platform: Default::default(),
    };
    let input = cap_stdin(&spec)?;
    cap_spec(&spec, input.as_deref(), &mut c)?;
    // The programs that offer its capability now, which the node
    // lets go once the config names it (a note only: where the
    // listing fails, none is named).
    let (before, _) = read_config(&paths).await?;
    let programs = if crate::config_cap::names(&before, c.split().0) {
        Vec::new()
    } else {
        cap_listing(&paths, &before)
            .await
            .map(|v| programs_offering(&v, c.split().0))
            .unwrap_or_default()
    };
    let held = std::sync::Mutex::new(Vec::new());
    edit(&paths, |cfg| {
        if cfg.capabilities.iter().any(|d| d.name == name) {
            return Err(format!(
                "a capability {name} is declared already; `cap edit` changes it"
            ));
        }
        let before = cfg.clone();
        cfg.capabilities.push(c.clone());
        *nerve_transport::sync::lock(&held) = crate::config_cap::hold_new(&before, cfg);
        Ok(())
    })
    .await?;
    w(out, format!("capability {name} added: {}", cap_line(&c)));
    let notes = CapNotes {
        installed: crate::service::is_service_node(&paths),
        held: nerve_transport::sync::into_inner(held),
        programs,
    };
    for note in notes.of(&c) {
        w(out, note);
    }
    Ok(())
}

/// `cap edit`: changes a capability node.toml declares.
pub(super) async fn edit_cap(
    paths: NodePaths,
    name: String,
    spec: CapSpec,
    command: Vec<String>,
    out: &mut dyn Write,
) -> Result<(), String> {
    let input = cap_stdin(&spec)?;
    let held = std::sync::Mutex::new(Vec::new());
    edit(&paths, |cfg| {
        let before = cfg.clone();
        let c = cfg
            .capabilities
            .iter_mut()
            .find(|d| d.name == name)
            .ok_or_else(|| {
                format!("no capability {name} is declared; `nerve-node cap` lists them")
            })?;
        if let Some(e) = &spec.effect {
            c.effect = parse_enum(e, "read, write, execute, sense or actuate")?;
        }
        if !command.is_empty() {
            c.command = command.clone();
        }
        cap_spec(&spec, input.as_deref(), c)?;
        *nerve_transport::sync::lock(&held) = crate::config_cap::hold_new(&before, cfg);
        Ok(())
    })
    .await?;
    let (cfg, _) = read_config(&paths).await?;
    let c = cfg
        .capabilities
        .iter()
        .find(|d| d.name == name)
        .ok_or_else(|| format!("no capability {name} is declared; `nerve-node cap` lists them"))?;
    w(out, format!("capability {name} changed: {}", cap_line(c)));
    let notes = CapNotes {
        installed: crate::service::is_service_node(&paths),
        held: nerve_transport::sync::into_inner(held),
        programs: Vec::new(),
    };
    for note in notes.of(c) {
        w(out, note);
    }
    Ok(())
}

/// `cap rm --center`: removes a capability that center added.
pub(super) async fn rm_added_cap(
    paths: NodePaths,
    name: String,
    center: String,
    out: &mut dyn Write,
) -> Result<(), String> {
    edit(&paths, |c| {
        let owners = c.capabilities.clone();
        let missing = no_center_named(c, &center);
        let e = c.center_mut(&center).ok_or(missing)?;
        if !crate::config_cap::remove_added(e, &name, &owners) {
            return Err(format!("center {center} added no capability {name}"));
        }
        Ok(())
    })
    .await?;
    w(out, format!("capability {name} of center {center} removed"));
    Ok(())
}

/// `cap rm`: removes a capability node.toml declares.
pub(super) async fn rm_cap(
    paths: NodePaths,
    name: String,
    out: &mut dyn Write,
) -> Result<(), String> {
    let held = std::sync::Mutex::new(Vec::new());
    edit(&paths, |c| {
        let was = c.clone();
        c.capabilities.retain(|d| d.name != name);
        if c.capabilities.len() == was.capabilities.len() {
            // One a center added is removed with that center named.
            let by: Vec<&str> = c
                .centers
                .iter()
                .filter(|e| e.capabilities.iter().any(|d| d.name == name))
                .map(|e| e.name.as_str())
                .collect();
            return Err(match by.first() {
                Some(first) => format!(
                    "no capability {name} is declared in node.toml; center {} added one: cap rm {name} --center {first}",
                    by.join(", center ")
                ),
                None => format!("no capability {name} is declared; `nerve-node cap` lists them"),
            });
        }
        // A center's own of that name that senses is offered again,
        // and waits for an `on` given for its command.
        *nerve_transport::sync::lock(&held) = crate::config_cap::hold_new(&was, c);
        Ok(())
    })
    .await?;
    w(out, format!("capability {name} removed"));
    for (center, name) in nerve_transport::sync::into_inner(held) {
        w(out, held_note(&center, &name));
    }
    Ok(())
}

/// What `cap` lists (crate::provider::listing): the running node's, over
/// its control socket (on Windows its pipe), else what the config alone
/// tells.
pub(super) async fn cap_listing(paths: &NodePaths, cfg: &NodeConfig) -> Result<Value, String> {
    #[cfg(unix)]
    let r = nerve_transport::ctl::call(&paths.ctl_socket(), "caps.list", json!({})).await;
    #[cfg(windows)]
    let r = crate::pipe::call(paths, "caps.list", json!({})).await;
    match r {
        Ok(v) => Ok(v),
        Err(e) if e == nerve_transport::ctl::NOT_RUNNING => Ok(crate::provider::listing(
            cfg,
            None,
            crate::service::is_service_node(paths),
        )),
        Err(e) => Err(e),
    }
}

/// The lines of `cap`: one per action (and a program's state key, event
/// or stream, with its kind), with its effect, where it comes
/// from and each center's setting (`center` only), the settings that name
/// no action offered now, and the programs.
fn cap_lines(cfg: &NodeConfig, v: &Value, center: Option<&str>) -> Vec<String> {
    let mut rows = v["capabilities"].as_array().cloned().unwrap_or_default();
    // What a center added is offered to it alone: one center's view leaves
    // out what the others added.
    if let Some(w) = center {
        rows.retain(|r| !added_by_other(r, w));
    }
    let text = |r: &Value, k: &str| r[k].as_str().unwrap_or("-").to_string();
    // A program's state key, event or stream says its kind after its effect.
    let effect = |r: &Value| match r["kind"].as_str() {
        Some(kind) => format!("{} {kind}", text(r, "effect")),
        None => text(r, "effect"),
    };
    let width = |k: &str| rows.iter().map(|r| text(r, k).len()).max().unwrap_or(0);
    let (wn, ws) = (width("name"), width("source"));
    let we = rows.iter().map(|r| effect(r).len()).max().unwrap_or(0);
    let mut lines = Vec::new();
    for r in &rows {
        let what = match r["broken"].as_str().or(r["left_out"].as_str()) {
            Some(why) => format!("left out: {why}"),
            None => r["centers"]
                .as_object()
                .into_iter()
                .flatten()
                .filter(|(c, _)| center.is_none_or(|w| w == c.as_str()))
                .map(|(c, set)| {
                    let set = set.as_str().unwrap_or_default();
                    // The running node says whether the center may use it
                    // now, and the switch where the owner set one.
                    let state = match (r["now"][c].as_str(), set) {
                        (_, "hidden") | (None, _) => set.to_string(),
                        (Some(now), "default") => now.to_string(),
                        // `settings`: its grant, not a switch.
                        (Some(now), "granted" | "not granted") => format!("{now} ({set})"),
                        (Some(now), set) => format!("{now} (set {set})"),
                    };
                    format!("{c}: {state}")
                })
                .collect::<Vec<_>>()
                .join(", "),
        };
        let line = format!(
            "{:wn$}  {:we$}  {:ws$}  {what}",
            text(r, "name"),
            effect(r),
            text(r, "source"),
        );
        lines.push(line.trim_end().to_string());
    }
    // A setting for a capability or action that nothing offers now still
    // counts once something does.
    for c in &cfg.centers {
        if center.is_some_and(|w| w != c.name) {
            continue;
        }
        let names: Vec<String> = rows
            .iter()
            .filter(|r| !added_by_other(r, &c.name))
            .map(|r| text(r, "name"))
            .collect();
        for (key, set) in &c.policy.caps {
            let offered = names
                .iter()
                .any(|n| n == key || n.split_once('.').is_some_and(|(cap, _)| cap == key));
            if !offered {
                lines.push(format!(
                    "{}: {key} {} (offered by nothing now)",
                    c.name,
                    enum_str(set)
                ));
            }
        }
    }
    if v["running"] == false {
        lines.push(
            "the node does not run: each center's switch shows (cap set); whether it may use an action now, and the programs' capabilities, show while the node runs"
                .into(),
        );
    }
    lines.extend(config_lines(v, center));
    lines.extend(program_lines(v));
    lines
}

/// Whether the row `r` of `cap --json` is of a capability a center other
/// than `center` added (crate::provider::listing gives it the source
/// `center NAME`).
pub(super) fn added_by_other(r: &Value, center: &str) -> bool {
    r["source"]
        .as_str()
        .and_then(|s| s.strip_prefix("center "))
        .is_some_and(|c| c != center)
}

/// The schema `spec` takes from stdin, if it takes one: read in the
/// command, from the owner's input (crate::owner::reads_input), never from
/// a file the node would open.
fn cap_stdin(spec: &CapSpec) -> Result<Option<String>, String> {
    if spec.params_stdin() && spec.result_stdin() {
        return Err("stdin holds one schema: give --params or --result as `-`, not both".into());
    }
    if !(spec.params_stdin() || spec.result_stdin()) {
        return Ok(None);
    }
    let mut text = String::new();
    std::io::Read::read_to_string(&mut std::io::stdin(), &mut text)
        .map_err(|e| format!("cannot read stdin: {e}"))?;
    Ok(Some(text))
}

/// Sets what `spec` gives of `c`, with `stdin` the schema [`cap_stdin`]
/// read: each one given replaces what `c` has.
fn cap_spec(
    spec: &CapSpec,
    stdin: Option<&str>,
    c: &mut nerve_policy::config::ConfigCapability,
) -> Result<(), String> {
    use nerve_policy::config::{Output, Platform};
    let stdin = || {
        stdin
            .map(str::to_string)
            .ok_or("nothing came on stdin".to_string())
    };
    if let Some(s) = &spec.summary {
        c.summary = s.trim().to_string();
    }
    let params = match (&spec.params, spec.params_stdin()) {
        (_, true) => Some(stdin()?),
        (p, false) => p.clone(),
    };
    if let Some(p) = params {
        c.params = if p.trim() == "none" {
            Value::Null
        } else {
            serde_json::from_str(&p).map_err(|e| format!("--params: not JSON: {e}"))?
        };
    }
    let result = match (&spec.result, spec.result_stdin()) {
        (_, true) => Some(stdin()?),
        (r, false) => r.clone(),
    };
    if let Some(r) = result {
        c.result = Output::parse(&r)?;
    }
    if let Some(t) = &spec.timeout {
        c.timeout_secs = match t.as_str() {
            "default" => None,
            n => Some(
                n.parse()
                    .map_err(|_| format!("--timeout {n}: seconds, or default"))?,
            ),
        };
    }
    if let Some(p) = &spec.platform {
        c.platform =
            Platform::parse(p).ok_or_else(|| format!("--platform {p}: any, linux or windows"))?;
    }
    Ok(())
}

/// One config capability in words: its command, and what else the owner
/// set.
fn cap_line(c: &nerve_policy::config::ConfigCapability) -> String {
    let mut line = c.command_line();
    if !c.platform.is_any() {
        line.push_str(&format!("; {} only", c.platform.as_str()));
    }
    if let Some(t) = c.timeout_secs {
        line.push_str(&format!("; timeout {t} s"));
    }
    line
}

/// What the owner is told of an action `name` that came to sense or
/// actuate and was switched off for `center` (crate::config_cap::hold_new).
pub(super) fn held_note(center: &str, name: &str) -> String {
    format!(
        "{center}: a switch or allow rule set before covered {name}; it is off there now until you turn it on"
    )
}

/// What the owner is told of `name`, an action `center` added that senses
/// or actuates, switched off as `config accept` took a file that turns it
/// on while a program keeps it out (crate::config_cap::hold_shadowed).
#[cfg(unix)]
pub(super) fn shadowed_note(center: &str, name: &str) -> String {
    let cap = name.split_once('.').map_or(name, |(c, _)| c);
    format!(
        "{center}: its own {name} senses or actuates and is left out while a program offers {cap}, so the file's on or allow rule for it is off there now; turn it on once the center is offered it (cap set {name} on --center {center}), or remove it (cap rm {name} --center {center})"
    )
}

/// What the owner is told of `name`, a switch `config accept` set to `off`
/// for `center`, which keeps one of its own under a program's capability:
/// the file's `on` or allow rule for it would go with the center's own
/// (crate::config_cap::hold_with_own).
#[cfg(unix)]
pub(super) fn with_own_note(center: &str, name: &str) -> String {
    let cap = name.split_once('.').map_or(name, |(c, _)| c);
    format!(
        "{center}: keeps a capability of its own under {cap}, so it is offered neither that one nor a program's {cap}, and the file's on or allow rule for {name} would go with the center's own when it is removed; {name} is off there now, and stays so: remove the center's first (cap --center {center} lists them, cap rm NAME --center {center} removes one), then turn on the program's (cap set {name} on --center {center})"
    )
}

/// What the owner is told of `scope`, an `on` or allow rule of `center`
/// that `config accept` took away with that center's own capability, which
/// the file no longer holds (crate::config_cap::drop_removed).
#[cfg(unix)]
pub(super) fn dropped_note(center: &str, scope: &str) -> String {
    format!(
        "{center}: its own capability is gone from the file, so its on and allow rules for {scope} went with it"
    )
}

/// The programs whose rows in `listing` (`caps.list`) offer the capability
/// `cap` now.
fn programs_offering(listing: &Value, cap: &str) -> Vec<String> {
    let mut found: Vec<String> = listing["capabilities"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|r| {
            r["name"]
                .as_str()
                .is_some_and(|n| n.split_once('.').map_or(n, |(c, _)| c) == cap)
        })
        .filter_map(|r| r["source"].as_str()?.strip_prefix("program "))
        .map(str::to_string)
        .collect();
    found.dedup();
    found
}

/// What the owner should know of a capability once `cap add` or `cap edit`
/// declared it.
struct CapNotes {
    /// Whether this is the installed node.
    installed: bool,
    /// The centers and actions `crate::config_cap::hold_new` switched off.
    held: Vec<(String, String)>,
    /// The programs that offered its capability and are let go.
    programs: Vec<String>,
}

impl CapNotes {
    /// The notes on `c`: where this node does not offer it; that the agent
    /// sees no description; that a center gets one
    /// that senses or actuates only once the owner allows it, and for which
    /// centers it was switched off; and which programs lost their
    /// capability to it.
    fn of(&self, c: &nerve_policy::config::ConfigCapability) -> Vec<String> {
        let mut notes = Vec::new();
        if let Some(why) = crate::config_cap::left_out(c, std::env::consts::OS, self.installed) {
            notes.push(format!("this node does not offer it: {why}"));
        }
        if c.summary.is_empty() {
            notes.push(format!(
                "it has no summary, so the agent sees no description of it (cap edit {} --summary TEXT)",
                c.name
            ));
        }
        if crate::config_cap::senses(c.effect) {
            notes.push(format!(
                "it {}s: a center gets it only once you turn it on for that center (cap set {} on --center NAME), in allowlist mode once you add an allow rule for it",
                c.effect.as_str(),
                c.name
            ));
        }
        for (center, name) in &self.held {
            notes.push(held_note(center, name));
        }
        for p in &self.programs {
            notes.push(format!(
                "the program {p} offered {} and is let go: node.toml's capability takes the name",
                c.split().0
            ));
        }
        notes
    }
}

/// The lines of `cap` for the capabilities of node.toml: each one's
/// command and what else the owner set. Of those the centers added, only
/// `center`'s where one is given.
fn config_lines(v: &Value, center: Option<&str>) -> Vec<String> {
    let added = v["added"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(move |e| center.is_none_or(|w| e["center"] == w));
    v["config"]
        .as_array()
        .into_iter()
        .flatten()
        .chain(added)
        .filter_map(|e| serde_json::from_value::<ConfigEntry>(e.clone()).ok())
        .map(|e| {
            // One a center added says which, and how it counts: as execute,
            // unless it senses or actuates, which only the owner turns on.
            // It says so as what the capability is, not whether it is on
            // now: the rows of `cap` above say that.
            let by = match &e.center {
                Some(c) if e.effect == nerve_proto::descriptor::Effect::Sense => {
                    format!(" (added by center {c}, senses: only you turn it on)")
                }
                Some(c) if e.effect == nerve_proto::descriptor::Effect::Actuate => {
                    format!(" (added by center {c}, actuates: only you turn it on)")
                }
                Some(c) => format!(" (added by center {c}, counted as execute)"),
                None => String::new(),
            };
            let c = nerve_policy::config::ConfigCapability {
                name: e.name,
                summary: String::new(),
                effect: e.effect,
                command: e.command,
                params: Value::Null,
                result: Default::default(),
                timeout_secs: e.timeout_secs,
                platform: nerve_policy::config::Platform::parse(&e.platform).unwrap_or_default(),
            };
            format!("capability {}{by}: {}", c.name, cap_line(&c))
        })
        .collect()
}

/// What [`config_lines`] reads of an entry of `cap --json`'s `config`.
#[derive(serde::Deserialize)]
struct ConfigEntry {
    name: String,
    effect: nerve_proto::descriptor::Effect,
    command: Vec<String>,
    timeout_secs: Option<u64>,
    platform: String,
    /// The center that added it; none for the owner's.
    #[serde(default)]
    center: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::tests::{json_of, load, program_path, run, setup};

    /// `cap` lists every action of the node's own capabilities with its
    /// effect, where it comes from and each center's setting (`--center`:
    /// that one's), a setting for what nothing offers now, and the programs
    /// allowed; a stopped node knows no program's capabilities and says so.
    #[test]
    fn cap_ls_lists_every_capability_with_its_effect_and_settings() {
        let (_d, paths) = setup(&["home", "lab"]);
        let desk = program_path("usr/bin/desk");
        run(
            &paths,
            &["cap", "set", "fs.write", "off", "--center", "home"],
        )
        .unwrap();
        run(&paths, &["cap", "set", "lamp", "on", "--center", "lab"]).unwrap();
        run(&paths, &["center", "settings", "on", "lab"]).unwrap();
        run(&paths, &["provider", "add", "desk", &desk]).unwrap();
        let ls = run(&paths, &["cap"]).unwrap();
        let line = |name: &str| {
            ls.lines()
                .find(|l| l.split_whitespace().next() == Some(name))
                .unwrap_or_else(|| panic!("no {name}: {ls}"))
                .split_whitespace()
                .collect::<Vec<_>>()
                .join(" ")
        };
        assert_eq!(
            line("fs.write"),
            "fs.write write built-in home: off, lab: default"
        );
        assert_eq!(
            line("exec.run"),
            "exec.run execute built-in home: default, lab: default"
        );
        // `settings`, which only the grant governs, is listed too.
        assert_eq!(
            line("settings.set"),
            "settings.set write built-in home: not granted, lab: granted"
        );
        assert!(ls.contains("lab: lamp on (offered by nothing now)"), "{ls}");
        assert!(ls.contains("the node does not run"), "{ls}");
        assert!(
            ls.contains(&format!("program desk: {desk}, the node does not run")),
            "{ls}"
        );
        let one = run(&paths, &["cap", "--center", "lab"]).unwrap();
        assert!(!one.contains("home:"), "{one}");
        assert!(one.contains("fs.write"), "{one}");
        assert!(run(&paths, &["cap", "--center", "nope"]).is_err());

        let v = json_of(&paths, &["cap"]);
        let write = v["capabilities"]
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["name"] == "fs.write")
            .unwrap();
        assert_eq!(write["effect"], "write", "{v}");
        assert_eq!(write["source"], "built-in", "{v}");
        assert_eq!(write["centers"], json!({"home": "off", "lab": "default"}));
        assert_eq!(v["running"], false, "{v}");
        assert_eq!(
            v["programs"],
            json!([{"name": "desk", "exe": desk, "attached": null}])
        );
        // Two centers and none picked: no one center's switches.
        assert!(v.get("known").is_none(), "{v}");
        let v = json_of(&paths, &["cap", "--center", "lab"]);
        assert_eq!(v["center"], "lab");
        assert_eq!(v["caps"], json!({"lamp": "on"}));
    }

    /// `cap add`, `edit` and `rm` declare the owner's own capabilities in
    /// node.toml, checked as the node checks them; `cap` lists them with
    /// their command and account, and says where this node does not offer
    /// one.
    /// A capability of node.toml that comes to sense or actuate, added or
    /// changed so, is switched off for each center whose earlier switch
    /// (its capability's, or its own while it only read) or allow rule
    /// covers it, and the owner is told; one switched off already, one that
    /// sensed before, and a center nothing covers are left as they are.
    #[test]
    fn a_capability_that_comes_to_sense_waits_for_the_owner() {
        let (_d, paths) = setup(&["lab", "ops", "quiet", "shut"]);
        let caps = |paths: &NodePaths, center: &str| {
            load(paths).center(center).unwrap().policy.caps.clone()
        };
        run(&paths, &["cap", "set", "probe", "on", "--center", "lab"]).unwrap();
        run(
            &paths,
            &["config", "add", "center.ops.policy.allow", "probe"],
        )
        .unwrap();
        run(&paths, &["cap", "set", "probe", "on", "--center", "shut"]).unwrap();
        run(
            &paths,
            &["cap", "set", "probe.cam", "off", "--center", "shut"],
        )
        .unwrap();
        let said = run(
            &paths,
            &[
                "cap",
                "add",
                "probe.cam",
                "--effect",
                "sense",
                "--summary",
                "A frame.",
                "--",
                "cam",
            ],
        )
        .unwrap();
        for center in ["lab", "ops"] {
            assert!(
                said.contains(&format!("{center}: a switch or allow rule set before covered probe.cam; it is off there now")),
                "{said}"
            );
            assert_eq!(
                caps(&paths, center).get("probe.cam"),
                Some(&CapSetting::Off),
                "{center}"
            );
        }
        assert!(
            !said.contains("quiet:") && !said.contains("shut:"),
            "{said}"
        );
        assert_eq!(caps(&paths, "quiet").get("probe.cam"), None);
        assert!(
            said.contains("in allowlist mode once you add an allow rule"),
            "{said}"
        );
        // The owner turns it on; a change that leaves it sensing keeps that.
        run(
            &paths,
            &["cap", "set", "probe.cam", "on", "--center", "lab"],
        )
        .unwrap();
        let said = run(
            &paths,
            &["cap", "edit", "probe.cam", "--summary", "A photo."],
        )
        .unwrap();
        assert!(!said.contains("off there now"), "{said}");
        assert_eq!(caps(&paths, "lab").get("probe.cam"), Some(&CapSetting::On));
        // One that read and comes to actuate: its own switch counts too.
        let said = run(
            &paths,
            &[
                "cap",
                "add",
                "probe.list",
                "--effect",
                "read",
                "--summary",
                "S.",
                "--",
                "ls",
            ],
        )
        .unwrap();
        assert!(!said.contains("off there now"), "{said}");
        run(
            &paths,
            &["cap", "set", "probe.list", "on", "--center", "quiet"],
        )
        .unwrap();
        let said = run(
            &paths,
            &["cap", "edit", "probe.list", "--effect", "actuate"],
        )
        .unwrap();
        for center in ["lab", "ops", "quiet"] {
            assert!(said.contains(&format!("{center}: a switch")), "{said}");
            assert_eq!(
                caps(&paths, center).get("probe.list"),
                Some(&CapSetting::Off),
                "{center}"
            );
        }
        // A switch left from a capability that was removed holds a new one
        // of that name too.
        run(
            &paths,
            &["cap", "set", "lamp.flash", "on", "--center", "quiet"],
        )
        .unwrap();
        let said = run(
            &paths,
            &[
                "cap",
                "add",
                "lamp.flash",
                "--effect",
                "actuate",
                "--",
                "flash",
            ],
        )
        .unwrap();
        assert!(said.contains("quiet: a switch"), "{said}");
        assert_eq!(
            caps(&paths, "quiet").get("lamp.flash"),
            Some(&CapSetting::Off)
        );
    }

    /// What `cap add` and `cap edit` tell the owner besides: that one with
    /// no summary shows the agent no description, and which programs lost
    /// their capability to it.
    #[test]
    fn cap_notes_say_what_the_owner_should_know() {
        let mut c = nerve_policy::config::ConfigCapability {
            name: "x.run".into(),
            summary: String::new(),
            effect: nerve_proto::descriptor::Effect::Execute,
            command: vec!["make".into()],
            params: Value::Null,
            result: Default::default(),
            timeout_secs: None,
            platform: Default::default(),
        };
        let notes = |c: &nerve_policy::config::ConfigCapability| {
            CapNotes {
                installed: true,
                held: Vec::new(),
                programs: vec!["desk".into()],
            }
            .of(c)
            .join("\n")
        };
        let said = notes(&c);
        assert!(said.contains("it has no summary"), "{said}");
        assert!(
            said.contains("the program desk offered x and is let go"),
            "{said}"
        );
        c.summary = "Builds.".into();
        assert!(!notes(&c).contains("summary"));
    }

    #[test]
    fn cap_add_edit_and_rm_declare_capabilities_of_node_toml() {
        let (_d, paths) = setup(&["lab"]);
        let params = r#"{"type": "object", "properties": {"path": {"type": "string", "x-nerve-path": "read"}}, "required": ["path"]}"#;
        let said = run(
            &paths,
            &[
                "cap",
                "add",
                "logs.tail",
                "--effect",
                "read",
                "--summary",
                "The end of a log.",
                "--params",
                params,
                "--timeout",
                "5",
                "--",
                "tail",
                "-n",
                "20",
                "--",
                "{path}",
            ],
        )
        .unwrap();
        assert!(
            said.contains("capability logs.tail added: tail -n 20 -- {path}; timeout 5 s"),
            "{said}"
        );
        let c = load(&paths).capabilities[0].clone();
        assert_eq!(c.command, ["tail", "-n", "20", "--", "{path}"]);
        assert_eq!(c.params["required"], json!(["path"]));
        assert_eq!(c.summary, "The end of a log.");
        assert_eq!(c.timeout_secs, Some(5));
        // A node run by hand has no nerve-run; Windows offers none yet.
        let not_here = if cfg!(target_os = "linux") {
            "this node does not offer it: runs as nerve-run"
        } else {
            "this node does not offer it: a node on"
        };
        assert!(said.contains(not_here), "{said}");
        // Checked as the node checks it.
        for (args, why) in [
            (
                &["cap", "add", "logs.tail", "--effect", "read", "--", "tail"][..],
                "declared already",
            ),
            (&["cap", "add", "logs.x", "--", "tail"], "needs --effect"),
            (
                &[
                    "cap", "add", "logs.x", "--effect", "read", "--", "cat", "{path}",
                ],
                "names no argument",
            ),
            (
                &["cap", "add", "fs.x", "--effect", "read", "--", "cat"],
                "the node's or the center's own",
            ),
            (
                &["cap", "add", "logs.x", "--effect", "look", "--", "cat"],
                "expected read, write",
            ),
            (
                &[
                    "cap", "add", "logs.x", "--effect", "read", "--params", "{", "--", "cat",
                ],
                "not JSON",
            ),
            (
                &[
                    "cap",
                    "add",
                    "logs.x",
                    "--effect",
                    "read",
                    "--account",
                    "owner",
                    "--",
                    "cat",
                ],
                "unexpected argument '--account'",
            ),
            (
                &[
                    "cap",
                    "add",
                    "logs.x",
                    "--effect",
                    "read",
                    "--timeout",
                    "99999",
                    "--",
                    "cat",
                ],
                "max_timeout_secs",
            ),
            (
                &["cap", "edit", "logs.none", "--timeout", "5"],
                "no capability logs.none",
            ),
            (&["cap", "rm", "logs.none"], "no capability logs.none"),
        ] {
            let e = run(&paths, args).unwrap_err();
            assert!(e.contains(why), "{args:?}: {e}");
        }
        assert!(run(&paths, &["cap", "add", "logs.x", "--effect", "read"]).is_err());
        assert_eq!(load(&paths).capabilities.len(), 1);
        // Edit: what is given replaces, the rest stays.
        let said = run(
            &paths,
            &[
                "cap",
                "edit",
                "logs.tail",
                "--timeout",
                "default",
                "--effect",
                "sense",
            ],
        )
        .unwrap();
        assert!(
            said.contains("capability logs.tail changed: tail -n 20 -- {path}\n"),
            "{said}"
        );
        assert!(
            said.contains("a center gets it only once you turn it on"),
            "{said}"
        );
        let c = load(&paths).capabilities[0].clone();
        assert_eq!(c.timeout_secs, None);
        assert_eq!(c.command, ["tail", "-n", "20", "--", "{path}"]);
        run(
            &paths,
            &[
                "cap",
                "edit",
                "logs.tail",
                "--params",
                "none",
                "--",
                "uptime",
            ],
        )
        .unwrap();
        let c = load(&paths).capabilities[0].clone();
        assert!(c.params.is_null());
        assert_eq!(c.command, ["uptime"]);
        // A new one for another platform.
        run(
            &paths,
            &[
                "cap",
                "add",
                "win.who",
                "--effect",
                "read",
                "--platform",
                "windows",
                "--result",
                r#"{"type": "string"}"#,
                "--",
                "whoami",
            ],
        )
        .unwrap();
        let ls = run(&paths, &["cap"]).unwrap();
        let line = |name: &str| {
            ls.lines()
                .find(|l| l.split_whitespace().next() == Some(name))
                .unwrap_or_else(|| panic!("no {name}: {ls}"))
                .split_whitespace()
                .collect::<Vec<_>>()
                .join(" ")
        };
        if cfg!(target_os = "linux") {
            // A node run by hand offers none and says why.
            assert_eq!(
                line("logs.tail"),
                "logs.tail sense config left out: runs as nerve-run, which only the installed node has (sudo nerve-node install)"
            );
            assert!(
                line("win.who").ends_with("left out: for windows only"),
                "{ls}"
            );
        }
        assert!(ls.contains("capability logs.tail: uptime\n"), "{ls}");
        assert!(
            ls.contains("capability win.who: whoami; windows only"),
            "{ls}"
        );
        let v = json_of(&paths, &["cap"]);
        assert_eq!(
            v["config"][1],
            json!({"name": "win.who", "summary": "", "effect": "read", "command": ["whoami"],
                   "params": null, "result": {"type": "string"}, "timeout_secs": null,
                   "platform": "windows"})
        );
        assert_eq!(v["config"][0]["result"], "text");
        let row = v["capabilities"]
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["name"] == "win.who")
            .unwrap();
        assert_eq!(row["source"], "config", "{row}");
        assert!(row["left_out"].is_string(), "{row}");
        // The changing commands say what they did as messages.
        let v = json_of(&paths, &["cap", "rm", "win.who"]);
        assert_eq!(v["messages"][0], "capability win.who removed", "{v}");
        run(&paths, &["cap", "rm", "logs.tail"]).unwrap();
        assert!(load(&paths).capabilities.is_empty());
    }

    /// `cap` of a running node asks it, on Windows over its pipe: it
    /// does not say the node does not run, and tells each center's state
    /// now.
    #[test]
    fn cap_ls_asks_the_running_node() {
        let (d, paths) = setup(&["home"]);
        let desk = program_path("usr/bin/desk");
        run(&paths, &["provider", "add", "desk", &desk]).unwrap();
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        let mut opts = NodeOptions::new(paths.clone());
        opts.home = d.path().to_path_buf();
        // Not the rights of whoever runs the tests: an elevated run must pass.
        opts.full_rights = Some(false);
        let daemon = rt.block_on(Daemon::start(opts)).unwrap();
        let ls = run(&paths, &["cap"]).unwrap();
        assert!(!ls.contains("does not run"), "{ls}");
        assert!(
            ls.contains(&format!("program desk: {desk}, not attached")),
            "{ls}"
        );
        let v = json_of(&paths, &["cap"]);
        assert_eq!(v["running"], true, "{v}");
        let read = v["capabilities"]
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["name"] == "fs.read")
            .unwrap();
        assert!(read["now"]["home"].is_string(), "{v}");
        // `settings` says what the grant leaves the center now.
        let settings = |ls: &str| {
            ls.lines()
                .find(|l| l.starts_with("settings.set "))
                .unwrap_or_else(|| panic!("no settings.set: {ls}"))
                .split_whitespace()
                .collect::<Vec<_>>()
                .join(" ")
        };
        assert_eq!(
            settings(&ls),
            "settings.set write built-in home: off (not granted)"
        );
        run(&paths, &["center", "settings", "on"]).unwrap();
        // On Windows the change goes to the file and the running node takes
        // it at its next reload (the service's reload event); on Unix the
        // node took it already, and this finds nothing newer.
        daemon.reload().unwrap();
        let ls = run(&paths, &["cap"]).unwrap();
        assert_eq!(
            settings(&ls),
            "settings.set write built-in home: on (granted)"
        );
        rt.block_on(daemon.stop());
    }

    /// `cap --json` names what `cap set` switches, so the app need not.
    #[test]
    fn cap_ls_json_names_the_switchable_capabilities() {
        let (_d, paths) = setup(&["home"]);
        run(&paths, &["cap", "set", "exec", "off"]).unwrap();
        let v = json_of(&paths, &["cap"]);
        let known = &v["known"];
        assert!(
            known["fs"].as_array().unwrap().contains(&json!("read")),
            "{v}"
        );
        assert!(
            known["exec"].as_array().unwrap().contains(&json!("run")),
            "{v}"
        );
        assert!(
            known.get("settings").is_none() && known.get("node").is_none(),
            "{v}"
        );
        assert_eq!(v["caps"], json!({"exec": "off"}));
    }
}
