//! `nerve-node rule`: a center's lists of commands that are allowed,
//! forbidden or run with sudo, and the guard built in before them.

use super::*;

/// The rules of `center` among `rules` whose conditions no longer fit what
/// the node offers now (nerve_policy::rules::stale), each with why. Empty,
/// and the node not asked, where no rule has conditions.
pub(super) async fn stale_rules<'r>(
    paths: &NodePaths,
    cfg: &NodeConfig,
    center: &str,
    rules: impl Iterator<Item = &'r String>,
) -> Result<Vec<(String, String)>, String> {
    let with: Vec<&String> = rules.filter(|r| rules::has_conditions(r)).collect();
    if with.is_empty() {
        return Ok(Vec::new());
    }
    let params = listed_params(&cap_listing(paths, cfg).await?, center);
    Ok(with
        .into_iter()
        .filter_map(|r| Some((r.clone(), rules::stale(r, &params)?)))
        .collect())
}

fn push_unique(list: &mut Vec<String>, rule: &str) {
    if !list.iter().any(|r| r == rule) {
        list.push(rule.to_string());
    }
}

impl List {
    pub(super) fn of(self, p: &mut nerve_policy::CenterPolicy) -> &mut Vec<String> {
        match self {
            List::Allow => &mut p.allow,
            List::Deny => &mut p.deny,
            List::Sudo => &mut p.sudo_allow,
        }
    }

    pub(super) fn word(self) -> &'static str {
        match self {
            List::Allow => "allow",
            List::Deny => "deny",
            List::Sudo => "sudo",
        }
    }

    fn label(self) -> &'static str {
        match self {
            List::Allow => "allow rule (allowlist mode)",
            List::Deny => "deny rule",
            List::Sudo => "sudo allow list",
        }
    }

    fn parse(word: &str) -> Option<List> {
        [List::Allow, List::Deny, List::Sudo]
            .into_iter()
            .find(|l| l.word() == word)
    }

    /// The entry a command line stands for, for `rule add`: the same as
    /// [`List::command_rule`], but a line in the pattern form of `config add`
    /// (`fs.read:~/notes/*`, `fs:~/private/*`) is refused. As a command it
    /// would become a rule that never matches. A single letter before the `:`
    /// is a drive (`C:\tools\x.exe`), not a capability. A rule with
    /// conditions on an action's arguments is taken as it is.
    fn entry(
        self,
        command: &str,
        action: Option<&str>,
        arg: Option<&str>,
        exact: bool,
    ) -> Result<String, String> {
        if let Some(action) = action {
            return self.action_rule(action, command, arg, exact);
        }
        if arg.is_some() {
            return Err("--arg names an argument of the action --action names".into());
        }
        // A rule with conditions on an action's arguments
        // (`lamp.set:room=office`) is the rule as it is; the node checks
        // its arguments against what the action takes as it saves it.
        let text = command.trim();
        if matches!(self, List::Allow | List::Deny)
            && rules::has_conditions(text)
            && rules::scope_of(text).contains('.')
        {
            rules::validate(text)?;
            return Ok(text.to_string());
        }
        if matches!(self, List::Allow | List::Deny)
            && let Some((scope, _)) = command.trim().split_once(':')
            && (scope.contains('.') || scope.len() > 1)
            && rules::valid_scope(scope)
        {
            let hint = if scope == "guard" {
                "; the guard's rules are built in".to_string()
            } else {
                String::new()
            };
            return Err(format!(
                "`{scope}:` is the pattern form for files and other actions, not a command: add it with `nerve-node config add center.<name>.policy.{}`{hint}",
                self.word()
            ));
        }
        self.command_rule(command)
    }

    /// What an edited entry becomes, for `rule edit`: an entry in the form
    /// `rule` shows (a `cap.action:pattern` rule; on the sudo list a pattern
    /// of a sudo command) as it is, a plain command line as `add` makes it.
    fn edited(self, new: &str) -> Result<String, String> {
        let new = new.trim();
        if new.is_empty() {
            return Err("the new entry is empty: `rule rm` takes an entry away".into());
        }
        match self {
            List::Allow | List::Deny => match new.split_once(':') {
                // A single letter before the `:` is a drive, not a
                // capability (`C:\tools\x.exe`).
                Some((scope, _)) if scope.len() > 1 && rules::valid_scope(scope) => {
                    rules::validate(new)?;
                    Ok(new.to_string())
                }
                _ => self.command_rule(new),
            },
            List::Sudo => {
                let glob = if sudo_command(new).is_some() {
                    new.to_string()
                } else {
                    format!("sudo {new}")
                };
                rules::validate_command_glob(&glob)?;
                Ok(glob)
            }
        }
    }

    /// The rule of an audit entry of `action` (`fs.read`) with `target`, as
    /// the audit buttons of the desktop app and of the center make it
    /// ([`rules::rule_for`]). A target that ends in `*` is the wildcard: a
    /// command's ` *`, a folder's `/*`, or `*` alone for the capability of
    /// an action without a target. With `exact` the target is taken as it
    /// is, a `*` in it too: the audit's Allow and Deny buttons hand over the
    /// command an agent sent, and its `rm -rf *` must not become every
    /// `rm -rf`. The sudo list takes sudo commands only.
    pub(crate) fn action_rule(
        self,
        action: &str,
        target: &str,
        arg: Option<&str>,
        exact: bool,
    ) -> Result<String, String> {
        // A cut target is no longer the call's, so no rule can name it.
        if nerve_policy::audit::is_cut_target(target) {
            return Err("the target was cut to its start, so a rule cannot name it".into());
        }
        let (cap, act) = action
            .split_once('.')
            .ok_or_else(|| format!("{action:?} is not a capability and action, like fs.read"))?;
        match self {
            List::Sudo if (cap, act) != ("exec", "run") => {
                Err("the sudo list is for sudo commands (--action exec.run)".into())
            }
            List::Sudo if arg.is_some() => {
                Err("the sudo list holds commands; --arg is for the allow and deny lists".into())
            }
            List::Sudo if exact => rules::sudo_rule_for(target, false),
            List::Sudo => self.command_rule(target),
            // `--arg FIELD=VALUE`: the value as the audit entry shows it,
            // which the rule then holds to; the node reads it as the
            // argument's type when it saves the rule.
            _ if arg.is_some() => {
                let (field, value) = arg
                    .and_then(|p| p.split_once('='))
                    .ok_or("--arg takes FIELD=VALUE, like room=office")?;
                rules::rule_for(cap, act, target, false, Some((field, &json!(value))))
            }
            _ if exact => {
                if (cap, act) == ("exec", "run") && sudo_command(target.trim()).is_some() {
                    // The same refusal as the command line without --exact.
                    self.command_rule(target)?;
                }
                rules::rule_for(cap, act, target, false, None)
            }
            _ if (cap, act) == ("exec", "run") => self.command_rule(target),
            List::Allow | List::Deny if cap == "fs" => match target.trim().strip_suffix("/*") {
                Some(folder) => {
                    if !folder.is_empty() && !folder.starts_with('/') {
                        return Err(format!("{target:?} is not an absolute path"));
                    }
                    Ok(format!("{action}:{}/*", rules::escape(folder)))
                }
                None => rules::rule_for(cap, act, target, false, None),
            },
            List::Allow | List::Deny => {
                let wildcard = target.trim() == "*";
                let target = if wildcard { "" } else { target };
                rules::rule_for(cap, act, target, wildcard, None)
            }
        }
    }

    /// The rule a command line stands for. The allow and deny lists hold
    /// `exec.run` rules; the sudo list holds the sudo command lines, and takes
    /// the command with or without the `sudo` in front. A trailing ` *` is
    /// the wildcard: every command that starts with the words before it.
    /// `rule rm` uses it as it is, so a rule is removed with the command
    /// line that made it.
    fn command_rule(self, command: &str) -> Result<String, String> {
        let command = command.trim();
        let sudo = match self {
            List::Allow if sudo_command(command).is_some() => {
                return Err(format!(
                    "a sudo command goes on the sudo list: `nerve-node rule add allow '{command}'` puts it there"
                ));
            }
            List::Allow | List::Deny => false,
            List::Sudo => true,
        };
        if command == "*" {
            return Err("a `*` alone names no command: put it after one, as in `git *`".into());
        }
        let line = if sudo && sudo_command(command).is_none() {
            format!("sudo {command}")
        } else {
            command.to_string()
        };
        let Some(start) = wildcard_start(&line) else {
            return if sudo {
                rules::sudo_rule_for(&line, false)
            } else {
                rules::rule_for("exec", "run", &line, false, None)
            };
        };
        let glob = format!("{} *", rules::escape(start));
        if sudo {
            // `sudo *` would be every command as root.
            let named = sudo_command(start)
                .is_some_and(|rest| rest.split_whitespace().any(|w| !w.starts_with('-')));
            if !named {
                return Err(format!(
                    "{line:?}: name the command after sudo before the *"
                ));
            }
            rules::validate_command_glob(&glob)?;
            Ok(glob)
        } else {
            let rule = format!("exec.run:{glob}");
            rules::validate(&rule)?;
            Ok(rule)
        }
    }
}

/// What `rule add allow` adds for a center in `mode`: in folder and user
/// mode the allow rules do not count, and nothing else would say so.
fn allow_rules_note(name: &str, mode: Mode) -> Option<String> {
    (mode != Mode::Allowlist).then(|| {
        format!(
            "note: {name} is in {} mode, where allow rules do not count; `nerve-node mode allowlist --center {name}` uses them",
            mode.as_str()
        )
    })
}

/// The words before a command line's trailing ` *`, its wildcard; `None`
/// for a line without one. A `*` alone names no command.
fn wildcard_start(line: &str) -> Option<&str> {
    let start = line.trim().strip_suffix('*')?;
    let trimmed = start.trim_end();
    (trimmed.len() < start.len() && !trimmed.is_empty()).then_some(trimmed)
}

/// What a rule made of `command` covers, said after `rule add` when the
/// command has a wildcard: `rm *` is every `rm`, not the files in a folder.
fn wildcard_note(list: List, command: &str) -> Option<String> {
    let start = wildcard_start(command)?;
    let verb = match list {
        List::Deny => "forbids",
        List::Allow | List::Sudo => "allows",
    };
    Some(if start.split_whitespace().count() == 1 {
        format!("it {verb} every `{start}` command")
    } else {
        format!("it {verb} every command that starts with `{start}`")
    })
}

/// The target of `rule add --action` that widens an audit entry's `target`
/// as the audit buttons' wildcard does: a command to its program (a sudo
/// command to its program after `sudo` and its flags), a path to its
/// folder, any other action to its capability.
pub fn wildcard_target(cap: &str, action: &str, target: &str) -> String {
    let target = target.trim();
    match (cap, action) {
        ("exec", "run") => {
            let mut words = Vec::new();
            let sudo = sudo_command(target).is_some();
            for (i, w) in target.split_whitespace().enumerate() {
                words.push(w);
                if !sudo || (i > 0 && !w.starts_with('-')) {
                    break;
                }
            }
            format!("{} *", words.join(" "))
        }
        ("fs", _) => {
            let target = target.trim_end_matches('/');
            let folder = target.rfind('/').map_or("", |i| &target[..i]);
            format!("{folder}/*")
        }
        _ => "*".into(),
    }
}

/// The entry of `list` that `text` names: `text` itself, or the entry that
/// `rule` prints as `text` (its tab, carriage return and line feed written
/// `\t`, `\r`, `\n`). Else `text`.
fn shown_entry(list: &[String], text: &str) -> String {
    if list.iter().any(|r| r == text) {
        return text.to_string();
    }
    let raw = rules::unescape_controls(text);
    if raw != text && list.contains(&raw) {
        raw
    } else {
        text.to_string()
    }
}

/// The entry of one list that `text` names for `rule rm`: as the list shows
/// it, or the command line that made it. An error when both forms are on
/// the list as two entries.
fn entry_on(list: List, l: &[String], text: &str, center: &str) -> Result<Option<String>, String> {
    let shown = shown_entry(l, text);
    let made = list.command_rule(text).ok();
    match made {
        Some(made) if made != shown && l.contains(&shown) && l.contains(&made) => Err(format!(
            "both {shown:?} and {made:?} are on the {}: remove {made:?} first with `nerve-node rule rm {word} '{made}' --center {center}`, and then {shown:?} with `nerve-node rule rm {word} '{shown}' --center {center}`",
            list.label(),
            word = list.word(),
        )),
        _ if l.contains(&shown) => Ok(Some(shown)),
        Some(made) if l.contains(&made) => Ok(Some(made)),
        _ => Ok(None),
    }
}

/// `rule`, `rule add|rm|edit|guard`.
pub(super) async fn rule_cmd(
    paths: &NodePaths,
    c: Option<RuleCmd>,
    shown_list: Option<List>,
    shown_center: CenterArg,
    out: &mut dyn Write,
) -> Result<(), String> {
    let Some(c) = c else {
        return show_rules(paths, shown_list, &shown_center, out).await;
    };
    match c {
        RuleCmd::Add {
            list,
            command,
            action,
            arg,
            exact,
            center,
        } => {
            // A sudo command goes on the sudo list: the command says where.
            let target_is_sudo = action.as_deref().is_none_or(|a| a == "exec.run")
                && sudo_command(command.trim()).is_some();
            let list = match list {
                AddList::Allow if target_is_sudo => List::Sudo,
                AddList::Allow => List::Allow,
                AddList::Deny => List::Deny,
            };
            let rule = match (list, &action) {
                (List::Sudo, None) => list.command_rule(&command)?,
                _ => list.entry(&command, action.as_deref(), arg.as_deref(), exact)?,
            };
            let name = edit_center(paths, &center, |e| {
                push_unique(list.of(&mut e.policy), &rule);
                Ok(())
            })
            .await?;
            let note = match list {
                List::Deny => "; commands it matches are forbidden",
                _ => "",
            };
            let _ = writeln!(out, "{name}: {} {rule:?}{note}", list.label());
            // A wildcard is said with --action too: an audit entry's target
            // copied by hand may end in ` *` without meaning every command.
            if !exact
                && arg.is_none()
                && action.as_deref().is_none_or(|a| a == "exec.run")
                && let Some(covers) = wildcard_note(list, &command)
            {
                let _ = writeln!(out, "{covers}");
            }
            // An allow rule that does not count where the center is now is
            // said, not left to look like it works.
            if list == List::Allow {
                let (cfg, _) = read_config(paths).await?;
                let mode = cfg.center(&name).map(|c| c.policy.mode_at(crate::now_ms()));
                if let Some(note) = mode.and_then(|m| allow_rules_note(&name, m)) {
                    let _ = writeln!(out, "{note}");
                }
            }
        }
        RuleCmd::Rm { words, center } => {
            // `rule rm [LIST] ENTRY`, and a line of `rule` as it shows all
            // three lists (`allow  exec.run:git status`).
            let (named, text) =
                match words.as_slice() {
                    [list, entry] => (
                        Some(List::parse(list).ok_or_else(|| {
                            format!("{list:?} is not a list: allow, deny or sudo")
                        })?),
                        entry.clone(),
                    ),
                    [entry] => match entry.split_once("  ").map(|(l, e)| (List::parse(l), e)) {
                        Some((Some(l), e)) => (Some(l), e.to_string()),
                        _ => (None, entry.clone()),
                    },
                    _ => return Err("name the entry to remove".into()),
                };
            let removed = std::sync::Mutex::new((List::Allow, String::new()));
            let name = edit_center(paths, &center, |e| {
                let name = e.name.clone();
                let lists = match named {
                    Some(l) => vec![l],
                    // Only a command that starts with `sudo` is looked for
                    // on the sudo list when no list is named.
                    None if sudo_command(text.trim()).is_some() => {
                        vec![List::Allow, List::Deny, List::Sudo]
                    }
                    None => vec![List::Allow, List::Deny],
                };
                let mut found = Vec::new();
                for l in lists {
                    if let Some(entry) = entry_on(l, l.of(&mut e.policy), &text, &name)? {
                        found.push((l, entry));
                    }
                }
                if rules::is_guard(text.trim()) {
                    return Err(format!(
                        "{text:?} is a rule of the guard, which is built in: it cannot be removed"
                    ));
                }
                let (list, rule) = match found.as_slice() {
                    [] => {
                        return Err(match named {
                            Some(l) => format!(
                                "{text:?} is not on the {}; `nerve-node rule {}` shows it",
                                l.label(),
                                l.word()
                            ),
                            None => format!(
                                "{text:?} is on no list of {name}; `nerve-node rule` shows them"
                            ),
                        });
                    }
                    [one] => one.clone(),
                    [(a, _), (b, _), ..] => {
                        return Err(format!(
                            "{text:?} is on the {} and the {} list: name the list, as in `nerve-node rule rm {} '{text}'`",
                            a.word(),
                            b.word(),
                            a.word()
                        ));
                    }
                };
                list.of(&mut e.policy).retain(|r| *r != rule);
                *nerve_transport::sync::lock(&removed) = (list, rule);
                Ok(())
            })
            .await?;
            let (list, removed) = nerve_transport::sync::into_inner(removed);
            let _ = writeln!(out, "{name}: removed {removed:?} from the {}", list.label());
        }
        RuleCmd::Edit {
            list,
            entry,
            new,
            center,
        } => {
            let done = std::sync::Mutex::new((String::new(), String::new()));
            let name = edit_center(paths, &center, |e| {
                let l = list.of(&mut e.policy);
                // The entry as `rule` prints it, with its line breaks written
                // `\n`: the new entry is written so too.
                let (entry, new) = match shown_entry(l, &entry) {
                    shown if shown == entry => (entry.clone(), new.clone()),
                    shown => (shown, rules::unescape_controls(&new)),
                };
                if rules::is_guard(&entry) {
                    return Err(format!(
                        "{entry:?} is a rule of the guard, which is built in: it cannot be changed"
                    ));
                }
                let rule = list.edited(&new)?;
                rules::check_not_a_listed_form(&rule, l)?;
                let Some(at) = l.iter().position(|r| *r == entry) else {
                    return Err(format!(
                        "{entry:?} is not on the {}; `nerve-node rule {}` shows it",
                        list.label(),
                        list.word()
                    ));
                };
                if rule == entry {
                    return Err(format!("{entry:?} is that already"));
                }
                // In its place; a copy of the new entry elsewhere on the
                // list goes, so the list holds each entry once.
                l[at] = rule.clone();
                let mut i = 0;
                l.retain(|r| {
                    i += 1;
                    i - 1 == at || *r != rule
                });
                *nerve_transport::sync::lock(&done) = (entry, rule);
                Ok(())
            })
            .await?;
            let (entry, rule) = nerve_transport::sync::into_inner(done);
            let _ = writeln!(
                out,
                "{name}: the {} {entry:?} is {rule:?} now",
                list.label()
            );
        }
    }
    Ok(())
}

/// How `rule` shows the guard, which every pairing has built in.
fn guard_line() -> String {
    format!(
        "guard: {} rules, built in, that keep the commands off Nerve itself (they catch mistakes, not someone who hides the name)",
        rules::GUARD.len()
    )
}

/// `rule [LIST]`: one list of a center, or all three.
async fn show_rules(
    paths: &NodePaths,
    list: Option<List>,
    center: &CenterArg,
    out: &mut dyn Write,
) -> Result<(), String> {
    let (cfg, _) = read_config(paths).await?;
    let name = pick_center(&cfg, center)?;
    let mut policy = cfg.center(&name).expect("picked").policy.clone();
    // The guard is built in: one line for it, and no stored copy of it.
    policy.deny.retain(|r| !rules::is_guard(r));
    // After the rules, so each line stays one rule `rule rm` takes:
    // those whose conditions no longer fit the action's arguments.
    let shown: Vec<(List, String)> = match list {
        Some(l) => vec![l],
        None => vec![List::Allow, List::Deny],
    }
    .into_iter()
    .filter(|l| *l != List::Sudo)
    .flat_map(|l| {
        l.of(&mut policy.clone())
            .iter()
            .map(|r| (l, r.clone()))
            .collect::<Vec<_>>()
    })
    .collect();
    let stale = stale_rules(paths, &cfg, &name, shown.iter().map(|(_, r)| r)).await?;
    let warn = |out: &mut dyn Write| {
        for (rule, why) in &stale {
            let Some((l, _)) = shown.iter().find(|(_, r)| r == rule) else {
                continue;
            };
            let scope = rules::scope_of(rule);
            let does = match l {
                // What it does depends on why it no longer fits: a
                // gone argument refuses every call, a value the action
                // no longer takes may refuse none.
                List::Deny => {
                    format!("as a deny rule it may refuse calls of {scope} it was not meant for")
                }
                _ => format!(
                    "as an allow rule it may not cover the calls of {scope} it was meant for"
                ),
            };
            let _ = writeln!(
                out,
                "warning: the {} {rule:?} no longer fits: {why}; {does} until you change it",
                l.label()
            );
        }
    };
    if let Some(list) = list {
        if list == List::Deny {
            let _ = writeln!(out, "{}", guard_line());
        }
        let entries = list.of(&mut policy);
        if entries.is_empty() {
            let more = if list == List::Deny { " else" } else { "" };
            let _ = writeln!(out, "{name}: nothing{more} on the {}", list.label());
        }
        for r in entries.iter() {
            let _ = writeln!(out, "{}", rules::escape_controls(r));
        }
        warn(out);
    } else {
        // All three: each line says which list it is on.
        let mut any = false;
        for list in [List::Allow, List::Deny, List::Sudo] {
            if list == List::Deny {
                let _ = writeln!(out, "deny  {}", guard_line());
            }
            for r in list.of(&mut policy).iter() {
                any = true;
                let _ = writeln!(out, "{}  {}", list.word(), rules::escape_controls(r));
            }
        }
        if !any {
            let _ = writeln!(out, "{name}: nothing else on any rule list");
        }
        warn(out);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::tests::{json_of, load, run, setup};

    /// An allow rule added where the center is not in allowlist mode is
    /// said not to count, with the command that makes it count.
    #[test]
    fn an_allow_rule_outside_allowlist_mode_is_said_not_to_count() {
        let (_d, paths) = setup(&["home"]);
        run(&paths, &["mode", "folder"]).unwrap();
        let out = run(&paths, &["rule", "add", "allow", "git status"]).unwrap();
        assert!(
            out.contains("note: home is in folder mode, where allow rules do not count; `nerve-node mode allowlist --center home` uses them"),
            "{out}"
        );
        // Deny rules count in every mode; in allowlist mode allow rules do.
        let out = run(&paths, &["rule", "add", "deny", "rm -rf /"]).unwrap();
        assert!(!out.contains("do not count"), "{out}");
        run(&paths, &["mode", "allowlist"]).unwrap();
        let out = run(&paths, &["rule", "add", "allow", "git log"]).unwrap();
        assert!(!out.contains("do not count"), "{out}");
    }

    /// With several centers the commands the ambiguous `rule rm` prints name
    /// the center, so they work as printed.
    #[test]
    fn the_rm_refusal_names_the_center_it_means() {
        let (_d, paths) = setup(&["home", "work"]);
        let made = "exec.run:exec.run:git log";
        for rule in ["exec.run:git log", made] {
            let list = "center.work.policy.allow";
            run(&paths, &["config", "add", list, rule]).unwrap();
        }
        let args = [
            "rule",
            "rm",
            "allow",
            "exec.run:git log",
            "--center",
            "work",
        ];
        let e = run(&paths, &args).unwrap_err();
        assert!(
            e.contains(&format!("rule rm allow '{made}' --center work")),
            "{e}"
        );
        assert!(
            e.contains("rule rm allow 'exec.run:git log' --center work"),
            "{e}"
        );
        // Run as printed.
        run(&paths, &["rule", "rm", "allow", made, "--center", "work"]).unwrap();
        run(&paths, &args).unwrap();
        assert!(load(&paths).center("work").unwrap().policy.allow.is_empty());
    }

    #[test]
    fn the_three_lists_add_remove_and_show() {
        let (_d, paths) = setup(&["home"]);
        run(&paths, &["rule", "add", "allow", "git status"]).unwrap();
        run(&paths, &["rule", "add", "deny", "git status"]).unwrap();
        // A trailing ` *` is the wildcard, and the command says what it
        // covers: `rm *` is every `rm`, not the files of a folder.
        let out = run(&paths, &["rule", "add", "deny", "rm *"]).unwrap();
        assert!(out.contains("it forbids every `rm` command"), "{out}");
        // A sudo command goes on the sudo list.
        let out = run(&paths, &["rule", "add", "allow", "sudo apt *"]).unwrap();
        assert!(out.contains("sudo allow list"), "{out}");
        assert!(
            out.contains("it allows every command that starts with `sudo apt`"),
            "{out}"
        );
        run(
            &paths,
            &["rule", "add", "allow", "sudo systemctl restart nginx"],
        )
        .unwrap();
        let p = load(&paths).centers[0].policy.clone();
        // Neither list loses a rule to the other; deny wins when they meet.
        assert_eq!(p.allow, ["exec.run:git status"]);
        assert_eq!(p.deny, ["exec.run:git status", "exec.run:rm *"]);
        assert_eq!(p.sudo_allow, ["sudo apt *", "sudo systemctl restart nginx"]);
        assert!(run(&paths, &["rule", "add", "allow", "  "]).is_err());
        // The sudo list is no list of its own to add to, and a `*` alone
        // names no command.
        assert!(run(&paths, &["rule", "add", "sudo", "apt update"]).is_err());
        assert!(run(&paths, &["rule", "add", "allow", "*"]).is_err());
        assert!(run(&paths, &["rule", "add", "allow", "sudo *"]).is_err());
        // The `cap.action:pattern` form is for `config add`; as a command it
        // would become a rule that never matches.
        for list in ["allow", "deny"] {
            let e = run(&paths, &["rule", "add", list, "exec.run:echo *"]).unwrap_err();
            assert!(e.contains("config add"), "{e}");
        }
        let e = run(&paths, &["rule", "add", "allow", "fs.read:~/notes/*"]).unwrap_err();
        assert!(e.contains("policy.allow"), "{e}");
        // So is the form with a capability alone, which the docs show.
        for (list, rule) in [("deny", "fs:~/private/*"), ("allow", "exec:git *")] {
            let e = run(&paths, &["rule", "add", list, rule]).unwrap_err();
            assert!(e.contains("config add"), "{e}");
        }
        assert_eq!(
            load(&paths).centers[0].policy.allow,
            ["exec.run:git status"]
        );
        // With the working rule on the list as well (added as the refusal
        // says), the arguments name neither of the two: the user picks one.
        let broken = "exec.run:fs:~/private/[*]";
        run(
            &paths,
            &["config", "add", "center.home.policy.deny", broken],
        )
        .unwrap();
        run(
            &paths,
            &["config", "add", "center.home.policy.deny", "fs:~/private/*"],
        )
        .unwrap();
        let e = run(&paths, &["rule", "rm", "deny", "fs:~/private/*"]).unwrap_err();
        assert!(
            e.contains(broken) && e.contains("\"fs:~/private/*\""),
            "{e}"
        );
        // The refusal's own instructions work, also for an entry as `ls`
        // shows the working one.
        assert!(
            e.contains(&format!("rule rm deny '{broken}' --center home")),
            "{e}"
        );
        let out = run(&paths, &["rule", "rm", "deny", broken]).unwrap();
        assert!(out.contains(broken), "{out}");
        assert_eq!(
            load(&paths).centers[0].policy.deny,
            ["exec.run:git status", "exec.run:rm *", "fs:~/private/*"]
        );
        run(&paths, &["rule", "rm", "deny", "fs:~/private/*"]).unwrap();
        for rule in ["exec.run:git log", "exec.run:exec.run:git log"] {
            let list = "center.home.policy.allow";
            run(&paths, &["config", "add", list, rule]).unwrap();
        }
        let e = run(&paths, &["rule", "rm", "allow", "exec.run:git log"]).unwrap_err();
        assert!(
            e.contains("rule rm allow 'exec.run:exec.run:git log'"),
            "{e}"
        );
        run(
            &paths,
            &["rule", "rm", "allow", "exec.run:exec.run:git log"],
        )
        .unwrap();
        run(&paths, &["rule", "rm", "allow", "exec.run:git log"]).unwrap();
        // A colon in a command that is not a scope stays a command.
        run(&paths, &["rule", "add", "allow", "C:\\tools\\x.exe"]).unwrap();
        run(&paths, &["rule", "rm", "allow", "C:\\tools\\x.exe"]).unwrap();
        assert_eq!(
            load(&paths).centers[0].policy.allow,
            ["exec.run:git status"]
        );
        // A glob character inside a command is the character itself.
        let out = run(&paths, &["rule", "add", "allow", "ls *.txt"]).unwrap();
        assert!(!out.contains("it allows every"), "{out}");
        assert!(load(&paths).centers[0].policy.allow[1].contains("[*]"));
        // Rules for other actions go in through `config add` and show in `ls`.
        run(
            &paths,
            &[
                "config",
                "add",
                "center.home.policy.allow",
                "fs.read:~/notes/*",
            ],
        )
        .unwrap();
        assert!(
            run(
                &paths,
                &["config", "add", "center.home.policy.allow", "~/notes"]
            )
            .is_err()
        );
        let ls = run(&paths, &["rule", "allow"]).unwrap();
        assert_eq!(ls.lines().count(), 3, "{ls}");
        assert!(ls.contains("fs.read:~/notes/*"), "{ls}");
        // An entry on two lists needs the list named.
        let e = run(&paths, &["rule", "rm", "git status"]).unwrap_err();
        assert!(
            e.contains("on the allow and the deny list")
                && e.contains("`nerve-node rule rm allow 'git status'`"),
            "{e}"
        );
        // rm takes the command like add, or an entry as ls shows it.
        run(&paths, &["rule", "rm", "allow", "git status"]).unwrap();
        run(&paths, &["rule", "rm", "allow", "fs.read:~/notes/*"]).unwrap();
        // Without a list: the one list the entry is on, the sudo list for a
        // sudo command.
        run(&paths, &["rule", "rm", "rm *"]).unwrap();
        run(&paths, &["rule", "rm", "sudo apt *"]).unwrap();
        let e = run(&paths, &["rule", "rm", "nothing here"]).unwrap_err();
        assert!(e.contains("is on no list of home"), "{e}");
        assert!(run(&paths, &["rule", "rm", "both", "x"]).is_err());
        let p = load(&paths).centers[0].policy.clone();
        assert_eq!(p.allow.len(), 1, "{:?}", p.allow);
        assert_eq!(p.deny, ["exec.run:git status"]);
        assert_eq!(p.sudo_allow, ["sudo systemctl restart nginx"]);
        // Something that is not on the list is an error.
        let e = run(&paths, &["rule", "rm", "deny", "ls"]).unwrap_err();
        assert!(e.contains("not on the deny rule"), "{e}");
        let ls = run(&paths, &["rule", "sudo"]).unwrap();
        assert_eq!(ls, "sudo systemctl restart nginx\n");
        // Without a list, `ls` shows all three, each line with its list.
        let all = run(&paths, &["rule"]).unwrap();
        assert!(all.contains("deny  exec.run:git status\n"), "{all}");
        assert!(
            all.contains("sudo  sudo systemctl restart nginx\n"),
            "{all}"
        );
        run(&paths, &["rule", "rm", "sudo", "systemctl restart nginx"]).unwrap();
        let ls = run(&paths, &["rule", "sudo"]).unwrap();
        assert!(ls.contains("nothing on the sudo allow list"), "{ls}");
    }

    /// The guard is built in: `rule` shows it as one line and hides a stored
    /// copy of its rules, which `rule rm` and `rule edit` cannot take off or
    /// change; the node holds it whatever the list says.
    #[test]
    fn the_guard_is_built_in_and_cannot_be_removed() {
        let (_d, paths) = setup(&["home"]);
        run(&paths, &["rule", "add", "deny", "rm *"]).unwrap();
        let guard = nerve_policy::rules::GUARD[2];
        run(&paths, &["config", "add", "center.home.policy.deny", guard]).unwrap();
        let deny = run(&paths, &["rule", "deny"]).unwrap();
        assert_eq!(
            deny,
            format!("{}\nexec.run:rm *\n", guard_line()),
            "the stored copy is not shown"
        );
        assert!(guard_line().starts_with(&format!(
            "guard: {} rules, built in",
            nerve_policy::rules::GUARD.len()
        )));
        let all = run(&paths, &["rule"]).unwrap();
        assert!(all.contains(&format!("deny  {}\n", guard_line())), "{all}");
        let v = json_of(&paths, &["rule"]);
        assert_eq!(v["deny"], json!(["exec.run:rm *"]), "{v}");
        assert_eq!(v["guard"], json!(nerve_policy::rules::GUARD), "{v}");
        for args in [
            &["rule", "rm", "deny", guard][..],
            &["rule", "rm", guard],
            &["rule", "edit", "deny", guard, "ls"],
        ] {
            let e = run(&paths, args).unwrap_err();
            assert!(
                e.contains("is a rule of the guard, which is built in"),
                "{args:?}: {e}"
            );
        }
        assert!(Cli::try_parse_from(["nerve-node", "rule", "guard"]).is_err());
        // A new pairing stores none of it: it is the node's own.
        assert!(
            crate::pair::new_entry_policy().deny.is_empty(),
            "a new pairing stores no guard"
        );
    }

    /// A rule of the guard is no command to `rule add`; the answer says the
    /// guard is built in.
    #[test]
    fn rule_add_says_the_guard_is_built_in() {
        let (_d, paths) = setup(&["home"]);
        let e = run(&paths, &["rule", "add", "deny", "guard:node-service"]).unwrap_err();
        assert!(e.contains("the guard's rules are built in"), "{e}");
        let e = run(&paths, &["rule", "add", "allow", "fs.read:~/notes/*"]).unwrap_err();
        assert!(!e.contains("guard"), "{e}");
    }

    /// `rule edit` changes one entry in its place, on any list and a rule of
    /// the guard too, as one change in the audit.
    #[test]
    fn rule_edit_changes_an_entry_in_place_as_one_change() {
        let (_d, paths) = setup(&["home"]);
        let policy = || load(&paths).centers[0].policy.clone();
        let changes = || {
            nerve_policy::audit::AuditLog::new(paths.audit_log())
                .read()
                .unwrap()
                .iter()
                .filter(|e| e["kind"] == "settings")
                .count()
        };
        for (list, rule) in [
            ("allow", "git status"),
            ("allow", "cargo test"),
            ("allow", "ls"),
            ("allow", "sudo apt update"),
        ] {
            run(&paths, &["rule", "add", list, rule]).unwrap();
        }
        let before = changes();
        // A plain command line becomes the rule `add` makes of it.
        let out = run(
            &paths,
            &[
                "rule",
                "edit",
                "allow",
                "exec.run:cargo test",
                "cargo test --workspace",
            ],
        )
        .unwrap();
        assert!(
            out.contains("\"exec.run:cargo test\" is \"exec.run:cargo test --workspace\" now"),
            "{out}"
        );
        assert_eq!(
            policy().allow,
            [
                "exec.run:git status",
                "exec.run:cargo test --workspace",
                "exec.run:ls"
            ]
        );
        assert_eq!(changes(), before + 1);
        // An entry in the form `ls` shows goes as it is; one that is on the
        // list already is not there twice.
        run(
            &paths,
            &["rule", "edit", "allow", "exec.run:ls", "fs.read:/srv/*"],
        )
        .unwrap();
        run(
            &paths,
            &[
                "rule",
                "edit",
                "allow",
                "fs.read:/srv/*",
                "exec.run:git status",
            ],
        )
        .unwrap();
        assert_eq!(
            policy().allow,
            ["exec.run:cargo test --workspace", "exec.run:git status"]
        );
        // The sudo list takes the command with or without its sudo.
        run(
            &paths,
            &["rule", "edit", "sudo", "sudo apt update", "apt upgrade"],
        )
        .unwrap();
        assert_eq!(policy().sudo_allow, ["sudo apt upgrade"]);
        // An older text of the guard is a rule of its own, edited like any
        // other.
        let guard = nerve_policy::rules::GUARD_OLD[18];
        run(&paths, &["config", "add", "center.home.policy.deny", guard]).unwrap();
        run(
            &paths,
            &["rule", "edit", "deny", guard, "exec.run:nerve-node *"],
        )
        .unwrap();
        assert_eq!(policy().deny, ["exec.run:nerve-node *"]);
        // What is not there, the same again, a bad pattern: refused, and
        // nothing changes.
        let now = policy();
        let n = changes();
        for (args, says) in [
            (
                &["rule", "edit", "allow", "exec.run:nope", "x"][..],
                "is not on",
            ),
            (
                &[
                    "rule",
                    "edit",
                    "deny",
                    "exec.run:nerve-node *",
                    "exec.run:nerve-node *",
                ],
                "that already",
            ),
            (
                &[
                    "rule",
                    "edit",
                    "deny",
                    "exec.run:nerve-node *",
                    "fs.read:[z-a]",
                ],
                "fs.read:[z-a]",
            ),
            (
                &["rule", "edit", "deny", "exec.run:nerve-node *", " "],
                "empty",
            ),
        ] {
            let e = run(&paths, args).unwrap_err();
            assert!(e.contains(says), "{args:?}: {e}");
        }
        assert_eq!(policy(), now);
        assert_eq!(changes(), n);
    }

    /// An older text of the guard holds a line break; `rule` writes it
    /// `\n` so a listing keeps a line a rule, and `rule rm` and `rule edit`
    /// take the entry as `ls` printed it.
    #[test]
    fn rule_ls_writes_line_breaks_out_and_rm_and_edit_take_them_back() {
        let (_d, paths) = setup(&["home"]);
        let deny = || load(&paths).centers[0].policy.deny.clone();
        let guard = &nerve_policy::rules::GUARD_OLD[..18];
        assert!(guard.iter().any(|g| g.contains('\n')));
        for old in guard {
            run(&paths, &["config", "add", "center.home.policy.deny", old]).unwrap();
        }
        let ls = run(&paths, &["rule", "deny"]).unwrap();
        // The guard's own line comes first.
        assert_eq!(ls.lines().count(), deny().len() + 1, "{ls}");
        for (line, rule) in ls.lines().skip(1).zip(deny()) {
            assert_eq!(line, nerve_policy::rules::escape_controls(&rule));
            assert!(!line.contains(['\t', '\r']), "{line:?}");
        }
        assert!(ls.contains("\\r\\n"), "{ls}");
        let all = run(&paths, &["rule"]).unwrap();
        assert_eq!(all.lines().count(), deny().len() + 1, "{all}");
        assert!(all.lines().all(|l| l.starts_with("deny  ")), "{all}");
        // The entry as `ls` printed it is removed; the raw one too.
        let shown = nerve_policy::rules::escape_controls(guard[9]);
        assert_ne!(shown, guard[9]);
        let out = run(&paths, &["rule", "rm", "deny", &shown]).unwrap();
        assert!(out.contains("removed"), "{out}");
        assert!(!deny().iter().any(|r| r == guard[9]));
        run(&paths, &["rule", "rm", "deny", guard[10]]).unwrap();
        assert!(!deny().iter().any(|r| r == guard[10]));
        // Edit: the entry and the new one both as `ls` prints them.
        let shown = nerve_policy::rules::escape_controls(guard[11]);
        let new = "exec.run:systemctl stop nerve-node\\n*";
        let out = run(&paths, &["rule", "edit", "deny", &shown, new]).unwrap();
        assert!(out.contains("now"), "{out}");
        assert!(!deny().iter().any(|r| r == guard[11]));
        assert!(
            deny()
                .iter()
                .any(|r| r == "exec.run:systemctl stop nerve-node\n*"),
            "{:?}",
            deny()
        );
        // A Windows path rule has backslashes before t, r and n: a rule as
        // it stands, added, listed, edited and removed on every OS.
        let paths_rules = [
            "exec.run:type C:\\tools\\x.exe",
            "exec.run:*C:\\Users\\nina\\repos\\*",
            "exec.run:\"C:\\Program Files\\nodejs\\node.exe\" --version",
        ];
        for own in paths_rules {
            run(&paths, &["config", "add", "center.home.policy.deny", own]).unwrap();
            let ls = run(&paths, &["rule", "deny"]).unwrap();
            assert!(ls.lines().any(|l| l == own), "{ls}");
        }
        run(
            &paths,
            &[
                "rule",
                "edit",
                "deny",
                paths_rules[0],
                "exec.run:type C:\\temp\\x.exe",
            ],
        )
        .unwrap();
        assert!(deny().iter().any(|r| r == "exec.run:type C:\\temp\\x.exe"));
        for own in &paths_rules[1..] {
            run(&paths, &["rule", "rm", "deny", own]).unwrap();
            assert!(!deny().iter().any(|r| r == own));
        }
        run(
            &paths,
            &["rule", "rm", "deny", "exec.run:type C:\\temp\\x.exe"],
        )
        .unwrap();
        // The listed text of a rule with a line break is not a rule: pasted
        // so, its `\n` would be the letter. Refused for a guard rule and for
        // an entry of the list, by `config add` and `rule edit`; nothing
        // changes.
        run(
            &paths,
            &["config", "add", "center.home.policy.deny", "exec.run:a\nb*"],
        )
        .unwrap();
        let before = deny();
        for listed in [
            nerve_policy::rules::escape_controls(guard[12]),
            nerve_policy::rules::escape_controls(guard[13]),
            "exec.run:a\\nb*".to_string(),
        ] {
            let e = run(
                &paths,
                &["config", "add", "center.home.policy.deny", &listed],
            )
            .unwrap_err();
            assert!(e.contains("how `rule` writes a rule"), "{e}");
            let e = run(&paths, &["rule", "edit", "deny", "exec.run:a\nb*", &listed]).unwrap_err();
            assert!(e.contains("how `rule` writes a rule"), "{e}");
        }
        assert_eq!(deny(), before);
        // Not there: refused, nothing changes.
        let now = deny();
        let e = run(&paths, &["rule", "rm", "deny", "exec.run:nope\\n"]).unwrap_err();
        assert!(e.contains("is not on"), "{e}");
        assert_eq!(deny(), now);
    }

    /// A rule with conditions on an action's arguments goes on with `rule
    /// add` (and `rule edit`, `config add`), checked against the schema of
    /// what the node offers: an argument the action does not take, a value
    /// not of its type, or an action nothing offers is refused. `--arg`
    /// makes the audit buttons' rule. `rule` says which rules no longer
    /// fit once their argument is gone, in text and JSON.
    #[test]
    fn rule_add_takes_typed_conditions_and_ls_flags_a_gone_argument() {
        let (_d, paths) = setup(&["home"]);
        let policy = || load(&paths).centers[0].policy.clone();
        let params = r#"{"type": "object", "required": ["room", "level"], "properties": {"room": {"type": "string"}, "level": {"type": "integer"}}}"#;
        run(
            &paths,
            &[
                "cap",
                "add",
                "lamp.set",
                "--effect=actuate",
                &format!("--params={params}"),
                "--",
                "echo",
                "{room}",
                "{level}",
            ],
        )
        .unwrap();
        run(
            &paths,
            &["rule", "add", "deny", "lamp.set:room=bedroom,level>50"],
        )
        .unwrap();
        run(&paths, &["rule", "add", "allow", "exec.signal:signal=term"]).unwrap();
        let said = run(
            &paths,
            &[
                "rule", "add", "allow", "", "--action", "lamp.set", "--arg", "level=20",
            ],
        )
        .unwrap();
        assert!(said.contains("\"lamp.set:level=20\""), "{said}");
        assert_eq!(
            policy().allow,
            ["exec.signal:signal=term", "lamp.set:level=20"]
        );
        assert_eq!(policy().deny, ["lamp.set:room=bedroom,level>50"]);
        for (args, why) in [
            (
                &["rule", "add", "deny", "lamp.set:size=1"][..],
                "lamp.set has no argument size; it takes level, room",
            ),
            (
                &["rule", "add", "deny", "lamp.set:level=high"],
                "is an integer",
            ),
            (
                &["rule", "add", "allow", "exec.signal:signal=stop"],
                "is one of term, kill, int",
            ),
            (
                &["rule", "add", "allow", "lamp.off:room=x"],
                "nothing offers lamp.off now",
            ),
            (
                &[
                    "config",
                    "add",
                    "center.home.policy.deny",
                    "lamp.set:size=1",
                ],
                "no argument size",
            ),
            (
                &[
                    "rule",
                    "edit",
                    "deny",
                    "lamp.set:room=bedroom,level>50",
                    "lamp.set:rooms=x",
                ],
                "no argument rooms",
            ),
            (
                &[
                    "rule", "add", "deny", "git", "--action", "exec.run", "--arg", "a=1",
                ],
                "names its command, not an argument",
            ),
            (
                &[
                    "rule", "add", "deny", "", "--action", "lamp.set", "--arg", "level",
                ],
                "--arg takes FIELD=VALUE",
            ),
        ] {
            let e = run(&paths, args).unwrap_err();
            assert!(e.contains(why), "{args:?}: {e}");
        }
        assert_eq!(policy().deny, ["lamp.set:room=bedroom,level>50"]);
        // `rule rm` takes it as `rule` shows it.
        run(&paths, &["rule", "rm", "lamp.set:level=20"]).unwrap();
        assert_eq!(policy().allow, ["exec.signal:signal=term"]);
        assert!(!run(&paths, &["rule"]).unwrap().contains("warning"));
        assert_eq!(json_of(&paths, &["rule"])["stale"], json!({}));
        // The capability takes no `room` now: the rule that names it stays,
        // and `rule` says what it does now.
        run(
            &paths,
            &[
                "cap",
                "edit",
                "lamp.set",
                r#"--params={"type": "object", "required": ["level"], "properties": {"level": {"type": "integer"}}}"#,
                "--",
                "echo",
                "{level}",
            ],
        )
        .unwrap();
        assert_eq!(policy().deny, ["lamp.set:room=bedroom,level>50"]);
        let warning = "warning: the deny rule \"lamp.set:room=bedroom,level>50\" no longer fits: lamp.set has no argument room; it takes level; as a deny rule it may refuse calls of lamp.set it was not meant for until you change it";
        for args in [&["rule"][..], &["rule", "deny"]] {
            let out = run(&paths, args).unwrap();
            assert!(out.lines().any(|l| l == warning), "{out}");
        }
        assert!(!run(&paths, &["rule", "allow"]).unwrap().contains("warning"));
        assert_eq!(
            json_of(&paths, &["rule"])["stale"],
            json!({"lamp.set:room=bedroom,level>50": "lamp.set has no argument room; it takes level"})
        );
    }

    /// `rule add --action` makes the rule an audit button makes for an entry
    /// of that action, a trailing `*` its wildcard, and `rule rm` takes the
    /// rule as `rule` shows it.
    #[test]
    fn rule_add_with_an_action_makes_the_audit_buttons_rule() {
        let (_d, paths) = setup(&["home"]);
        let policy = || load(&paths).centers[0].policy.clone();
        run(
            &paths,
            &[
                "rule",
                "add",
                "allow",
                "/srv/data/a.txt",
                "--action",
                "fs.read",
            ],
        )
        .unwrap();
        run(
            &paths,
            &["rule", "add", "deny", "/srv/data/*", "--action", "fs.write"],
        )
        .unwrap();
        run(
            &paths,
            &["rule", "add", "allow", "*", "--action", "settings.read"],
        )
        .unwrap();
        run(
            &paths,
            &["rule", "add", "deny", "make *", "--action", "exec.run"],
        )
        .unwrap();
        // A sudo command goes on the sudo list here too.
        run(
            &paths,
            &["rule", "add", "allow", "sudo apt *", "--action", "exec.run"],
        )
        .unwrap();
        assert_eq!(policy().allow, ["fs.read:/srv/data/a.txt", "settings"]);
        assert_eq!(policy().deny, ["fs.write:/srv/data/*", "exec.run:make *"]);
        assert_eq!(policy().sudo_allow, ["sudo apt *"]);
        // The same as the center's buttons for the same entries, the
        // wildcard as `wildcard_target` writes the button's.
        for (list, cap, action, target, wildcard) in [
            ("allow", "fs", "read", "/srv/data/a.txt", false),
            ("deny", "fs", "write", "/srv/data/a.txt", true),
            ("deny", "exec", "run", "make all", true),
            ("allow", "settings", "read", "", true),
        ] {
            let rule = rules::rule_for(cap, action, target, wildcard, None).unwrap();
            let l = if list == "allow" {
                policy().allow
            } else {
                policy().deny
            };
            assert!(l.contains(&rule), "{rule}");
            if wildcard {
                let wide = wildcard_target(cap, action, target);
                let made = List::Allow
                    .action_rule(&format!("{cap}.{action}"), &wide, None, false)
                    .unwrap();
                assert_eq!(made, rule, "{wide}");
            }
        }
        assert_eq!(
            wildcard_target("exec", "run", "sudo -n apt install x"),
            "sudo -n apt *"
        );
        assert_eq!(
            List::Sudo
                .action_rule("exec.run", "sudo -n apt *", None, false)
                .unwrap(),
            rules::sudo_rule_for("sudo -n apt install x", true).unwrap()
        );
        run(&paths, &["rule", "rm", "fs.write:/srv/data/*"]).unwrap();
        assert_eq!(policy().deny, ["exec.run:make *"]);
        let e = run(
            &paths,
            &["rule", "add", "deny", "srv/*", "--action", "fs.read"],
        )
        .unwrap_err();
        assert!(e.contains("not an absolute path"), "{e}");
        let e = run(&paths, &["rule", "add", "allow", "x", "--action", "read"]).unwrap_err();
        assert!(e.contains("capability and action"), "{e}");
        let cut = format!(
            "{}… [cut at {n} of {} characters]",
            "a".repeat(nerve_policy::audit::TARGET_MAX_CHARS),
            nerve_policy::audit::TARGET_MAX_CHARS + 5,
            n = nerve_policy::audit::TARGET_MAX_CHARS
        );
        let e = run(
            &paths,
            &["rule", "add", "deny", &cut, "--action", "exec.run"],
        )
        .unwrap_err();
        assert!(e.contains("cut"), "{e}");
    }

    /// The audit's exact buttons (`--exact`) keep a `*` at the end of the
    /// command an agent sent: Allow on `rm -rf *` is that one command, not
    /// every `rm -rf`, and the same on the sudo list and for a path. Without
    /// `--exact` the trailing `*` is the wildcard, and `rule add` says so.
    #[test]
    fn the_exact_buttons_keep_a_trailing_star_as_it_is() {
        let (_d, paths) = setup(&["home"]);
        let policy = || load(&paths).centers[0].policy.clone();
        for (list, target, action) in [
            ("allow", "rm -rf *", "exec.run"),
            ("allow", "sudo chown -R me *", "exec.run"),
            ("deny", "/srv/data/*", "fs.read"),
        ] {
            let out = run(
                &paths,
                &["rule", "add", list, target, "--action", action, "--exact"],
            )
            .unwrap();
            assert!(!out.contains("every"), "{out}");
        }
        assert_eq!(policy().allow, ["exec.run:rm -rf [*]"]);
        assert_eq!(policy().sudo_allow, ["sudo chown -R me [*]"]);
        assert_eq!(policy().deny, ["fs.read:/srv/data/[*]"]);
        // `--exact` keeps the refusal of a sudo command on the allow list's
        // own form and needs --action.
        assert!(run(&paths, &["rule", "add", "allow", "rm *", "--exact"]).is_err());
        let out = run(
            &paths,
            &["rule", "add", "allow", "git add *", "--action", "exec.run"],
        )
        .unwrap();
        assert!(
            out.contains("it allows every command that starts with `git add`"),
            "{out}"
        );
        assert!(policy().allow.contains(&"exec.run:git add *".to_string()));
    }
}
