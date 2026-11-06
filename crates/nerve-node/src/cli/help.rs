//! The help the command line prints and the center serves: the top help
//! in groups, and the cards of [`help`], built from the clap definitions.

use super::*;

/// The command list as `nerve-node --help` has it, for anything that shows
/// the commands elsewhere (the center's help page). It is read from the
/// [`Cli`] definition above, so a new command or flag shows up there by
/// being written once; [`SECTIONS`] only says where on the page it goes.
#[derive(Debug, Clone, Serialize)]
pub struct Help {
    /// What the node is.
    pub about: String,
    /// The options every command takes and those that commands on several
    /// cards take alike (`--center`), said once, at the end of the page.
    pub options: Vec<ArgHelp>,
    /// Options every command takes.
    #[serde(skip)]
    pub global: Vec<ArgHelp>,
    /// Arguments that cards on different places take alike (`--center`),
    /// said once here and left out of the cards.
    #[serde(skip)]
    pub common: Vec<ArgHelp>,
    /// The cards, grouped by what a person wants to do, in reading order.
    pub sections: Vec<Section>,
}

/// Where each command stands on the help page: the heading, the sentence
/// under it, and the cards. A card is the commands named in one slice: a
/// noun with its verbs (`["folder"]`), or loose commands that belong
/// together (`["panic", "unlock"]`). A command missing here still shows up,
/// in a section of its own, and a test fails until it is placed.
const SECTIONS: &[(&str, &str, &[&[&str]])] = &[
    (
        "Set up",
        "Install the node as a service, set it up, keep it current, and back it up.",
        &[
            &["install", "uninstall"],
            &["setup"],
            &["update"],
            &["backup", "restore"],
            &["service"],
        ],
    ),
    ("Centers", "Pair this machine with centers.", &[&["center"]]),
    (
        "What a center may do",
        "Every center has its own rights on this machine.",
        &[&["mode"], &["folder"], &["network"], &["rule"], &["sudo"]],
    ),
    (
        "Watch and stop",
        "See what the node did, and stop it.",
        &[&["status"], &["audit"], &["log"], &["panic", "unlock"]],
    ),
    (
        "More",
        "Capabilities, proxy and relay, the web UI, any setting, the foreground run.",
        &[
            &["cap"],
            &["provider"],
            &["proxy"],
            &["relay"],
            &["ui"],
            &["config"],
            &["run"],
        ],
    ),
];

/// The top page of `nerve-node --help`: the commands in the groups of
/// [`SECTIONS`], one line each, then the options every command takes, which
/// the commands' own pages leave out.
pub const TOP_TEMPLATE: &str = "{about-with-newline}\n{usage-heading} {usage}{after-help}";

/// What [`TOP_TEMPLATE`] lists, read from the [`Cli`] definition.
pub fn top_help(program: &str) -> String {
    let root = Cli::command();
    let mut out = String::new();
    let width = root
        .get_subcommands()
        .filter(|c| visible(c))
        .map(|c| c.get_name().len())
        .max()
        .unwrap_or(8);
    for (name, _, cards) in SECTIONS {
        out.push_str(&format!("{name}:\n"));
        for c in cards.iter().flat_map(|c| c.iter()) {
            if let Some(cmd) = root.find_subcommand(c) {
                out.push_str(&format!("  {c:width$}  {}\n", about_of(cmd)));
            }
        }
        out.push('\n');
    }
    out.push_str("Options every command takes:\n");
    for a in root.get_arguments().filter(|a| a.is_global_set()) {
        let h = arg_help(a);
        out.push_str(&format!("  {:25}  {}\n", h.name, h.about));
    }
    out.push_str(&format!(
        "\n`{program} <command> --help` says more of one command; the user guide is in docs/user."
    ));
    out
}

/// The command as `--help` shows it: the top page of [`top_help`], and each
/// command's long page (`<command> --help`) ending on its user guide page.
pub fn help_pages(cmd: clap::Command, program: &'static str) -> clap::Command {
    let names: Vec<String> = cmd
        .get_subcommands()
        .map(|c| c.get_name().to_string())
        .collect();
    names
        .iter()
        .fold(cmd, |cmd, name| {
            cmd.mut_subcommand(name, |c| {
                c.after_long_help(format!(
                    "More in the user guide: {}",
                    guide_url(doc_of(name))
                ))
            })
        })
        .name(program)
        .bin_name(program)
        .help_template(TOP_TEMPLATE)
        .after_help(top_help(program))
}

/// What a bare `nerve-node` prints: the commands of every day.
pub fn everyday(program: &str) -> String {
    format!(
        "{program} links this machine to its Nerve centers.

  sudo {program} install                 install it as a service, then pair a center
  {program} status                       how it is, and what to do next
  {program} center add -                 pair with a center: paste the link
  {program} folder add ~/project rwx     let the center use a folder
  {program} rule add allow '<command>'   allow a command (allowlist mode)
  {program} audit                        what was allowed and refused

`{program} --help` lists every command."
    )
}

/// A heading with its sentence, and the cards below it.
#[derive(Debug, Clone, Serialize)]
pub struct Section {
    pub name: String,
    /// What the section is for, said once for all its cards.
    #[serde(rename = "line")]
    pub about: String,
    pub cards: Vec<Card>,
}

/// One thing a person looks up: a noun with its verbs, or loose commands
/// that go together.
#[derive(Debug, Clone, Serialize)]
pub struct Card {
    /// `folder`, `panic / unlock`.
    pub name: String,
    /// What it is for, one line; empty when its commands say it themselves.
    #[serde(rename = "line")]
    pub about: String,
    /// The rest of what it is for, folded under the line.
    pub more: String,
    /// The page of the user guide that says more (docs/user/<doc>).
    pub doc: String,
    /// The commands that only hold more commands (`folder`), which the card
    /// covers without a line of their own.
    pub holds: Vec<String>,
    /// Arguments that two or more verbs take in the same way, said once.
    pub shared_args: Vec<ArgHelp>,
    pub verbs: Vec<Verb>,
}

/// A command that does something.
#[derive(Debug, Clone, Serialize)]
pub struct Verb {
    /// The words after `nerve-node`: `status`, `folder add`.
    pub name: String,
    /// The usage line, for example `nerve-node folder add [OPTIONS] <PATH>`.
    pub usage: String,
    /// The explanation's first line: the command's `about`.
    #[serde(rename = "line")]
    pub about: String,
    /// The rest of the explanation (its `long_about`), folded.
    pub more: String,
    /// Its own arguments and flags, without the global and the shared ones.
    pub args: Vec<ArgHelp>,
    /// Every argument and flag it takes but the global ones, the shared
    /// ones too: for a page that shows one command on its own (the desktop
    /// app's reference), where the card's and the page's are not in sight.
    #[serde(skip)]
    pub takes: Vec<ArgHelp>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ArgHelp {
    /// How it is written: `--for <HOURS>`, `<PATH>`, `--refused`.
    pub name: String,
    /// The explanation's first line; empty when the argument has none.
    #[serde(rename = "line")]
    pub about: String,
    /// The rest of the explanation (its long help), folded.
    pub more: String,
    /// Whether it can be left out.
    pub optional: bool,
}

impl Help {
    /// Every verb, card by card.
    pub fn verbs(&self) -> impl Iterator<Item = &Verb> {
        self.sections
            .iter()
            .flat_map(|s| &s.cards)
            .flat_map(|c| &c.verbs)
    }

    /// Every command the page covers: the verbs and the commands that only
    /// hold more commands.
    pub fn command_names(&self) -> Vec<&str> {
        let cards = self.sections.iter().flat_map(|s| &s.cards);
        let holds = cards.clone().flat_map(|c| &c.holds).map(String::as_str);
        let verbs = self.verbs().map(|v| v.name.as_str());
        holds.chain(verbs).collect()
    }
}

fn visible(c: &clap::Command) -> bool {
    // clap adds a `help` sub-command of its own to every level.
    c.get_name() != "help" && !c.is_hide_set()
}

/// Reads [`Help`] from the [`Cli`] definition.
pub fn help() -> Help {
    let mut root = Cli::command();
    root.build();
    let mut left: Vec<&clap::Command> = root.get_subcommands().filter(|c| visible(c)).collect();
    let mut sections = Vec::new();
    for (name, about, cards) in SECTIONS {
        let mut out = Vec::new();
        for names in *cards {
            let cmds: Vec<&clap::Command> = names
                .iter()
                .filter_map(|n| root.find_subcommand(n))
                .collect();
            left.retain(|c| !names.contains(&c.get_name()));
            out.extend(cards_of(&cmds));
        }
        sections.push(Section {
            name: (*name).into(),
            about: (*about).into(),
            cards: out,
        });
    }
    if !left.is_empty() {
        sections.push(Section {
            name: "Other commands".into(),
            about: String::new(),
            cards: left.into_iter().flat_map(|c| cards_of(&[c])).collect(),
        });
    }
    let common = hoist_common(&mut sections);
    let global: Vec<ArgHelp> = root
        .get_arguments()
        .filter(|a| a.is_global_set())
        .map(arg_help)
        .collect();
    Help {
        about: about_of(&root),
        options: global.iter().chain(&common).cloned().collect(),
        global,
        common,
        sections,
    }
}

/// Takes the arguments that two or more cards have alike out of the cards.
fn hoist_common(sections: &mut [Section]) -> Vec<ArgHelp> {
    let args_of = |c: &Card| -> Vec<ArgHelp> {
        let own = c.verbs.iter().flat_map(|v| &v.args);
        c.shared_args.iter().chain(own).cloned().collect()
    };
    let mut common: Vec<ArgHelp> = Vec::new();
    for a in sections.iter().flat_map(|s| &s.cards).flat_map(args_of) {
        let on = sections
            .iter()
            .flat_map(|s| &s.cards)
            .filter(|c| args_of(c).contains(&a))
            .count();
        if on > 1 && !common.contains(&a) {
            common.push(a);
        }
    }
    for c in sections.iter_mut().flat_map(|s| &mut s.cards) {
        c.shared_args.retain(|a| !common.contains(a));
        for v in &mut c.verbs {
            v.args.retain(|a| !common.contains(a));
        }
    }
    common
}

fn about_of(c: &clap::Command) -> String {
    c.get_about().map(ToString::to_string).unwrap_or_default()
}

/// The long text after a first `line` (clap's long help is the line, a
/// blank line and the rest): the rest, or nothing.
fn rest_of(long: Option<String>, line: &str) -> String {
    let long = long.unwrap_or_default();
    match long.strip_prefix(line) {
        Some(rest) => rest.trim().to_string(),
        None if long == line => String::new(),
        None => long,
    }
}

/// The user guide's page for a command of the top level.
pub fn doc_of(command: &str) -> &'static str {
    match command.split([' ', '/']).next().unwrap_or_default() {
        "install" | "uninstall" | "setup" | "update" | "service" | "run" => "install.md",
        "backup" | "restore" => "backup.md",
        "center" | "proxy" | "relay" => "pair.md",
        "mode" | "folder" => "folders-and-modes.md",
        "network" => "network.md",
        "rule" | "sudo" => "rules.md",
        "status" | "audit" | "log" | "panic" | "unlock" => "watch-and-stop.md",
        "cap" | "provider" => "capabilities.md",
        "ui" => "web-uis.md",
        "config" => "settings.md",
        _ => "commands.md",
    }
}

/// The user guide's page `doc` as this build has it: the docs at the
/// release's tag in a release build, at `main` in any other.
pub fn guide_url(doc: &str) -> String {
    format!(
        "https://github.com/prometheion/nerve-protocol/blob/{}/docs/user/{doc}",
        nerve_transport::webui::GUIDE_REF
    )
}

fn cards_of(cmds: &[&clap::Command]) -> Vec<Card> {
    if let [one] = cmds
        && one.has_subcommands()
    {
        return noun_cards(one, one.get_name());
    }
    let verbs = cmds.iter().map(|c| verb(c, c.get_name())).collect();
    let names: Vec<&str> = cmds.iter().map(|c| c.get_name()).collect();
    vec![card(&names.join(" / "), String::new(), Vec::new(), verbs)]
}

fn card(name: &str, about: String, holds: Vec<String>, mut verbs: Vec<Verb>) -> Card {
    card_with(
        name,
        about,
        String::new(),
        holds,
        std::mem::take(&mut verbs),
    )
}

fn card_with(
    name: &str,
    about: String,
    more: String,
    holds: Vec<String>,
    mut verbs: Vec<Verb>,
) -> Card {
    // An argument that two verbs take alike is said once, on the card.
    let mut shared: Vec<ArgHelp> = Vec::new();
    for a in verbs.iter().flat_map(|v| &v.args) {
        if !shared.contains(a) && verbs.iter().filter(|v| v.args.contains(a)).count() > 1 {
            shared.push(a.clone());
        }
    }
    for v in &mut verbs {
        v.args.retain(|a| !shared.contains(a));
    }
    Card {
        name: name.into(),
        about,
        more,
        doc: doc_of(name).into(),
        holds,
        shared_args: shared,
        verbs,
    }
}

/// The cards of a noun (`folder`): its verbs on one card, and a card for
/// each sub-noun below it.
fn noun_cards(noun: &clap::Command, name: &str) -> Vec<Card> {
    let (holders, leaves): (Vec<_>, Vec<_>) = noun
        .get_subcommands()
        .filter(|c| visible(c))
        .partition(|c| c.has_subcommands());
    let mut out = Vec::new();
    // A noun that also runs on its own (`audit`, beside `audit clear`) is
    // its card's first verb, and holds nothing.
    let alone = !noun.is_subcommand_required_set();
    let holds = if alone { Vec::new() } else { vec![name.into()] };
    if !leaves.is_empty() {
        let verbs = alone
            .then(|| verb(noun, name))
            .into_iter()
            .chain(
                leaves
                    .iter()
                    .map(|c| verb(c, &format!("{name} {}", c.get_name()))),
            )
            .collect();
        let line = about_of(noun);
        let more = rest_of(noun.get_long_about().map(ToString::to_string), &line);
        out.push(card_with(name, line, more, holds, verbs));
    }
    for h in &holders {
        out.extend(noun_cards(h, &format!("{name} {}", h.get_name())));
    }
    if !alone
        && !out.iter().any(|c| c.holds.iter().any(|h| h == name))
        && let Some(first) = out.first_mut()
    {
        first.holds.insert(0, name.into());
    }
    out
}

fn verb(sub: &clap::Command, name: &str) -> Verb {
    let usage = sub.clone().render_usage().to_string();
    // A command that also holds others has their form on a second line:
    // that is theirs.
    let usage = usage.lines().next().unwrap_or_default();
    let args: Vec<ArgHelp> = sub
        .get_arguments()
        .filter(|a| !a.is_global_set() && !matches!(a.get_id().as_str(), "help" | "version"))
        .map(arg_help)
        .collect();
    let line = about_of(sub);
    Verb {
        name: name.into(),
        usage: usage.strip_prefix("Usage: ").unwrap_or(usage).to_string(),
        more: rest_of(sub.get_long_about().map(ToString::to_string), &line),
        about: line,
        takes: args.clone(),
        args,
    }
}

fn arg_help(a: &clap::Arg) -> ArgHelp {
    let value = a
        .get_value_names()
        .and_then(|v| v.first())
        .map_or_else(|| a.get_id().as_str().to_uppercase(), ToString::to_string);
    let name = match a.get_long() {
        Some(long) if a.get_action().takes_values() => format!("--{long} <{value}>"),
        Some(long) => format!("--{long}"),
        None => format!("<{value}>"),
    };
    let line = a.get_help().map(ToString::to_string).unwrap_or_default();
    ArgHelp {
        name,
        more: rest_of(a.get_long_help().map(ToString::to_string), &line),
        about: line,
        optional: !a.is_required_set(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every command and sub-command name of the clap definition, walked
    /// here on its own so the test does not trust [`help`] to find them;
    /// not the hidden ones, which are for programs.
    fn all_names(cmd: &clap::Command, prefix: &str, out: &mut Vec<String>) {
        for sub in cmd.get_subcommands() {
            if sub.get_name() == "help" || sub.is_hide_set() {
                continue;
            }
            let name = format!("{prefix}{}", sub.get_name());
            all_names(sub, &format!("{name} "), out);
            out.push(name);
        }
    }

    #[test]
    fn help_lists_every_command_with_an_explanation() {
        let mut names = Vec::new();
        all_names(&Cli::command(), "", &mut names);
        assert!(names.len() > 40, "{names:?}");
        let h = help();
        // Every command is on a card, once: the ones that do something as a
        // verb, the ones that only hold more commands in the card's `holds`.
        let mut listed: Vec<String> = h.command_names().iter().map(|n| n.to_string()).collect();
        let mut want = names.clone();
        want.sort();
        listed.sort();
        assert_eq!(listed, want);
        for s in &h.sections {
            assert!(!s.about.is_empty(), "section `{}` has no sentence", s.name);
            assert!(!s.cards.is_empty(), "section `{}` is empty", s.name);
        }
        for v in h.verbs() {
            assert!(!v.about.is_empty(), "`{}` has no explanation", v.name);
            assert!(
                v.usage.starts_with(&format!("nerve-node {}", v.name)),
                "{}",
                v.usage
            );
        }
        // Every command is placed in SECTIONS, none in the catch-all.
        let names: Vec<&str> = h.sections.iter().map(|s| s.name.as_str()).collect();
        assert_eq!(
            names,
            [
                "Set up",
                "Centers",
                "What a center may do",
                "Watch and stop",
                "More",
            ]
        );
        // A noun is one card with its verbs; `rule` has the three lists as
        // an argument, not as three sub-trees.
        let card = |n: &str| {
            h.sections
                .iter()
                .flat_map(|s| &s.cards)
                .find(|c| c.name == n)
                .unwrap_or_else(|| panic!("no card `{n}`"))
        };
        let rule = card("rule");
        let rule_verbs: Vec<&str> = rule.verbs.iter().map(|v| v.name.as_str()).collect();
        assert_eq!(rule_verbs, ["rule", "rule add", "rule rm", "rule edit"]);
        assert!(rule.holds.is_empty());
        assert!(
            rule.verbs[1].usage.contains("<LIST>"),
            "{}",
            rule.verbs[1].usage
        );
        assert!(
            rule.verbs[0].usage.contains("[LIST]"),
            "{}",
            rule.verbs[0].usage
        );
        // `provider` is a noun of its own: bare, it shows.
        let provider: Vec<&str> = card("provider")
            .verbs
            .iter()
            .map(|v| v.name.as_str())
            .collect();
        assert_eq!(provider, ["provider", "provider add", "provider rm"]);
        assert_eq!(card("panic / unlock").verbs.len(), 2);
        assert_eq!(card("install / uninstall").verbs.len(), 2);
        assert_eq!(card("setup").verbs.len(), 1);
        assert_eq!(card("update").verbs.len(), 1);
        // What several verbs take alike is said once, on the card, and what
        // several cards take alike once on the page.
        let folder = card("folder");
        assert!(folder.shared_args.iter().any(|a| a.name == "<PATH>"));
        assert!(h.common.iter().any(|a| a.name == "--center <CENTER>"));
        let cards: Vec<&Card> = h.sections.iter().flat_map(|s| &s.cards).collect();
        for a in &h.common {
            assert!(cards.iter().all(|c| !c.shared_args.contains(a)));
            assert!(h.verbs().all(|v| !v.args.contains(a)));
        }
        // `config add` and `rm` take the key of a list, the other verbs
        // the key of any setting; each text is said once on the card.
        let key = card("config");
        let keys: Vec<&str> = key
            .shared_args
            .iter()
            .filter(|a| a.name == "<KEY>")
            .map(|a| a.about.as_str())
            .collect();
        assert_eq!(keys.len(), 2, "{keys:?}");
        assert!(
            keys.iter()
                .any(|k| k.contains("of a list") && k.contains(".policy.allow")),
            "{keys:?}"
        );
        assert!(keys.iter().any(|k| k.contains(".policy.mode")), "{keys:?}");
        // The rights of `folder add` are required, so the page does not call
        // them optional.
        let add = h.verbs().find(|v| v.name == "folder add").unwrap();
        assert!(
            add.args
                .iter()
                .any(|a| a.name == "<RIGHTS>" && !a.about.is_empty() && !a.optional),
            "{:?}",
            add.args
        );
        // What can be left out says so.
        let mode = h.verbs().find(|v| v.name == "mode").unwrap();
        assert!(
            mode.args
                .iter()
                .any(|a| a.name == "--for <HOURS>" && a.optional)
        );
        assert!(mode.args.iter().any(|a| a.name == "<MODE>" && a.optional));
        // The options every command takes are listed once, not per command.
        assert!(h.global.iter().any(|a| a.name.starts_with("--config-dir")));
        assert!(add.args.iter().all(|a| !a.name.starts_with("--config-dir")));
        // No usage line, and no explanation of a verb, is on the page twice.
        let mut usages: Vec<&str> = h.verbs().map(|v| v.usage.as_str()).collect();
        usages.sort();
        usages.dedup();
        assert_eq!(usages.len(), h.verbs().count());
        let mut abouts: Vec<&str> = h.verbs().map(|v| v.about.as_str()).collect();
        abouts.sort();
        let n = abouts.len();
        abouts.dedup();
        assert_eq!(abouts.len(), n, "two commands say the same");
    }

    /// One line first (plan 4.1): every command's `about` and every
    /// argument's `help` is at most 80 characters; the rest is the long
    /// help, shown by `--help`.
    #[test]
    fn every_help_line_is_short() {
        fn walk(c: &clap::Command, at: &str, long: &mut Vec<String>) {
            if let Some(a) = c.get_about() {
                let a = a.to_string();
                if a.chars().count() > 80 {
                    long.push(format!("{at}: {a}"));
                }
            }
            for arg in c.get_arguments() {
                if let Some(h) = arg.get_help() {
                    let h = h.to_string();
                    if h.chars().count() > 80 {
                        long.push(format!("{at} {}: {h}", arg.get_id()));
                    }
                }
            }
            for s in c.get_subcommands() {
                walk(s, &format!("{at} {}", s.get_name()), long);
            }
        }
        let mut long = Vec::new();
        walk(&Cli::command(), "nerve-node", &mut long);
        assert!(long.is_empty(), "{long:#?}");
    }

    /// `--help` lists the commands in the four groups and More, one line
    /// each, and names the options every command takes there only; a
    /// command's long page ends on its guide page.
    #[test]
    fn the_top_help_is_in_groups_and_short() {
        let mut cmd = help_pages(Cli::command(), "nerve-node");
        let top = cmd.render_help().to_string();
        let mut at = 0;
        for g in [
            "Set up:",
            "Centers:",
            "What a center may do:",
            "Watch and stop:",
            "More:",
            "Options every command takes:",
        ] {
            let i = top[at..]
                .find(g)
                .unwrap_or_else(|| panic!("{g} missing or out of order:\n{top}"));
            at += i + g.len();
        }
        for c in Cli::command().get_subcommands().filter(|c| visible(c)) {
            let line = format!("  {:9}  {}", c.get_name(), about_of(c));
            assert_eq!(top.matches(&line).count(), 1, "{line}\n{top}");
        }
        assert!(top.lines().all(|l| l.chars().count() <= 100), "{top}");
        assert!(top.contains("--json"), "{top}");
        let folder = cmd.find_subcommand_mut("folder").unwrap();
        assert!(!folder.render_help().to_string().contains("--json"));
        let long = folder.render_long_help().to_string();
        assert!(
            long.ends_with(&format!(
                "More in the user guide: https://github.com/prometheion/nerve-protocol/blob/{}/docs/user/folders-and-modes.md\n",
                nerve_transport::webui::GUIDE_REF
            )),
            "{long}"
        );
        // Bare, it names the commands of every day, each one that exists.
        let day = everyday("nerve-node");
        for l in day.lines().filter(|l| l.starts_with("  ")) {
            let word = l
                .split_whitespace()
                .find(|w| *w != "sudo" && *w != "nerve-node")
                .unwrap();
            assert!(Cli::command().find_subcommand(word).is_some(), "{l}");
        }
        assert_eq!(
            day.lines().filter(|l| l.starts_with("  ")).count(),
            6,
            "{day}"
        );
    }

    /// The help data has a line and its rest for each item, and a guide
    /// page for each card, from the same split as `--help`.
    #[test]
    fn the_help_data_folds_the_rest() {
        let h = help();
        let mode = h.verbs().find(|v| v.name == "mode").unwrap();
        assert_eq!(
            mode.about,
            "Choose how much a center may do: folder, allowlist or user mode (as you)"
        );
        assert!(
            mode.more.starts_with("Show each center's mode"),
            "{}",
            mode.more
        );
        let arg = mode.args.iter().find(|a| a.name == "<MODE>").unwrap();
        assert!(
            arg.about.contains("reads what all accounts may"),
            "{}",
            arg.about
        );
        // The widest mode says in the first line that it runs as you (round
        // 2, security 1).
        assert!(arg.about.contains("`user` (as you)"), "{}", arg.about);
        assert!(arg.more.contains("protected files aside"), "{}", arg.more);
        for s in &h.sections {
            for c in &s.cards {
                assert!(c.doc.ends_with(".md"), "{}", c.name);
                let file = format!("{}/../../docs/user/{}", env!("CARGO_MANIFEST_DIR"), c.doc);
                assert!(
                    std::path::Path::new(&file).exists(),
                    "{} names {}",
                    c.name,
                    c.doc
                );
            }
        }
        assert!(h.options.iter().any(|o| o.name == "--json"));
        assert!(h.options.iter().any(|o| o.name.starts_with("--center")));
        let json = serde_json::to_value(&h).unwrap();
        assert!(json.get("global").is_none() && json["sections"][0].get("line").is_some());
    }

    /// The help page calls no command not done.
    #[test]
    fn no_command_is_called_not_done() {
        let text = Cli::command().render_help().to_string();
        assert!(!text.contains("not done"), "{text}");
        assert!(text.contains("install"), "{text}");
        let page = serde_json::to_string(&help()).unwrap();
        assert!(!page.to_lowercase().contains("not done"), "{page}");
    }

    #[test]
    fn every_argument_is_explained() {
        let h = help();
        let cards = h.sections.iter().flat_map(|s| &s.cards);
        for a in &h.common {
            assert!(!a.about.is_empty(), "{} has no explanation", a.name);
        }
        for c in cards.clone() {
            for a in &c.shared_args {
                assert!(
                    !a.about.is_empty(),
                    "`{}` {} has no explanation",
                    c.name,
                    a.name
                );
            }
        }
        for v in h.verbs() {
            for a in &v.args {
                assert!(
                    !a.about.is_empty(),
                    "`{}` {} has no explanation",
                    v.name,
                    a.name
                );
            }
        }
    }
}
