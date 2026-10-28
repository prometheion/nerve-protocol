//! The command reference of the Help page: every `nerve-node` command, read
//! from the CLI's own definition (nerve_node::cli::help), with an example
//! and the place in the app that does the same. The app's own part, the
//! example and the place, is written here once per command; a test fails
//! for a command that has none, so a new one cannot be left out.

use std::collections::BTreeSet;

use slint::{Model, ModelRc, SharedString, VecModel};

use crate::{HelpArg, Page, RefGroup, RefRow};

/// Where in the app a command's work is done: the page, the tab of
/// Settings (-1 for none), and its name in words; no page when the app
/// does not do it.
type Place = (Option<Page>, i32, &'static str);

const NOT_HERE: Place = (None, -1, "");

/// The app's part of each command: its words after `nerve-node`, an
/// example, and where the app does the same.
const COMMANDS: &[(&str, &str, Place)] = &[
    (
        "install",
        "sudo nerve-node install",
        (None, -1, "The installer: open the downloaded file"),
    ),
    (
        "uninstall",
        "sudo nerve-node uninstall --purge",
        (Some(Page::Settings), 5, "Settings › App › Uninstall"),
    ),
    (
        "service start",
        "nerve-node service start",
        (Some(Page::Overview), -1, "Overview › Start"),
    ),
    (
        "service stop",
        "nerve-node service stop",
        (Some(Page::Overview), -1, "Overview › Stop"),
    ),
    (
        "service restart",
        "nerve-node service restart",
        (Some(Page::Overview), -1, "Overview › Restart"),
    ),
    (
        "service status",
        "nerve-node service status",
        (Some(Page::Overview), -1, "Overview"),
    ),
    (
        "setup",
        "nerve-node setup",
        (
            Some(Page::Overview),
            -1,
            "Overview › Set up, while no center is paired",
        ),
    ),
    (
        "update",
        "sudo nerve-node update",
        (Some(Page::Settings), 5, "Settings › App › Update"),
    ),
    (
        "backup",
        "nerve-node backup ~/nerve.backup",
        (Some(Page::Settings), 4, "Settings › Backup"),
    ),
    (
        "restore",
        "nerve-node restore ~/nerve.backup",
        (Some(Page::Settings), 4, "Settings › Backup › Restore"),
    ),
    (
        "center add",
        "nerve-node center add 'nerve://pair?center=…&code=…&pin=…'",
        (Some(Page::Centers), -1, "Centers › Pair a center"),
    ),
    (
        "center rm",
        "nerve-node center rm --center lab",
        (Some(Page::Centers), -1, "Centers › Unpair"),
    ),
    (
        "center ls",
        "nerve-node center ls",
        (Some(Page::Centers), -1, "Centers"),
    ),
    (
        "center pause",
        "nerve-node center pause --center lab",
        (Some(Page::Centers), -1, "Centers › Pause"),
    ),
    (
        "center resume",
        "nerve-node center resume --center lab",
        (Some(Page::Centers), -1, "Centers › Resume"),
    ),
    (
        "center rotate-key",
        "nerve-node center rotate-key --center lab",
        (Some(Page::Centers), -1, "Centers › New key"),
    ),
    (
        "center grant",
        "nerve-node center grant settings write --center lab",
        (Some(Page::Centers), -1, "Centers › Settings grant"),
    ),
    (
        "proxy set",
        "nerve-node proxy set http://proxy.example:3128",
        (Some(Page::Settings), 2, "Settings › Network"),
    ),
    (
        "proxy rm",
        "nerve-node proxy rm",
        (Some(Page::Settings), 2, "Settings › Network"),
    ),
    (
        "proxy ls",
        "nerve-node proxy ls",
        (Some(Page::Settings), 2, "Settings › Network"),
    ),
    (
        "relay set",
        "nerve-node relay set 0.0.0.0:7490",
        (Some(Page::Relay), -1, "Relay › Turn on"),
    ),
    (
        "relay off",
        "nerve-node relay off",
        (Some(Page::Relay), -1, "Relay › Turn off"),
    ),
    (
        "relay add",
        "nerve-node relay add lab-pc --address relay.example",
        (Some(Page::Relay), -1, "Relay › Add a node"),
    ),
    (
        "relay set-centers",
        "nerve-node relay set-centers lab-pc --center home",
        (Some(Page::Relay), -1, "Relay › Centers and limits"),
    ),
    (
        "relay set-limits",
        "nerve-node relay set-limits lab-pc --max-links 12",
        (Some(Page::Relay), -1, "Relay › Centers and limits"),
    ),
    (
        "relay token",
        "nerve-node relay token lab-pc",
        (Some(Page::Relay), -1, "Relay › New link"),
    ),
    (
        "relay rm",
        "nerve-node relay rm lab-pc",
        (Some(Page::Relay), -1, "Relay › Remove"),
    ),
    (
        "relay ls",
        "nerve-node relay ls",
        (Some(Page::Relay), -1, "Relay"),
    ),
    (
        "mode set",
        "nerve-node mode set folder --center lab",
        (Some(Page::Policy), -1, "Permissions › Mode"),
    ),
    (
        "folder add",
        "nerve-node folder add ~/projects +r +w --center lab",
        (
            Some(Page::Policy),
            -1,
            "Permissions › Folders › Add a folder",
        ),
    ),
    (
        "folder set",
        "nerve-node folder set ~/projects -w --center lab",
        (Some(Page::Policy), -1, "Permissions › Folders"),
    ),
    (
        "folder rm",
        "nerve-node folder rm ~/projects --center lab",
        (Some(Page::Policy), -1, "Permissions › Folders"),
    ),
    (
        "folder ls",
        "nerve-node folder ls --center lab",
        (Some(Page::Policy), -1, "Permissions › Folders"),
    ),
    (
        "rule add",
        "nerve-node rule add allow 'git status' --center lab",
        (
            Some(Page::Policy),
            -1,
            "Permissions › Allowed commands / Forbidden commands › Add",
        ),
    ),
    (
        "rule rm",
        "nerve-node rule rm allow 'git status' --center lab",
        (
            Some(Page::Policy),
            -1,
            "Permissions › Allowed commands / Forbidden commands",
        ),
    ),
    (
        "rule edit",
        "nerve-node rule edit allow 'exec.run:git status' 'git status --short'",
        (
            Some(Page::Policy),
            -1,
            "Permissions › Allowed commands / Forbidden commands › Edit",
        ),
    ),
    (
        "rule ls",
        "nerve-node rule ls --center lab",
        (
            Some(Page::Policy),
            -1,
            "Permissions › Allowed commands / Forbidden commands",
        ),
    ),
    (
        "rule guard",
        "nerve-node rule guard --center lab",
        (
            Some(Page::Policy),
            -1,
            "Permissions › Add the guard / Update the guard",
        ),
    ),
    (
        "cap set",
        "nerve-node cap set exec.signal off --center lab",
        (Some(Page::Policy), -1, "Permissions › Capabilities"),
    ),
    (
        "cap ls",
        "nerve-node cap ls --center lab",
        (Some(Page::Policy), -1, "Permissions › Capabilities"),
    ),
    (
        "cap add",
        "nerve-node cap add sensors.read --effect sense -- sensors -j",
        NOT_HERE,
    ),
    (
        "cap edit",
        "nerve-node cap edit sensors.read --timeout 10",
        NOT_HERE,
    ),
    ("cap rm", "nerve-node cap rm sensors.read", NOT_HERE),
    (
        "cap provider allow",
        "nerve-node cap provider allow desk /usr/lib/nerve-desktop/nerve-desktop",
        (Some(Page::Settings), 6, "Settings › Advanced › Add"),
    ),
    (
        "cap provider rm",
        "nerve-node cap provider rm desk",
        (Some(Page::Settings), 6, "Settings › Advanced › Remove"),
    ),
    (
        "cap provider ls",
        "nerve-node cap provider ls",
        (Some(Page::Settings), 6, "Settings › Advanced"),
    ),
    (
        "sudo on",
        "nerve-node sudo on",
        (Some(Page::Policy), -1, "Permissions › Sudo › Turn on"),
    ),
    (
        "sudo off",
        "nerve-node sudo off",
        (Some(Page::Policy), -1, "Permissions › Sudo › Turn off"),
    ),
    (
        "sudo status",
        "nerve-node sudo status",
        (Some(Page::Policy), -1, "Permissions › Sudo"),
    ),
    (
        "config get",
        "nerve-node config get log.level",
        (Some(Page::Settings), 6, "Settings › Advanced"),
    ),
    (
        "config set",
        "nerve-node config set log.level debug",
        (Some(Page::Settings), 6, "Settings › Advanced"),
    ),
    (
        "config unset",
        "nerve-node config unset log.level",
        (Some(Page::Settings), 6, "Settings › Advanced"),
    ),
    (
        "config add",
        "nerve-node config add center.lab.policy.allow 'fs.read:~/notes/*'",
        (Some(Page::Settings), 6, "Settings › Advanced › Add"),
    ),
    (
        "config remove",
        "nerve-node config remove center.lab.policy.allow 'fs.read:~/notes/*'",
        (Some(Page::Settings), 6, "Settings › Advanced › Remove"),
    ),
    (
        "config accept",
        "nerve-node config accept",
        (
            Some(Page::Settings),
            6,
            "Settings › Advanced › Take node.toml as it is",
        ),
    ),
    ("run", "nerve-node run", NOT_HERE),
    (
        "status",
        "nerve-node status",
        (Some(Page::Overview), -1, "Overview"),
    ),
    (
        "audit",
        "nerve-node audit --denied --last 20",
        (Some(Page::Audit), -1, "Audit"),
    ),
    (
        "audit clear",
        "nerve-node audit clear",
        (Some(Page::Audit), -1, "Audit › Clear"),
    ),
    (
        "log",
        "nerve-node log --problems",
        (Some(Page::Log), -1, "Log"),
    ),
    (
        "log clear",
        "nerve-node log clear",
        (Some(Page::Log), -1, "Log › Clear"),
    ),
    (
        "panic",
        "nerve-node panic",
        (Some(Page::Overview), -1, "Overview › Panic"),
    ),
    (
        "unlock",
        "nerve-node unlock",
        (Some(Page::Overview), -1, "Overview › Unlock"),
    ),
];

/// The topic of a part of the CLI's help, in the app's words: its pages'
/// names where they have one.
fn topic(section: &str) -> String {
    match section {
        "Install and set up" => "Install".into(),
        "What a center may do" => "Permissions".into(),
        other => other.into(),
    }
}

/// The first sentence of `about`, to stand beside the command's name.
fn first_line(about: &str) -> String {
    let end = [". ", "; "]
        .iter()
        .filter_map(|s| about.find(s))
        .min()
        .unwrap_or(about.len());
    about[..end].trim_end_matches('.').to_string()
}

/// One command as the reference shows it.
#[derive(Debug, Clone)]
pub struct Command {
    pub topic: String,
    pub name: String,
    pub about: String,
    pub usage: String,
    pub args: Vec<(String, String)>,
    pub example: String,
    pub place: Place,
}

impl Command {
    /// Whether it matches `filter`: words of its name, explanation, usage
    /// or arguments, in any case, every word somewhere.
    pub fn matches(&self, filter: &str) -> bool {
        let text = format!(
            "{} {} {} {} {}",
            self.topic,
            self.name,
            self.about,
            self.usage,
            self.args
                .iter()
                .map(|(n, a)| format!("{n} {a}"))
                .collect::<Vec<_>>()
                .join(" ")
        )
        .to_lowercase();
        filter
            .split_whitespace()
            .all(|w| text.contains(&w.to_lowercase()))
    }
}

/// Every command of the CLI, by topic in the help's order.
pub fn commands(h: &nerve_node::cli::Help) -> Vec<Command> {
    let mut out = Vec::new();
    for s in &h.sections {
        for c in &s.cards {
            for v in &c.verbs {
                let (example, place) = COMMANDS
                    .iter()
                    .find(|(n, _, _)| *n == v.name)
                    .map(|(_, e, p)| (e.to_string(), *p))
                    .unwrap_or((format!("nerve-node {}", v.name), NOT_HERE));
                // Each row stands alone: what this command takes, not what
                // its card's other commands take.
                let args = v
                    .takes
                    .iter()
                    .map(|a| (a.name.clone(), a.about.clone()))
                    .collect();
                out.push(Command {
                    topic: topic(&s.name),
                    name: v.name.clone(),
                    about: v.about.clone(),
                    usage: v.usage.clone(),
                    args,
                    example,
                    place,
                });
            }
        }
    }
    out
}

/// What of the reference the owner opened: commands by name, and the topics
/// they closed (a topic is open until then). Each opens and closes on its
/// own, and a new filter or order keeps them.
#[derive(Debug, Default)]
pub struct Opened {
    pub commands: BTreeSet<String>,
    pub shut_topics: BTreeSet<String>,
}

impl Opened {
    /// Opens a shut command, or shuts an open one, also where `shown`
    /// shows it now: in place, so the rest of the page stays as it is.
    pub fn toggle_command(&mut self, shown: &ModelRc<RefGroup>, name: &str) {
        let open = !self.commands.remove(name);
        if open {
            self.commands.insert(name.to_string());
        }
        for g in shown.iter() {
            for (i, mut r) in g.rows.iter().enumerate() {
                if r.name == name {
                    r.open = open;
                    g.rows.set_row_data(i, r);
                }
            }
        }
    }

    /// [`Opened::toggle_command`] for a topic.
    pub fn toggle_topic(&mut self, shown: &ModelRc<RefGroup>, name: &str) {
        let open = self.shut_topics.remove(name);
        if !open {
            self.shut_topics.insert(name.to_string());
        }
        for (i, mut g) in shown.iter().enumerate() {
            if g.name == name {
                g.open = open;
                shown.set_row_data(i, g);
            }
        }
    }
}

/// What the reference shows for `filter`: by topic, or with `by_name` one
/// list from A to Z; topics with no match left out; open what `opened`
/// says.
pub fn groups(all: &[Command], filter: &str, by_name: bool, opened: &Opened) -> Vec<RefGroup> {
    let picked: Vec<&Command> = all.iter().filter(|c| c.matches(filter)).collect();
    let row = |c: &Command| RefRow {
        topic: c.topic.as_str().into(),
        name: c.name.as_str().into(),
        line: first_line(&c.about).into(),
        // Only what the line beside the name does not say already.
        about: if first_line(&c.about) == c.about.trim_end_matches('.') {
            SharedString::new()
        } else {
            c.about.as_str().into()
        },
        usage: c.usage.as_str().into(),
        args: ModelRc::new(VecModel::from(
            c.args
                .iter()
                .map(|(n, a)| HelpArg {
                    name: n.as_str().into(),
                    about: a.as_str().into(),
                })
                .collect::<Vec<_>>(),
        )),
        example: c.example.as_str().into(),
        in_app: c.place.0.is_some(),
        page: c.place.0.unwrap_or(Page::Help),
        tab: c.place.1,
        place: SharedString::from(c.place.2),
        open: opened.commands.contains(&c.name),
    };
    let group = |name: &str, rows: Vec<&Command>| RefGroup {
        name: name.into(),
        open: name.is_empty() || !opened.shut_topics.contains(name),
        rows: ModelRc::new(VecModel::from(
            rows.into_iter().map(row).collect::<Vec<_>>(),
        )),
    };
    if by_name {
        let mut rows = picked;
        rows.sort_by(|a, b| a.name.cmp(&b.name));
        if rows.is_empty() {
            return Vec::new();
        }
        return vec![group("", rows)];
    }
    let mut topics: Vec<&str> = Vec::new();
    for c in &picked {
        if !topics.contains(&c.topic.as_str()) {
            topics.push(&c.topic);
        }
    }
    topics
        .into_iter()
        .map(|t| group(t, picked.iter().copied().filter(|c| c.topic == t).collect()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every command of the CLI has its example and place here, and nothing
    /// here names a command the CLI has not.
    #[test]
    fn every_command_has_its_example_and_place() {
        let h = nerve_node::cli::help();
        let names: Vec<String> = h.verbs().map(|v| v.name.clone()).collect();
        for n in &names {
            assert!(
                COMMANDS.iter().any(|(c, _, _)| c == n),
                "`{n}` has no example and place in the reference"
            );
        }
        for (c, example, _) in COMMANDS {
            assert!(names.iter().any(|n| n == c), "`{c}` is no command");
            assert!(
                example.starts_with(&format!("nerve-node {c}"))
                    || example.starts_with(&format!("sudo nerve-node {c}")),
                "`{c}`: {example}"
            );
        }
    }

    /// A row lists what its command takes, once each: not what the other
    /// commands of its card take.
    #[test]
    fn a_row_has_the_arguments_of_its_command() {
        let all = commands(&nerve_node::cli::help());
        let args = |name: &str| -> Vec<String> {
            let c = all.iter().find(|c| c.name == name).unwrap();
            c.args.iter().map(|(n, _)| n.clone()).collect()
        };
        for c in &all {
            let mut names: Vec<&str> = c.args.iter().map(|(n, _)| n.as_str()).collect();
            names.sort();
            let n = names.len();
            names.dedup();
            assert_eq!(names.len(), n, "`{}` lists an argument twice", c.name);
            // What is written in place (`<NAME>`) is in the usage line of
            // the command that takes it, `[NAME]` when it can be left out.
            for (a, _) in &c.args {
                if let Some(value) = a.strip_prefix('<').and_then(|a| a.strip_suffix('>')) {
                    let left_out = format!("[{value}]");
                    assert!(
                        c.usage.contains(a.as_str()) || c.usage.contains(&left_out),
                        "`{}`: {a}",
                        c.name
                    );
                }
            }
        }
        assert!(!args("relay ls").contains(&"<NAME>".to_string()));
        assert!(!args("folder ls").contains(&"<PATH>".to_string()));
        assert_eq!(args("rule ls").iter().filter(|a| *a == "<LIST>").count(), 1);
        assert!(args("folder add").contains(&"<PATH>".to_string()));
        // What many commands take is said on the row of each, too.
        assert!(args("mode set").contains(&"--center <CENTER>".to_string()));
        // The search finds what a command takes, and only that.
        let found = groups(&all, "the folder.", false, &Opened::default());
        assert!(
            found
                .iter()
                .flat_map(|g| g.rows.iter().collect::<Vec<_>>())
                .all(|r| r.name != "folder ls")
        );
    }

    /// The texts of the app's pages, the string literals of ui/*.slint.
    fn ui_texts() -> Vec<String> {
        let files = [
            include_str!("../ui/app.slint"),
            include_str!("../ui/audit.slint"),
            include_str!("../ui/centers.slint"),
            include_str!("../ui/log.slint"),
            include_str!("../ui/overview.slint"),
            include_str!("../ui/permissions.slint"),
            include_str!("../ui/relay.slint"),
            include_str!("../ui/settings.slint"),
        ];
        let mut out = Vec::new();
        for f in files {
            for line in f.lines() {
                let line = line.trim_start();
                if line.starts_with("//") {
                    continue;
                }
                let mut quoted = line.split('"');
                quoted.next();
                while let Some(text) = quoted.next() {
                    out.push(text.trim().trim_end_matches('…').to_string());
                    quoted.next();
                }
            }
        }
        out
    }

    /// Each step of a place in the app is a word the app shows there, and
    /// a place in Settings names its tab, which "In the app" opens.
    #[test]
    fn every_place_in_the_app_is_there() {
        let texts = ui_texts();
        let settings = include_str!("../ui/settings.slint");
        let tabs: Vec<&str> = settings
            .lines()
            .find_map(|l| l.trim().strip_prefix("tabs: ["))
            .unwrap()
            .trim_end_matches("];")
            .split(", ")
            .map(|t| t.trim_matches('"'))
            .collect();
        let pages = [
            (Page::Overview, "Overview"),
            (Page::Centers, "Centers"),
            (Page::Relay, "Relay"),
            (Page::Policy, "Permissions"),
            (Page::Audit, "Audit"),
            (Page::Log, "Log"),
            (Page::Settings, "Settings"),
        ];
        for (name, _, (page, tab, place)) in COMMANDS {
            let Some(page) = page else { continue };
            // What follows a comma says when, and is no step.
            let place = place.split(", ").next().unwrap();
            let steps: Vec<&str> = place.split(" › ").collect();
            let label = pages.iter().find(|(p, _)| p == page).unwrap().1;
            assert_eq!(steps[0], label, "`{name}`: {place}");
            if *page == Page::Settings {
                assert!(*tab >= 0, "`{name}` opens no tab");
                assert_eq!(steps.get(1), tabs.get(*tab as usize), "`{name}`: {place}");
            }
            for step in &steps[1..] {
                for word in step.split(" / ") {
                    assert!(
                        texts.iter().any(|t| t == word),
                        "`{name}`: the app shows no \"{word}\""
                    );
                }
            }
        }
    }

    /// `rule guard` runs from two buttons of one banner: one for a pairing
    /// without the guard, one for a pairing that holds its older texts.
    #[test]
    fn the_guard_row_names_both_of_its_buttons() {
        let (_, _, (_, _, place)) = COMMANDS
            .iter()
            .find(|(c, _, _)| *c == "rule guard")
            .unwrap();
        for button in ["Add the guard", "Update the guard"] {
            assert!(
                place.contains(button),
                "`rule guard` does not name \"{button}\""
            );
        }
    }

    #[test]
    fn the_reference_filters_and_sorts() {
        let all = commands(&nerve_node::cli::help());
        let topics = groups(&all, "", false, &Opened::default());
        let names: Vec<String> = topics.iter().map(|g| g.name.to_string()).collect();
        assert_eq!(
            names,
            [
                "Install",
                "Pair and connect",
                "Permissions",
                "Run and watch"
            ]
        );
        let pair = &topics[1];
        let add = pair.rows.iter().find(|r| r.name == "center add").unwrap();
        assert_eq!(add.page, Page::Centers);
        assert!(add.in_app);
        assert_eq!(
            add.line,
            "Pair this machine with a center, using the pairing link it showed"
        );
        assert_eq!(add.about, "", "the line says it all");
        let rotate = pair
            .rows
            .iter()
            .find(|r| r.name == "center rotate-key")
            .unwrap();
        assert!(rotate.about.contains("7 more days"), "{}", rotate.about);
        // A filter: every word somewhere, in any case; the topics without a
        // match go.
        let found = groups(&all, "PIN relay", false, &Opened::default());
        assert_eq!(
            found.len(),
            1,
            "{:?}",
            found.iter().map(|g| g.name.to_string()).collect::<Vec<_>>()
        );
        assert!(found[0].rows.iter().any(|r| r.name == "proxy set"));
        assert!(groups(&all, "no-such-thing", false, &Opened::default()).is_empty());
        // From A to Z: one list.
        let az = groups(&all, "center", true, &Opened::default());
        assert_eq!(az.len(), 1);
        let n: Vec<String> = az[0].rows.iter().map(|r| r.name.to_string()).collect();
        let mut sorted = n.clone();
        sorted.sort();
        assert_eq!(n, sorted);
        assert!(n.contains(&"center add".to_string()));
        assert_eq!(first_line("Give a key; then more. And more."), "Give a key");
    }

    /// Commands and topics open and close each on their own, in place, and
    /// stay so across a new filter or order.
    #[test]
    fn commands_and_topics_open_each_on_their_own() {
        let all = commands(&nerve_node::cli::help());
        let mut opened = Opened::default();
        let shown = ModelRc::new(VecModel::from(groups(&all, "", false, &opened)));
        let row = |shown: &ModelRc<RefGroup>, name: &str| {
            shown
                .iter()
                .flat_map(|g| g.rows.iter().collect::<Vec<_>>())
                .find(|r| r.name == name)
                .unwrap()
        };
        let topic =
            |shown: &ModelRc<RefGroup>, name: &str| shown.iter().find(|g| g.name == name).unwrap();
        assert!(shown.iter().all(|g| g.open), "topics start open");
        assert!(!row(&shown, "center add").open);
        opened.toggle_command(&shown, "center add");
        opened.toggle_command(&shown, "relay add");
        assert!(row(&shown, "relay add").open);
        assert!(
            row(&shown, "center add").open,
            "a second one closed the first"
        );
        opened.toggle_topic(&shown, "Install");
        assert!(!topic(&shown, "Install").open);
        assert!(topic(&shown, "Permissions").open);
        // A new filter, and A to Z, keep what is open.
        let again = ModelRc::new(VecModel::from(groups(&all, "add", false, &opened)));
        assert!(row(&again, "center add").open && row(&again, "relay add").open);
        assert!(!row(&again, "folder add").open);
        let az = ModelRc::new(VecModel::from(groups(&all, "", true, &opened)));
        assert!(az.row_data(0).unwrap().open, "the list from A to Z is open");
        assert!(row(&az, "center add").open);
        opened.toggle_command(&shown, "center add");
        assert!(!row(&shown, "center add").open);
        assert!(row(&shown, "relay add").open);
        opened.toggle_topic(&shown, "Install");
        assert!(topic(&shown, "Install").open);
    }
}
