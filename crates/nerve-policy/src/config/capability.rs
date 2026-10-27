//! Capabilities the owner declares in `node.toml` (`[[capability]]`,
//! docs/user/config-capabilities.md): each one is one action, `cap.action`,
//! that runs one fixed program with fixed arguments and the call's arguments
//! filled in as whole arguments. The node runs it itself (as `nerve-run` by
//! default, or as the owner), never through a shell, and returns its output.
//!
//! The schemas are JSON text in the file, as the owner writes them anywhere
//! else, and are held to the subset a center checks (nerve_proto::schema).

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::{Map, Value, json};

use nerve_proto::descriptor::{Effect, bad_member_name, plain_line};
use nerve_proto::schema::{self, Role};

/// The capabilities that are the node's own, and the ones the center serves
/// itself on every node (`job`, `stream`): no program and no capability of
/// the config may take their names, so no call meant for them reaches it,
/// and a center never leaves its capability out for the name.
pub const BUILT_IN: &[&str] = &["node", "fs", "exec", "settings", "audit", "job", "stream"];

/// The most `[[capability]]` entries a node keeps: far past what an owner
/// declares, and a bound on what every descriptor carries.
pub const MAX_CAPABILITIES: usize = 64;

/// The most elements of one command.
pub const MAX_COMMAND: usize = 64;

/// What the `result` of an entry is when the file says none.
pub const TEXT: &str = "text";

/// One capability of the config: the action `name` (`cap.action`) runs
/// `command` and returns what it prints.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConfigCapability {
    /// `cap.action`, as rules, `cap set` and the audit name it.
    pub name: String,
    /// One line for the agent: what it does.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub summary: String,
    pub effect: Effect,
    /// The program and its arguments. An element `{field}` is the call's
    /// argument `field`, as one whole argument; one left out (or null) is
    /// left out, so it stands after a `--` element and comes last. A value
    /// that starts with `-` is taken only after a `--` element, where the
    /// program reads no options.
    pub command: Vec<String>,
    /// The arguments schema, JSON text; none takes no arguments.
    #[serde(
        default,
        skip_serializing_if = "Value::is_null",
        serialize_with = "json_text",
        deserialize_with = "from_json_text"
    )]
    pub params: Value,
    /// What the call returns: what the program prints as text (`text`, the
    /// default), or as JSON that fits this result schema.
    #[serde(default, skip_serializing_if = "Output::is_text")]
    pub result: Output,
    /// How long it may run; the node's `limits.default_timeout_secs` when
    /// unset. At most `limits.max_timeout_secs`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout_secs: Option<u64>,
    #[serde(default, skip_serializing_if = "RunsAs::is_default")]
    pub account: RunsAs,
    #[serde(default, skip_serializing_if = "Platform::is_any")]
    pub platform: Platform,
}

/// The account a config capability runs as. There is no other: never the
/// node's own `nerve`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum RunsAs {
    /// The installed Linux node's command account, held to the folders.
    #[default]
    #[serde(rename = "nerve-run")]
    NerveRun,
    /// The owner, with the owner's rights (root where root is the owner).
    #[serde(rename = "owner")]
    Owner,
}

impl RunsAs {
    pub fn is_default(&self) -> bool {
        *self == RunsAs::NerveRun
    }

    pub fn as_str(self) -> &'static str {
        match self {
            RunsAs::NerveRun => "nerve-run",
            RunsAs::Owner => "owner",
        }
    }

    pub fn parse(s: &str) -> Option<RunsAs> {
        match s {
            "nerve-run" => Some(RunsAs::NerveRun),
            "owner" => Some(RunsAs::Owner),
            _ => None,
        }
    }
}

/// Where a config capability runs: a node offers only those of its own
/// platform.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Platform {
    #[default]
    Any,
    Linux,
    Windows,
}

impl Platform {
    pub fn is_any(&self) -> bool {
        *self == Platform::Any
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Platform::Any => "any",
            Platform::Linux => "linux",
            Platform::Windows => "windows",
        }
    }

    pub fn parse(s: &str) -> Option<Platform> {
        match s {
            "any" => Some(Platform::Any),
            "linux" => Some(Platform::Linux),
            "windows" => Some(Platform::Windows),
            _ => None,
        }
    }

    /// Whether it is meant for the platform `os` (`std::env::consts::OS`).
    pub fn takes(self, os: &str) -> bool {
        match self {
            Platform::Any => true,
            Platform::Linux => os == "linux",
            Platform::Windows => os == "windows",
        }
    }
}

/// What a config capability's call returns.
#[derive(Debug, Clone, Default, PartialEq)]
pub enum Output {
    /// What the program prints, as text.
    #[default]
    Text,
    /// What it prints parsed as JSON, which must fit this schema.
    Json(Value),
}

impl Output {
    pub fn is_text(&self) -> bool {
        *self == Output::Text
    }

    /// `text`, or a JSON result schema as text.
    pub fn parse(s: &str) -> Result<Output, String> {
        if s.trim() == TEXT {
            return Ok(Output::Text);
        }
        serde_json::from_str(s)
            .map(Output::Json)
            .map_err(|e| format!("result: `text` or a JSON schema: {e}"))
    }

    /// The result schema the descriptor publishes.
    pub fn schema(&self) -> Value {
        match self {
            Output::Text => json!({"type": "string"}),
            Output::Json(s) => s.clone(),
        }
    }
}

impl std::fmt::Display for Output {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Output::Text => f.write_str(TEXT),
            Output::Json(s) => write!(f, "{s}"),
        }
    }
}

impl Serialize for Output {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for Output {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Output, D::Error> {
        Output::parse(&String::deserialize(d)?).map_err(serde::de::Error::custom)
    }
}

fn json_text<S: Serializer>(v: &Value, s: S) -> Result<S::Ok, S::Error> {
    s.serialize_str(&v.to_string())
}

fn from_json_text<'de, D: Deserializer<'de>>(d: D) -> Result<Value, D::Error> {
    let text = String::deserialize(d)?;
    serde_json::from_str(&text).map_err(|e| serde::de::Error::custom(format!("params: {e}")))
}

/// The argument an element of a command stands for: `{field}` as a whole,
/// with no blank or brace in `field`. Any other element is taken as it is.
fn placeholder(element: &str) -> Option<&str> {
    let inner = element.strip_prefix('{')?.strip_suffix('}')?;
    let plain =
        !inner.is_empty() && !inner.contains(|c: char| c.is_whitespace() || "{}".contains(c));
    plain.then_some(inner)
}

/// The arguments schema `params` takes (an object schema), and its
/// properties.
fn properties(params: &Value) -> Option<&Map<String, Value>> {
    params.get("properties").and_then(Value::as_object)
}

/// Whether the schema `s` of a filled-in argument takes only values that
/// fill one argument: a string, a number, an integer or a boolean, or null
/// for one left out.
fn scalar(s: &Value) -> bool {
    let fits = |t: &Value| {
        matches!(
            t.as_str(),
            Some("string" | "number" | "integer" | "boolean" | "null")
        )
    };
    match s.get("type") {
        Some(Value::Array(ts)) => !ts.is_empty() && ts.iter().all(fits),
        Some(t) => fits(t) && t != "null",
        // An `enum` of plain values needs no type.
        None => s
            .get("enum")
            .and_then(Value::as_array)
            .is_some_and(|e| e.iter().all(|v| !v.is_object() && !v.is_array())),
    }
}

/// Whether the schema `s` of a filled-in argument takes null, which leaves
/// it out as well.
fn nullable(s: &Value) -> bool {
    match s.get("type") {
        Some(Value::Array(ts)) => ts.iter().any(|t| t == "null"),
        Some(t) => t == "null",
        None => s
            .get("enum")
            .and_then(Value::as_array)
            .is_some_and(|e| e.contains(&Value::Null)),
    }
}

/// Whether `program` is a name looked up in PATH or a full path, in the
/// form of the platform the entry is for: the file may be read on another
/// one, which leaves it out.
fn program_named(program: &str, platform: Platform) -> bool {
    let unix = program.starts_with('/') || !program.contains('/');
    let b = program.as_bytes();
    let drive = b.len() > 2 && b[0].is_ascii_alphabetic() && b[1] == b':' && b"/\\".contains(&b[2]);
    let windows = drive || program.starts_with("\\\\") || !program.contains(['/', '\\']);
    match platform {
        Platform::Linux => unix,
        Platform::Windows => windows,
        Platform::Any => unix || windows,
    }
}

impl ConfigCapability {
    /// The capability and the action of `name`.
    pub fn split(&self) -> (&str, &str) {
        self.name.split_once('.').unwrap_or((&self.name, ""))
    }

    /// The arguments schema the descriptor publishes: the declared one, or
    /// one that takes no arguments.
    pub fn params_schema(&self) -> Value {
        if self.params.is_null() {
            json!({"type": "object", "properties": {}, "additionalProperties": false})
        } else {
            self.params.clone()
        }
    }

    /// The checks serde cannot do. `max_timeout_secs` is the node's
    /// `limits.max_timeout_secs`.
    pub fn validate(&self, max_timeout_secs: u64) -> Result<(), String> {
        let n = &self.name;
        let Some((cap, action)) = n.split_once('.') else {
            return Err(format!(
                "capability {n:?}: name it `cap.action`, like sensors.read"
            ));
        };
        for part in [cap, action] {
            if let Some(why) = bad_member_name(part) {
                return Err(format!("capability {n:?}: {why}"));
            }
        }
        if BUILT_IN.contains(&cap) {
            return Err(format!(
                "capability {n}: {cap} is the node's or the center's own"
            ));
        }
        if !self.summary.is_empty() && !plain_line(&self.summary) {
            return Err(format!(
                "capability {n}: the summary is one line, without blanks at either end"
            ));
        }
        if let Some(t) = self.timeout_secs
            && !(1..=max_timeout_secs).contains(&t)
        {
            return Err(format!(
                "capability {n}: timeout_secs {t}: 1 to the node's limits.max_timeout_secs ({max_timeout_secs})"
            ));
        }
        if !self.params.is_null() {
            schema::check(&self.params, Role::Params).map_err(|e| {
                format!("capability {n}: params: {}", schema::brief(&e.to_string()))
            })?;
        }
        if let Output::Json(s) = &self.result {
            schema::check(s, Role::Result).map_err(|e| {
                format!("capability {n}: result: {}", schema::brief(&e.to_string()))
            })?;
        }
        self.check_command()
            .map_err(|e| format!("capability {n}: command: {e}"))
    }

    /// The command: a fixed program, whole-element placeholders that each
    /// name an argument of `params` that fills one argument, and every
    /// argument used.
    fn check_command(&self) -> Result<(), String> {
        let Some(program) = self.command.first() else {
            return Err("give the program and its arguments".into());
        };
        if self.command.len() > MAX_COMMAND {
            return Err(format!("at most {MAX_COMMAND} elements"));
        }
        if self.command.iter().any(|e| e.contains('\0')) {
            return Err("an element holds a NUL character".into());
        }
        if program.is_empty() || placeholder(program).is_some() {
            return Err("the first element is the program, fixed".into());
        }
        // A program named by a relative path would be looked for in the
        // account's home, where it runs.
        if !program_named(program, self.platform) {
            return Err(format!(
                "the program {program:?}: a name looked up in PATH, or a full path"
            ));
        }
        let empty = Map::new();
        let props = properties(&self.params).unwrap_or(&empty);
        let required: Vec<&str> = self
            .params
            .get("required")
            .and_then(Value::as_array)
            .map(|r| r.iter().filter_map(Value::as_str).collect())
            .unwrap_or_default();
        let mut used = std::collections::BTreeSet::new();
        let mut options = true;
        // The argument a call may leave out that came last, after `--`.
        let mut optional: Option<&str> = None;
        for e in &self.command[1..] {
            if options && e == "--" {
                options = false;
                continue;
            }
            // A left-out argument drops its element, so the elements after
            // it move up: an option before it would take the next one as its
            // value, and an argument after it would stand in its place.
            if let Some(last) = optional
                && placeholder(e) != Some(last)
            {
                return Err(format!(
                    "{{{last}}} may be left out, so it comes last: {e} would move into its place"
                ));
            }
            if let Some(field) = placeholder(e) {
                let s = props
                    .get(field)
                    .ok_or_else(|| format!("{e} names no argument of params"))?;
                if !scalar(s) {
                    return Err(format!(
                        "{e}: the argument {field} must be a string, number, integer or boolean, which fills one argument"
                    ));
                }
                if !required.contains(&field) || nullable(s) {
                    if options {
                        return Err(format!(
                            "{e}: a call may leave {field} out, so it stands after a -- element (or give it in required, not null)"
                        ));
                    }
                    optional = Some(field);
                }
                used.insert(field);
                continue;
            }
            // `--file={path}` would be one argument holding the value, which
            // the program may read as an option of its own.
            if let Some(field) = props.keys().find(|f| e.contains(&format!("{{{f}}}"))) {
                return Err(format!(
                    "{e:?}: a placeholder is a whole element; give {{{field}}} as its own"
                ));
            }
        }
        if let Some(unused) = props.keys().find(|f| !used.contains(f.as_str())) {
            return Err(format!(
                "the argument {unused} of params is in no element; name it as {{{unused}}}"
            ));
        }
        Ok(())
    }

    /// The program and its arguments for a call with `args`, which fit
    /// `params` already: each placeholder becomes the argument's value as
    /// one element (a string as it is, a number or boolean as JSON writes
    /// it), never read by a shell; one left out (or null) is left out. A
    /// value that starts with `-` before the first `--` element is refused:
    /// the program would read it as an option.
    pub fn argv(&self, args: &Map<String, Value>) -> Result<Vec<String>, String> {
        let mut out = Vec::with_capacity(self.command.len());
        let mut options = true;
        for (i, e) in self.command.iter().enumerate() {
            if i > 0 && options && e == "--" {
                options = false;
                out.push(e.clone());
                continue;
            }
            let Some(field) = placeholder(e).filter(|_| i > 0) else {
                out.push(e.clone());
                continue;
            };
            let text = match args.get(field) {
                None | Some(Value::Null) => continue,
                Some(Value::String(s)) => s.clone(),
                Some(v @ (Value::Number(_) | Value::Bool(_))) => v.to_string(),
                Some(_) => return Err(format!("{field}: one value, not a list or an object")),
            };
            if text.contains('\0') {
                return Err(format!("{field}: holds a NUL character"));
            }
            if options && text.starts_with('-') {
                return Err(format!(
                    "{field}: a value that starts with - would be read as an option here; {} takes it only after --",
                    self.name
                ));
            }
            out.push(text);
        }
        Ok(out)
    }

    /// The command as one line, for the audit and `cap ls`: an element that
    /// holds a blank, a quote, a backslash or a control character is quoted
    /// with its escapes, as JSON writes a string, so the line stays one.
    pub fn command_line(&self) -> String {
        self.command
            .iter()
            .map(|e| {
                let plain = !e.is_empty()
                    && !e.contains(|c: char| {
                        c.is_whitespace() || c.is_control() || "'\"\\".contains(c)
                    });
                if plain {
                    e.clone()
                } else {
                    Value::String(e.clone()).to_string()
                }
            })
            .collect::<Vec<_>>()
            .join(" ")
    }
}

/// Checks the config's capabilities: each one alone, and their names once
/// each.
pub fn validate_all(caps: &[ConfigCapability], max_timeout_secs: u64) -> Result<(), String> {
    if caps.len() > MAX_CAPABILITIES {
        return Err(format!("at most {MAX_CAPABILITIES} [[capability]] entries"));
    }
    let mut names = std::collections::BTreeSet::new();
    for c in caps {
        c.validate(max_timeout_secs)?;
        if !names.insert(c.name.as_str()) {
            return Err(format!("two capabilities are named {}", c.name));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::NodeConfig;

    /// A `[[capability]]` table with `extra` lines.
    fn entry(name: &str, command: &str, extra: &str) -> String {
        format!(
            "[[capability]]\nname = \"{name}\"\neffect = \"read\"\ncommand = {command}\n{extra}\n"
        )
    }

    const PATH_PARAMS: &str = r#"params = '{"type": "object", "properties": {"path": {"type": "string", "x-nerve-path": "read"}, "lines": {"type": "integer"}}, "required": ["path", "lines"], "additionalProperties": false}'"#;

    #[test]
    fn config_capabilities_parse_and_round_trip() {
        let text = format!(
            "{}{}",
            entry(
                "logs.tail",
                r#"["tail", "-n", "{lines}", "--", "{path}"]"#,
                &format!(
                    "summary = \"The end of a log.\"\n{PATH_PARAMS}\ntimeout_secs = 5\naccount = \"owner\"\nplatform = \"linux\""
                ),
            ),
            entry(
                "sensors.read",
                r#"["sensors", "-j"]"#,
                "result = '{\"type\": \"object\"}'"
            )
            .replace("\"read\"\ncommand", "\"sense\"\ncommand"),
        );
        let c = NodeConfig::parse(&text).unwrap();
        let [tail, sensors] = &c.capabilities[..] else {
            panic!("two: {:?}", c.capabilities)
        };
        assert_eq!(tail.split(), ("logs", "tail"));
        assert_eq!(tail.effect, Effect::Read);
        assert_eq!(tail.summary, "The end of a log.");
        assert_eq!(
            tail.params["properties"]["path"]["x-nerve-path"],
            json!("read")
        );
        assert_eq!(tail.result, Output::Text);
        assert_eq!(tail.timeout_secs, Some(5));
        assert_eq!(tail.account, RunsAs::Owner);
        assert_eq!(tail.platform, Platform::Linux);
        assert_eq!(sensors.effect, Effect::Sense);
        assert_eq!(sensors.result, Output::Json(json!({"type": "object"})));
        // The defaults: nerve-run, any platform, the node's timeout.
        assert_eq!(sensors.account, RunsAs::NerveRun);
        assert_eq!(sensors.platform, Platform::Any);
        assert_eq!(sensors.timeout_secs, None);
        assert!(sensors.params.is_null());
        assert_eq!(
            sensors.params_schema(),
            json!({"type": "object", "properties": {}, "additionalProperties": false})
        );
        // Round trip; the defaults stay out of the file.
        let again = c.to_toml();
        assert_eq!(NodeConfig::parse(&again).unwrap(), c, "{again}");
        let sensors_part = &again[again.rfind("[[capability]]").unwrap()..];
        for absent in ["account", "platform", "timeout_secs", "params", "summary"] {
            assert!(!sensors_part.contains(absent), "{absent}: {sensors_part}");
        }
        assert!(!NodeConfig::default().to_toml().contains("capability"));
        // A center's document holds none of it.
        let doc = json!({"capability": []});
        assert!(serde_json::from_value::<crate::CenterDocument>(doc).is_err());
    }

    #[test]
    fn bad_config_capabilities_are_refused() {
        let ok_params =
            r#"params = '{"type": "object", "properties": {"path": {"type": "string"}}}'"#;
        for (name, command, extra, why) in [
            ("sensors", r#"["sensors"]"#, "", "cap.action"),
            ("a.b.c", r#"["x"]"#, "", "letters, digits"),
            ("fs.extra", r#"["x"]"#, "", "the node's or the center's own"),
            ("job.x", r#"["x"]"#, "", "the node's or the center's own"),
            ("stream.x", r#"["x"]"#, "", "the node's or the center's own"),
            ("a.b", "[]", "", "the program"),
            (
                "a.b",
                r#"["{path}"]"#,
                ok_params,
                "the first element is the program",
            ),
            ("a.b", r#"["./run.sh"]"#, "", "a name looked up in PATH"),
            ("a.b", r#"["cat", "{path}"]"#, "", "names no argument"),
            (
                "a.b",
                r#"["cat", "{other}"]"#,
                ok_params,
                "names no argument",
            ),
            (
                "a.b",
                r#"["cat", "--file={path}"]"#,
                ok_params,
                "a whole element",
            ),
            ("a.b", r#"["cat"]"#, ok_params, "in no element"),
            (
                "a.b",
                r#"["cat", "{path}"]"#,
                r#"params = '{"type": "object", "properties": {"path": {"type": "array"}}}'"#,
                "fills one argument",
            ),
            (
                "a.b",
                r#"["cat", "{path}"]"#,
                r#"params = '{"type": "object", "properties": {"path": {"oneOf": [{"type": "string"}]}}}'"#,
                "params:",
            ),
            (
                "a.b",
                r#"["cat"]"#,
                r#"params = '{"type": "string"}'"#,
                "params:",
            ),
            ("a.b", r#"["cat"]"#, "params = 'not json'", "params"),
            (
                "a.b",
                r#"["cat"]"#,
                r#"result = '{"oneOf": []}'"#,
                "result:",
            ),
            ("a.b", r#"["cat"]"#, "result = 'html'", "result"),
            ("a.b", r#"["cat"]"#, "timeout_secs = 0", "timeout_secs 0"),
            (
                "a.b",
                r#"["cat"]"#,
                "timeout_secs = 3601",
                "max_timeout_secs (3600)",
            ),
            (
                "a.b",
                r#"["cat"]"#,
                "account = \"nerve\"",
                "unknown variant",
            ),
            ("a.b", r#"["cat"]"#, "account = \"root\"", "unknown variant"),
            ("a.b", r#"["cat"]"#, "platform = \"mac\"", "unknown variant"),
            ("a.b", r#"["cat"]"#, "summary = \"two\\nlines\"", "one line"),
            ("a.b", r#"["cat"]"#, "shell = true", "unknown field"),
            // A call may leave out an argument that is not required or takes
            // null: then before `--` an option would take the next element,
            // and after it a later element would move into its place.
            (
                "a.b",
                r#"["tail", "-n", "{lines}", "--", "{path}"]"#,
                r#"params = '{"type": "object", "properties": {"path": {"type": "string"}, "lines": {"type": "integer"}}, "required": ["path"]}'"#,
                "stands after a -- element",
            ),
            (
                "a.b",
                r#"["cat", "{path}"]"#,
                r#"params = '{"type": "object", "properties": {"path": {"type": ["string", "null"]}}, "required": ["path"]}'"#,
                "stands after a -- element",
            ),
            (
                "a.b",
                r#"["cat", "{path}"]"#,
                r#"params = '{"type": "object", "properties": {"path": {"enum": ["a", null]}}, "required": ["path"]}'"#,
                "stands after a -- element",
            ),
            (
                "a.b",
                r#"["cp", "--", "{a}", "{b}"]"#,
                r#"params = '{"type": "object", "properties": {"a": {"type": "string"}, "b": {"type": "string"}}, "required": ["b"]}'"#,
                "{a} may be left out, so it comes last: {b}",
            ),
            (
                "a.b",
                r#"["cp", "--", "{a}", "/x"]"#,
                ok_params.replace("path", "a").as_str(),
                "{a} may be left out, so it comes last: /x",
            ),
        ] {
            let text = entry(name, command, extra);
            let e = NodeConfig::parse(&text).unwrap_err();
            assert!(e.contains(why), "{name} {command} {extra}: {e}");
        }
        // A lower maximum holds a timeout too.
        let text = format!(
            "[limits]\nmax_timeout_secs = 10\n{}",
            entry("a.b", r#"["cat"]"#, "timeout_secs = 11")
        );
        assert!(NodeConfig::parse(&text).unwrap_err().contains("(10)"));
        // A name once.
        let one = entry("a.b", r#"["cat"]"#, "");
        let e = NodeConfig::parse(&format!("{one}{one}")).unwrap_err();
        assert!(e.contains("two capabilities are named a.b"), "{e}");
        // Two actions of one capability are two entries.
        let two = format!("{one}{}", entry("a.c", r#"["cat"]"#, ""));
        assert_eq!(NodeConfig::parse(&two).unwrap().capabilities.len(), 2);
        // A bound on how many.
        let many: String = (0..=MAX_CAPABILITIES)
            .map(|i| entry(&format!("a.n{i}"), r#"["cat"]"#, ""))
            .collect();
        assert!(NodeConfig::parse(&many).unwrap_err().contains("at most"));
    }

    fn cap(command: &[&str], params: Value) -> ConfigCapability {
        ConfigCapability {
            name: "files.show".into(),
            summary: String::new(),
            effect: Effect::Read,
            command: command.iter().map(|s| s.to_string()).collect(),
            params,
            result: Output::Text,
            timeout_secs: None,
            account: RunsAs::NerveRun,
            platform: Platform::Any,
        }
    }

    fn args(v: Value) -> Map<String, Value> {
        v.as_object().unwrap().clone()
    }

    #[test]
    fn arguments_fill_whole_elements_as_data() {
        let params = json!({"type": "object", "properties": {
            "path": {"type": "string"}, "n": {"type": "integer"}, "all": {"type": ["boolean", "null"]}},
            "required": ["path", "n"]});
        let c = cap(
            &["show", "{n}", "--", "{path}", "{path}", "{all}", "{all}"],
            params,
        );
        c.validate(60).unwrap();
        let line = "a b; rm -rf x $(id) `id` | cat > /tmp/y";
        assert_eq!(
            c.argv(&args(json!({"path": line, "n": 3, "all": true})))
                .unwrap(),
            ["show", "3", "--", line, line, "true", "true"]
        );
        // Left out or null: no element.
        assert_eq!(
            c.argv(&args(json!({"path": "p", "n": 1, "all": null})))
                .unwrap(),
            ["show", "1", "--", "p", "p"]
        );
        assert_eq!(
            c.argv(&args(json!({"path": "p", "n": 1}))).unwrap(),
            ["show", "1", "--", "p", "p"]
        );
        // Option-like before `--` is refused, after it it is an argument.
        let e = c.argv(&args(json!({"path": "p", "n": -1}))).unwrap_err();
        assert!(e.contains("would be read as an option"), "{e}");
        assert_eq!(
            c.argv(&args(json!({"path": "-rf", "n": 1}))).unwrap(),
            ["show", "1", "--", "-rf", "-rf"]
        );
        // A value that is no element is refused.
        assert!(c.argv(&args(json!({"path": "a\0b", "n": 1}))).is_err());
        // Without `--` an option-like value never passes.
        let plain = cap(
            &["show", "{path}"],
            json!({"type": "object", "properties": {"path": {"type": "string"}}, "required": ["path"]}),
        );
        plain.validate(60).unwrap();
        assert!(plain.argv(&args(json!({"path": "--help"}))).is_err());
        assert_eq!(
            plain.argv(&args(json!({"path": "x"}))).unwrap(),
            ["show", "x"]
        );
        // Braces that name no argument stay as they are.
        let lit = cap(&["jq", "{}", "{ .a }"], Value::Null);
        lit.validate(60).unwrap();
        assert_eq!(lit.argv(&Map::new()).unwrap(), ["jq", "{}", "{ .a }"]);
    }

    #[test]
    fn the_command_line_quotes_what_holds_blanks() {
        let c = cap(
            &[
                "grep",
                "-e",
                "a b",
                "it's",
                "x\ny",
                "\u{1b}[1m",
                "",
                "--",
                "{x}",
            ],
            Value::Null,
        );
        assert_eq!(
            c.command_line(),
            r#"grep -e "a b" "it's" "x\ny" "\u001b[1m" "" -- {x}"#
        );
    }

    #[test]
    fn a_program_is_named_in_the_form_of_its_platform() {
        for (program, platform, ok) in [
            ("sensors", Platform::Any, true),
            ("/usr/bin/sensors", Platform::Linux, true),
            ("/usr/bin/sensors", Platform::Any, true),
            ("/usr/bin/sensors", Platform::Windows, false),
            ("C:/Windows/System32/whoami.exe", Platform::Windows, true),
            ("C:\\Windows\\System32\\whoami.exe", Platform::Windows, true),
            ("C:/Windows/System32/whoami.exe", Platform::Any, true),
            ("C:/Windows/System32/whoami.exe", Platform::Linux, false),
            ("whoami.exe", Platform::Windows, true),
            ("bin\\run.bat", Platform::Windows, false),
            ("./run.sh", Platform::Any, false),
            ("./run.sh", Platform::Linux, false),
        ] {
            let mut c = cap(&[program], Value::Null);
            c.platform = platform;
            let r = c.validate(60);
            assert_eq!(r.is_ok(), ok, "{program} {platform:?}: {r:?}");
            if !ok {
                assert!(r.unwrap_err().contains("a name looked up in PATH"));
            }
        }
    }

    #[test]
    fn a_platform_takes_its_own_os() {
        assert!(Platform::Any.takes("linux") && Platform::Any.takes("windows"));
        assert!(Platform::Linux.takes("linux") && !Platform::Linux.takes("windows"));
        assert!(Platform::Windows.takes("windows") && !Platform::Windows.takes("linux"));
        for p in [Platform::Any, Platform::Linux, Platform::Windows] {
            assert_eq!(Platform::parse(p.as_str()), Some(p));
        }
        for a in [RunsAs::NerveRun, RunsAs::Owner] {
            assert_eq!(RunsAs::parse(a.as_str()), Some(a));
        }
        assert_eq!(RunsAs::parse("nerve"), None);
    }
}
