//! Conditions on a call's arguments (#152, C1): the pattern of a rule for
//! any action but the `fs` ones and `exec.run` (docs/dev/policy-engine.md).
//!
//! A pattern is one or more conditions joined by `,`, each `field`, an
//! operator and a value: `=` and `!=` compare a string, number or boolean,
//! `<`, `<=`, `>` and `>=` a number, and `~` matches a string against a glob.
//! A field is a top-level property of the action's arguments schema, and a
//! value is read as that property's type. A `,` in a value is written `\,`
//! (a `,` inside a glob's `{a,b}` or `[...]` needs none), a `\` before it
//! `\\`. An argument the schema marks as a path (`x-nerve-path`) is matched
//! as a path: its value as the node resolved it, `~/` the owner's home.
//!
//! The rule is checked against the schema the node or the center publishes
//! when it is written ([`check`]); the node and the action checker match it
//! with the same code ([`Conditions`]). A call whose value does not fit a
//! condition's type, or that leaves the argument out, fails closed: an
//! allow rule does not cover it, a deny rule does.

use globset::{GlobBuilder, GlobMatcher};
use serde_json::{Map, Value};

/// The most conditions one rule holds.
pub const MAX_CONDITIONS: usize = 16;

/// How a condition compares the argument with its value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Op {
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
    /// `~`: a glob over the whole string (or path).
    Like,
}

impl Op {
    pub fn as_str(self) -> &'static str {
        match self {
            Op::Eq => "=",
            Op::Ne => "!=",
            Op::Lt => "<",
            Op::Le => "<=",
            Op::Gt => ">",
            Op::Ge => ">=",
            Op::Like => "~",
        }
    }

    fn numeric(self) -> bool {
        matches!(self, Op::Lt | Op::Le | Op::Gt | Op::Ge)
    }
}

/// One condition as written: its value without the escapes of `\,` and `\\`
/// for `=` and `!=`, a glob as written for `~`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Condition {
    pub field: String,
    pub op: Op,
    pub value: String,
}

/// Whether a rule of `scope` (`cap` or `cap.action`) holds conditions after
/// its `:`: any scope but the `fs` ones, `exec.run` (their patterns are
/// paths and command lines) and the guard's.
pub fn takes_conditions(scope: &str) -> bool {
    let cap = scope.split('.').next().unwrap_or(scope);
    cap != crate::rules::FS && scope != "exec.run" && scope != "guard"
}

/// Whether `c` may be part of a field's name: the names a schema gives its
/// properties, as rules can write them.
fn field_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_' || c == '-'
}

/// The conditions of `pattern`, as written, or why it is none.
pub fn parse(pattern: &str) -> Result<Vec<Condition>, String> {
    let parts = split(pattern);
    if parts.len() > MAX_CONDITIONS {
        return Err(format!(
            "{} conditions; a rule holds at most {MAX_CONDITIONS}",
            parts.len()
        ));
    }
    parts.into_iter().map(condition).collect()
}

/// `pattern` cut at each `,` that is not escaped and not inside a glob's
/// `{...}` or `[...]`. Only a `~` condition is a glob: in the value of any
/// other a `[` or `{` is a character like any, so one left open does not
/// take the conditions after it into the value.
fn split(pattern: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let (mut start, mut braces, mut bracket, mut escaped) = (0, 0usize, false, false);
    // Whether the condition being read is a glob: the first character
    // after its field's name says.
    let mut glob = None;
    for (i, c) in pattern.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        if glob.is_none() && !field_char(c) {
            glob = Some(c == '~');
        }
        let in_glob = glob == Some(true);
        match c {
            '\\' => escaped = true,
            '[' if in_glob && !bracket => bracket = true,
            ']' if bracket => bracket = false,
            '{' if in_glob && !bracket => braces += 1,
            '}' if in_glob && !bracket => braces = braces.saturating_sub(1),
            ',' if !bracket && braces == 0 => {
                out.push(&pattern[start..i]);
                start = i + 1;
                glob = None;
            }
            _ => {}
        }
    }
    out.push(&pattern[start..]);
    out
}

fn condition(text: &str) -> Result<Condition, String> {
    let end = text.find(|c: char| !field_char(c)).unwrap_or(text.len());
    let (field, rest) = text.split_at(end);
    if field.is_empty() {
        return Err(format!(
            "condition {text:?}: it starts with an argument's name, then =, !=, <, <=, >, >= or ~ and a value (room=office)"
        ));
    }
    let op = [
        ("!=", Op::Ne),
        ("<=", Op::Le),
        (">=", Op::Ge),
        ("=", Op::Eq),
        ("<", Op::Lt),
        (">", Op::Gt),
        ("~", Op::Like),
    ]
    .into_iter()
    .find(|(s, _)| rest.starts_with(s));
    let Some((sign, op)) = op else {
        return Err(format!(
            "condition {text:?}: after {field} comes =, !=, <, <=, >, >= or ~ and a value"
        ));
    };
    let raw = &rest[sign.len()..];
    let value = match op {
        Op::Like => raw.to_string(),
        _ => unescape(raw),
    };
    if op != Op::Eq && op != Op::Ne && value.is_empty() {
        return Err(format!(
            "condition {text:?}: the value after {sign} is empty"
        ));
    }
    Ok(Condition {
        field: field.to_string(),
        op,
        value,
    })
}

/// A value without its escapes: `\,` is `,` and `\\` is `\`; any other `\`
/// stays, so a Windows path needs none.
fn unescape(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    let mut chars = raw.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\\'
            && let Some(&n) = chars.peek()
            && (n == ',' || n == '\\')
        {
            out.push(n);
            chars.next();
        } else {
            out.push(c);
        }
    }
    out
}

/// `value` as a condition writes it after `=`: a `,` and a `\` escaped.
pub fn escape_value(value: &str) -> String {
    value.replace('\\', "\\\\").replace(',', "\\,")
}

/// The condition that pins `field` to `value`, the call's argument: what an
/// audit button writes. Only a string, a number or a boolean can be pinned.
pub fn pin(field: &str, value: &Value) -> Result<String, String> {
    if field.is_empty() || !field.chars().all(field_char) {
        return Err(format!("{field:?} is not an argument a rule can name"));
    }
    let text = match value {
        Value::String(s) => escape_value(s),
        Value::Number(n) => n.to_string(),
        Value::Bool(b) => b.to_string(),
        _ => {
            return Err(format!(
                "{field} is not a string, number or boolean, so a rule cannot pin it"
            ));
        }
    };
    Ok(format!("{field}={text}"))
}

/// What a property of an arguments schema holds, as a condition reads it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    String,
    Path,
    Integer,
    Number,
    Boolean,
}

impl Kind {
    fn of(schema: &Value) -> Result<Kind, &'static str> {
        if schema.get("x-nerve-path").is_some() {
            return Ok(Kind::Path);
        }
        let mut types: Vec<&str> = match schema.get("type") {
            Some(Value::String(t)) => vec![t.as_str()],
            Some(Value::Array(a)) => a.iter().filter_map(Value::as_str).collect(),
            _ => Vec::new(),
        };
        // An `enum` without a type has the type of its choices.
        if types.is_empty()
            && let Some(choices) = schema.get("enum").and_then(Value::as_array)
        {
            for c in choices {
                let t = match c {
                    Value::String(_) => "string",
                    Value::Bool(_) => "boolean",
                    Value::Number(n) if n.is_f64() => "number",
                    Value::Number(_) => "integer",
                    Value::Null => "null",
                    _ => "object",
                };
                if !types.contains(&t) {
                    types.push(t);
                }
            }
            // Whole numbers among other numbers are numbers.
            if types.contains(&"number") {
                types.retain(|t| *t != "integer");
            }
        }
        let mut kinds = types.into_iter().filter(|t| *t != "null");
        match (kinds.next(), kinds.next()) {
            (Some("string"), None) => Ok(Kind::String),
            (Some("integer"), None) => Ok(Kind::Integer),
            (Some("number"), None) => Ok(Kind::Number),
            (Some("boolean"), None) => Ok(Kind::Boolean),
            (None, _) => Err("its schema gives it no type"),
            _ => Err("only a string, a number or a boolean can be pinned"),
        }
    }

    fn word(self) -> &'static str {
        match self {
            Kind::String => "a string",
            Kind::Path => "a path",
            Kind::Integer => "an integer",
            Kind::Number => "a number",
            Kind::Boolean => "a boolean",
        }
    }
}

/// The top-level properties of the arguments schema `params`.
fn properties(params: &Value) -> Option<&Map<String, Value>> {
    params.get("properties").and_then(Value::as_object)
}

/// The arguments `args` of a call that the schema `params` names, for the
/// audit: one it leaves out is no argument of the action, and a rule cannot
/// name it. A path argument is kept only where `resolved`, the call's paths
/// having been resolved as the rules match them; before that, a pin of one
/// would name the spelling the agent gave, not the place.
pub fn declared(params: &Value, args: &Map<String, Value>, resolved: bool) -> Map<String, Value> {
    let Some(props) = properties(params) else {
        return Map::new();
    };
    args.iter()
        .filter(|(k, _)| {
            props
                .get(*k)
                .is_some_and(|s| resolved || s.get("x-nerve-path").is_none())
        })
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect()
}

/// The arguments of `params` a rule can name, with their kind, for the
/// forms that offer them: `room (a string: office, kitchen)`.
pub fn fields(params: &Value) -> Vec<String> {
    let Some(props) = properties(params) else {
        return Vec::new();
    };
    props
        .iter()
        .filter(|(name, _)| name.chars().all(field_char))
        .filter_map(|(name, s)| {
            let kind = Kind::of(s).ok()?;
            let choices = s
                .get("enum")
                .and_then(Value::as_array)
                .map(|e| {
                    e.iter()
                        .filter(|v| !v.is_null())
                        .map(|v| v.as_str().map_or_else(|| v.to_string(), str::to_string))
                        .collect::<Vec<_>>()
                        .join(", ")
                })
                .filter(|e| !e.is_empty());
            Some(match choices {
                Some(c) => format!("{name} ({}: {c})", kind.word()),
                None => format!("{name} ({})", kind.word()),
            })
        })
        .collect()
}

/// The first condition of `pattern` that the center cannot tell on a path
/// argument of `params`: a `!=` with a value from the home (`~/…`), which
/// [`PathStyle::AnyHome`] leaves open, so a blocklist entry with it refuses
/// every call of the action. `None` where there is none.
pub fn home_not_equal(pattern: &str, params: &Value) -> Option<String> {
    let props = properties(params)?;
    parse(pattern).ok()?.into_iter().find_map(|c| {
        let path = props.get(&c.field)?.get("x-nerve-path").is_some();
        (path && c.op == Op::Ne && c.value.starts_with('~'))
            .then(|| format!("{}!={}", c.field, c.value))
    })
}

/// Checks `pattern` against the arguments schema `params` of `scope`'s
/// action, as the rule is written: each field must be one of its top-level
/// properties, each value of that property's type, and an operator one its
/// type takes.
pub fn check(scope: &str, pattern: &str, params: &Value) -> Result<(), String> {
    for c in parse(pattern)? {
        check_one(scope, &c, params)?;
    }
    Ok(())
}

fn check_one(scope: &str, c: &Condition, params: &Value) -> Result<(), String> {
    let props = properties(params);
    let Some(s) = props.and_then(|p| p.get(&c.field)) else {
        let takes: Vec<&str> = props
            .into_iter()
            .flat_map(|p| p.keys())
            .map(String::as_str)
            // Only names a rule can write: a schema's own text reaches the
            // owner's terminal here, and a name may hold anything.
            .filter(|n| n.chars().all(field_char))
            .collect();
        return Err(if takes.is_empty() {
            format!("{scope} takes no arguments, so it has no {}", c.field)
        } else {
            format!(
                "{scope} has no argument {}; it takes {}",
                c.field,
                takes.join(", ")
            )
        });
    };
    let kind = Kind::of(s).map_err(|why| format!("{scope} argument {}: {why}", c.field))?;
    let bad_op = || {
        format!(
            "{scope} argument {} is {}, which {} does not compare",
            c.field,
            kind.word(),
            c.op.as_str()
        )
    };
    match kind {
        Kind::String | Kind::Path if c.op.numeric() => return Err(bad_op()),
        Kind::Integer | Kind::Number | Kind::Boolean if c.op == Op::Like => return Err(bad_op()),
        Kind::Boolean if c.op.numeric() => return Err(bad_op()),
        _ => {}
    }
    let not_a = |what: &str| {
        format!(
            "{scope} argument {} is {what}, and {:?} is not one",
            c.field, c.value
        )
    };
    // A path condition names a place as the node resolves one, which is
    // absolute: a path, one from the home (`~`), or for `~` a glob that
    // starts with a wildcard. A string's `~/` is no home. So a rule written
    // for a path argument that is a plain string now, or the other way
    // round, no longer fits, and is flagged. An exact value (`=`, `!=`) of a
    // string may start with `~/` like any text, and a pin from the audit
    // writes one; only a glob (`~`) that starts at the home is a lost mark.
    match kind {
        Kind::Path if !path_form(&c.value, c.op == Op::Like) => {
            return Err(format!(
                "{scope} argument {} is a path, and {:?} is none: it starts with /, ~ or a drive{}",
                c.field,
                c.value,
                if c.op == Op::Like {
                    ", or a wildcard"
                } else {
                    ""
                }
            ));
        }
        Kind::String if c.op == Op::Like && from_home(&c.value) => {
            return Err(format!(
                "{scope} argument {} is a string, not a path, so {:?} does not start at the home",
                c.field, c.value
            ));
        }
        _ => {}
    }
    match kind {
        Kind::Integer if Number::parse(&c.value).is_none_or(|n| !n.integral()) => {
            return Err(not_a("an integer"));
        }
        Kind::Number if Number::parse(&c.value).is_none() => return Err(not_a("a number")),
        Kind::Boolean if !matches!(c.value.as_str(), "true" | "false") => {
            return Err(not_a("a boolean (true or false)"));
        }
        Kind::String if c.op == Op::Like => {
            string_glob(&c.value).map_err(|e| format!("condition {}~: {e}", c.field))?;
        }
        Kind::Path if c.op == Op::Like => {
            glob(&c.value, false).map_err(|e| format!("condition {}~: {e}", c.field))?;
        }
        _ => {}
    }
    // A value no call may give would make the rule match nothing (or, as a
    // deny's `!=`, everything).
    if let Some(choices) = s.get("enum").and_then(Value::as_array)
        && matches!(c.op, Op::Eq | Op::Ne)
        && !choices.iter().any(|v| literal_is(v, &c.value))
    {
        let listed: Vec<String> = choices
            .iter()
            .filter(|v| !v.is_null())
            .map(|v| v.as_str().map_or_else(|| v.to_string(), str::to_string))
            // Not a choice with a character a terminal acts on: the schema's
            // own text reaches the owner here.
            .filter(|v| !v.chars().any(crate::config::unseen))
            .collect();
        return Err(format!(
            "{scope} argument {} is one of {}, not {:?}",
            c.field,
            listed.join(", "),
            c.value
        ));
    }
    Ok(())
}

/// Whether `value` may name a place as the node resolves one: an absolute
/// path (`/…`, `\\…`, `C:…`), one from the home (`~`), or, for a glob
/// (`glob`), one that starts with a wildcard.
fn path_form(value: &str, glob: bool) -> bool {
    let drive = value.as_bytes().get(1) == Some(&b':') && value.as_bytes()[0].is_ascii_alphabetic();
    value.starts_with(['/', '\\', '~']) || drive || glob && value.starts_with(['*', '?', '[', '{'])
}

/// Whether `value` starts at the home, as a path condition writes it.
fn from_home(value: &str) -> bool {
    value == "~" || value.starts_with("~/") || value.starts_with("~\\")
}

/// Whether the enum choice `v` is the value `text` names.
fn literal_is(v: &Value, text: &str) -> bool {
    match v {
        Value::String(s) => s == text,
        Value::Number(n) => {
            Number::parse(text).is_some_and(|t| t.cmp(n) == Some(std::cmp::Ordering::Equal))
        }
        Value::Bool(b) => text == if *b { "true" } else { "false" },
        _ => false,
    }
}

/// Why `pattern` no longer fits the arguments schema `params` of `scope`
/// (an argument it names is gone, or has another type now), or `None`.
/// `params` is `None` where the action is not published now. A rule that
/// no longer fits still decides as written, which is no longer what was
/// meant: where an argument it names is gone, a deny refuses every call of
/// its action and an allow covers none; where the action no longer takes
/// its value, an `=` holds for no call.
pub fn stale(scope: &str, pattern: &str, params: Option<&Value>) -> Option<String> {
    let Some(params) = params else {
        return Some(format!(
            "{scope} is not offered now, so its arguments cannot be checked"
        ));
    };
    check(scope, pattern, params).err()
}

/// A number as a condition writes it, compared exactly while both sides are
/// integers.
#[derive(Debug, Clone, Copy)]
enum Number {
    Int(i128),
    Float(f64),
}

impl Number {
    fn parse(text: &str) -> Option<Number> {
        if let Ok(i) = text.parse::<i128>() {
            return Some(Number::Int(i));
        }
        // Only the plain decimal forms: `inf`, `NaN` and the like are none.
        let plain = text
            .bytes()
            .all(|b| b.is_ascii_digit() || matches!(b, b'.' | b'-' | b'+' | b'e' | b'E'));
        text.parse::<f64>()
            .ok()
            .filter(|f| plain && f.is_finite())
            .map(Number::Float)
    }

    fn integral(self) -> bool {
        match self {
            Number::Int(_) => true,
            Number::Float(f) => f.fract() == 0.0 && f.abs() < 9.007_199_254_740_992e15,
        }
    }

    /// How `arg`, the call's number, compares with this one.
    fn cmp(self, arg: &serde_json::Number) -> Option<std::cmp::Ordering> {
        let int = arg
            .as_i64()
            .map(i128::from)
            .or_else(|| arg.as_u64().map(i128::from));
        match (self, int) {
            (Number::Int(lit), Some(a)) => Some(a.cmp(&lit)),
            (Number::Int(lit), None) => arg.as_f64()?.partial_cmp(&(lit as f64)),
            (Number::Float(lit), _) => arg.as_f64()?.partial_cmp(&lit),
        }
    }
}

fn glob(pattern: &str, case_insensitive: bool) -> Result<GlobMatcher, globset::Error> {
    GlobBuilder::new(pattern)
        .case_insensitive(case_insensitive)
        .empty_alternates(true)
        .build()
        .map(|g| g.compile_matcher())
}

/// The glob of `~` over a string. A `\` escapes in it on every system, as
/// the docs say (`\,` is a `,`); globset leaves that off on Windows, where
/// a path glob takes `\` for a separator.
///
/// globset also turns a `\` of the matched text into `/` on Windows, so a
/// literal `\` could never match there. Both sides therefore carry a `\` as
/// one private character (`\\` in the pattern, `\` in the text), on every system.
fn string_glob(pattern: &str) -> Result<GlobMatcher, globset::Error> {
    let mut mapped = String::with_capacity(pattern.len());
    let mut chars = pattern.chars().peekable();
    while let Some(c) = chars.next() {
        match (c, chars.peek()) {
            ('\\', Some('\\')) => {
                chars.next();
                mapped.push(BACKSLASH);
            }
            ('\\', Some(&next)) => {
                chars.next();
                mapped.push('\\');
                mapped.push(next);
            }
            _ => mapped.push(c),
        }
    }
    GlobBuilder::new(&mapped)
        .backslash_escape(true)
        .empty_alternates(true)
        .build()
        .map(|g| g.compile_matcher())
}

/// Stands for a `\` in a string glob and in the text it is matched with.
const BACKSLASH: char = '\u{E000}';

/// What a call gives for one field.
#[derive(Debug, Clone, PartialEq)]
pub enum Arg<'a> {
    /// Left out, or `null`.
    Missing,
    /// A value of the arguments.
    Value(&'a Value),
    /// A path argument (`x-nerve-path`) as the node resolved it, in the
    /// wire form; at the center the path as the call names it.
    Path(String),
}

/// How a path condition reads `~` and case.
#[derive(Debug, Clone, Copy)]
pub enum PathStyle<'a> {
    /// The node's: `~` and `~/` are this home (in the wire form), and a
    /// path ignores case on Windows, as NTFS does.
    Home(&'a str),
    /// The center's: it does not know the node's home, so `~` stands for
    /// any (`*`), and a path ignores case everywhere (the node is the
    /// authority; this errs wide). A `!=` errs narrow instead, as a wider
    /// glob would let calls through that the node refuses: it compares
    /// with case, and a value from the home is one it cannot tell.
    AnyHome,
}

/// One condition, ready to match.
struct Compiled {
    field: String,
    op: Op,
    value: String,
    number: Option<Number>,
    /// The glob of `~` over a string.
    text: Option<GlobMatcher>,
    /// The glob a path argument is matched with: `~`'s, or the exact value
    /// of `=` and `!=`.
    path: Option<GlobMatcher>,
    /// That glob's text, which [`Conditions::below`] looks at.
    path_pattern: String,
    /// Whether path text is compared without case.
    fold: bool,
}

/// The conditions of one rule, compiled.
pub struct Conditions {
    conds: Vec<Compiled>,
}

impl Conditions {
    /// Compiles `pattern`, its paths read by `style`.
    pub fn compile(pattern: &str, style: PathStyle) -> Result<Conditions, String> {
        let conds = parse(pattern)?
            .into_iter()
            .map(|c| {
                // Where the center errs wide, a `!=` must err narrow: a
                // wider glob has more hits, so it would refuse fewer calls.
                // It compares with case, and a value from the home is one it
                // cannot tell (the node does).
                let fold = match style {
                    PathStyle::Home(_) => cfg!(windows),
                    PathStyle::AnyHome => c.op != Op::Ne,
                };
                let blind = matches!(style, PathStyle::AnyHome)
                    && c.op == Op::Ne
                    && c.value.starts_with('~');
                let as_path = match c.op {
                    Op::Like => c.value.clone(),
                    _ => crate::rules::escape(&c.value),
                };
                let path_pattern = match style {
                    PathStyle::Home(home) => crate::rules::expand_home(&as_path, home, true),
                    PathStyle::AnyHome => match as_path.strip_prefix('~') {
                        Some(rest) => format!("*{rest}"),
                        None => as_path,
                    },
                };
                let bad =
                    |e: globset::Error| format!("condition {}{}: {e}", c.field, c.op.as_str());
                let text = (c.op == Op::Like)
                    .then(|| string_glob(&c.value))
                    .transpose()
                    .map_err(bad)?;
                let path = (matches!(c.op, Op::Eq | Op::Ne | Op::Like) && !blind)
                    .then(|| glob(&path_win(&path_pattern), fold))
                    .transpose()
                    .map_err(bad)?;
                Ok(Compiled {
                    number: Number::parse(&c.value),
                    field: c.field,
                    op: c.op,
                    value: c.value,
                    text,
                    path,
                    path_pattern,
                    fold,
                })
            })
            .collect::<Result<Vec<_>, String>>()?;
        Ok(Conditions { conds })
    }

    /// The fields the conditions name, in order, once each.
    pub fn fields(&self) -> Vec<&str> {
        let mut out: Vec<&str> = Vec::new();
        for c in &self.conds {
            if !out.contains(&c.field.as_str()) {
                out.push(&c.field);
            }
        }
        out
    }

    /// Whether the call meets every condition: an allow rule covers it.
    /// A condition the call's value does not fit, or that it leaves out,
    /// is not met.
    pub fn met<'a>(&self, arg: impl Fn(&str) -> Arg<'a>) -> bool {
        self.conds
            .iter()
            .all(|c| c.holds(&arg(&c.field)) == Some(true))
    }

    /// Whether no condition is known to fail: a deny rule covers the call.
    /// Where the call's value does not fit a condition, or it leaves the
    /// argument out, the node cannot tell, so the rule counts.
    pub fn may_hold<'a>(&self, arg: impl Fn(&str) -> Arg<'a>) -> bool {
        self.conds
            .iter()
            .all(|c| c.holds(&arg(&c.field)) != Some(false))
    }

    /// Whether a place strictly below the folder `dir`, the path argument
    /// `field`, may meet the conditions, which a deny rule then refuses: a
    /// program handed a folder works below it. A `~` or `=` on `field` may
    /// cover such a place where the text its pattern starts with, up to its
    /// first wildcard, lies below `dir`, or `dir` below that text when a
    /// wildcard follows; that is wider than the pattern, the side to err on.
    /// The other conditions hold as for the call, and one on `field` that
    /// cannot cover a place below asks nothing more.
    pub fn below<'a>(&self, field: &str, dir: &str, arg: impl Fn(&str) -> Arg<'a>) -> bool {
        let on_field = |c: &&Compiled| c.field == field && matches!(c.op, Op::Eq | Op::Like);
        self.conds.iter().any(|c| on_field(&c))
            && self.conds.iter().all(|c| {
                if on_field(&c) {
                    c.may_cover_below(dir)
                } else {
                    c.holds(&arg(&c.field)) != Some(false)
                }
            })
    }
}

/// A pattern as globset reads a path: on Windows its `\` is a `/`, as
/// globset makes of the path it matches.
fn path_win(pattern: &str) -> String {
    if cfg!(windows) {
        pattern.replace('\\', "/")
    } else {
        pattern.to_string()
    }
}

impl Compiled {
    /// Whether the call's `arg` meets this condition, or `None` where it
    /// cannot tell: the argument is left out or of another type.
    fn holds(&self, arg: &Arg) -> Option<bool> {
        use std::cmp::Ordering::{Equal, Greater, Less};
        let compare = |o: std::cmp::Ordering| match self.op {
            Op::Eq => o == Equal,
            Op::Ne => o != Equal,
            Op::Lt => o == Less,
            Op::Le => o != Greater,
            Op::Gt => o == Greater,
            Op::Ge => o != Less,
            Op::Like => unreachable!("not a comparison"),
        };
        match arg {
            Arg::Missing | Arg::Value(Value::Null) => None,
            Arg::Path(p) => {
                let g = self.path.as_ref()?;
                let hit = g.is_match(p);
                match self.op {
                    Op::Eq | Op::Like => Some(hit),
                    Op::Ne => Some(!hit),
                    _ => None,
                }
            }
            Arg::Value(Value::String(s)) => match self.op {
                Op::Eq => Some(*s == self.value),
                Op::Ne => Some(*s != self.value),
                Op::Like => Some(
                    self.text
                        .as_ref()?
                        .is_match(s.replace('\\', &BACKSLASH.to_string())),
                ),
                _ => None,
            },
            Arg::Value(Value::Number(n)) if self.op != Op::Like => {
                Some(compare(self.number?.cmp(n)?))
            }
            Arg::Value(Value::Bool(b)) => {
                let lit = match self.value.as_str() {
                    "true" => true,
                    "false" => false,
                    _ => return None,
                };
                match self.op {
                    Op::Eq => Some(*b == lit),
                    Op::Ne => Some(*b != lit),
                    _ => None,
                }
            }
            Arg::Value(_) => None,
        }
    }

    fn may_cover_below(&self, dir: &str) -> bool {
        let fold = |s: &str| {
            if self.fold {
                path_win(s).to_lowercase()
            } else {
                s.to_string()
            }
        };
        let dir = fold(dir);
        let below = if dir.ends_with('/') {
            dir
        } else {
            format!("{dir}/")
        };
        let pattern = fold(&self.path_pattern);
        let wild = pattern.find(['*', '?', '[', '{']);
        let fixed = &pattern[..wild.unwrap_or(pattern.len())];
        fixed.starts_with(&below) || wild.is_some() && below.starts_with(fixed)
    }
}

/// The value `args`, a call's arguments, give for `field`. A path argument
/// is the caller's to give as [`Arg::Path`].
pub fn arg_of<'a>(args: Option<&'a Map<String, Value>>, field: &str) -> Arg<'a> {
    match args.and_then(|a| a.get(field)) {
        None | Some(Value::Null) => Arg::Missing,
        Some(v) => Arg::Value(v),
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use serde_json::json;

    fn lamp() -> Value {
        json!({"type": "object", "properties": {
            "room": {"type": "string", "enum": ["office", "kitchen", "bed room"]},
            "label": {"type": ["string", "null"]},
            "brightness": {"type": "integer", "minimum": 0, "maximum": 100},
            "warmth": {"type": "number"},
            "on": {"type": "boolean"},
            "file": {"type": "string", "x-nerve-path": "read"},
            "colors": {"type": "array", "items": {"type": "string"}},
            "signal": {"enum": ["term", "kill"]},
            "level": {"enum": [1, 2, 3]},
        }})
    }

    /// The parser table: each condition as written, and the ones it refuses.
    #[test]
    fn conditions_are_read_as_written() {
        let one = |t: &str| parse(t).unwrap();
        let c = |f: &str, op, v: &str| Condition {
            field: f.into(),
            op,
            value: v.into(),
        };
        for (text, want) in [
            ("room=office", vec![c("room", Op::Eq, "office")]),
            ("room!=office", vec![c("room", Op::Ne, "office")]),
            ("brightness<=50", vec![c("brightness", Op::Le, "50")]),
            ("brightness>=5", vec![c("brightness", Op::Ge, "5")]),
            ("brightness<5", vec![c("brightness", Op::Lt, "5")]),
            ("brightness>5", vec![c("brightness", Op::Gt, "5")]),
            ("label~of*", vec![c("label", Op::Like, "of*")]),
            ("label=", vec![c("label", Op::Eq, "")]),
            ("label==x", vec![c("label", Op::Eq, "=x")]),
            (
                "room=office,brightness<=50",
                vec![c("room", Op::Eq, "office"), c("brightness", Op::Le, "50")],
            ),
            // An escaped comma is part of the value, as is a `\` before
            // anything else; a glob's own commas need no escape.
            ("label=a\\,b", vec![c("label", Op::Eq, "a,b")]),
            ("label=C:\\temp\\\\", vec![c("label", Op::Eq, "C:\\temp\\")]),
            ("label~{a,b}*", vec![c("label", Op::Like, "{a,b}*")]),
            ("label~[,x]", vec![c("label", Op::Like, "[,x]")]),
            // Outside a glob a `[` or `{` is a character like any: one left
            // open does not swallow the conditions after it.
            (
                "label=a[b,level>5",
                vec![c("label", Op::Eq, "a[b"), c("level", Op::Gt, "5")],
            ),
            (
                "label!={x,on=true",
                vec![c("label", Op::Ne, "{x"), c("on", Op::Eq, "true")],
            ),
            (
                "label~{a,b},room=[x",
                vec![c("label", Op::Like, "{a,b}"), c("room", Op::Eq, "[x")],
            ),
            ("my_field-2=1", vec![c("my_field-2", Op::Eq, "1")]),
        ] {
            assert_eq!(one(text), want, "{text}");
        }
        for bad in [
            "",
            "=office",
            "room",
            "room office",
            "room =office",
            "room<=",
            "room~",
            "room=a,",
            ",room=a",
            "ro.om=a",
        ] {
            assert!(parse(bad).is_err(), "{bad}");
        }
        let many = vec!["a=1"; MAX_CONDITIONS + 1].join(",");
        assert!(parse(&many).is_err());
        assert!(parse(&many[4..]).is_ok());
    }

    /// The rule is checked against the schema as it is written: the field
    /// must be there, the value of its type, the operator one it takes.
    #[test]
    fn a_condition_is_typed_against_the_schema() {
        let p = lamp();
        for ok in [
            "room=office",
            "room!=bed room",
            "label~*x*",
            "label=",
            "brightness<=50",
            "brightness=50",
            "brightness>=1e1",
            "warmth<0.5",
            "warmth=-3",
            "on=true",
            "on!=false",
            "file~~/notes/*",
            "file=/srv/a",
            "file=~",
            "file~**/.env",
            "file=C:\\data\\a",
            "file~\\\\server\\*",
            "label=~x",
            "room=office,brightness<=50,on=true",
            "signal=term",
            "level>=2",
        ] {
            check("lamp.set", ok, &p).unwrap_or_else(|e| panic!("{ok}: {e}"));
        }
        for (bad, why) in [
            ("size=1", "lamp.set has no argument size; it takes"),
            ("room=garage", "is one of office, kitchen, bed room"),
            ("room<3", "which < does not compare"),
            ("brightness=half", "is an integer"),
            ("brightness<=2.5", "is an integer"),
            ("brightness~5*", "which ~ does not compare"),
            ("warmth>=warm", "is a number"),
            ("warmth<inf", "is a number"),
            ("on=yes", "is a boolean"),
            ("on>true", "which > does not compare"),
            ("file<=3", "which <= does not compare"),
            ("colors=red", "only a string, a number or a boolean"),
            ("label~[", "condition label~"),
            ("signal=stop", "is one of term, kill"),
            ("level=4", "is one of 1, 2, 3"),
            ("level~1", "which ~ does not compare"),
            // A path is matched as the node resolves it, which is absolute;
            // a string's `~/` is no home.
            ("file=notes/a", "is a path, and \"notes/a\" is none"),
            ("file~notes/*", "or a wildcard"),
            ("file=", "is a path"),
            ("label~~/notes/*", "is a string, not a path"),
        ] {
            let e = check("lamp.set", bad, &p).unwrap_err();
            assert!(e.contains(why), "{bad}: {e}");
        }
        // An exact string may start with `~/` like any text: an audit's pin
        // of one has to be writable.
        assert!(check("lamp.set", "label=~/a", &p).is_ok());
        assert!(check("lamp.set", "label!=~/a", &p).is_ok());
        let e = check("lamp.off", "room=x", &json!({"type": "object"})).unwrap_err();
        assert_eq!(e, "lamp.off takes no arguments, so it has no room");
        // A rule whose field is gone says so, and one whose action is gone.
        assert_eq!(stale("lamp.set", "room=office", Some(&p)), None);
        let gone = json!({"type": "object", "properties": {"brightness": {"type": "integer"}}});
        assert!(
            stale("lamp.set", "room=office", Some(&gone))
                .unwrap()
                .contains("no argument room")
        );
        assert!(stale("lamp.set", "room=office", None).is_some());
        // A path argument that is a plain string now, or the other way
        // round, is flagged too: the rule no longer matches as written.
        let plain = json!({"type": "object", "properties": {"file": {"type": "string"},
                                                            "label": {"type": "string", "x-nerve-path": "read"}}});
        assert!(
            stale("lamp.set", "file~~/secret/*", Some(&plain))
                .unwrap()
                .contains("is a string, not a path")
        );
        assert!(
            stale("lamp.set", "label=draft", Some(&plain))
                .unwrap()
                .contains("is a path")
        );
    }

    /// The arguments `v` as a rule reads them.
    pub(crate) fn by<'v>(v: &'v Value) -> impl Fn(&str) -> Arg<'v> + 'v {
        move |f| arg_of(v.as_object(), f)
    }

    fn compile(pattern: &str) -> Conditions {
        Conditions::compile(pattern, PathStyle::Home("/h")).unwrap()
    }

    /// Each operator on each type, and a value of another type or a missing
    /// one, which no allow rule covers and every deny rule does.
    #[test]
    fn a_condition_matches_by_the_values_type_and_fails_closed() {
        let args = json!({"room": "office", "brightness": 40, "warmth": 0.25,
                          "on": true, "label": null, "big": 18446744073709551615u64});
        let args = args.as_object().unwrap();
        let arg = |f: &str| arg_of(Some(args), f);
        let met = |p: &str| compile(p).met(arg);
        let may = |p: &str| compile(p).may_hold(arg);
        for (pattern, want) in [
            ("room=office", true),
            ("room=kitchen", false),
            ("room!=kitchen", true),
            ("room~off*", true),
            ("room~kit*", false),
            ("brightness=40", true),
            ("brightness=40.0", true),
            ("brightness!=40", false),
            ("brightness<=40", true),
            ("brightness<40", false),
            ("brightness>=41", false),
            ("brightness>39.5", true),
            ("warmth<0.5", true),
            ("warmth>=0.25", true),
            ("warmth=0.3", false),
            ("on=true", true),
            ("on!=true", false),
            ("big>18446744073709551614", true),
            ("big=18446744073709551615", true),
            ("room=office,brightness<=50", true),
            ("room=office,brightness>50", false),
        ] {
            assert_eq!(met(pattern), want, "met {pattern}");
            assert_eq!(may(pattern), want, "may hold {pattern}");
        }
        // Not known: left out, null, or another type than the condition's.
        for pattern in [
            "size=1",
            "label=x",
            "label!=x",
            "room<5",
            "brightness~4*",
            "brightness=forty",
            "on=1",
            "on<=1",
            "room=office,size=1",
        ] {
            assert!(!met(pattern), "met {pattern}");
            assert!(may(pattern), "may hold {pattern}");
        }
        // One condition known to fail is enough for a deny to pass.
        assert!(!may("room=kitchen,size=1"));
        // An object or a list is no value a condition reads.
        let odd = json!({"room": ["office"], "brightness": {"v": 1}});
        let odd = odd.as_object().unwrap();
        for p in ["room=office", "brightness=1"] {
            assert!(!compile(p).met(|f| arg_of(Some(odd), f)), "{p}");
            assert!(compile(p).may_hold(|f| arg_of(Some(odd), f)), "{p}");
        }
    }

    /// A path argument is matched as a path: `~/` is the owner's home at
    /// the node and any home at the center, `=` names one path, and a
    /// Windows path ignores case. A place below a handed folder may meet a
    /// condition on that folder's field.
    #[test]
    fn a_path_argument_is_matched_as_a_path() {
        let path = |p: &str| Arg::Path(p.into());
        let node = |pattern: &str, p: &str| compile(pattern).met(|_| path(p));
        assert!(node("file~~/notes/*", "/h/notes/a"));
        assert!(!node("file~~/notes/*", "/x/notes/a"));
        assert!(node("file=~/a[1]", "/h/a[1]"));
        assert!(!node("file=/h/a*", "/h/ab"));
        assert!(node("file!=/h/a", "/h/b"));
        assert_eq!(node("file~/W/*", "/w/x"), cfg!(windows));
        let center = |pattern: &str, p: &str| {
            Conditions::compile(pattern, PathStyle::AnyHome)
                .unwrap()
                .met(|_| path(p))
        };
        assert!(center("file~~/.ssh/*", "/home/any/.ssh/id"));
        assert!(center("file~/W/*", "/w/x"));
        // A folder that may hold what the rule names.
        let c = compile("file~~/work/clients/*,on=true");
        let (yes, no) = (json!({"on": true}), json!({"on": false}));
        for dir in ["/h", "/h/work", "/h/work/", "/h/work/clients"] {
            assert!(c.below("file", dir, by(&yes)), "{dir}");
        }
        for dir in ["/h/workshop", "/h/other", "/h/work/clientele"] {
            assert!(!c.below("file", dir, by(&yes)), "{dir}");
        }
        assert!(!c.below("file", "/h/work", by(&no)));
        assert!(!c.below("other", "/h/work", by(&yes)));
        assert!(compile("file=/h/data/key.pem").below("file", "/h/data", |_| Arg::Missing));
        assert!(
            !compile("file=/h/data/key.pem").below("file", "/h/data/key.pem", |_| Arg::Missing)
        );
        assert!(!compile("file!=/h/x").below("file", "/h", |_| Arg::Missing));
    }

    /// A `\` escapes in a `~` over a string on every system, so `\,` is a
    /// `,` and a `\\` a `\`; globset alone leaves that off on Windows.
    #[test]
    fn a_string_glob_reads_its_escapes_everywhere() {
        let args = json!({"label": "draft,v2", "level": 1});
        assert!(compile("label~draft\\,*").met(by(&args)));
        assert!(!compile("label~draft\\,*").met(by(&json!({"label": "draft;v2"}))));
        let slash = json!({"label": "a\\b"});
        assert!(compile("label~a\\\\b").met(by(&slash)));
        assert!(check("lamp.set", "label~draft\\,*", &lamp()).is_ok());
    }

    /// The center cannot tell a node's home and its case, and errs wide; a
    /// `!=` on a path has to err narrow there, or it refuses less than the
    /// node does.
    #[test]
    fn a_path_not_equal_errs_narrow_at_the_center() {
        let any = |pattern: &str, p: &str| {
            Conditions::compile(pattern, PathStyle::AnyHome)
                .unwrap()
                .may_hold(|_| Arg::Path(p.into()))
        };
        for (pattern, p) in [
            ("file!=~/inbox.md", "/h/proj/inbox.md"),
            ("file!=~/inbox.md", "/etc/inbox.md"),
            ("file!=/srv/in.txt", "/srv/IN.TXT"),
        ] {
            // The node refuses these, so the center has to as well.
            assert!(any(pattern, p), "{pattern} {p}");
        }
        // Where both read it alike nothing is lost.
        assert!(!any("file!=/srv/in.txt", "/srv/in.txt"));
        assert!(any("file!=/srv/in.txt", "/srv/other.txt"));
    }

    /// A schema's own argument names reach the terminal in the "it takes"
    /// text, so a name a rule cannot write is left out of it.
    #[test]
    fn the_takes_text_names_only_what_a_rule_can_write() {
        let params = json!({"type": "object", "properties": {
            "room": {"type": "string"},
            "x\u{1b}[2K\u{9b}": {"type": "string"}}});
        let e = check("lamp.set", "size=1", &params).unwrap_err();
        assert!(e.ends_with("it takes room"), "{e:?}");
    }

    /// The choices an enum lists reach the terminal as well.
    #[test]
    fn the_enum_text_lists_no_unseen_characters() {
        let params = json!({"type": "object", "properties": {
            "room": {"type": "string", "enum": ["office", "a\u{1b}[2A\u{9b}"]}}});
        let e = check("lamp.set", "room=attic", &params).unwrap_err();
        assert!(e.contains("is one of office,"), "{e:?}");
        assert!(!e.contains('\u{1b}') && !e.contains('\u{9b}'), "{e:?}");
    }

    /// A `!=` with a value from the home on a path argument is the one the
    /// center cannot tell.
    #[test]
    fn a_home_not_equal_on_a_path_is_found() {
        let params = lamp();
        assert_eq!(
            home_not_equal("file!=~/inbox.md", &params).as_deref(),
            Some("file!=~/inbox.md")
        );
        assert!(home_not_equal("file!=/srv/in.md", &params).is_none());
        assert!(home_not_equal("file~~/in*", &params).is_none());
        assert!(home_not_equal("room!=~/x", &params).is_none());
    }

    /// The audit keeps the arguments the schema names, and a path only once
    /// it is resolved.
    #[test]
    fn the_audit_keeps_what_the_schema_names() {
        let args = json!({"room": "office", "file": "/x/../y", "junk": 1, "brightness": 5});
        let args = args.as_object().unwrap();
        let keys = |resolved: bool| -> Vec<String> {
            declared(&lamp(), args, resolved).keys().cloned().collect()
        };
        assert_eq!(keys(true), ["brightness", "file", "room"]);
        assert_eq!(keys(false), ["brightness", "room"]);
        assert!(declared(&json!({"type": "object"}), args, true).is_empty());
    }

    /// A pinned string reads back as the value it was made of, whatever it
    /// holds, and a condition written after it stays a condition of its
    /// own.
    #[test]
    fn a_pinned_value_reads_back_as_it_was() {
        for value in [
            "a{b",
            "x[y",
            "a}b]c",
            "line\nbreak",
            " padded ",
            "a,b\\c\\",
            "C:\\temp\\,x",
            "room=x",
            "",
        ] {
            let pinned = pin("label", &json!(value)).unwrap();
            let rule = format!("{pinned},level>3");
            let conds = parse(&rule).unwrap();
            assert_eq!(conds.len(), 2, "{rule:?}: {conds:?}");
            assert_eq!(conds[0].value, value, "{rule:?}");
            assert_eq!(
                conds[1],
                Condition {
                    field: "level".into(),
                    op: Op::Gt,
                    value: "3".into(),
                }
            );
            let args = json!({"label": value, "level": 4});
            assert!(compile(&rule).met(by(&args)), "{rule:?}");
            let other = json!({"label": format!("{value}."), "level": 4});
            assert!(!compile(&rule).may_hold(by(&other)), "{rule:?}");
        }
    }

    /// What an audit button pins, and the fields a form offers.
    #[test]
    fn a_pin_names_the_value_and_a_form_its_fields() {
        assert_eq!(pin("room", &json!("office")).unwrap(), "room=office");
        assert_eq!(pin("room", &json!("a,b\\c")).unwrap(), "room=a\\,b\\\\c");
        assert_eq!(pin("n", &json!(5)).unwrap(), "n=5");
        assert_eq!(pin("w", &json!(0.5)).unwrap(), "w=0.5");
        assert_eq!(pin("on", &json!(false)).unwrap(), "on=false");
        assert!(pin("l", &json!([1])).is_err());
        assert!(pin("a.b", &json!(1)).is_err());
        // A pin matches the value it was made of.
        let args = json!({"room": "a,b\\c", "n": 5});
        let args = args.as_object().unwrap();
        for (f, v) in [("room", json!("a,b\\c")), ("n", json!(5))] {
            let p = pin(f, &v).unwrap();
            assert!(compile(&p).met(|f| arg_of(Some(args), f)), "{p}");
        }
        assert_eq!(
            fields(&lamp()),
            [
                "brightness (an integer)",
                "file (a path)",
                "label (a string)",
                "level (an integer: 1, 2, 3)",
                "on (a boolean)",
                "room (a string: office, kitchen, bed room)",
                "signal (a string: term, kill)",
                "warmth (a number)",
            ]
        );
    }
}
