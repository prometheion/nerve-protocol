//! The subset of JSON Schema a published schema may use, and the check of
//! call arguments against such a schema (docs/dev/spec/protocol.md §6).
//!
//! A node publishes a schema for the arguments and the result of each action.
//! A center shows them to a model, and the node and the center check every
//! call's arguments against them, so a schema has to mean the same thing at
//! every end. Only a small subset is therefore accepted: one type (or one type
//! and `null`), properties, items, enums and bounds; no references,
//! alternatives, conditions, patterns or formats. `check` says whether a
//! schema keeps to the subset, `validate` whether arguments fit a schema that
//! does, and `path_args` which arguments are paths (`x-nerve-path`).
//!
//! Both walk with a stack of their own instead of recursing, so a schema or
//! arguments nested ten thousand deep cannot overflow the stack.

use std::cmp::Ordering;
use std::fmt;

use serde::{Deserialize, Serialize};
use serde_json::{Map, Number, Value};

/// The only `$schema` a schema may name, and only at its root.
pub const DIALECT: &str = "https://json-schema.org/draft/2020-12/schema";
/// How deep an arguments schema may nest. The root is level 1; the schema of
/// a property or of an array's items is one level below its parent's.
pub const MAX_PARAMS_DEPTH: usize = 3;
/// How deep a result schema may nest, counted as for arguments. One level
/// more than arguments, for a list of records (`{entries: [{name}]}`).
pub const MAX_RESULT_DEPTH: usize = 4;
/// The most properties one object schema may name.
pub const MAX_PROPERTIES: usize = 32;
/// The most bytes a schema may take as compact JSON text.
pub const MAX_TEXT_BYTES: usize = 16 * 1024;
/// The most values one `enum` may list. Each argument is compared with
/// them in turn, so this bounds the work per argument; a longer choice is
/// more than a model can read anyway.
pub const MAX_ENUM_VALUES: usize = 256;
/// The most characters of a reason [`brief`] keeps.
pub const BRIEF_MAX: usize = 300;

/// What a schema describes, which sets how deep it may nest and what its
/// root must be.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// An action's arguments: the root is `type: "object"`.
    Params,
    /// An action's result (or an event's data, or a state document): any
    /// root, one level deeper.
    Result,
}

impl Role {
    pub fn max_depth(self) -> usize {
        match self {
            Role::Params => MAX_PARAMS_DEPTH,
            Role::Result => MAX_RESULT_DEPTH,
        }
    }
}

/// Why a schema is outside the subset. `pointer` is a JSON Pointer (RFC 6901)
/// into the schema, empty for the root.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SchemaError {
    pub pointer: String,
    pub reason: String,
}

impl fmt::Display for SchemaError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.pointer.is_empty() {
            f.write_str(&self.reason)
        } else {
            write!(f, "{}: {}", self.pointer, self.reason)
        }
    }
}

impl std::error::Error for SchemaError {}

/// A reason for leaving out a schema as a node or a center repeats it (a
/// status line, an answer, the Overview): one line, cut to [`BRIEF_MAX`]
/// characters. The pointer and the reason hold property names and keywords
/// of the schema as they are, and those are the publisher's choice.
pub fn brief(text: &str) -> String {
    let one: String = text
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    match one.char_indices().nth(BRIEF_MAX) {
        Some((end, _)) => format!("{}…", &one[..end]),
        None => one,
    }
}

/// Which argument does not fit and what was expected there. `field` is a
/// dotted path (`sudo.sealed`, `items[2]`), empty for the arguments as a
/// whole; `expected` is plain words ("an integer from 1 to 600").
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArgError {
    pub field: String,
    pub expected: String,
}

impl fmt::Display for ArgError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let field = if self.field.is_empty() {
            "the arguments"
        } else {
            &self.field
        };
        write!(f, "{field}: expected {}", self.expected)
    }
}

impl std::error::Error for ArgError {}

/// The `invalid_args` error of arguments that do not fit, with the field and
/// what was expected there in its `data`, so a caller can tell them apart
/// from the text.
impl From<ArgError> for crate::RpcError {
    fn from(e: ArgError) -> crate::RpcError {
        crate::RpcError::invalid_args(e.to_string())
            .with("field", Value::String(e.field))
            .with("expected", Value::String(e.expected))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Ty {
    Null,
    Boolean,
    Object,
    Array,
    Number,
    Integer,
    String,
}

impl Ty {
    fn parse(s: &str) -> Option<Ty> {
        Some(match s {
            "null" => Ty::Null,
            "boolean" => Ty::Boolean,
            "object" => Ty::Object,
            "array" => Ty::Array,
            "number" => Ty::Number,
            "integer" => Ty::Integer,
            "string" => Ty::String,
            _ => return None,
        })
    }

    fn noun(self) -> &'static str {
        match self {
            Ty::Null => "null",
            Ty::Boolean => "a boolean",
            Ty::Object => "an object",
            Ty::Array => "an array",
            Ty::Number => "a number",
            Ty::Integer => "an integer",
            Ty::String => "a string",
        }
    }

    /// An integer is a JSON number without a fraction or an exponent, as
    /// serde reads one into an integer field: `1.0` is not one.
    fn fits(self, v: &Value) -> bool {
        match self {
            Ty::Null => v.is_null(),
            Ty::Boolean => v.is_boolean(),
            Ty::Object => v.is_object(),
            Ty::Array => v.is_array(),
            Ty::Number => v.is_number(),
            Ty::Integer => v.is_i64() || v.is_u64(),
            Ty::String => v.is_string(),
        }
    }
}

/// A schema's `type`: one type, and whether `null` is allowed besides it.
#[derive(Debug, Clone, Copy)]
struct Types {
    ty: Ty,
    null: bool,
}

impl Types {
    fn fits(self, v: &Value) -> bool {
        self.ty.fits(v) || (self.null && v.is_null())
    }

    fn is(self, tys: &[Ty]) -> bool {
        tys.contains(&self.ty)
    }
}

/// The `type` of a schema as the subset allows it; `Err` says why not.
fn types(v: &Value) -> Result<Types, String> {
    let name = |v: &Value| {
        v.as_str()
            .and_then(Ty::parse)
            .ok_or_else(|| format!("{v} is not a type name"))
    };
    match v {
        Value::Array(a) => match a.as_slice() {
            [x, y] => match (name(x)?, name(y)?) {
                (Ty::Null, Ty::Null) => Err("names null twice".into()),
                (ty, Ty::Null) | (Ty::Null, ty) => Ok(Types { ty, null: true }),
                _ => Err("one type, or one type and \"null\"".into()),
            },
            _ => Err("one type, or one type and \"null\"".into()),
        },
        v => Ok(Types {
            ty: name(v)?,
            null: false,
        }),
    }
}

/// Keywords of JSON Schema the subset leaves out on purpose, with what to
/// do instead. Any other keyword it does not know is refused as unknown.
fn left_out(word: &str) -> Option<&'static str> {
    Some(match word {
        "$ref" | "$defs" | "definitions" | "$id" | "$anchor" | "$dynamicRef" | "$dynamicAnchor" => {
            "references are not supported: write the schema out in place"
        }
        "oneOf" | "anyOf" | "allOf" | "not" => {
            "alternatives are not supported: use one schema, with enum for a choice of values"
        }
        "if" | "then" | "else" | "dependentRequired" | "dependentSchemas" => {
            "conditions are not supported"
        }
        "patternProperties" | "propertyNames" => {
            "property patterns are not supported: name each property"
        }
        "pattern" | "format" => {
            "patterns and formats are not supported: say what the text holds in description"
        }
        _ => return None,
    })
}

/// A pointer one step below `at`, escaped as RFC 6901 asks.
fn below(at: &str, step: &str) -> String {
    format!("{at}/{}", step.replace('~', "~0").replace('/', "~1"))
}

/// Whether `schema` keeps to the subset for `role`: see the module text and
/// docs/dev/spec/protocol.md §6 for what it allows. The first problem found
/// is returned.
pub fn check(schema: &Value, role: Role) -> Result<(), SchemaError> {
    // The size first: it bounds the walk's work (an `enum`'s values are
    // compared with each other), and `text_len` stops soon after the limit.
    if text_len(schema, MAX_TEXT_BYTES) > MAX_TEXT_BYTES {
        return Err(SchemaError {
            pointer: String::new(),
            reason: format!("the schema is over {} KiB", MAX_TEXT_BYTES / 1024),
        });
    }
    if role == Role::Params && schema.get("type") != Some(&Value::from("object")) {
        return Err(SchemaError {
            pointer: String::new(),
            reason: "the arguments schema must be type \"object\"".into(),
        });
    }
    let max = role.max_depth();
    let mut stack = vec![(schema, String::new(), 1, false)];
    while let Some((s, at, depth, argument)) = stack.pop() {
        if depth > max {
            return Err(SchemaError {
                pointer: at,
                reason: format!("nests deeper than {max} levels"),
            });
        }
        let Some(m) = s.as_object() else {
            return Err(SchemaError {
                pointer: at,
                reason: "a schema must be an object".into(),
            });
        };
        let mut next = Vec::new();
        let at_root = depth == 1;
        node(m, &at, at_root, argument, &mut next)?;
        // The properties of an arguments schema's root are its arguments.
        let arguments = at_root && role == Role::Params;
        stack.extend(
            next.into_iter()
                .rev()
                .map(|(s, p, property)| (s, p, depth + 1, arguments && property)),
        );
    }
    Ok(())
}

/// Checks the keywords of one schema object and adds the schemas below it to
/// `next`, each with whether it is a property's. `argument` says whether
/// this one is an argument: a property of an arguments schema's root.
fn node<'a>(
    m: &'a Map<String, Value>,
    at: &str,
    root: bool,
    argument: bool,
    next: &mut Vec<(&'a Value, String, bool)>,
) -> Result<(), SchemaError> {
    let fail = |word: &str, reason: String| SchemaError {
        pointer: below(at, word),
        reason,
    };
    let types = match m.get("type") {
        Some(v) => Some(types(v).map_err(|r| fail("type", r))?),
        None => None,
    };
    // A keyword for one kind of value needs that type, so a schema cannot
    // ask for a string's length of something that may be a number.
    let needs = |word: &str, tys: &[Ty], what: &str| match types {
        Some(t) if t.is(tys) => Ok(()),
        _ => Err(fail(word, format!("{word} needs type {what}"))),
    };
    let count = |word: &str, v: &Value| {
        v.as_u64()
            .ok_or_else(|| fail(word, "must be a whole number of 0 or more".into()))
    };
    for (word, v) in m {
        if let Some(why) = left_out(word) {
            return Err(fail(word, format!("{word}: {why}")));
        }
        match word.as_str() {
            "type" => {}
            "properties" => {
                needs(word, &[Ty::Object], "object")?;
                let Some(props) = v.as_object() else {
                    return Err(fail(word, "must be an object of schemas".into()));
                };
                if props.len() > MAX_PROPERTIES {
                    return Err(fail(
                        word,
                        format!("names more than {MAX_PROPERTIES} properties"),
                    ));
                }
                let at = below(at, word);
                next.extend(props.iter().map(|(k, s)| (s, below(&at, k), true)));
            }
            "required" => {
                needs(word, &[Ty::Object], "object")?;
                let props = m.get("properties").and_then(Value::as_object);
                let Some(names) = v.as_array() else {
                    return Err(fail(word, "must be an array of property names".into()));
                };
                for (i, n) in names.iter().enumerate() {
                    let Some(n) = n.as_str() else {
                        return Err(fail(word, format!("{n} is not a property name")));
                    };
                    if !props.is_some_and(|p| p.contains_key(n)) {
                        return Err(fail(
                            word,
                            format!("names {n:?}, which properties does not"),
                        ));
                    }
                    if names[..i].iter().any(|x| x == n) {
                        return Err(fail(word, format!("names {n:?} twice")));
                    }
                }
            }
            "additionalProperties" => {
                needs(word, &[Ty::Object], "object")?;
                if !v.is_boolean() {
                    return Err(fail(word, "must be true or false".into()));
                }
            }
            "items" => {
                needs(word, &[Ty::Array], "array")?;
                next.push((v, below(at, word), false));
            }
            "enum" => match v.as_array() {
                Some(e) if e.len() > MAX_ENUM_VALUES => {
                    return Err(fail(
                        word,
                        format!("lists more than {MAX_ENUM_VALUES} values"),
                    ));
                }
                Some(e) if !e.is_empty() => {
                    if let Some(t) = types
                        && let Some(x) = e.iter().find(|x| !t.fits(x))
                    {
                        return Err(fail(word, format!("{x} does not fit the type")));
                    }
                }
                _ => return Err(fail(word, "must be an array of at least one value".into())),
            },
            "const" => {
                if let Some(t) = types
                    && !t.fits(v)
                {
                    return Err(fail(word, format!("{v} does not fit the type")));
                }
            }
            "minimum" | "maximum" | "exclusiveMinimum" | "exclusiveMaximum" => {
                needs(word, &[Ty::Integer, Ty::Number], "integer or number")?;
                if !v.is_number() {
                    return Err(fail(word, "must be a number".into()));
                }
            }
            "minLength" | "maxLength" => {
                needs(word, &[Ty::String], "string")?;
                count(word, v)?;
            }
            "minItems" | "maxItems" => {
                needs(word, &[Ty::Array], "array")?;
                count(word, v)?;
            }
            "x-nerve-path" => {
                needs(word, &[Ty::String], "string")?;
                if v != "read" && v != "write" {
                    return Err(fail(word, "must be \"read\" or \"write\"".into()));
                }
                // The node checks only the arguments themselves against its
                // folders and rules: a path deeper down would pass unchecked.
                if !argument {
                    return Err(fail(
                        word,
                        "marks an argument only: a property of the arguments schema's root".into(),
                    ));
                }
            }
            "description" | "title" => {
                if !v.is_string() {
                    return Err(fail(word, "must be a string".into()));
                }
            }
            "examples" => {
                if !v.is_array() {
                    return Err(fail(word, "must be an array".into()));
                }
            }
            "default" => {}
            "$schema" => {
                if !root {
                    return Err(fail(word, "$schema belongs at the root only".into()));
                }
                if v != DIALECT {
                    return Err(fail(word, format!("only {DIALECT} is supported")));
                }
            }
            _ => return Err(fail(word, format!("unknown keyword {word}"))),
        }
    }
    if types.is_none() && !m.contains_key("enum") && !m.contains_key("const") {
        return Err(SchemaError {
            pointer: at.into(),
            reason: "names no type, enum or const".into(),
        });
    }
    // Bounds that no value can meet are a mistake in the schema, not a
    // refusal of every call: neither a pair of them nor a value of enum or
    // const outside them.
    for (lo, hi) in [("minLength", "maxLength"), ("minItems", "maxItems")] {
        if let (Some(Value::Number(l)), Some(Value::Number(h))) = (m.get(lo), m.get(hi))
            && cmp_num(l, h) == Some(Ordering::Greater)
        {
            return Err(fail(lo, format!("{lo} is above {hi}")));
        }
    }
    if let (Some(l), Some(h)) = num_bounds(m) {
        let integer = types.is_some_and(|t| t.ty == Ty::Integer);
        let empty = if integer {
            l.first_integer() > h.last_integer()
        } else {
            match cmp_num(l.n, h.n) {
                Some(Ordering::Greater) => true,
                Some(Ordering::Equal) => l.exclusive || h.exclusive,
                _ => false,
            }
        };
        if empty {
            let what = if integer { "integer" } else { "number" };
            return Err(fail(
                l.word,
                format!("{} and {} leave no {what} between them", l.word, h.word),
            ));
        }
    }
    let off = |word: &str, x: &Value| {
        fail(
            word,
            format!("{x} does not keep to the schema's other keywords"),
        )
    };
    // An enum's own values are in it, so they are held to the type and the
    // bounds without looking each one up in the enum again. Next to a const
    // they need not equal it, as in JSON Schema; the const must be one of
    // them, which the check of the const below asks.
    if let Some(Value::Array(e)) = m.get("enum")
        && let Some(x) = e.iter().find(|x| !keeps(m, x))
    {
        return Err(off("enum", x));
    }
    if let Some(c) = m.get("const")
        && !fits(m, c)
    {
        return Err(off("const", c));
    }
    Ok(())
}

/// A numeric bound of a schema: its keyword, its number, and whether the
/// number itself is out (`exclusiveMinimum`, `exclusiveMaximum`).
#[derive(Clone, Copy)]
struct Bound<'a> {
    word: &'static str,
    n: &'a Number,
    exclusive: bool,
}

impl Bound<'_> {
    /// The least integer a lower bound lets through. An integer is an `i64`
    /// or a `u64` (see `Ty::fits`), so a bound past that range lets through
    /// one past its end, and a float bound far out cannot overflow here.
    fn first_integer(self) -> i128 {
        let i = match (int(self.n), self.exclusive) {
            (Some(i), false) => i,
            (Some(i), true) => i + 1,
            (None, false) => self.n.as_f64().unwrap_or(f64::NAN).ceil() as i128,
            (None, true) => (self.n.as_f64().unwrap_or(f64::NAN).floor() as i128).saturating_add(1),
        };
        i.clamp(i128::from(i64::MIN), i128::from(u64::MAX) + 1)
    }

    /// The greatest integer an upper bound lets through, held to the
    /// integers as `first_integer` is.
    fn last_integer(self) -> i128 {
        let i = match (int(self.n), self.exclusive) {
            (Some(i), false) => i,
            (Some(i), true) => i - 1,
            (None, false) => self.n.as_f64().unwrap_or(f64::NAN).floor() as i128,
            (None, true) => (self.n.as_f64().unwrap_or(f64::NAN).ceil() as i128).saturating_sub(1),
        };
        i.clamp(i128::from(i64::MIN) - 1, i128::from(u64::MAX))
    }
}

/// The lower and the upper numeric bound of `m` that a value has to meet:
/// `fits` applies all four keywords, so of `minimum` and `exclusiveMinimum`
/// the larger one counts, and the exclusive one when they are equal (the
/// same for the upper pair).
fn num_bounds(m: &Map<String, Value>) -> (Option<Bound<'_>>, Option<Bound<'_>>) {
    let bound = |word: &'static str, exclusive: bool| {
        m.get(word)
            .and_then(Value::as_number)
            .map(|n| Bound { word, n, exclusive })
    };
    fn tighter<'a>(a: Option<Bound<'a>>, b: Option<Bound<'a>>, lower: bool) -> Option<Bound<'a>> {
        match (a, b) {
            (Some(a), Some(b)) => Some(match cmp_num(a.n, b.n) {
                Some(Ordering::Equal) if b.exclusive => b,
                Some(Ordering::Less) if lower => b,
                Some(Ordering::Greater) if !lower => b,
                _ => a,
            }),
            (a, b) => a.or(b),
        }
    }
    (
        tighter(
            bound("minimum", false),
            bound("exclusiveMinimum", true),
            true,
        ),
        tighter(
            bound("maximum", false),
            bound("exclusiveMaximum", true),
            false,
        ),
    )
}

/// The length of `v` as compact JSON text, counted without building it. The
/// count stops soon after it passes `limit`.
fn text_len(v: &Value, limit: usize) -> usize {
    let quoted = |s: &str| serde_json::to_string(s).map_or(s.len() + 2, |q| q.len());
    let mut n = 0;
    let mut stack = vec![v];
    while let Some(v) = stack.pop() {
        if n > limit {
            break;
        }
        n += match v {
            Value::Null | Value::Bool(true) => 4,
            Value::Bool(false) => 5,
            Value::Number(x) => x.to_string().len(),
            Value::String(s) => quoted(s),
            Value::Array(a) => {
                stack.extend(a);
                2 + a.len().saturating_sub(1)
            }
            Value::Object(o) => {
                stack.extend(o.values());
                2 + o.len().saturating_sub(1) + o.keys().map(|k| quoted(k) + 1).sum::<usize>()
            }
        };
    }
    n
}

/// A JSON number as an exact integer, if it is one.
fn int(n: &Number) -> Option<i128> {
    n.as_i64()
        .map(i128::from)
        .or_else(|| n.as_u64().map(i128::from))
}

/// Compares two JSON numbers, exactly when both are integers.
fn cmp_num(a: &Number, b: &Number) -> Option<Ordering> {
    match (int(a), int(b)) {
        (Some(x), Some(y)) => Some(x.cmp(&y)),
        _ => a.as_f64()?.partial_cmp(&b.as_f64()?),
    }
}

/// One step of the path to a field: a property's name or an item's index.
#[derive(Clone, Copy)]
enum Step<'a> {
    Name(&'a str),
    Index(usize),
}

/// The dotted path of `steps` (`entries[2].name`), and `name` below it.
fn path(steps: &[Step], name: Option<&str>) -> String {
    let mut out = String::new();
    for step in steps.iter().copied().chain(name.map(Step::Name)) {
        match step {
            Step::Name(n) if out.is_empty() => out.push_str(n),
            Step::Name(n) => {
                out.push('.');
                out.push_str(n);
            }
            Step::Index(i) => out.push_str(&format!("[{i}]")),
        }
    }
    out
}

/// What `validate` has left to look at.
enum Todo<'a> {
    /// `value` against `schema`, at the path of the first `depth` steps and
    /// then `step`.
    One {
        schema: &'a Value,
        value: &'a Value,
        depth: usize,
        step: Option<Step<'a>>,
    },
    /// The items of an array from `next` on, each against `schema`. An
    /// array is taken one item at a time, so a long one costs no more
    /// memory than a short one.
    Items {
        schema: &'a Value,
        values: &'a [Value],
        next: usize,
        depth: usize,
    },
}

/// What an action does at a path argument (`x-nerve-path`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathMark {
    Read,
    Write,
}

impl PathMark {
    pub fn as_str(self) -> &'static str {
        match self {
            PathMark::Read => "read",
            PathMark::Write => "write",
        }
    }
}

/// The arguments of the arguments schema `params` that are paths: each
/// property of its root marked `x-nerve-path`, with what the action does
/// there, in the schema's order. `check` keeps the marker to those
/// properties, of type string.
pub fn path_args(params: &Value) -> Vec<(String, PathMark)> {
    let Some(props) = params.get("properties").and_then(Value::as_object) else {
        return Vec::new();
    };
    props
        .iter()
        .filter_map(|(name, s)| {
            let mark = match s.get("x-nerve-path")?.as_str()? {
                "read" => PathMark::Read,
                "write" => PathMark::Write,
                _ => return None,
            };
            Some((name.clone(), mark))
        })
        .collect()
}

/// Whether `params` may be the params schema of a program's stream
/// (`stream.open`): as an action's arguments, with no argument marked
/// `x-nerve-path`. A stream's open is decided as a call that names no path,
/// so a path there would reach the program unjudged; a program that reads
/// at a path offers that as an action, whose paths the node judges.
pub fn check_stream_params(params: &Value) -> Result<(), SchemaError> {
    check(params, Role::Params)?;
    match path_args(params).into_iter().next() {
        Some((name, _)) => Err(SchemaError {
            pointer: below(&below("", "properties"), &name) + "/x-nerve-path",
            reason: "a stream takes no path; one read at a path is an action's".into(),
        }),
        None => Ok(()),
    }
}

/// Whether `args` fit `schema`, a schema that passed `check`. The first
/// argument that does not fit is returned with what was expected there.
/// Keywords `check` refuses are not looked at, so an unchecked schema is not
/// a reliable guard.
pub fn validate(schema: &Value, args: &Value) -> Result<(), ArgError> {
    // The path to the value at hand; a field's path is only written out
    // when it does not fit.
    let mut steps: Vec<Step> = Vec::new();
    let mut stack = vec![Todo::One {
        schema,
        value: args,
        depth: 0,
        step: None,
    }];
    while let Some(todo) = stack.pop() {
        let (s, v, depth, step) = match todo {
            Todo::One {
                schema,
                value,
                depth,
                step,
            } => (schema, value, depth, step),
            Todo::Items {
                schema,
                values,
                next,
                depth,
            } => {
                if next + 1 < values.len() {
                    stack.push(Todo::Items {
                        schema,
                        values,
                        next: next + 1,
                        depth,
                    });
                }
                (schema, &values[next], depth, Some(Step::Index(next)))
            }
        };
        steps.truncate(depth);
        steps.extend(step);
        let Some(m) = s.as_object() else { continue };
        if !fits(m, v) {
            return Err(ArgError {
                field: path(&steps, None),
                expected: expected(m),
            });
        }
        let depth = steps.len();
        match v {
            Value::Object(o) => {
                let props = m.get("properties").and_then(Value::as_object);
                let required = m.get("required").and_then(Value::as_array);
                for name in required.into_iter().flatten().filter_map(Value::as_str) {
                    if !o.contains_key(name) {
                        let what = props
                            .and_then(|p| p.get(name))
                            .and_then(Value::as_object)
                            .map_or_else(|| "a value".into(), expected);
                        return Err(ArgError {
                            field: path(&steps, Some(name)),
                            expected: format!("{what} (required)"),
                        });
                    }
                }
                let closed = m.get("additionalProperties") == Some(&Value::Bool(false));
                // At most one entry per property the schema names, so this
                // stays small however many fields the value has.
                let mut next = Vec::new();
                for (k, x) in o {
                    match props.and_then(|p| p.get(k)) {
                        Some(s) => next.push(Todo::One {
                            schema: s,
                            value: x,
                            depth,
                            step: Some(Step::Name(k)),
                        }),
                        None if closed => {
                            let known: Vec<&str> = props
                                .into_iter()
                                .flatten()
                                .map(|(k, _)| k.as_str())
                                .collect();
                            let expected = if known.is_empty() {
                                "no field of this name; this takes none".into()
                            } else {
                                format!("no field of this name; known: {}", known.join(", "))
                            };
                            return Err(ArgError {
                                field: path(&steps, Some(k)),
                                expected,
                            });
                        }
                        None => {}
                    }
                }
                stack.extend(next.into_iter().rev());
            }
            Value::Array(a) => {
                if let Some(items) = m.get("items")
                    && !a.is_empty()
                {
                    stack.push(Todo::Items {
                        schema: items,
                        values: a,
                        next: 0,
                        depth,
                    });
                }
            }
            _ => {}
        }
    }
    Ok(())
}

/// Whether `v` meets the keywords of `m` that concern `v` itself, not its
/// members.
fn fits(m: &Map<String, Value>, v: &Value) -> bool {
    keeps(m, v) && is_listed(m, v) && m.get("const").is_none_or(|c| same(c, v))
}

/// Whether `v` is one of `m`'s `enum`, if it has one.
fn is_listed(m: &Map<String, Value>, v: &Value) -> bool {
    match m.get("enum") {
        Some(Value::Array(e)) => e.iter().any(|x| same(x, v)),
        _ => true,
    }
}

/// Whether two values are equal as JSON Schema counts it: numbers by their
/// value, so `1.0` is `1`, and arrays and objects member by member.
fn same<'a>(mut a: &'a Value, mut b: &'a Value) -> bool {
    // Filled only for arrays and objects, so comparing two plain values,
    // which an argument against an enum mostly is, allocates nothing.
    let mut stack = Vec::new();
    loop {
        match (a, b) {
            // Two integers or two floats are equal as `Number`s exactly
            // when their values are; only an integer and a float need the
            // comparison by value.
            (Value::Number(x), Value::Number(y)) => {
                if x != y && (x.is_f64() == y.is_f64() || cmp_num(x, y) != Some(Ordering::Equal)) {
                    return false;
                }
            }
            (Value::Array(x), Value::Array(y)) => {
                if x.len() != y.len() {
                    return false;
                }
                stack.extend(x.iter().zip(y));
            }
            (Value::Object(x), Value::Object(y)) => {
                if x.len() != y.len() {
                    return false;
                }
                for (k, v) in x {
                    let Some(w) = y.get(k) else { return false };
                    stack.push((v, w));
                }
            }
            (a, b) => {
                if a != b {
                    return false;
                }
            }
        }
        let Some((x, y)) = stack.pop() else {
            return true;
        };
        (a, b) = (x, y);
    }
}

/// Whether `v` has `m`'s type and keeps to its bounds. As in JSON Schema, a
/// bound applies only to values of its kind.
fn keeps(m: &Map<String, Value>, v: &Value) -> bool {
    if let Some(Ok(t)) = m.get("type").map(types)
        && !t.fits(v)
    {
        return false;
    }
    let bound = |word: &str| m.get(word).and_then(Value::as_number);
    let count = |word: &str| m.get(word).and_then(Value::as_u64);
    match v {
        Value::Number(x) => {
            let past = |word: &str, bad: &[Ordering]| {
                bound(word).is_some_and(|b| cmp_num(x, b).is_some_and(|o| bad.contains(&o)))
            };
            !(past("minimum", &[Ordering::Less])
                || past("exclusiveMinimum", &[Ordering::Less, Ordering::Equal])
                || past("maximum", &[Ordering::Greater])
                || past("exclusiveMaximum", &[Ordering::Greater, Ordering::Equal]))
        }
        Value::String(s) => {
            let n = s.chars().count() as u64;
            count("minLength").is_none_or(|l| n >= l) && count("maxLength").is_none_or(|h| n <= h)
        }
        Value::Array(a) => {
            let n = a.len() as u64;
            count("minItems").is_none_or(|l| n >= l) && count("maxItems").is_none_or(|h| n <= h)
        }
        _ => true,
    }
}

/// What a value of schema `m` is, in plain words: "an integer from 1 to
/// 600", "one of \"term\", \"kill\"", "a string, or null".
fn expected(m: &Map<String, Value>) -> String {
    if let Some(c) = m.get("const") {
        return format!("exactly {c}");
    }
    // An enum's values say themselves whether null is one of them.
    if let Some(Value::Array(e)) = m.get("enum") {
        let values: Vec<String> = e.iter().map(Value::to_string).collect();
        return format!("one of {}", values.join(", "));
    }
    let Some(t) = m.get("type").and_then(|t| types(t).ok()) else {
        return "a value".into();
    };
    let mut s = format!("{}{}", t.ty.noun(), bounds(t.ty, m));
    if t.null && t.ty != Ty::Null {
        s.push_str(", or null");
    }
    s
}

/// The bounds of `m` for a value of type `ty`, as words to follow its noun.
fn bounds(ty: Ty, m: &Map<String, Value>) -> String {
    let count = |word: &str| m.get(word).and_then(Value::as_u64);
    let sized = |lo: Option<u64>, hi: Option<u64>, unit: &str| {
        let unit = |n: u64| {
            if n == 1 {
                unit.to_string()
            } else {
                format!("{unit}s")
            }
        };
        match (lo, hi) {
            (Some(l), Some(h)) if l == h => format!(" of exactly {l} {}", unit(h)),
            (Some(l), Some(h)) => format!(" of {l} to {h} {}", unit(h)),
            (Some(l), None) => format!(" of at least {l} {}", unit(l)),
            (None, Some(h)) => format!(" of at most {h} {}", unit(h)),
            (None, None) => String::new(),
        }
    };
    match ty {
        Ty::Integer | Ty::Number => {
            // The bounds a value has to meet, so the words never name a
            // range the refused value is inside.
            let (lo, hi) = num_bounds(m);
            if let (Some(l), Some(h)) = (lo, hi)
                && !l.exclusive
                && !h.exclusive
            {
                return format!(" from {} to {}", l.n, h.n);
            }
            let mut parts = Vec::new();
            if let Some(l) = lo {
                parts.push(if l.exclusive {
                    format!("above {}", l.n)
                } else {
                    format!("{} or more", l.n)
                });
            }
            if let Some(h) = hi {
                parts.push(if h.exclusive {
                    format!("below {}", h.n)
                } else {
                    format!("{} or less", h.n)
                });
            }
            match parts.first() {
                None => String::new(),
                Some(p) if p.ends_with("or more") || p.ends_with("or less") => {
                    format!(" of {}", parts.join(" and "))
                }
                Some(_) => format!(" {}", parts.join(" and ")),
            }
        }
        Ty::String => sized(count("minLength"), count("maxLength"), "character"),
        Ty::Array => sized(count("minItems"), count("maxItems"), "item"),
        _ => String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// An arguments schema with one property `a` of schema `s`.
    fn with(s: Value) -> Value {
        json!({"type": "object", "properties": {"a": s}})
    }

    /// Takes a deeply nested value apart level by level, since dropping it
    /// whole would recurse once per level.
    fn take_apart(v: Value) {
        let mut stack = vec![v];
        while let Some(v) = stack.pop() {
            match v {
                Value::Object(o) => stack.extend(o.into_iter().map(|(_, v)| v)),
                Value::Array(a) => stack.extend(a),
                _ => {}
            }
        }
    }

    #[test]
    fn allowed_keywords() {
        // The schema of property `a` of an arguments schema.
        let inner = [
            json!({"type": "string"}),
            json!({"type": ["integer", "null"]}),
            json!({"type": ["null", "object"]}),
            json!({"type": "null"}),
            json!({"type": "object", "properties": {"b": {"type": "boolean"}}}),
            json!({"type": "object", "properties": {}}),
            json!({"type": "object"}),
            json!({"type": "object", "properties": {"b": {"type": "string"}}, "required": ["b"]}),
            json!({"type": "object", "additionalProperties": false}),
            json!({"type": "object", "additionalProperties": true}),
            json!({"type": "array", "items": {"type": "number"}}),
            json!({"enum": ["a", 1, null]}),
            json!({"type": "string", "enum": ["a", "b"]}),
            json!({"type": ["string", "null"], "enum": ["a", null]}),
            json!({"const": "x"}),
            json!({"type": "integer", "const": 3}),
            json!({"type": "integer", "minimum": 0}),
            json!({"type": "number", "maximum": 1.5}),
            json!({"type": "number", "exclusiveMinimum": 0}),
            json!({"type": "integer", "exclusiveMaximum": 10}),
            json!({"type": "integer", "minimum": 2, "maximum": 2}),
            json!({"type": "string", "minLength": 1}),
            json!({"type": "string", "maxLength": 64}),
            json!({"type": "array", "minItems": 1}),
            json!({"type": "array", "maxItems": 5}),
            json!({"type": "integer", "default": 5}),
            json!({"type": "string", "description": "a name"}),
            json!({"type": "string", "title": "Name"}),
            json!({"type": "string", "examples": ["x"]}),
            json!({"type": "string", "x-nerve-path": "read"}),
            json!({"type": ["string", "null"], "x-nerve-path": "write"}),
            // Bounds with something between them.
            json!({"type": "number", "minimum": 5, "maximum": 5}),
            json!({"type": "number", "exclusiveMinimum": 1, "exclusiveMaximum": 2}),
            json!({"type": "integer", "exclusiveMinimum": 1, "exclusiveMaximum": 3}),
            json!({"type": "integer", "minimum": 1.5, "maximum": 2.5}),
            json!({"type": "integer", "minimum": 0, "exclusiveMinimum": 3, "maximum": 4}),
            json!({"type": "integer", "exclusiveMinimum": -1e300, "exclusiveMaximum": 1e300}),
            json!({"type": "integer", "minimum": 1e19, "maximum": 1e20}),
            json!({"type": "integer", "minimum": 1, "enum": [1, 2]}),
            json!({"type": ["integer", "null"], "minimum": 1, "enum": [1, null]}),
            json!({"type": "string", "maxLength": 3, "const": "abc"}),
            // Next to a const, the other enum values need not equal it.
            json!({"type": "integer", "enum": [1, 2], "const": 1}),
            json!({"enum": ["x", "y"], "const": "x"}),
        ];
        for s in inner {
            assert_eq!(check(&with(s.clone()), Role::Params), Ok(()), "{s}");
        }
        let root = [
            json!({"type": "object"}),
            json!({"type": "object", "additionalProperties": false, "properties": {}}),
            json!({"$schema": "https://json-schema.org/draft/2020-12/schema", "type": "object"}),
        ];
        for s in root {
            assert_eq!(check(&s, Role::Params), Ok(()), "{s}");
        }
    }

    /// The arguments marked `x-nerve-path`, with what the action does there:
    /// the properties of the root only, in order.
    #[test]
    fn path_args_names_the_marked_arguments() {
        let params = json!({"type": "object", "properties": {
            "from": {"type": "string", "x-nerve-path": "read"},
            "name": {"type": "string"},
            "to": {"type": ["string", "null"], "x-nerve-path": "write"}}});
        assert_eq!(check(&params, Role::Params), Ok(()));
        assert_eq!(
            path_args(&params),
            [
                ("from".to_string(), PathMark::Read),
                ("to".to_string(), PathMark::Write)
            ]
        );
        assert_eq!(path_args(&json!({"type": "object"})), []);
    }

    /// A marker deeper down than an argument, or in a result, would mark a
    /// path the node never checks: the schema is refused.
    #[test]
    fn a_path_marker_below_the_arguments_is_refused() {
        let marked = json!({"type": "string", "x-nerve-path": "read"});
        for (params, pointer) in [
            (
                with(json!({"type": "object", "properties": {"p": marked.clone()}})),
                "/properties/a/properties/p/x-nerve-path",
            ),
            (
                with(json!({"type": "array", "items": marked.clone()})),
                "/properties/a/items/x-nerve-path",
            ),
        ] {
            let e = check(&params, Role::Params).expect_err(pointer);
            assert_eq!(e.pointer, pointer, "{e}");
            assert!(e.reason.contains("marks an argument only"), "{e}");
        }
        let result = json!({"type": "object", "properties": {"p": marked}});
        let e = check(&result, Role::Result).expect_err("in a result");
        assert_eq!(e.pointer, "/properties/p/x-nerve-path", "{e}");
    }

    #[test]
    fn refused_keywords() {
        // In property `a`: the keyword the refusal points at, the schema, and
        // words its reason holds.
        let inner = [
            ("$ref", json!({"$ref": "#/$defs/x"}), "references"),
            (
                "$defs",
                json!({"type": "object", "$defs": {}}),
                "references",
            ),
            (
                "definitions",
                json!({"type": "object", "definitions": {}}),
                "references",
            ),
            ("$id", json!({"type": "string", "$id": "x"}), "references"),
            (
                "oneOf",
                json!({"oneOf": [{"type": "string"}]}),
                "alternatives",
            ),
            ("anyOf", json!({"anyOf": []}), "alternatives"),
            (
                "allOf",
                json!({"type": "string", "allOf": []}),
                "alternatives",
            ),
            ("not", json!({"type": "string", "not": {}}), "alternatives"),
            ("if", json!({"type": "string", "if": {}}), "conditions"),
            ("then", json!({"type": "string", "then": {}}), "conditions"),
            ("else", json!({"type": "string", "else": {}}), "conditions"),
            (
                "patternProperties",
                json!({"type": "object", "patternProperties": {}}),
                "name each",
            ),
            (
                "pattern",
                json!({"type": "string", "pattern": "^a"}),
                "patterns",
            ),
            (
                "format",
                json!({"type": "string", "format": "email"}),
                "formats",
            ),
            (
                "nullable",
                json!({"type": "string", "nullable": true}),
                "unknown keyword",
            ),
            (
                "$comment",
                json!({"type": "string", "$comment": "x"}),
                "unknown keyword",
            ),
            ("type", json!({"type": ["string", "integer"]}), "one type"),
            (
                "type",
                json!({"type": ["string", "integer", "null"]}),
                "one type",
            ),
            ("type", json!({"type": ["null", "null"]}), "null twice"),
            ("type", json!({"type": "int"}), "not a type name"),
            (
                "properties",
                json!({"type": "string", "properties": {}}),
                "needs type object",
            ),
            (
                "properties",
                json!({"type": "object", "properties": []}),
                "object of schemas",
            ),
            (
                "required",
                json!({"type": "object", "required": ["x"]}),
                "properties does not",
            ),
            (
                "required",
                json!({"type": "object", "required": [1]}),
                "not a property name",
            ),
            (
                "additionalProperties",
                json!({"type": "object", "additionalProperties": {}}),
                "true",
            ),
            (
                "items",
                json!({"type": "object", "items": {"type": "string"}}),
                "needs type array",
            ),
            (
                "items",
                json!({"type": "array", "items": [{"type": "string"}]}),
                "must be an object",
            ),
            ("enum", json!({"enum": []}), "at least one value"),
            (
                "enum",
                json!({"type": "string", "enum": ["a", 1]}),
                "does not fit",
            ),
            (
                "const",
                json!({"type": "integer", "const": 1.5}),
                "does not fit",
            ),
            (
                "minimum",
                json!({"type": "string", "minimum": 1}),
                "needs type integer or number",
            ),
            (
                "minimum",
                json!({"type": "integer", "minimum": "1"}),
                "must be a number",
            ),
            (
                "minimum",
                json!({"type": "integer", "minimum": 3, "maximum": 2}),
                "minimum and maximum leave no integer",
            ),
            (
                "minimum",
                json!({"type": "number", "minimum": 3, "maximum": 2}),
                "leave no number",
            ),
            (
                "exclusiveMinimum",
                json!({"type": "integer", "exclusiveMinimum": 5, "maximum": 5}),
                "exclusiveMinimum and maximum leave no integer",
            ),
            (
                "minimum",
                json!({"type": "integer", "minimum": 5, "exclusiveMaximum": 5}),
                "minimum and exclusiveMaximum leave no integer",
            ),
            (
                "exclusiveMinimum",
                json!({"type": "number", "exclusiveMinimum": 5, "exclusiveMaximum": 5}),
                "leave no number",
            ),
            (
                "exclusiveMinimum",
                json!({"type": "number", "minimum": 5, "exclusiveMinimum": 5, "maximum": 5}),
                "leave no number",
            ),
            (
                "exclusiveMinimum",
                json!({"type": "integer", "exclusiveMinimum": 1, "exclusiveMaximum": 2}),
                "leave no integer",
            ),
            (
                "minimum",
                json!({"type": "integer", "minimum": 1.2, "maximum": 1.8}),
                "leave no integer",
            ),
            // Bounds far past what an integer can be (an i64 or a u64).
            (
                "exclusiveMinimum",
                json!({"type": "integer", "exclusiveMinimum": 1e300, "maximum": 5}),
                "exclusiveMinimum and maximum leave no integer",
            ),
            (
                "minimum",
                json!({"type": "integer", "minimum": -5, "exclusiveMaximum": -1e300}),
                "minimum and exclusiveMaximum leave no integer",
            ),
            (
                "minimum",
                json!({"type": "integer", "minimum": 1e20, "maximum": 1e21}),
                "leave no integer",
            ),
            (
                "minimum",
                json!({"type": "integer", "minimum": -1e21, "maximum": -1e20}),
                "leave no integer",
            ),
            (
                "enum",
                json!({"type": "integer", "minimum": 5, "enum": [5, 1]}),
                "1 does not keep to",
            ),
            (
                "const",
                json!({"type": "string", "maxLength": 2, "const": "abc"}),
                "does not keep to",
            ),
            (
                "const",
                json!({"type": "integer", "enum": [1, 2], "const": 3}),
                "3 does not keep to",
            ),
            (
                "minLength",
                json!({"enum": ["a"], "minLength": 1}),
                "needs type string",
            ),
            (
                "maxLength",
                json!({"type": "string", "maxLength": -1}),
                "whole number",
            ),
            (
                "minLength",
                json!({"type": "string", "minLength": 3, "maxLength": 2}),
                "above",
            ),
            (
                "minItems",
                json!({"type": "string", "minItems": 1}),
                "needs type array",
            ),
            (
                "minItems",
                json!({"type": "array", "minItems": 3, "maxItems": 2}),
                "above",
            ),
            (
                "x-nerve-path",
                json!({"type": "integer", "x-nerve-path": "read"}),
                "needs type string",
            ),
            (
                "x-nerve-path",
                json!({"type": "string", "x-nerve-path": "exec"}),
                "\"read\" or",
            ),
            (
                "description",
                json!({"type": "string", "description": 1}),
                "must be a string",
            ),
            (
                "examples",
                json!({"type": "string", "examples": "x"}),
                "must be an array",
            ),
            (
                "$schema",
                json!({"type": "string", "$schema": DIALECT}),
                "root only",
            ),
        ];
        for (word, s, reason) in inner {
            let e = check(&with(s.clone()), Role::Params).expect_err(word);
            assert_eq!(e.pointer, format!("/properties/a/{word}"), "{s}: {e}");
            assert!(e.reason.contains(reason), "{s}: {e}");
        }
        // Refused as a whole: the pointer and words the reason holds.
        let whole = [
            (with(json!({})), "/properties/a", "names no type"),
            (with(json!(true)), "/properties/a", "must be an object"),
            (
                json!({"type": "object", "properties": {"a": {"type": "string"}},
                       "required": ["a", "a"]}),
                "/required",
                "twice",
            ),
            (
                json!({"$schema": "http://json-schema.org/draft-07/schema#", "type": "object"}),
                "/$schema",
                "only",
            ),
            (json!({"type": "string"}), "", "type \"object\""),
            (json!({"type": ["object", "null"]}), "", "type \"object\""),
            (Value::Null, "", "type \"object\""),
        ];
        for (s, pointer, reason) in whole {
            let e = check(&s, Role::Params).unwrap_err();
            assert_eq!(e.pointer, pointer, "{s}: {e}");
            assert!(e.reason.contains(reason), "{s}: {e}");
        }
    }

    #[test]
    fn pointers_are_escaped() {
        let s =
            json!({"type": "object", "properties": {"a/b~c": {"type": "string", "format": "x"}}});
        let e = check(&s, Role::Params).unwrap_err();
        assert_eq!(e.pointer, "/properties/a~1b~0c/format");
        assert!(
            e.to_string()
                .starts_with("/properties/a~1b~0c/format: format: "),
            "{e}"
        );
    }

    /// A stream's params are an action's, but mark no path: the node would
    /// not judge one.
    #[test]
    fn a_streams_params_mark_no_path() {
        let plain = json!({"type": "object", "properties": {"every_ms": {"type": "integer"}}});
        assert!(check_stream_params(&plain).is_ok());
        let path = json!({"type": "object", "properties": {
            "every_ms": {"type": "integer"},
            "a/file": {"type": "string", "x-nerve-path": "read"}}});
        let e = check_stream_params(&path).unwrap_err();
        assert_eq!(e.pointer, "/properties/a~1file/x-nerve-path", "{e}");
        assert!(e.reason.contains("a stream takes no path"), "{e}");
        let e = check_stream_params(&json!({"type": "string"})).unwrap_err();
        assert!(e.reason.contains("type \"object\""), "{e}");
    }

    /// `depth` levels of objects, each with one property below it.
    fn nested(depth: usize) -> Value {
        let mut s = json!({"type": "string"});
        for _ in 1..depth {
            s = json!({"type": "object", "properties": {"a": s}});
        }
        s
    }

    #[test]
    fn depth_limits() {
        assert_eq!(check(&nested(3), Role::Params), Ok(()));
        let e = check(&nested(4), Role::Params).unwrap_err();
        assert_eq!(e.pointer, "/properties/a/properties/a/properties/a");
        assert!(e.reason.contains("deeper than 3"), "{e}");
        // A result may hold a list of records, one level more.
        assert_eq!(check(&nested(4), Role::Result), Ok(()));
        let list = json!({"type": "object", "properties": {"entries": {"type": "array",
            "items": {"type": "object", "properties": {"name": {"type": "string"}}}}}});
        assert_eq!(check(&list, Role::Result), Ok(()));
        assert!(check(&list, Role::Params).is_err());
        let e = check(&nested(5), Role::Result).unwrap_err();
        assert!(e.reason.contains("deeper than 4"), "{e}");
        // Items count as a level, as properties do.
        let items = json!({"type": "object", "properties": {"a": {"type": "array",
            "items": {"type": "array", "items": {"type": "string"}}}}});
        assert!(check(&items, Role::Params).is_err());
        assert_eq!(check(&items, Role::Result), Ok(()));
    }

    #[test]
    fn a_result_root_may_be_any_type() {
        assert_eq!(check(&json!({"type": "string"}), Role::Result), Ok(()));
        assert_eq!(
            check(&json!({"type": ["integer", "null"]}), Role::Result),
            Ok(())
        );
        let e = check(&json!({}), Role::Result).unwrap_err();
        assert!(e.reason.contains("names no type"), "{e}");
    }

    #[test]
    fn property_limit() {
        let props = |n: usize| -> Map<String, Value> {
            (0..n)
                .map(|i| (format!("p{i}"), json!({"type": "string"})))
                .collect()
        };
        let s = json!({"type": "object", "properties": props(MAX_PROPERTIES)});
        assert_eq!(check(&s, Role::Params), Ok(()));
        let s = json!({"type": "object", "properties": props(MAX_PROPERTIES + 1)});
        let e = check(&s, Role::Params).unwrap_err();
        assert_eq!(e.pointer, "/properties");
        assert!(e.reason.contains("more than 32"), "{e}");
    }

    #[test]
    fn text_limit() {
        // One property whose description fills the schema to the byte.
        let s = |len: usize| with(json!({"type": "string", "description": "x".repeat(len)}));
        let base = serde_json::to_string(&s(0)).unwrap().len();
        let at = s(MAX_TEXT_BYTES - base);
        assert_eq!(serde_json::to_string(&at).unwrap().len(), MAX_TEXT_BYTES);
        assert_eq!(check(&at, Role::Params), Ok(()));
        let e = check(&s(MAX_TEXT_BYTES - base + 1), Role::Params).unwrap_err();
        assert_eq!(e.pointer, "");
        assert!(e.reason.contains("over 16 KiB"), "{e}");
    }

    #[test]
    fn a_long_enum_is_refused_for_its_size_at_once() {
        // An enum's values are compared with each other, so a schema far
        // over the limit is refused before that work, not after it.
        let e: Vec<Value> = (0..50_000).map(Value::from).collect();
        let s = with(json!({"type": "integer", "enum": e}));
        let start = std::time::Instant::now();
        let e = check(&s, Role::Params).unwrap_err();
        assert!(e.reason.contains("over 16 KiB"), "{e}");
        let took = start.elapsed();
        assert!(took < std::time::Duration::from_secs(1), "{took:?}");
    }

    #[test]
    fn enum_limit() {
        // Each argument is compared with an enum's values in turn, so their
        // number is held to a limit as the properties are.
        let e = |n: usize| -> Vec<Value> { (0..n).map(Value::from).collect() };
        let s = with(json!({"type": "integer", "enum": e(MAX_ENUM_VALUES)}));
        assert_eq!(check(&s, Role::Params), Ok(()));
        let s = with(json!({"type": "integer", "enum": e(MAX_ENUM_VALUES + 1)}));
        let e = check(&s, Role::Params).unwrap_err();
        assert_eq!(e.pointer, "/properties/a/enum");
        assert!(e.reason.contains("more than 256 values"), "{e}");
    }

    #[test]
    fn enum_and_const_compare_numbers_by_value() {
        let ok = |s: Value, a: Value| {
            let s = with(s);
            assert_eq!(check(&s, Role::Params), Ok(()), "{s}");
            assert_eq!(validate(&s, &json!({"a": a})), Ok(()), "{s} {a}");
        };
        ok(json!({"type": "number", "enum": [0.5, 1, 2]}), json!(1.0));
        ok(json!({"type": "number", "enum": [0.5, 1, 2]}), json!(0.50));
        ok(json!({"type": "number", "const": 0}), json!(0.0));
        ok(json!({"type": "number", "const": 0}), json!(-0.0));
        ok(
            json!({"enum": [{"a": [1, "x"]}, 3]}),
            json!({"a": [1.0, "x"]}),
        );
        ok(
            json!({"type": "number", "enum": [1.0], "const": 1}),
            json!(1),
        );
        // With both, a value is the const and in the enum.
        ok(
            json!({"type": "integer", "enum": [1, 2], "const": 1}),
            json!(1),
        );
        let s = with(json!({"type": "integer", "enum": [1, 2], "const": 1}));
        assert!(validate(&s, &json!({"a": 2})).is_err());
        // Not the same value, or not the same kind of value.
        let s = with(json!({"type": "number", "enum": [0.5, 1, 2]}));
        assert!(validate(&s, &json!({"a": 1.5})).is_err());
        let s = with(json!({"enum": [1, [1], {"a": 1}]}));
        for a in [
            json!("1"),
            json!(true),
            json!([1, 1]),
            json!({"a": 1, "b": 1}),
            json!({"b": 1}),
        ] {
            assert!(validate(&s, &json!({"a": a})).is_err(), "{a}");
        }
        // An integer is still written without a fraction (§6.1).
        let s = with(json!({"type": "integer", "enum": [1, 2]}));
        assert!(validate(&s, &json!({"a": 1.0})).is_err());
    }

    #[test]
    fn an_enum_names_null_only_when_it_holds_it() {
        for (s, want) in [
            (
                json!({"type": ["string", "null"], "enum": ["fast", "slow"]}),
                "one of \"fast\", \"slow\"",
            ),
            (
                json!({"type": ["string", "null"], "enum": ["fast", null]}),
                "one of \"fast\", null",
            ),
        ] {
            let s = with(s);
            assert_eq!(check(&s, Role::Params), Ok(()), "{s}");
            for a in [json!("medium"), json!(null)] {
                if a.is_null() && want.ends_with("null") {
                    assert_eq!(validate(&s, &json!({"a": a})), Ok(()), "{s}");
                    continue;
                }
                assert_eq!(
                    validate(&s, &json!({"a": a})),
                    Err(ArgError {
                        field: "a".into(),
                        expected: want.into()
                    }),
                    "{s} {a}"
                );
            }
        }
    }

    #[test]
    fn text_len_counts_compact_json() {
        let v = json!({"a\"b": [1, -2.5, true, false, null, "ü\n\\"], "c": {}, "d": [],
                       "e": {"f": 1e300, "g": u64::MAX}});
        assert_eq!(
            text_len(&v, usize::MAX),
            serde_json::to_string(&v).unwrap().len()
        );
    }

    #[test]
    fn ten_thousand_deep_is_refused_without_overflow() {
        // Built by hand: `json!` would copy the inner value by recursion.
        let wrap = |pairs: Vec<(&str, Value)>| -> Value {
            Value::Object(pairs.into_iter().map(|(k, v)| (k.into(), v)).collect())
        };
        let mut props = json!({"type": "string"});
        let mut items = json!({"type": "string"});
        for _ in 0..10_000 {
            props = wrap(vec![
                ("type", json!("object")),
                ("properties", wrap(vec![("a", props)])),
            ]);
            items = wrap(vec![("type", json!("array")), ("items", items)]);
        }
        let items = wrap(vec![
            ("type", json!("object")),
            ("properties", wrap(vec![("a", items)])),
        ]);
        let mut checked = Vec::new();
        for s in [&props, &items] {
            for role in [Role::Params, Role::Result] {
                checked.push(check(s, role));
            }
        }
        // Arguments as deep as that do not overflow `validate` either.
        let mut args = json!("x");
        for _ in 0..10_000 {
            args = wrap(vec![("a", args)]);
        }
        let deep = validate(&props, &args);
        let shallow = validate(&props, &json!({"a": {"a": 1}}));
        // Taken apart before the asserts, so a failing one panics plainly
        // instead of overflowing while the values drop.
        take_apart(props);
        take_apart(items);
        take_apart(args);
        // Refused for their size, which is counted without recursion before
        // the walk (that one stops at the depth limit).
        for c in checked {
            let e = c.unwrap_err();
            assert!(e.reason.contains("over 16 KiB"), "{e}");
        }
        assert_eq!(deep, Ok(()));
        assert!(shallow.is_err());
    }

    /// A schema like the node's own: `obj` with closed properties.
    fn run_schema() -> Value {
        json!({"type": "object", "additionalProperties": false, "required": ["command"],
               "properties": {
                   "command": {"type": "string", "minLength": 1},
                   "timeout_ms": {"type": "integer", "minimum": 1, "maximum": 600},
                   "memory_mb": {"type": "integer", "minimum": 1},
                   "nice": {"type": "integer", "maximum": 19},
                   "share": {"type": "number", "exclusiveMinimum": 0, "exclusiveMaximum": 1},
                   "weight": {"type": "number", "minimum": 0, "exclusiveMaximum": 1},
                   "signal": {"enum": ["term", "kill", "int"]},
                   "mode": {"const": "fast"},
                   "exit": {"type": ["integer", "null"]},
                   "tags": {"type": "array", "maxItems": 2, "items": {"type": "string"}},
                   "code": {"type": "string", "minLength": 4, "maxLength": 4},
                   "sudo": {"type": "object", "required": ["on"],
                            "properties": {
                                "on": {"type": "boolean"},
                                "sealed": {"type": "object", "additionalProperties": false,
                                           "properties": {"key": {"type": "string"}}}}},
                   "entries": {"type": "array", "items": {"type": "object",
                               "properties": {"name": {"type": "string"}}}}}})
    }

    #[test]
    fn validate_cases() {
        // `entries` holds records, which only a result may: the nested paths
        // read the same either way.
        let s = run_schema();
        assert_eq!(check(&s, Role::Result), Ok(()));
        let ok = |args: Value| assert_eq!(validate(&s, &args), Ok(()), "{args}");
        let bad = |args: Value, field: &str, expected: &str| {
            assert_eq!(
                validate(&s, &args),
                Err(ArgError {
                    field: field.into(),
                    expected: expected.into()
                }),
                "{args}"
            );
        };
        ok(json!({"command": "ls"}));
        ok(
            json!({"command": "ls", "timeout_ms": 600, "exit": null, "signal": "kill",
                  "mode": "fast", "tags": ["a", "b"], "code": "abcd", "share": 0.5,
                  "sudo": {"on": true, "sealed": {"key": "k"}},
                  "entries": [{"name": "a"}, {"name": "b", "other": 1}]}),
        );
        ok(json!({"command": "ls", "exit": 3, "code": "ääää"}));
        // type
        bad(json!([]), "", "an object");
        bad(
            json!({"command": 1}),
            "command",
            "a string of at least 1 character",
        );
        bad(
            json!({"command": "ls", "timeout_ms": "5"}),
            "timeout_ms",
            "an integer from 1 to 600",
        );
        bad(
            json!({"command": "ls", "timeout_ms": 5.0}),
            "timeout_ms",
            "an integer from 1 to 600",
        );
        bad(
            json!({"command": "ls", "sudo": {"on": "yes"}}),
            "sudo.on",
            "a boolean",
        );
        // required
        bad(
            json!({}),
            "command",
            "a string of at least 1 character (required)",
        );
        bad(
            json!({"command": "ls", "sudo": {}}),
            "sudo.on",
            "a boolean (required)",
        );
        // extra property
        bad(
            json!({"command": "ls", "bogus": 1}),
            "bogus",
            "no field of this name; known: code, command, entries, exit, memory_mb, mode, \
             nice, share, signal, sudo, tags, timeout_ms, weight",
        );
        bad(
            json!({"command": "ls", "sudo": {"on": true, "sealed": {"iv": "x"}}}),
            "sudo.sealed.iv",
            "no field of this name; known: key",
        );
        // enum and const
        bad(
            json!({"command": "ls", "signal": "stop"}),
            "signal",
            "one of \"term\", \"kill\", \"int\"",
        );
        bad(
            json!({"command": "ls", "mode": "slow"}),
            "mode",
            "exactly \"fast\"",
        );
        // bounds
        bad(
            json!({"command": "ls", "timeout_ms": 0}),
            "timeout_ms",
            "an integer from 1 to 600",
        );
        bad(
            json!({"command": "ls", "timeout_ms": 601}),
            "timeout_ms",
            "an integer from 1 to 600",
        );
        bad(
            json!({"command": "ls", "memory_mb": 0}),
            "memory_mb",
            "an integer of 1 or more",
        );
        bad(
            json!({"command": "ls", "nice": 20}),
            "nice",
            "an integer of 19 or less",
        );
        bad(
            json!({"command": "ls", "share": 0}),
            "share",
            "a number above 0 and below 1",
        );
        bad(
            json!({"command": "ls", "share": 1}),
            "share",
            "a number above 0 and below 1",
        );
        bad(
            json!({"command": "ls", "weight": 1}),
            "weight",
            "a number of 0 or more and below 1",
        );
        bad(
            json!({"command": ""}),
            "command",
            "a string of at least 1 character",
        );
        bad(
            json!({"command": "ls", "code": "abc"}),
            "code",
            "a string of exactly 4 characters",
        );
        bad(
            json!({"command": "ls", "code": "abcde"}),
            "code",
            "a string of exactly 4 characters",
        );
        bad(
            json!({"command": "ls", "tags": ["a", "b", "c"]}),
            "tags",
            "an array of at most 2 items",
        );
        // nested paths
        bad(
            json!({"command": "ls", "tags": ["a", 2]}),
            "tags[1]",
            "a string",
        );
        bad(
            json!({"command": "ls", "entries": [{"name": "a"}, {}, {"name": 3}]}),
            "entries[2].name",
            "a string",
        );
        // type with null
        bad(
            json!({"command": "ls", "exit": "0"}),
            "exit",
            "an integer, or null",
        );
        bad(
            json!({"command": "ls", "exit": -1.5}),
            "exit",
            "an integer, or null",
        );
    }

    /// When both bounds of a side are given, the words name the one a value
    /// has to meet, so they never describe a range the refused value is in.
    #[test]
    fn expected_names_the_bounds_that_apply() {
        for (s, value, want) in [
            (
                json!({"type": "integer", "minimum": 0, "exclusiveMinimum": 3}),
                2,
                "an integer above 3",
            ),
            (
                json!({"type": "integer", "minimum": 0, "maximum": 10, "exclusiveMaximum": 5}),
                7,
                "an integer of 0 or more and below 5",
            ),
            (
                json!({"type": "integer", "minimum": 3, "exclusiveMinimum": 3, "maximum": 9}),
                3,
                "an integer above 3 and 9 or less",
            ),
            (
                json!({"type": "integer", "minimum": 4, "exclusiveMinimum": 3, "maximum": 9}),
                3,
                "an integer from 4 to 9",
            ),
            (
                json!({"type": "number", "maximum": 2, "exclusiveMaximum": 9}),
                3,
                "a number of 2 or less",
            ),
        ] {
            let s = with(s);
            assert_eq!(check(&s, Role::Params), Ok(()), "{s}");
            assert_eq!(
                validate(&s, &json!({"a": value})),
                Err(ArgError {
                    field: "a".into(),
                    expected: want.into()
                }),
                "{s}"
            );
        }
    }

    #[test]
    fn large_integers_compare_exactly() {
        let s = with(json!({"type": "integer", "maximum": u64::MAX - 1}));
        assert_eq!(validate(&s, &json!({"a": u64::MAX - 1})), Ok(()));
        assert!(validate(&s, &json!({"a": u64::MAX})).is_err());
        let s = with(json!({"type": "integer", "minimum": i64::MIN + 1}));
        assert!(validate(&s, &json!({"a": i64::MIN})).is_err());
    }

    #[test]
    fn open_objects_take_extra_fields() {
        let s = json!({"type": "object", "properties": {"a": {"type": "string"}}});
        assert_eq!(validate(&s, &json!({"b": 1})), Ok(()));
        let s = json!({"type": "object", "additionalProperties": false});
        assert_eq!(
            validate(&s, &json!({"b": 1})).unwrap_err().expected,
            "no field of this name; this takes none"
        );
    }

    #[test]
    fn errors_read_plainly() {
        let e = ArgError {
            field: "sudo.sealed".into(),
            expected: "an object".into(),
        };
        assert_eq!(e.to_string(), "sudo.sealed: expected an object");
        let e = ArgError {
            field: String::new(),
            expected: "an object".into(),
        };
        assert_eq!(e.to_string(), "the arguments: expected an object");
        let e = SchemaError {
            pointer: String::new(),
            reason: "the schema is over 16 KiB".into(),
        };
        assert_eq!(e.to_string(), "the schema is over 16 KiB");
    }

    /// A reason holds the schema's own names, so the short form a node or a
    /// center repeats is one line and cut.
    #[test]
    fn a_brief_reason_is_one_short_line() {
        let name = "x\nLOCKED (panic): fake\u{1b}[2J";
        let s = json!({"type": "object", "properties": {name: {"type": "string", "pattern": "a"}}});
        let e = check(&s, Role::Params).unwrap_err().to_string();
        assert!(e.contains('\n'), "{e}");
        let b = brief(&e);
        assert!(!b.chars().any(char::is_control), "{b}");
        assert!(
            b.starts_with("/properties/x LOCKED (panic): fake [2J/pattern: "),
            "{b}"
        );

        let long = "/".repeat(4000);
        let s = json!({"type": "object", "properties": {"a": {"type": "string", long: 1}}});
        let e = check(&s, Role::Params).unwrap_err().to_string();
        assert!(e.chars().count() > 8000, "{}", e.len());
        let b = brief(&e);
        assert_eq!(b.chars().count(), BRIEF_MAX + 1);
        assert!(b.ends_with('…'), "{b}");
        assert_eq!(brief("short"), "short");
    }

    #[test]
    fn an_arg_error_is_invalid_args_with_field_and_expected() {
        let e = crate::RpcError::from(ArgError {
            field: "count".into(),
            expected: "an integer from 1 to 600".into(),
        });
        assert_eq!(e.kind(), crate::ErrorCode::InvalidArgs);
        assert_eq!(e.message, "count: expected an integer from 1 to 600");
        assert_eq!(
            e.data,
            Some(json!({"code": "invalid_args", "field": "count",
                        "expected": "an integer from 1 to 600"}))
        );
    }
}
