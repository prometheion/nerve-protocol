//! A form for a capability of `node.toml` or one a center adds: what the
//! desktop app's dialog and the center's Capabilities tab hold, checked with
//! the node's own rules ([`ConfigCapability::validate`]), so all of them say
//! the same about the same capability; the node checks again on save.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use nerve_proto::schema::{self, Role};

use super::{ConfigCapability, Output, Platform};

fn s(v: &Value) -> &str {
    v.as_str().unwrap_or_default()
}

/// What a form holds of a capability of node.toml (the desktop app's
/// `cap add` and `cap edit` dialog) or of one a center adds (the center's
/// Capabilities tab), as it was typed. The schemas are JSON
/// text, empty for none (no arguments, the printed text as the result); the
/// timeout is seconds, empty for the node's default.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct CapForm {
    pub name: String,
    pub summary: String,
    pub effect: String,
    pub command: String,
    pub params: String,
    pub result: String,
    pub timeout: String,
    pub platform: String,
}

/// What is wrong with each field of a [`CapForm`], "" where nothing is.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct CapFormErrors {
    pub name: String,
    pub summary: String,
    pub effect: String,
    pub command: String,
    pub params: String,
    pub result: String,
    pub timeout: String,
    pub platform: String,
}

impl CapFormErrors {
    pub fn none(&self) -> bool {
        *self == CapFormErrors::default()
    }

    /// The first problem, in the order of the fields; "" for none.
    pub fn first(&self) -> &str {
        [
            &self.name,
            &self.summary,
            &self.effect,
            &self.command,
            &self.params,
            &self.result,
            &self.timeout,
            &self.platform,
        ]
        .into_iter()
        .find(|e| !e.is_empty())
        .map_or("", |e| e.as_str())
    }
}

/// The words of a command as a form takes it on one line: words apart
/// by blanks; a word with blanks, quotes or a line break in double quotes,
/// with the escapes of JSON (as `cap ls` writes it, so an edit gives back
/// what it showed), or in single quotes as it is.
pub fn command_words(line: &str) -> Result<Vec<String>, String> {
    let mut words = Vec::new();
    let mut rest = line.trim_start();
    while let Some(c) = rest.chars().next() {
        let (word, after) = match c {
            '"' => {
                // The end: the next quote no backslash escapes.
                let mut end = None;
                let mut escaped = false;
                for (i, ch) in rest.char_indices().skip(1) {
                    match ch {
                        '\\' if !escaped => escaped = true,
                        '"' if !escaped => {
                            end = Some(i);
                            break;
                        }
                        _ => escaped = false,
                    }
                }
                let end = end.ok_or("a double quote is not closed")?;
                let word: String = serde_json::from_str(&rest[..=end])
                    .map_err(|e| format!("in double quotes: {e}"))?;
                (word, &rest[end + 1..])
            }
            '\'' => {
                let end = rest[1..].find('\'').ok_or("a single quote is not closed")? + 1;
                (rest[1..end].to_string(), &rest[end + 1..])
            }
            _ => {
                let end = rest.find(char::is_whitespace).unwrap_or(rest.len());
                let word = &rest[..end];
                if word.contains(['"', '\'']) {
                    return Err(format!("{word}: put the whole word in quotes"));
                }
                (word.to_string(), &rest[end..])
            }
        };
        if after.chars().next().is_some_and(|c| !c.is_whitespace()) {
            return Err("a quoted word ends at a blank".into());
        }
        words.push(word);
        rest = after.trim_start();
    }
    Ok(words)
}

/// A schema field of a form: nothing for an empty one, else its JSON,
/// checked as the center checks it (nerve_proto::schema::check).
fn schema_field(text: &str, role: Role) -> Result<Value, String> {
    if text.trim().is_empty() {
        return Ok(Value::Null);
    }
    let v: Value = serde_json::from_str(text).map_err(|e| format!("not JSON: {e}"))?;
    schema::check(&v, role).map_err(|e| schema::brief(&e.to_string()))?;
    Ok(v)
}

/// The capability `form` holds, checked with the node's own rules for a
/// capability of node.toml ([`ConfigCapability::validate`], the schemas
/// with the center's), or what is wrong with each field, so a form says
/// it while it is typed in; the node checks again when it is saved. `max_timeout_secs` is the node's
/// limit as far as the form's side knows it. The node's checks stop at the first
/// problem, so a field shows its own once those before it are right.
pub fn capability(
    form: &CapForm,
    max_timeout_secs: u64,
) -> Result<ConfigCapability, Box<CapFormErrors>> {
    let mut e = CapFormErrors::default();
    let params = schema_field(&form.params, Role::Params).unwrap_or_else(|why| {
        e.params = why;
        Value::Null
    });
    let result = match schema_field(&form.result, Role::Result) {
        Ok(Value::Null) => Output::Text,
        Ok(v) => Output::Json(v),
        Err(why) => {
            e.result = why;
            Output::Text
        }
    };
    let command = command_words(&form.command).unwrap_or_else(|why| {
        e.command = why;
        Vec::new()
    });
    let timeout_secs = match form.timeout.trim() {
        "" => None,
        t => match t.parse() {
            Ok(n) => Some(n),
            Err(_) => {
                e.timeout = "seconds, as a whole number".into();
                None
            }
        },
    };
    // A choice the form does not offer is said, not taken for another:
    // what is saved is what the form holds.
    let effect = serde_json::from_value(Value::String(form.effect.clone())).unwrap_or_else(|_| {
        e.effect = "read, write, execute, sense or actuate".into();
        nerve_proto::descriptor::Effect::Read
    });
    let platform = Platform::parse(&form.platform).unwrap_or_else(|| {
        e.platform = "any, linux or windows".into();
        Platform::Any
    });
    let name = form.name.trim();
    let c = ConfigCapability {
        name: name.to_string(),
        summary: form.summary.trim().to_string(),
        effect,
        command,
        params,
        result,
        timeout_secs,
        platform,
    };
    let Err(why) = c.validate(max_timeout_secs) else {
        return if e.none() { Ok(c) } else { Err(Box::new(e)) };
    };
    let quoted = format!("capability {name:?}: ");
    let plain = format!("capability {name}: ");
    let why = why
        .strip_prefix(&quoted)
        .or_else(|| why.strip_prefix(&plain))
        .unwrap_or(&why)
        .to_string();
    // Where the field it names has a problem of its own already, that one
    // is what to fix first.
    let into = |field: &mut String, text: &str| {
        if field.is_empty() {
            *field = text.to_string();
        }
    };
    if let Some(rest) = why.strip_prefix("command: ") {
        // Its placeholders name the arguments, which wait for their schema.
        if e.params.is_empty() {
            into(&mut e.command, rest);
        }
    } else if why.starts_with("timeout_secs") {
        into(&mut e.timeout, &why);
    } else if why.starts_with("the summary") {
        into(&mut e.summary, &why);
    } else if !(why.starts_with("params: ") || why.starts_with("result: ")) {
        into(&mut e.name, &why);
    }
    // A schema's own problem is its field's already; any other shows.
    if e.none() {
        e.name = why;
    }
    Err(Box::new(e))
}

/// What is wrong with each field of `form` ([`capability`]), "" where
/// nothing is.
pub fn check(form: &CapForm, max_timeout_secs: u64) -> CapFormErrors {
    capability(form, max_timeout_secs)
        .err()
        .map(|e| *e)
        .unwrap_or_default()
}

/// A form's fields for a capability as `cap ls --json` (its `config`) and
/// `settings.get` give it ([`ConfigCapability::entry`]): what was declared,
/// the command as `cap ls` writes it.
pub fn of_entry(entry: &Value) -> CapForm {
    let words: Vec<String> = entry["command"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(str::to_string)
        .collect();
    let pretty = |v: &Value| serde_json::to_string_pretty(v).unwrap_or_default();
    CapForm {
        name: s(&entry["name"]).into(),
        summary: s(&entry["summary"]).into(),
        effect: s(&entry["effect"]).into(),
        command: ConfigCapability::line(&words),
        params: match &entry["params"] {
            Value::Null => String::new(),
            v => pretty(v),
        },
        result: match &entry["result"] {
            Value::String(_) | Value::Null => String::new(),
            v => pretty(v),
        },
        timeout: entry["timeout_secs"]
            .as_u64()
            .map(|t| t.to_string())
            .unwrap_or_default(),
        platform: match s(&entry["platform"]) {
            "" => "any".into(),
            p => p.into(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A form gives the capability it holds, or its problems field by
    /// field; what `entry` gives of a capability is that capability's form
    /// again, as the desktop app's dialog and the center's tab fill it.
    #[test]
    fn a_form_gives_its_capability_or_what_is_wrong() {
        let form = CapForm {
            name: "say.back".into(),
            summary: " Says it back. ".into(),
            effect: "read".into(),
            command: "echo \"a b\" {word}".into(),
            params: r#"{"type": "object", "properties": {"word": {"type": "string"}}, "required": ["word"]}"#.into(),
            result: String::new(),
            timeout: "5".into(),
            platform: "linux".into(),
        };
        let c = capability(&form, 60).unwrap();
        assert_eq!(c.command, ["echo", "a b", "{word}"]);
        assert_eq!(c.summary, "Says it back.");
        assert_eq!((c.timeout_secs, c.platform), (Some(5), Platform::Linux));
        assert!(check(&form, 60).none());
        let again = of_entry(&c.entry());
        assert_eq!(capability(&again, 60).unwrap(), c);
        // Over the node's limit, and with an empty name.
        let e = check(&form, 4);
        assert!(e.timeout.contains("limits.max_timeout_secs (4)"), "{e:?}");
        assert_eq!(e.first(), e.timeout);
        // A choice it does not offer is said, not taken for read or any.
        for (effect, platform) in [
            ("Sense", "linux"),
            ("", "linux"),
            ("read", "Linux"),
            ("read", ""),
        ] {
            let odd = CapForm {
                effect: effect.into(),
                platform: platform.into(),
                ..form.clone()
            };
            let e = capability(&odd, 60).unwrap_err();
            let said = if effect == "read" {
                &e.platform
            } else {
                &e.effect
            };
            assert!(
                !said.is_empty() && e.first() == said,
                "{effect} {platform}: {e:?}"
            );
        }
        let empty = CapForm {
            name: String::new(),
            ..form
        };
        let e = capability(&empty, 60).unwrap_err();
        assert!(!e.name.is_empty() && e.first() == e.name, "{e:?}");
        assert_eq!(CapFormErrors::default().first(), "");
    }
}
