//! The center's audit feed: the recent `audit/decision` events of all its
//! nodes, in memory for the web UI (never on disk). A node can send refused
//! calls as fast as its link allows, with any target, so every entry is cut
//! as the node's own log cuts it and the feed is bounded in count and size.

use std::collections::VecDeque;

use serde_json::{Map, Value};

use crate::util;

/// The most decisions the feed keeps; the oldest go first.
pub const AUDIT_KEEP: usize = 500;
/// The most bytes the feed keeps, counted as the entries' JSON, which is
/// also what `/api/audit` answers with. 500 ordinary decisions take well
/// under half of it; it bites only when entries carry long cut targets.
pub const AUDIT_MAX_BYTES: usize = 1024 * 1024;
/// The most bytes of a field other than the target (cap, action, code,
/// session, node name).
const FIELD_MAX: usize = 200;
/// The fields an entry keeps: the event's (docs/dev/spec/protocol.md §7.5), `by`,
/// which the web UI shows, and the node the center adds. Anything else a
/// node sends is dropped, so no other field can make an entry large.
const FIELDS: [&str; 12] = [
    "ts", "cap", "action", "target", "decision", "code", "session", "by", "node_id", "node",
    // The action checker's own decisions carry this: `{layer, scope,
    // detail}`, all short and built by the center, so it cannot blow an
    // entry up.
    "checker",
    // The call's arguments an audit button may pin: kept as the node keeps
    // them (nerve_policy::audit::pinnable_args), bounded in count and size.
    "args",
];

#[derive(Debug, Default)]
pub struct AuditFeed {
    /// Each entry with its size in bytes.
    entries: VecDeque<(Value, usize)>,
    bytes: usize,
}

impl AuditFeed {
    /// Adds a decision, cut to size, and drops the oldest past the limits.
    pub fn push(&mut self, e: Value) {
        let e = trim(e);
        let size = e.to_string().len();
        self.entries.push_back((e, size));
        self.bytes += size;
        while self.entries.len() > AUDIT_KEEP || self.bytes > AUDIT_MAX_BYTES {
            let Some((_, s)) = self.entries.pop_front() else {
                break;
            };
            self.bytes -= s;
        }
    }

    /// The decisions, oldest first.
    pub fn list(&self) -> Vec<Value> {
        self.entries.iter().map(|(e, _)| e.clone()).collect()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The bytes the decisions take as JSON.
    pub fn bytes(&self) -> usize {
        self.bytes
    }
}

/// The entry with only the known fields: the target cut to
/// [`nerve_policy::audit::TARGET_MAX_CHARS`] characters and marked as the
/// node marks it, every other text clipped, `ts` kept as a number.
fn trim(e: Value) -> Value {
    let Value::Object(o) = e else {
        return Value::Object(Map::new());
    };
    let mut out = Map::new();
    for (k, v) in o {
        if !FIELDS.contains(&k.as_str()) {
            continue;
        }
        let v = match v {
            Value::Number(n) if k == "ts" => Value::Number(n),
            Value::String(s) if k == "target" => nerve_policy::audit::cut_target(&s).into(),
            Value::String(s) if k != "ts" => util::clip(&s, FIELD_MAX).into(),
            // The checker marker: an object the center built, kept with its
            // `layer`, `scope` (global or node) and `detail` strings clipped.
            // What a node sends as `args` is held to what a node keeps:
            // strings, numbers and booleans, the strings short, a few.
            Value::Object(o) if k == "args" => match nerve_policy::audit::pinnable(&o) {
                Some(a) => Value::Object(a),
                None => continue,
            },
            Value::Object(o) if k == "checker" => {
                let mut m = Map::new();
                for key in ["layer", "scope", "detail"] {
                    if let Some(Value::String(s)) = o.get(key) {
                        m.insert(key.into(), util::clip(s, FIELD_MAX).into());
                    }
                }
                Value::Object(m)
            }
            _ => continue,
        };
        out.insert(k, v);
    }
    Value::Object(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn refused(target: String) -> Value {
        json!({"ts": 1, "cap": "exec", "action": "run", "target": target,
               "decision": "forbidden", "code": "forbidden",
               "node_id": "n1", "node": "box-1"})
    }

    /// A target past 512 characters is kept cut and marked, the rest as sent.
    #[test]
    fn a_long_target_is_kept_cut() {
        let mut f = AuditFeed::default();
        f.push(refused("é".repeat(2000)));
        f.push(refused("ls -l".into()));
        let l = f.list();
        let t = l[0]["target"].as_str().unwrap();
        assert_eq!(
            t,
            format!("{}… [cut at 512 of 2000 characters]", "é".repeat(512))
        );
        assert_eq!(l[1], refused("ls -l".into()));
    }

    /// Ten thousand refused calls with large targets: the feed stays within
    /// its count and its size, keeps the newest, and counts its bytes right.
    #[test]
    fn the_feed_does_not_grow_past_its_limits() {
        let mut f = AuditFeed::default();
        for i in 0..10_000 {
            f.push(refused(format!("{i} {}", "€".repeat(3000))));
            assert!(f.len() <= AUDIT_KEEP && f.bytes() <= AUDIT_MAX_BYTES);
        }
        let l = f.list();
        assert!(!l.is_empty());
        assert!(
            l.last().unwrap()["target"]
                .as_str()
                .unwrap()
                .starts_with("9999 ")
        );
        let real: usize = l.iter().map(|e| e.to_string().len()).sum();
        assert_eq!(real, f.bytes());
        // The answer of /api/audit is the feed itself.
        let answer = json!({"decisions": l}).to_string();
        assert!(
            answer.len() <= AUDIT_MAX_BYTES + AUDIT_KEEP + 64,
            "{}",
            answer.len()
        );
    }

    /// No other field makes an entry large: unknown ones are dropped and
    /// the known ones clipped.
    #[test]
    fn other_fields_cannot_make_an_entry_large() {
        let mut f = AuditFeed::default();
        let mut e = refused("ls".into());
        e["code"] = json!("c".repeat(10_000));
        e["extra"] = json!("x".repeat(10_000));
        e["ts"] = json!("x".repeat(10_000));
        f.push(e);
        f.push(json!(["not", "an", "object"]));
        let l = f.list();
        assert!(l[0].get("extra").is_none());
        assert!(l[0].get("ts").is_none());
        assert!(l[0]["code"].as_str().unwrap().len() <= FIELD_MAX + "…".len());
        assert!(f.bytes() < 1024, "{}", f.bytes());
        assert_eq!(l[1], json!({}));
    }

    /// A checker decision keeps its `checker` marker (layer and detail), with
    /// the strings clipped and nothing else inside.
    #[test]
    fn the_checker_marker_is_kept() {
        let mut f = AuditFeed::default();
        let mut e = refused("rm -rf /".into());
        e["by"] = json!("action checker");
        e["checker"] = json!({"layer": "blocklist", "scope": "node", "detail": "exec.run:rm -rf /", "evil": "x".repeat(9999)});
        f.push(e);
        let l = f.list();
        assert_eq!(l[0]["by"], "action checker");
        assert_eq!(l[0]["checker"]["layer"], "blocklist");
        assert_eq!(l[0]["checker"]["scope"], "node");
        assert_eq!(l[0]["checker"]["detail"], "exec.run:rm -rf /");
        assert!(l[0]["checker"].get("evil").is_none());
    }
}
