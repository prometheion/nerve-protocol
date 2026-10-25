//! The center's state file, `state.json` in the state folder (mode 0600).
//!
//! It holds what the center must remember across restarts: its id and name,
//! the paired nodes with their public keys and last descriptor, the harness
//! tokens (hashed) and the statistics. It never
//! holds file contents, command output or secrets: the descriptor cache is the
//! node's own description of itself, and the statistics are counts and timings.

use std::collections::BTreeMap;
use std::path::Path;

use serde::{Deserialize, Serialize};

use nerve_proto::Descriptor;
use nerve_transport::log::Level;

use crate::catalog::Catalog;
use crate::checker::CheckerConfig;

pub const FILE: &str = "state.json";
/// The default statistics retention.
pub const RETENTION_DAYS: u32 = 30;
/// The default lifetime of a pairing code, in minutes.
pub const PAIR_CODE_MINUTES: u32 = 10;
/// The longest lifetime the owner may set for a pairing code: 24 hours.
pub const PAIR_CODE_MAX_MINUTES: u32 = 1440;
const DAY_MS: u64 = 86_400_000;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Store {
    pub center_id: String,
    pub center_name: String,
    #[serde(default)]
    pub nodes: BTreeMap<String, NodeRecord>,
    #[serde(default)]
    pub harness_tokens: Vec<TokenRecord>,
    #[serde(default = "d_retention")]
    pub retention_days: u32,
    /// How long a pairing code made from now on stays valid, in minutes.
    #[serde(default = "d_pair_code_minutes")]
    pub pair_code_minutes: u32,
    #[serde(default)]
    pub stats: BTreeMap<String, NodeStats>,
    /// What the center logs (docs/user/logs.md); the `--log` flag overrides
    /// it for one run.
    #[serde(default)]
    pub log_level: Level,
    /// The last rotation of the center's key (docs/dev/spec/protocol.md
    /// §4.10), while nodes are told of it. Public values only: the keys are
    /// in their PEM files.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_rotation: Option<KeyRotation>,
    /// How many rotations of its key the center started: a restore keeps
    /// the keys of the state that is further along, here or in the backup.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub key_rotations: u32,
    /// The action checker's settings (docs/dev/action-checker.md): the
    /// blocklist, the saved allow rules, the decision model and the switches.
    #[serde(default)]
    pub checker: CheckerConfig,
}

fn is_zero(n: &u32) -> bool {
    *n == 0
}

/// A rotation of the center's TLS key: what `center.rotate` tells the
/// nodes, and how far it got.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct KeyRotation {
    pub started_ms: u64,
    /// When the center serves the new key at the latest.
    pub until_ms: u64,
    /// The SubjectPublicKeyInfo of the old and the new key, base64url.
    pub old_spki: String,
    pub new_spki: String,
    /// The old key's signature over the rotate message, base64url.
    pub sig: String,
    /// When the center started to serve the new key. It goes on telling the
    /// nodes, with no grace left, so they drop the old pin.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub finished_ms: Option<u64>,
}

fn d_retention() -> u32 {
    RETENTION_DAYS
}

fn d_pair_code_minutes() -> u32 {
    PAIR_CODE_MINUTES
}

impl Store {
    pub fn new(center_id: String, center_name: String) -> Store {
        Store {
            center_id,
            center_name,
            nodes: BTreeMap::new(),
            harness_tokens: Vec::new(),
            retention_days: RETENTION_DAYS,
            pair_code_minutes: PAIR_CODE_MINUTES,
            stats: BTreeMap::new(),
            log_level: Level::default(),
            key_rotation: None,
            key_rotations: 0,
            checker: CheckerConfig::default(),
        }
    }

    pub fn load(dir: &Path) -> std::io::Result<Option<Store>> {
        match std::fs::read(dir.join(FILE)) {
            Ok(b) => {
                let mut s: Store = serde_json::from_slice(&b).map_err(|e| {
                    std::io::Error::other(format!("{} is not valid: {e}", dir.join(FILE).display()))
                })?;
                // The catalogs are not in the file: they come from the
                // cached descriptors, so tools stay listed while a node is
                // offline.
                for n in s.nodes.values_mut() {
                    n.catalog = n
                        .descriptor
                        .as_ref()
                        .map(Catalog::build)
                        .unwrap_or_default();
                }
                Ok(Some(s))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }

    pub fn save(&self, dir: &Path) -> std::io::Result<()> {
        Store::write_file(dir, &self.file_bytes()?)
    }

    /// The text of the state file, without writing it.
    pub fn file_bytes(&self) -> std::io::Result<Vec<u8>> {
        serde_json::to_vec_pretty(self).map_err(std::io::Error::other)
    }

    /// Writes `text` from [`Store::file_bytes`] as the state file.
    pub fn write_file(dir: &Path, text: &[u8]) -> std::io::Result<()> {
        nerve_transport::files::write_private(&dir.join(FILE), text)
    }

    pub fn node_by_name(&self, name: &str) -> Option<&NodeRecord> {
        self.nodes.values().find(|n| n.name == name)
    }

    /// The node that holds `public_key`, as its key or as its old one in
    /// the grace of a rotation.
    pub fn node_by_key(&self, public_key: &str) -> Option<&NodeRecord> {
        self.nodes.values().find(|n| {
            n.public_key == public_key
                || n.old_key
                    .as_ref()
                    .is_some_and(|o| o.public_key == public_key)
        })
    }

    /// Today's statistics bucket of `node`.
    pub fn day(&mut self, node: &str, now_ms: u64) -> &mut DayStats {
        self.stats
            .entry(node.to_string())
            .or_default()
            .days
            .entry(now_ms / DAY_MS)
            .or_default()
    }

    /// Drops statistics days older than the retention.
    pub fn prune_stats(&mut self, now_ms: u64) {
        let keep_from = (now_ms / DAY_MS).saturating_sub(u64::from(self.retention_days));
        for s in self.stats.values_mut() {
            s.days.retain(|d, _| *d >= keep_from);
        }
        self.stats.retain(|_, s| !s.days.is_empty());
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeRecord {
    pub id: String,
    /// The center's name for the node; unique among this center's nodes.
    pub name: String,
    /// The node's Ed25519 public key for this center, hex. The node id stays
    /// the one of the key it paired with when the key is rotated.
    pub public_key: String,
    /// The key the node rotated away from, taken until its grace ends
    /// (docs/dev/spec/protocol.md §4.10).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub old_key: Option<OldKey>,
    /// How many rotations of its key the node made here: a restore keeps
    /// the keys of the record that is further along.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub key_rotations: u32,
    pub platform: String,
    pub arch: String,
    pub paired_ms: u64,
    /// The owner switched the node off in the center: it stays paired and
    /// connected, but the agent is offered none of its tools and no call
    /// reaches it.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub disabled: bool,
    #[serde(default)]
    pub last_seen_ms: u64,
    /// Why the node said it was going away before its last link dropped.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub going_away: Option<String>,
    /// The last full descriptor, so tools stay listed while the node is offline.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub descriptor: Option<Descriptor>,
    /// The descriptor as the center checked it ([`Catalog`]), built again
    /// with it and never written: it is derived data. Read under the store
    /// lock like the descriptor.
    #[serde(skip)]
    pub catalog: Catalog,
}

impl NodeRecord {
    /// Keeps `d` as the node's descriptor, with its catalog.
    pub fn set_descriptor(&mut self, d: Descriptor) {
        self.catalog = Catalog::build(&d);
        self.descriptor = Some(d);
    }
}

/// A node's replaced key and the end of its grace.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OldKey {
    pub public_key: String,
    /// Milliseconds since the Unix epoch; from then on the key is refused.
    pub until_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenRecord {
    pub id: String,
    pub label: String,
    /// Hex SHA-256 of the token; the token itself is shown once and not kept.
    pub hash: String,
    pub created_ms: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NodeStats {
    /// Day number (days since the Unix epoch) to that day's numbers.
    #[serde(default)]
    pub days: BTreeMap<u64, DayStats>,
}

/// One node's numbers for one day. Counts and timings only.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct DayStats {
    #[serde(default)]
    pub online_ms: u64,
    #[serde(default)]
    pub links: u64,
    /// Links that ended without a `bye`.
    #[serde(default)]
    pub drops: u64,
    /// `cap.action` to its calls.
    #[serde(default)]
    pub calls: BTreeMap<String, CallStats>,
    /// Error code to count.
    #[serde(default)]
    pub errors: BTreeMap<String, u64>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct CallStats {
    pub count: u64,
    pub errors: u64,
    pub total_ms: u64,
    pub max_ms: u64,
}

impl DayStats {
    pub fn add(&mut self, o: &DayStats) {
        self.online_ms += o.online_ms;
        self.links += o.links;
        self.drops += o.drops;
        for (k, c) in &o.calls {
            let m = self.calls.entry(k.clone()).or_default();
            m.count += c.count;
            m.errors += c.errors;
            m.total_ms += c.total_ms;
            m.max_ms = m.max_ms.max(c.max_ms);
        }
        for (k, n) in &o.errors {
            *self.errors.entry(k.clone()).or_default() += n;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_pairing_code_lifetime_defaults_to_ten_minutes() {
        assert_eq!(Store::new("c".into(), "home".into()).pair_code_minutes, 10);
        // A state file without the setting reads as ten minutes.
        let old = r#"{"center_id": "c", "center_name": "home"}"#;
        let s: Store = serde_json::from_str(old).unwrap();
        assert_eq!(s.pair_code_minutes, 10);
    }

    #[test]
    fn stats_are_pruned_by_retention() {
        let mut s = Store::new("c".into(), "home".into());
        s.retention_days = 2;
        let today = 100 * DAY_MS;
        s.day("n", today - 5 * DAY_MS).links = 1;
        s.day("n", today).links = 2;
        s.prune_stats(today);
        let days = &s.stats["n"].days;
        assert_eq!(days.len(), 1);
        assert_eq!(days[&100].links, 2);
    }

    fn record(id: &str) -> NodeRecord {
        NodeRecord {
            id: id.into(),
            name: id.into(),
            public_key: "00".into(),
            old_key: None,
            key_rotations: 0,
            platform: "linux".into(),
            arch: "x86_64".into(),
            paired_ms: 1,
            disabled: false,
            last_seen_ms: 0,
            going_away: None,
            descriptor: None,
            catalog: Catalog::default(),
        }
    }

    /// The catalog is derived from the descriptor: it is not in the state
    /// file, and a load builds it again, so a restarted center offers an
    /// offline node's tools as before and leaves out the same units.
    #[test]
    fn the_catalog_is_built_after_a_load_and_never_written() {
        use crate::tools::tests::{cap, desc};
        use nerve_proto::Effect;
        use serde_json::json;
        let dir = tempfile::tempdir().unwrap();
        let mut s = Store::new("c".into(), "home".into());
        let mut n = record("a");
        n.set_descriptor(desc(
            "a",
            vec![
                cap(
                    "fs",
                    "fs",
                    &[("read", Effect::Read, json!({"type": "object"}))],
                ),
                cap(
                    "lamp",
                    "",
                    &[("dim", Effect::Actuate, json!({"$ref": "#/defs/level"}))],
                ),
            ],
        ));
        assert_eq!(n.catalog.units.len(), 1);
        s.nodes.insert("a".into(), n);
        s.save(dir.path()).unwrap();
        let text = std::fs::read_to_string(dir.path().join(FILE)).unwrap();
        assert!(
            !text.contains("\"units\"") && !text.contains("\"broken\""),
            "{text}"
        );
        let back = Store::load(dir.path()).unwrap().unwrap();
        assert_eq!(back.nodes["a"].catalog, s.nodes["a"].catalog);
        assert_eq!(back.nodes["a"].catalog.units[0].name, "fs.read");
        assert_eq!(back.nodes["a"].catalog.broken[0].name, "lamp.dim");
    }

    #[test]
    fn the_disabled_flag_survives_a_restart() {
        let dir = tempfile::tempdir().unwrap();
        let mut s = Store::new("c".into(), "home".into());
        s.nodes.insert("a".into(), record("a"));
        s.nodes.insert("b".into(), record("b"));
        s.nodes.get_mut("b").unwrap().disabled = true;
        s.save(dir.path()).unwrap();
        let back = Store::load(dir.path()).unwrap().unwrap();
        assert!(!back.nodes["a"].disabled);
        assert!(back.nodes["b"].disabled);
    }

    #[test]
    fn a_state_file_without_the_flag_reads_a_node_as_enabled() {
        let old = r#"{"center_id":"c","center_name":"home","nodes":{"a":{"id":"a","name":"a",
            "public_key":"00","platform":"linux","arch":"x86_64","paired_ms":1}}}"#;
        let s: Store = serde_json::from_str(old).unwrap();
        assert!(!s.nodes["a"].disabled);
    }
}
