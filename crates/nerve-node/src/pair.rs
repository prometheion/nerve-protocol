//! Pairing with a center (spec §2): the preview the owner confirms, the
//! `POST /nerve/v0/pair`, and storing the key and the center entry.

use serde_json::Value;

use nerve_policy::config::{SettingsGrant, valid_center_name};
use nerve_policy::{CenterEntry, CenterPolicy};
use nerve_proto::link::{PairLink, PairRequest, PairResponse};
use nerve_proto::{PAIR_CHECK_PATH, PAIR_PATH};
use nerve_transport::keys::NodeKey;

use crate::paths::NodePaths;

/// The largest pairing response the node reads.
const RESPONSE_MAX: usize = 64 * 1024;

/// What the owner sees before confirming: where the node will link to, and
/// what the center may do by default.
pub fn preview(link: &PairLink, name: Option<&str>) -> String {
    let mut s = format!("Pair this node with the center at {}\n", link.center);
    match &link.pin {
        Some(pin) => s.push_str(&format!("  certificate pin: {pin}\n")),
        None if link.center.tls => {
            s.push_str("  certificate: checked against the system's roots\n")
        }
        None => s.push_str("  WARNING: plain http, nothing on the way is encrypted\n"),
    }
    if let Some(n) = name {
        s.push_str(&format!("  local name: {n}\n"));
    }
    s.push_str(
        "Defaults for this center:\n  \
         mode folder (writes and commands only in the folders you give it, none yet;\n  \
         \x20 on the installed node a read may also go where every account may read)\n  \
         settings off (the center cannot change this node's settings)\n  \
         the guard (deny rules that keep its commands off this node itself)\n",
    );
    s
}

/// What a check of a pairing link found before the owner says yes: whether
/// the center answers on the way the pairing takes, whether its certificate
/// is the one the link pins (or one the system trusts), and what the center
/// says of the code (protocol §3.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Check {
    /// `ok`, `unreachable` or `certificate`.
    pub reach: &'static str,
    /// The center's word for the code: `open`, `used`, `gone` or `busy`;
    /// `unknown` when the center has no check (protocol §3.2) or did not
    /// answer it; `None` when it was not reached.
    pub code: Option<String>,
    /// Why pairing cannot work now, in words; `None` when it can, or may.
    pub problem: Option<String>,
}

impl Check {
    /// Whether pairing can work: nothing stands in its way that the check
    /// found. A code the center did not speak of may still pair.
    pub fn ready(&self) -> bool {
        self.problem.is_none()
    }

    /// The check in one sentence, for the preview.
    pub fn said(&self) -> String {
        if let Some(p) = &self.problem {
            return format!("cannot pair: {p}");
        }
        match self.code.as_deref() {
            Some("open") => "checked: the center answers and the code is valid".into(),
            _ => {
                "checked: the center answers; it did not say whether the code is still valid".into()
            }
        }
    }

    pub fn json(&self) -> Value {
        serde_json::json!({
            "ready": self.ready(),
            "reach": self.reach,
            "code": self.code,
            "problem": self.problem,
            "said": self.said(),
        })
    }
}

/// Checks `link` without pairing: it opens the way [`pair`] would (through
/// the proxy or relay, with the link's pin) and asks the center whether the
/// code is still open. The code is neither used up nor counted as a try.
pub async fn check(paths: &NodePaths, link: &PairLink) -> Result<Check, String> {
    nerve_transport::init_crypto();
    let (cfg, _) = crate::cli::read_config(paths).await?;
    let proxy = crate::link::proxy_for(paths, &cfg, &link.center)
        .await
        .map_err(|e| format!("bad proxy: {e}"))?;
    let mut io =
        match nerve_transport::net::open(&link.center, link.pin.as_deref(), proxy.as_ref()).await {
            Ok(io) => io,
            Err(e) => {
                // A refused certificate says "TLS with <url>: …"; anything
                // before it is the way there.
                let reach = if e.starts_with("TLS with") {
                    "certificate"
                } else {
                    "unreachable"
                };
                let problem = if reach == "certificate" {
                    e
                } else {
                    format!("the center does not answer: {e}")
                };
                return Ok(Check {
                    reach,
                    code: None,
                    problem: Some(problem),
                });
            }
        };
    let path = format!("{}{}", link.center.base, PAIR_CHECK_PATH);
    let body = serde_json::json!({ "code": link.code });
    let answer = nerve_transport::http::post_json(
        &mut io,
        &link.center.authority(),
        &path,
        &body,
        RESPONSE_MAX,
    )
    .await;
    let code = match answer {
        Ok(r) if r.status == 200 => serde_json::from_slice::<Value>(&r.body)
            .ok()
            .and_then(|v| v["code"].as_str().map(str::to_string))
            .filter(|c| ["open", "used", "gone", "busy"].contains(&c.as_str()))
            .unwrap_or_else(|| "unknown".into()),
        // A center without the check (404), or one that failed it: the
        // pairing itself will say.
        _ => "unknown".into(),
    };
    let problem = match code.as_str() {
        "used" => Some(
            "the code is used: a machine paired with it. Make a new link in the center's web UI"
                .into(),
        ),
        "gone" => Some(
            "the code is expired, out of tries or unknown. Make a new link in the center's web UI"
                .into(),
        ),
        _ => None,
    };
    Ok(Check {
        reach: "ok",
        code: Some(code),
        problem,
    })
}

/// Pairs with the center in `link` and stores the result: the node key
/// (a 0600 file `keys/<name>.key`, or the system keyring with
/// `machine.secret_storage = "keyring"`) and a `[[center]]` entry with the
/// default policy. Returns the new entry.
pub async fn pair(
    paths: &NodePaths,
    link: &PairLink,
    name: Option<&str>,
) -> Result<CenterEntry, String> {
    nerve_transport::init_crypto();
    let (cfg, _) = crate::cli::read_config(paths).await?;
    let key = NodeKey::generate()?;
    let req = PairRequest {
        code: link.code.clone(),
        name: crate::descriptor::node_name(&cfg),
        platform: std::env::consts::OS.into(),
        arch: std::env::consts::ARCH.into(),
        public_key: key.public_hex(),
    };
    let body = serde_json::to_value(&req).map_err(|e| e.to_string())?;
    // The pair request goes the way the link will: a node that reaches its
    // centers only through a proxy or a relay (protocol §4.7, §4.8) pairs
    // through it too, and a proxy that fails is not bypassed.
    let proxy = crate::link::proxy_for(paths, &cfg, &link.center)
        .await
        .map_err(|e| format!("bad proxy: {e}"))?;
    let mut io =
        nerve_transport::net::open(&link.center, link.pin.as_deref(), proxy.as_ref()).await?;
    let path = format!("{}{}", link.center.base, PAIR_PATH);
    let resp = nerve_transport::http::post_json(
        &mut io,
        &link.center.authority(),
        &path,
        &body,
        RESPONSE_MAX,
    )
    .await?;
    let v: Value = serde_json::from_slice(&resp.body).unwrap_or(Value::Null);
    if resp.status != 200 {
        let why = v
            .get("error")
            .and_then(|e| e.get("message").or(Some(e)))
            .map(|m| {
                m.as_str()
                    .map(str::to_string)
                    .unwrap_or_else(|| m.to_string())
            })
            .unwrap_or_else(|| format!("HTTP {}", resp.status));
        return Err(format!("the center refused the pairing: {why}"));
    }
    let r: PairResponse =
        serde_json::from_value(v).map_err(|e| format!("bad pairing response: {e}"))?;
    if r.node_id != key.node_id() {
        return Err("the center answered with another node id".into());
    }

    let entry_name = name
        .map(str::to_string)
        .unwrap_or_else(|| local_name(&r.center_name));
    if !valid_center_name(&entry_name) {
        return Err(format!(
            "{entry_name:?} is not a valid center name (1-64 of A-Z a-z 0-9 - _, starting and ending with a letter or digit)"
        ));
    }
    let entry = CenterEntry {
        name: entry_name.clone(),
        url: link.center.to_string(),
        pin: link.pin.clone(),
        center_id: r.center_id.clone(),
        node_id: r.node_id.clone(),
        settings: SettingsGrant::Off,
        paused: false,
        revoked: false,
        unknown: false,
        public_key: None,
        key_rotations: 0,
        pin_rotations: 0,
        old_pin: None,
        // A new pairing starts in folder mode, with no folder yet, and with
        // the guard against an agent that drives the node itself
        // (nerve_policy::rules::GUARD).
        policy: CenterPolicy {
            mode: nerve_policy::Mode::Folder,
            deny: nerve_policy::rules::GUARD
                .iter()
                .map(|g| g.to_string())
                .collect(),
            ..CenterPolicy::default()
        },
    };

    // The key goes first, where `machine.secret_storage` says: an entry
    // without its key cannot dial, a key without an entry is just a stray
    // that the next pairing replaces.
    if cfg.center(&entry_name).is_some() {
        return Err(format!("a center named {entry_name} is paired already"));
    }
    let storage = cfg.machine.secret_storage;
    crate::secrets::store_center_key(paths, storage, &entry_name, &key)?;
    let added = entry.clone();
    let r = crate::cli::edit(paths, move |c| {
        if c.center(&added.name).is_some() {
            return Err(format!("a center named {} is paired already", added.name));
        }
        if let Some(old) = c.centers.iter().find(|e| e.center_id == added.center_id) {
            return Err(format!("this center is paired already as {}", old.name));
        }
        c.centers.push(added.clone());
        Ok(())
    })
    .await;
    if let Err(e) = r {
        let _ = crate::secrets::remove_center_key(paths, storage, &entry_name);
        return Err(e);
    }
    Ok(entry)
}

/// A local name from the center's display name: the allowed characters
/// kept, the rest turned into `-`.
fn local_name(center_name: &str) -> String {
    let s: String = center_name
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '-'
            }
        })
        .take(64)
        .collect();
    let s = s.trim_matches(['-', '_']).to_string();
    if s.is_empty() { "center".into() } else { s }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_names() {
        assert_eq!(local_name("Home Lab"), "Home-Lab");
        assert_eq!(local_name("  "), "center");
        assert_eq!(local_name("_-x_"), "x");
        assert_eq!(local_name("conformance-center"), "conformance-center");
    }
}
