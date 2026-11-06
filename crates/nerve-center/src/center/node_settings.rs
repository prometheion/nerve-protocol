//! The node's settings as the center reads and changes them for its
//! owner: only with the node's `settings = write` grant.

use super::*;

impl Center {
    // ---- Settings (only with the node's `settings = write` grant) ----

    pub async fn node_settings(&self, node_id: &str) -> Result<Value, RpcError> {
        let link = self
            .link(node_id)
            .ok_or_else(|| RpcError::new(ErrorCode::Unavailable, "the node is offline"))?;
        link.call(
            msg::method::GET,
            json!({"cap": "settings", "keys": ["document", "version", "sudo"]}),
            Some(SHORT_CALL),
        )
        .await
    }

    pub async fn set_node_settings(
        &self,
        node_id: &str,
        document: Value,
        if_version: Value,
    ) -> Result<Value, RpcError> {
        let r = self.send_settings(node_id, document, if_version).await;
        self.log_change(node_id, "settings saved", "save the settings", &r);
        r
    }

    async fn send_settings(
        &self,
        node_id: &str,
        document: Value,
        if_version: Value,
    ) -> Result<Value, RpcError> {
        let link = self
            .link(node_id)
            .ok_or_else(|| RpcError::new(ErrorCode::Unavailable, "the node is offline"))?;
        link.call(
            msg::method::INVOKE,
            json!({"cap": "settings", "action": "set", "args": {"document": document, "if_version": if_version}, "ctx": {}}),
            Some(SHORT_CALL),
        )
        .await
    }

    /// Logs what a change to a node's settings from the web UI came to: `done`
    /// when the node took it, else that it refused to `wanted`.
    fn log_change(&self, node_id: &str, done: &str, wanted: &str, r: &Result<Value, RpcError>) {
        match r {
            Ok(v) => {
                let version = v
                    .get("version")
                    .map(|v| format!(" (version {v})"))
                    .unwrap_or_default();
                self.note(
                    Level::Info,
                    Some(node_id),
                    format!("{done} from the web UI{version}"),
                );
            }
            Err(e) => self.note(
                Level::Warn,
                Some(node_id),
                format!(
                    "the node did not {wanted} from the web UI ({}): {}",
                    e.kind().as_str(),
                    util::clip_bytes(&e.message, 300)
                ),
            ),
        }
    }

    /// A one-shot offer to seal the node's sudo password for (docs/dev/spec/protocol.md
    /// §7.4.1). The center checks that the paired node signed it for this
    /// center, so a client seals only for that node.
    pub async fn node_sudo_offer(&self, node_id: &str) -> Result<Value, RpcError> {
        let link = self
            .link(node_id)
            .ok_or_else(|| RpcError::new(ErrorCode::Unavailable, "the node is offline"))?;
        let public = self
            .public_key(node_id)
            .ok_or_else(|| RpcError::new(ErrorCode::Unavailable, "the node is not paired"))?;
        let v = link
            .call(
                msg::method::INVOKE,
                json!({"cap": "settings", "action": "sudo-offer", "args": {}, "ctx": {}}),
                Some(SHORT_CALL),
            )
            .await?;
        let offer: nerve_transport::sudo::Offer = serde_json::from_value(json!({
            "offer": v["offer"], "key": v["key"], "ts": v["ts"],
        }))
        .map_err(|e| RpcError::internal(format!("the node's sudo offer: {e}")))?;
        let sig = v["sig"].as_str().unwrap_or_default();
        if !nerve_transport::keys::verify_sudo_offer(&public, &self.id(), &offer, sig) {
            return Err(RpcError::internal(
                "the node's sudo offer is not signed with its paired key",
            ));
        }
        Ok(json!({"offer": offer.offer, "key": offer.key, "ts": offer.ts}))
    }

    /// Switches the node's sudo on (with a password sealed for one of its
    /// offers) or off. The center only relays the sealed box; it cannot
    /// open it and keeps no copy.
    pub async fn set_node_sudo(
        &self,
        node_id: &str,
        on: bool,
        sealed: Option<Value>,
    ) -> Result<Value, RpcError> {
        let link = self
            .link(node_id)
            .ok_or_else(|| RpcError::new(ErrorCode::Unavailable, "the node is offline"))?;
        let mut args = json!({"on": on});
        if let Some(sealed) = sealed {
            args["sealed"] = sealed;
        }
        let r = link
            .call(
                msg::method::INVOKE,
                json!({"cap": "settings", "action": "sudo", "args": args, "ctx": {}}),
                Some(SHORT_CALL),
            )
            .await;
        // The password is sealed for the node; the center never sees it.
        let (done, wanted) = if on {
            ("sudo switched on", "switch sudo on")
        } else {
            ("sudo switched off", "switch sudo off")
        };
        self.log_change(node_id, done, wanted, &r);
        r
    }

    /// Adds `rule` to one list of this center's policy on the node, from the
    /// audit tab (design §11 9a): `allow`, `deny`, or `sudo` for the sudo
    /// allow list. A button only adds; it never takes a rule off the other
    /// list. The node checks and may refuse the document.
    pub async fn add_rule(&self, node_id: &str, list: &str, rule: &str) -> Result<Value, RpcError> {
        let key = policy_list(list)?;
        let cur = self.node_settings(node_id).await?;
        let mut doc = cur.get("document").cloned().unwrap_or_else(|| json!({}));
        let version = cur.get("version").cloned().unwrap_or(Value::Null);
        put_rule(&mut doc, key, rule)?;
        let r = self.send_settings(node_id, doc, version).await;
        let done = format!("rule added to the {list} list ({rule})");
        self.log_change(
            node_id,
            &done,
            &format!("add a rule to the {list} list"),
            &r,
        );
        r
    }

    // ---- Capabilities (the web UI's tab; changes need the settings grant) ----

    /// What the Capabilities tab shows of the node `node_id`: its units as
    /// the center has them (its own `job` and `stream` aside), each with its
    /// effect and where it comes from, the ones the center left out with the
    /// reason, and, where the node gave this center the settings grant
    /// `write` and is online, the capabilities this center added there as
    /// the node keeps them, each also as the form shows it. A node without
    /// the grant is shown read only: the center may change nothing there.
    pub async fn node_caps(&self, node_id: &str) -> Result<Value, String> {
        let found = self.read(|s| {
            s.nodes.get(node_id).map(|n| {
                let units = cap_units(&n.catalog.units);
                let write = n.descriptor.as_ref().is_some_and(settings_write);
                let node = json!({"id": n.id, "name": n.name, "platform": n.platform});
                (node, units, n.catalog.broken.clone(), write)
            })
        });
        let (node, units, broken, write) = found.ok_or("no such machine")?;
        let link = self.link(node_id);
        let added = match (&link, write) {
            (Some(l), true) => {
                let got = l
                    .call(
                        msg::method::GET,
                        json!({"cap": "settings", "keys": ["capabilities"]}),
                        Some(SHORT_CALL),
                    )
                    .await;
                match got {
                    Ok(v) => added_of(&v),
                    Err(e) => json!({"error": e.message}),
                }
            }
            _ => Value::Null,
        };
        Ok(
            json!({"node": node, "online": link.is_some(), "settings_write": write,
                  "units": units, "broken": broken, "added": added}),
        )
    }

    /// Adds (`adding`) or replaces a capability of this center's own on the
    /// node, from the form of the Capabilities tab: checked here first by
    /// the node's own rules (nerve_policy::config::form), then sent as
    /// `settings.cap-add` or `cap-edit`; the node checks it again, against
    /// its own limits, and may refuse it.
    pub async fn save_cap(
        &self,
        node_id: &str,
        c: &nerve_policy::config::ConfigCapability,
        adding: bool,
    ) -> Result<Value, RpcError> {
        let action = if adding { "cap-add" } else { "cap-edit" };
        let r = self
            .settings_action(node_id, action, json!({"capability": c.entry()}))
            .await;
        let (done, wanted) = if adding {
            (format!("capability {} added", c.name), "add a capability")
        } else {
            (
                format!("capability {} changed", c.name),
                "change a capability",
            )
        };
        self.log_change(node_id, &done, wanted, &r);
        r
    }

    /// Removes the capability `name` this center added on the node.
    pub async fn remove_cap(&self, node_id: &str, name: &str) -> Result<Value, RpcError> {
        let r = self
            .settings_action(node_id, "cap-rm", json!({"name": name}))
            .await;
        let done = format!("capability {name} removed");
        self.log_change(node_id, &done, "remove a capability", &r);
        r
    }

    /// Runs the settings action `action` on the node and, once the node took
    /// it, fetches the node's description before it answers: the node says
    /// that it changed by an event, which the center follows in a task of its
    /// own, and a page that asks for the tab right after the answer would
    /// get the units from before the change.
    async fn settings_action(
        &self,
        node_id: &str,
        action: &str,
        args: Value,
    ) -> Result<Value, RpcError> {
        let link = self
            .link(node_id)
            .ok_or_else(|| RpcError::new(ErrorCode::Unavailable, "the node is offline"))?;
        let r = link
            .call(
                msg::method::INVOKE,
                json!({"cap": "settings", "action": action, "args": args, "ctx": {}}),
                Some(SHORT_CALL),
            )
            .await?;
        self.refresh(&link).await;
        Ok(r)
    }
}

/// The rows of the Capabilities tab for a node's `units`: all but the
/// center's own, told as the catalog tells them (catalog::is_center), not
/// by the provider a node names.
fn cap_units(units: &[catalog::Unit]) -> Vec<Value> {
    units
        .iter()
        .filter(|u| !catalog::is_center(u))
        .map(|u| {
            json!({"name": u.name, "effect": u.effect, "kind": u.kind.as_str(),
                   "summary": &*u.description, "source": unit_source(&u.provider),
                   "off": u.off})
        })
        .collect()
}

/// What the Capabilities tab shows of a node's answer to `get
/// settings.capabilities`: its `{entries, refused}`, each entry also as the
/// form shows it. The answer is the node's word, so one of another shape
/// is said as such, and an entry the form cannot show ([`shown`]) is left
/// out.
fn added_of(answer: &Value) -> Value {
    let Some(added) = answer.get("capabilities").and_then(Value::as_object) else {
        return json!({"error": "the machine's answer has no list of capabilities"});
    };
    let mut added = added.clone();
    if let Some(entries) = added.get_mut("entries").and_then(Value::as_array_mut) {
        entries.retain(shown);
        for e in entries.iter_mut() {
            let form = json!(nerve_policy::config::form::of_entry(e));
            if let Some(o) = e.as_object_mut() {
                o.insert("form".into(), form);
            }
        }
    }
    Value::Object(added)
}

/// Where a unit comes from, as the Capabilities tab says it: the node's
/// own, the owner's node.toml, this center (it added it), or a program the
/// owner allows.
fn unit_source(provider: &str) -> String {
    match provider {
        "node" => "built-in".into(),
        "config" => "the owner's node.toml".into(),
        nerve_policy::config::CENTER_ADDED => "this center".into(),
        p => format!("program {p}"),
    }
}

/// The node gave this center `settings = write`: its descriptor carries the
/// `settings` capability (spec §7.4).
pub fn settings_write(d: &Descriptor) -> bool {
    d.capability("settings")
        .is_some_and(|c| c.exposure != Exposure::Off)
}

/// The key of the policy list a button writes to. The settings document is
/// the node's center entry (nerve-policy): `policy.allow`, `policy.deny` and
/// `policy.sudo_allow`. A node with another layout refuses the document and
/// the web UI shows why.
fn policy_list(list: &str) -> Result<&'static str, RpcError> {
    match list {
        "allow" => Ok("allow"),
        "deny" => Ok("deny"),
        "sudo" => Ok("sudo_allow"),
        _ => Err(RpcError::invalid_args("the list is allow, deny or sudo")),
    }
}

/// Puts `rule` on `policy.<key>` of a settings document, unless it is there.
fn put_rule(doc: &mut Value, key: &str, rule: &str) -> Result<(), RpcError> {
    let no_room = || RpcError::invalid_args("the node's settings document has no room for rules");
    let list = doc
        .as_object_mut()
        .ok_or_else(no_room)?
        .entry("policy")
        .or_insert_with(|| json!({}))
        .as_object_mut()
        .ok_or_else(no_room)?
        .entry(key)
        .or_insert_with(|| json!([]))
        .as_array_mut()
        .ok_or_else(|| RpcError::invalid_args("the node's rules are not lists"))?;
    if !list.iter().any(|v| v == rule) {
        list.push(json!(rule));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The Capabilities tab leaves out the center's own units by their
    /// capability, so a node's provider named `center` stays, and shows a
    /// node's answer of another shape as such instead of failing on it, and
    /// an entry whose schema it would not keep not at all.
    #[test]
    fn the_capabilities_tab_takes_the_nodes_word_as_data() {
        use crate::tools::tests::{cap, desc};
        let mut lamp = cap(
            "lamp",
            "",
            &[(
                "on",
                nerve_proto::descriptor::Effect::Execute,
                json!({"type": "object"}),
            )],
        );
        lamp.provider = catalog::CENTER.into();
        let c = catalog::Catalog::build(&desc("box", vec![lamp]));
        assert!(
            c.units.iter().any(catalog::is_center),
            "the center's own are in"
        );
        let rows = cap_units(&c.units);
        let names: Vec<&str> = rows.iter().filter_map(|r| r["name"].as_str()).collect();
        assert_eq!(names, ["lamp.on"]);
        assert_eq!(rows[0]["source"], "program center");
        for odd in [
            json!(1),
            json!({"capabilities": 1}),
            json!({"capabilities": "x"}),
            json!({"capabilities": [1]}),
        ] {
            assert!(added_of(&odd)["error"].is_string(), "{odd}");
        }
        let entry = json!({"name": "say.back", "effect": "read", "command": ["echo"]});
        let v = added_of(&json!({"capabilities": {"entries": [1, "x", entry], "refused": null}}));
        let entries = v["entries"].as_array().unwrap();
        assert_eq!(entries.len(), 1, "{v}");
        assert_eq!(entries[0]["form"]["name"], "say.back");
        assert_eq!(entries[0]["form"]["command"], "echo");
        assert!(added_of(&json!({"capabilities": {"entries": 3}}))["entries"] == 3);
        // A schema nested deeper than a node keeps, or of another shape, is
        // left out before the form prints it; one in the subset is shown.
        let mut deep = json!(0);
        for _ in 0..100 {
            deep = json!([deep, 0]);
        }
        let schema = json!({"type": "object", "properties": {"word": {"type": "string"}}});
        let with = |key: &str, v: &Value| {
            let mut e = json!({"name": "say.back", "effect": "read", "command": ["echo"]});
            e[key] = v.clone();
            e
        };
        let v = added_of(&json!({"capabilities": {"entries": [
            with("params", &deep), with("result", &deep), with("params", &json!("text")),
            with("params", &schema), with("result", &json!("text")), with("result", &schema),
        ]}}));
        let entries = v["entries"].as_array().unwrap();
        assert_eq!(entries.len(), 3, "{v}");
        assert!(
            entries[0]["form"]["params"]
                .as_str()
                .unwrap()
                .contains("word")
        );
    }

    #[test]
    fn a_button_only_adds_a_rule_to_its_list() {
        let mut d = json!({"policy": {"deny": ["exec.run:git push*"], "allow": ["exec.run:ls"]}});
        put_rule(&mut d, "allow", "exec.run:git *").unwrap();
        put_rule(&mut d, "allow", "exec.run:git *").unwrap();
        put_rule(&mut d, "deny", "exec.run:git *").unwrap();
        put_rule(&mut d, "sudo_allow", "sudo apt update").unwrap();
        // Nothing leaves the other list; a repeat adds nothing.
        assert_eq!(
            d["policy"],
            json!({
                "allow": ["exec.run:ls", "exec.run:git *"],
                "deny": ["exec.run:git push*", "exec.run:git *"],
                "sudo_allow": ["sudo apt update"],
            })
        );
        // A document without a policy gets one.
        let mut d = json!({});
        put_rule(&mut d, "deny", "camera").unwrap();
        assert_eq!(d["policy"]["deny"], json!(["camera"]));
        assert!(put_rule(&mut json!([]), "deny", "x").is_err());
        assert!(put_rule(&mut json!({"policy": {"deny": 1}}), "deny", "x").is_err());
        assert_eq!(policy_list("sudo").unwrap(), "sudo_allow");
        assert!(policy_list("permit").is_err());
    }

    #[test]
    fn audit_buttons_write_rules_for_every_action() {
        let rule =
            |list, cap, action, target, wild| audit_rule(list, cap, action, target, wild, None);
        assert_eq!(
            rule("allow", "exec", "run", "git status", false).unwrap(),
            "exec.run:git status"
        );
        assert_eq!(
            rule("allow", "exec", "run", "git status", true).unwrap(),
            "exec.run:git *"
        );
        assert_eq!(
            rule("deny", "exec", "run", "rm -rf /tmp/x", true).unwrap(),
            "exec.run:rm *"
        );
        assert_eq!(
            rule("allow", "fs", "read", "/home/u/a.txt", false).unwrap(),
            "fs.read:/home/u/a.txt"
        );
        assert_eq!(
            rule("deny", "fs", "write", "/home/u/a.txt", true).unwrap(),
            "fs.write:/home/u/*"
        );
        assert_eq!(
            rule("allow", "camera", "snap", "camera.snap", false).unwrap(),
            "camera.snap"
        );
        assert_eq!(
            rule("deny", "camera", "snap", "camera.snap", true).unwrap(),
            "camera"
        );
        assert_eq!(
            rule("sudo", "exec", "run", "sudo apt update", false).unwrap(),
            "sudo apt update"
        );
        assert_eq!(
            rule("sudo", "exec", "run", "sudo apt update", true).unwrap(),
            "sudo apt *"
        );
        for (list, cap, action, target) in [
            ("permit", "exec", "run", "ls"),
            ("allow", "exec", "run", "  "),
            ("allow", "fs", "read", ""),
            ("allow", "fs", "read", "relative/path"),
            ("sudo", "exec", "run", "ls"),
            ("sudo", "fs", "read", "/a"),
            ("allow", "", "run", "ls"),
        ] {
            assert!(
                rule(list, cap, action, target, false).is_err(),
                "{list} {cap}.{action} {target:?}"
            );
        }
        // A target the audit cut is not the command any more.
        let cut = nerve_policy::audit::cut_target(&"x".repeat(600)).into_owned();
        for list in ["allow", "deny", "sudo"] {
            assert!(rule(list, "exec", "run", &cut, false).is_err(), "{list}");
            assert!(rule(list, "exec", "run", &cut, true).is_err(), "{list}");
        }
        // A provider's call is long-pathed: the rule is its action, which the
        // cut target does not change.
        let cut = nerve_policy::audit::cut_target(&"/srv/a/".repeat(100)).into_owned();
        assert!(nerve_policy::audit::is_cut_target(&cut));
        assert_eq!(
            rule("allow", "photos", "export", &cut, false).unwrap(),
            "photos.export"
        );
        assert_eq!(
            rule("deny", "photos", "export", &cut, true).unwrap(),
            "photos"
        );
        assert!(rule("allow", "fs", "write", &cut, false).is_err());
        assert!(rule("allow", "exec", "signal", &cut, false).is_ok());
    }
}
