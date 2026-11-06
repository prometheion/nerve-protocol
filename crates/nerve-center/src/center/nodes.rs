//! The paired nodes: their names, removal and alerts, and their links
//! coming, parking and going.

use super::*;

impl Center {
    // ---- Nodes ----

    pub fn rename(&self, node_id: &str, name: &str) -> Result<(), String> {
        if !nerve_proto::valid_node_name(name) {
            return Err("a node name is 1 to 32 characters of a-z, 0-9 and -, starting and ending with a letter or digit".into());
        }
        let old = self.update(|s| {
            if s.nodes.values().any(|n| n.name == name && n.id != node_id) {
                return Err("another node already has this name".to_string());
            }
            // As at pairing: a node's id as a name would point at that node.
            if s.nodes.contains_key(name) {
                return Err("this name is a node's id".to_string());
            }
            let n = s.nodes.get_mut(node_id).ok_or("no such node")?;
            Ok(std::mem::replace(&mut n.name, name.to_string()))
        })?;
        self.note(
            Level::Info,
            Some(node_id),
            format!("the node was renamed from {old}"),
        );
        self.changed(Change::Nodes);
        Ok(())
    }

    /// Switches a node off or on for the agent. The link stays as it is;
    /// `list` and the call path look at the flag, and the calls that run on
    /// the node (jobs too, and a program's streams and subscriptions) are
    /// stopped: the owner who disables a machine wants the agent's work
    /// there to end, not to run on unseen.
    pub fn set_disabled(&self, node_id: &str, disabled: bool) -> Result<(), String> {
        self.update(|s| {
            s.nodes.get_mut(node_id).ok_or("no such node")?.disabled = disabled;
            Ok::<(), String>(())
        })?;
        if disabled {
            let sessions: Vec<Arc<Session>> =
                self.sessions.lock().unwrap().values().cloned().collect();
            for sess in sessions {
                let stops = sess.jobs.lock().unwrap().stop_on(node_id);
                for stop in stops {
                    let _ = stop.send(Stop::Disabled);
                }
                // A program's open streams and the subscriptions to its
                // events are no jobs, but run there all the same: the node
                // gets `stream.close` and `unsub`, and the agent reads none
                // of what came meanwhile once the node is enabled again.
                let units = sess.streams.lock().unwrap().units_on(node_id);
                for c in units {
                    c.close("the node was disabled in the center");
                }
            }
        }
        self.note(
            Level::Info,
            Some(node_id),
            if disabled {
                "the node was disabled: the agent is offered none of its capabilities and calls to it are refused"
            } else {
                "the node was enabled"
            },
        );
        self.changed(Change::Nodes);
        Ok(())
    }

    /// Removes a node: `bye revoked` on its link, and its record goes.
    pub async fn remove(&self, node_id: &str) -> Result<(), String> {
        if !self.knows(node_id) {
            return Err("no such node".into());
        }
        let link = self.links.lock().unwrap().remove(node_id);
        if let Some(l) = link {
            l.bye(ByeReason::Revoked).await;
            // A parked link has no connection for the bye; its calls end.
            l.fail_all();
        }
        self.forget(node_id, "removed by the owner; its link got bye revoked")
            .map_err(|e| {
                format!(
                    "{e}; the node is removed now, but it is paired again when the center starts unless the state file can be written by then"
                )
            })
    }

    /// Drops a node's record (a remove, or the node's `bye unpaired`); `why`
    /// goes to the log. An error says the state file did not take it
    /// ([`Center::update_kept`]).
    pub fn forget(&self, node_id: &str, why: &str) -> Result<(), String> {
        let name = self.node_name(node_id);
        let (had, saved) = self.update_kept(|s| {
            s.stats.remove(node_id);
            s.nodes.remove(node_id).is_some()
        });
        if had {
            self.down.lock().unwrap().remove(node_id);
            self.log.record(
                Level::Info,
                Some((&name, node_id)),
                &format!("the node is no longer paired: {why}"),
            );
            self.changed(Change::Nodes);
        }
        saved
    }

    pub fn alert(&self, node_id: &str, text: &str) {
        self.note(Level::Warn, Some(node_id), text);
        let mut a = self.alerts.lock().unwrap();
        a.push_back(json!({"ts": now_ms(), "node": node_id, "text": text}));
        while a.len() > ALERTS_KEEP {
            a.pop_front();
        }
        drop(a);
        self.changed(Change::Nodes);
    }

    pub fn alerts(&self) -> Vec<Value> {
        self.alerts.lock().unwrap().iter().cloned().collect()
    }

    /// A link is up; `resumed` when it carries on a link that dropped.
    pub(crate) fn link_up(&self, link: Arc<Link>, hello: &Hello, resumed: bool) {
        let id = link.node_id.clone();
        self.links.lock().unwrap().insert(id.clone(), link.clone());
        let now = now_ms();
        self.update(|s| {
            if let Some(n) = s.nodes.get_mut(&id) {
                n.last_seen_ms = now;
                n.going_away = None;
            }
            if !resumed {
                s.day(&id, now).links += 1;
            }
        });
        let gap = self
            .down
            .lock()
            .unwrap()
            .remove(&id)
            .map(|t| util::span(t.elapsed()));
        let line = match (resumed, gap) {
            (true, gap) => format!(
                "link resumed{} with {} waiting on it (node software {})",
                gap.map(|g| format!(" after {g}")).unwrap_or_default(),
                plural(link.waiting() as u32, "call"),
                hello.software.version
            ),
            (false, Some(g)) => format!(
                "link up again after {g} (node software {})",
                hello.software.version
            ),
            (false, None) => format!("link up (node software {})", hello.software.version),
        };
        self.note(Level::Info, Some(&id), line);
        self.changed(Change::Nodes);
        let c = self.clone();
        tokio::spawn(async move {
            c.refresh(&link).await;
            if c.read(|s| {
                s.nodes
                    .get(&link.node_id)
                    .and_then(|n| n.descriptor.as_ref())
                    .is_some_and(|d| d.capability("audit").is_some())
            }) {
                let _ = link
                    .call(
                        msg::method::SUB,
                        json!({"topics": ["audit/decision"]}),
                        Some(SHORT_CALL),
                    )
                    .await;
            }
        });
    }

    /// The node's old link is given up because the node connected again and
    /// the old one did not answer a ping: told as the drop it is, with how long
    /// it had been silent, which the wait before the new link counts from. The
    /// old link stops being the node's here, so its own end, whenever it
    /// comes, is detail. A link that ended while the ping was waited for has
    /// told its drop already, and says nothing more.
    pub(crate) fn link_replaced(&self, old: &Arc<Link>) {
        {
            let mut links = self.links.lock().unwrap();
            let current = links.get(&old.node_id).is_some_and(|l| Arc::ptr_eq(l, old));
            if !current {
                return;
            }
            links.remove(&old.node_id);
        }
        // A link that dropped while the center pinged it was told as a
        // drop then, and is not a second one.
        if old.is_parked() {
            return;
        }
        let silent = old.silent_for();
        let gone = Instant::now()
            .checked_sub(silent)
            .unwrap_or_else(Instant::now);
        self.down.lock().unwrap().insert(old.node_id.clone(), gone);
        self.note(
            Level::Warn,
            Some(&old.node_id),
            format!(
                "link dropped: the node connected again and this link did not answer a ping, so it was replaced (it was up for {}, silent for {})",
                util::span(old.since.elapsed()),
                util::span(silent)
            ),
        );
    }

    /// The connection of a link the node can resume dropped (spec §4.9): the
    /// node is offline, and the calls on the link wait for the grace. After
    /// it, a link still parked from connection `conn` ends like any other.
    /// `up` is how long that connection was up.
    pub(crate) fn link_parked(
        &self,
        link: &Arc<Link>,
        clean: bool,
        why: &str,
        silent: Duration,
        conn: u64,
        up: Duration,
    ) {
        let id = link.node_id.clone();
        {
            // A link replaced by the connection that then failed to resume
            // it is the node's again, so that the next one finds it.
            let mut links = self.links.lock().unwrap();
            let other = links
                .get(&id)
                .is_some_and(|l| !l.is_closed() && !Arc::ptr_eq(l, link));
            if !other {
                links.insert(id.clone(), link.clone());
            }
        }
        let now = now_ms();
        let online = up.as_millis() as u64;
        self.update_soon(|s| {
            if let Some(n) = s.nodes.get_mut(&id) {
                n.last_seen_ms = now;
            }
            if s.nodes.contains_key(&id) {
                let d = s.day(&id, now);
                d.online_ms += online;
                if !clean {
                    d.drops += 1;
                }
            }
        });
        let gone = Instant::now()
            .checked_sub(silent)
            .unwrap_or_else(Instant::now);
        self.down.lock().unwrap().entry(id.clone()).or_insert(gone);
        let grace = self.grace();
        self.note(
            Level::Warn,
            Some(&id),
            format!(
                "link dropped: {why} (it was up for {}); keeping it for {} for the node to resume, with {} waiting",
                util::span(up),
                util::span(grace),
                plural(link.waiting() as u32, "call")
            ),
        );
        self.changed(Change::Nodes);
        let (c, link) = (self.clone(), link.clone());
        tokio::spawn(async move {
            tokio::time::sleep(grace).await;
            let n = link.waiting();
            if !link.expire(conn) {
                return;
            }
            {
                let mut links = c.links.lock().unwrap();
                if links.get(&id).is_some_and(|l| Arc::ptr_eq(l, &link)) {
                    links.remove(&id);
                }
            }
            c.note(
                Level::Warn,
                Some(&id),
                format!(
                    "the node did not resume its link within {}; {} on it failed with connection_lost",
                    util::span(grace),
                    plural(n as u32, "call")
                ),
            );
            c.changed(Change::Nodes);
        });
    }

    /// A link's connection `conn` ended, after it was up for `up`. `clean`
    /// is whether the node said bye; `why` is what ended it, for the log.
    /// `silent` is how long nothing had come from the node, which the wait
    /// before its next link counts from.
    pub(crate) fn link_down(
        &self,
        link: &Arc<Link>,
        clean: bool,
        why: &str,
        silent: Duration,
        conn: u64,
        up: Duration,
    ) {
        let id = &link.node_id;
        let now = now_ms();
        let online = up.as_millis() as u64;
        // A newer connection resumed the link: the node is up on it. This
        // one's time and its drop still count.
        if !link.current(conn) {
            self.update_soon(|s| {
                if s.nodes.contains_key(id) {
                    let d = s.day(id, now);
                    d.online_ms += online;
                    d.drops += 1;
                }
            });
            self.note(
                Level::Debug,
                Some(id),
                format!("an earlier connection of a resumed link ended: {why}"),
            );
            return;
        }
        // A link the node's newer one replaced is no longer the node's: its end
        // says nothing about the node, which is up.
        let current = {
            let mut links = self.links.lock().unwrap();
            let current = links.get(id).is_some_and(|l| Arc::ptr_eq(l, link));
            if current {
                links.remove(id);
            }
            current
        };
        self.update_soon(|s| {
            if current && let Some(n) = s.nodes.get_mut(id) {
                n.last_seen_ms = now;
            }
            if s.nodes.contains_key(id) {
                let d = s.day(id, now);
                d.online_ms += online;
                if !clean {
                    d.drops += 1;
                }
            }
        });
        if !current {
            self.note(
                Level::Debug,
                Some(id),
                format!(
                    "a link that was replaced ended: {why} (it was up for {})",
                    util::span(up)
                ),
            );
            self.changed(Change::Nodes);
            return;
        }
        let gone = Instant::now()
            .checked_sub(silent)
            .unwrap_or_else(Instant::now);
        self.down.lock().unwrap().insert(id.clone(), gone);
        let (level, verb) = if clean {
            (Level::Info, "closed")
        } else {
            (Level::Warn, "dropped")
        };
        self.note(
            level,
            Some(id),
            format!("link {verb}: {why} (it was up for {})", util::span(up)),
        );
        self.changed(Change::Nodes);
    }

    /// Fetches the full descriptor and keeps it.
    pub(super) async fn refresh(&self, link: &Arc<Link>) {
        match link
            .call(
                msg::method::DESCRIBE,
                json!({"detail": "full"}),
                Some(SHORT_CALL),
            )
            .await
        {
            Ok(v) => match serde_json::from_value::<Descriptor>(v) {
                // A unit with a bad name or a schema the center cannot check
                // is left out on its own (`Catalog`); the rest stays usable.
                Ok(d) => {
                    let broken = self.update(|s| {
                        let n = s.nodes.get_mut(&link.node_id)?;
                        n.set_descriptor(d);
                        let first = n.catalog.broken.first()?.clone();
                        Some((first, n.catalog.broken.len()))
                    });
                    // One line however many: a node may leave out thousands,
                    // and the overview lists them all.
                    if let Some((b, count)) = broken {
                        let more = if count > 1 {
                            format!(" (and {} more, listed in the overview)", count - 1)
                        } else {
                            String::new()
                        };
                        self.note(
                            Level::Warn,
                            Some(&link.node_id),
                            format!(
                                "the center leaves out {} of the node's description: {}{more}",
                                b.name, b.reason
                            ),
                        );
                    }
                    self.changed(Change::Nodes);
                }
                Err(e) => self.note(
                    Level::Warn,
                    Some(&link.node_id),
                    format!("the node sent a description the center cannot read: {e}"),
                ),
            },
            // A link that ended meanwhile says so on its own.
            Err(e) => self.note(
                if e.kind() == ErrorCode::ConnectionLost {
                    Level::Debug
                } else {
                    Level::Warn
                },
                Some(&link.node_id),
                format!("asking the node for its description failed: {}", e.message),
            ),
        }
    }

    pub(crate) fn on_event(&self, link: &Arc<Link>, ev: Event) {
        let node = link.node_id.clone();
        match (ev.cap.as_str(), ev.name.as_str()) {
            ("node", "descriptor_changed" | "capability_changed") => {
                self.note(
                    Level::Debug,
                    Some(&node),
                    "the node's description changed; fetching it again",
                );
                let c = self.clone();
                let l = link.clone();
                tokio::spawn(async move { c.refresh(&l).await });
            }
            ("node", "going_away") => {
                let why = ev
                    .data
                    .get("reason")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string();
                self.update(|s| {
                    if let Some(n) = s.nodes.get_mut(&node) {
                        n.going_away = Some(util::clip_bytes(&why, 200));
                    }
                });
                self.note(
                    Level::Info,
                    Some(&node),
                    format!("the node is going away: {}", util::clip_bytes(&why, 200)),
                );
                self.changed(Change::Nodes);
            }
            ("settings", "changed") => {
                let version = ev.data.get("version").and_then(Value::as_u64);
                self.note(
                    Level::Info,
                    Some(&node),
                    match version {
                        Some(v) => format!("the node's settings changed (version {v})"),
                        None => "the node's settings changed".to_string(),
                    },
                );
                self.changed(Change::Nodes);
            }
            ("audit", "decision") => {
                let name = self.node_name(&node);
                let mut e = ev.data.clone();
                if let Some(o) = e.as_object_mut() {
                    // The action checker's marker is the center's own: from a
                    // node it would draw a refusal of the center's model, with
                    // Allow buttons that save a center rule the node chose.
                    o.remove("checker");
                    if o.get("by")
                        .and_then(Value::as_str)
                        .is_some_and(|b| b.trim().eq_ignore_ascii_case("action checker"))
                    {
                        o.remove("by");
                    }
                    o.insert("node_id".into(), json!(node));
                    o.insert("node".into(), json!(name));
                    o.entry("ts").or_insert(json!(ev.ts));
                }
                self.audit.lock().unwrap().push(e);
                self.changed(Change::Audit);
            }
            // A program's event, for the sessions subscribed to it.
            _ => {
                link.event(&ev);
            }
        }
    }

    pub fn node_name(&self, node_id: &str) -> String {
        self.read(|s| {
            s.nodes
                .get(node_id)
                .map(|n| n.name.clone())
                .unwrap_or_default()
        })
    }

    pub fn audit(&self) -> Vec<Value> {
        self.audit.lock().unwrap().list()
    }

    /// The nodes as the web UI shows them.
    pub fn nodes_json(&self) -> Value {
        let links: BTreeMap<String, Arc<Link>> = self.links.lock().unwrap().clone();
        // Which sessions use each node, read before the state is locked (see
        // `Inner::store`): `sessions_json` holds a session's node set while
        // it names the nodes.
        let sessions: Vec<Arc<Session>> = self.sessions.lock().unwrap().values().cloned().collect();
        let mut used: HashMap<String, Vec<String>> = HashMap::new();
        for x in &sessions {
            for n in x.nodes.lock().unwrap().iter() {
                used.entry(n.clone()).or_default().push(x.id.clone());
            }
        }
        let nodes: Vec<Value> = self.read(|s| {
            s.nodes
                .values()
                .map(|n| {
                    let link = links.get(&n.id).filter(|l| l.is_live());
                    let d = n.descriptor.as_ref();
                    // Whether the agent is offered anything of a capability:
                    // one whose every action was left out, or that the node's
                    // owner turned off, is listed for the owner, but `list`
                    // does not count it.
                    let offered: BTreeSet<&str> =
                        n.catalog.units.iter().map(|u| u.cap.as_str()).collect();
                    let caps: Vec<Value> = d
                        .map(|d| {
                            d.capabilities
                                .iter()
                                .map(|c| json!({"id": c.id, "profile": c.profile, "exposure": c.exposure, "summary": c.summary,
                                                "offered": c.exposure != Exposure::Off && offered.contains(c.id.as_str())}))
                                .collect()
                        })
                        .unwrap_or_default();
                    let used_by = used.get(&n.id).cloned().unwrap_or_default();
                    json!({
                        "id": n.id,
                        "name": n.name,
                        "platform": n.platform,
                        "arch": n.arch,
                        "online": link.is_some(),
                        "status": link.map(|l| l.status.lock().unwrap().clone()),
                        "since_ms": link.map(|l| l.since_ms),
                        "last_seen_ms": n.last_seen_ms,
                        "paired_ms": n.paired_ms,
                        "going_away": n.going_away,
                        "disabled": n.disabled,
                        "key_grace_until_ms": n.old_key.as_ref().map(|o| o.until_ms),
                        "summary": d.map(|d| d.summary.clone()).unwrap_or_default(),
                        "software": d.map(|d| d.node.software.version.clone()),
                        "capabilities": caps,
                        // The folders the machine gave this center, its own
                        // aside; none known for a machine that tells none.
                        "folders": d.and_then(|d| d.access.as_ref())
                            .map(|a| a.folders.iter().filter(|f| !f.own).count()),
                        // Units the center leaves out, with the reason, for
                        // the owner: the agent is not offered them.
                        "broken": n.catalog.broken,
                        "sessions": used_by,
                        "settings_write": d.is_some_and(settings_write),
                    })
                })
                .collect()
        });
        json!(nodes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::center::tests::{lines, node_record, open, pair_body};

    /// A node removed while the state file cannot be written is gone at
    /// once, but the answer says it is not kept yet; the next flush keeps it.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_removal_that_cannot_be_written_is_said() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let c = open(dir.path(), None);
        c.update(|s| {
            s.nodes.insert("n1".into(), node_record("n1", "linux"));
        });
        let mode = |m| std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(m));
        mode(0o500).unwrap();
        let e = c.remove("n1").await.unwrap_err();
        mode(0o700).unwrap();
        assert!(e.starts_with(UNWRITABLE), "{e}");
        assert!(!c.knows("n1"));
        assert!(
            Store::load(dir.path())
                .unwrap()
                .unwrap()
                .nodes
                .contains_key("n1")
        );
        c.flush();
        assert!(Store::load(dir.path()).unwrap().unwrap().nodes.is_empty());
    }

    /// The owner's note on a machine is kept on one line, refused when long,
    /// shown by `list()` for that machine only, and outlives the machine's
    /// pairing like its other settings; a note of blanks is no setting.
    #[test]
    fn the_owners_note_shows_for_its_node_only_and_survives_forget() {
        let dir = tempfile::tempdir().unwrap();
        let c = open(dir.path(), None);
        c.update(|s| {
            s.nodes.insert("n1".into(), node_record("n1", "linux"));
            s.nodes.insert("n2".into(), node_record("n2", "linux"));
        });
        let with = |id: &str, note: &str| {
            let mut cfg = c.read(|s| s.checker.clone());
            cfg.nodes.insert(
                id.into(),
                NodeSettings {
                    note: note.into(),
                    ..Default::default()
                },
            );
            cfg
        };
        c.apply_checker_config(with("n1", "  test VM;\nits databases hold throwaway data "))
            .unwrap();
        let notes = || -> Vec<(String, Option<String>)> {
            c.listed_nodes()
                .into_iter()
                .map(|n| (n.id, n.note))
                .collect()
        };
        let n1 = Some("test VM; its databases hold throwaway data".to_string());
        assert_eq!(
            notes(),
            [("n1".to_string(), n1.clone()), ("n2".to_string(), None)]
        );
        // Too long is refused as a whole, and names the machine.
        let e = c
            .apply_checker_config(with("n2", &"x".repeat(checker::config::NOTE_MAX + 1)))
            .unwrap_err();
        assert!(e.contains("machine n2") && e.contains("at most 400"), "{e}");
        assert_eq!(notes()[1].1, None);
        let mut both = with("n2", &"x".repeat(checker::config::NOTE_MAX));
        both.nodes.insert(
            "n3".into(),
            NodeSettings {
                note: " \n ".into(),
                ..Default::default()
            },
        );
        c.apply_checker_config(both).unwrap();
        let kept = c.read(|s| s.checker.nodes.clone());
        assert_eq!(kept.keys().collect::<Vec<_>>(), ["n1", "n2"]);
        // Unpaired and paired again, the machine has its note back.
        c.forget("n1", "test").unwrap();
        assert_eq!(notes().len(), 1);
        assert_eq!(
            c.read(|s| s.checker.nodes["n1"].note.clone()),
            n1.clone().unwrap()
        );
        c.update(|s| {
            s.nodes.insert("n1".into(), node_record("n1", "linux"));
        });
        assert_eq!(notes()[0], ("n1".to_string(), n1));
    }

    /// `list` and `execute` find a node by its id or its name, so neither
    /// pairing nor a rename lets a name be a node's id, which would make it
    /// point at that node.
    #[test]
    fn a_name_is_never_a_nodes_id() {
        let dir = tempfile::tempdir().unwrap();
        let c = open(dir.path(), None);
        let pair = |name: &str, key: u8| {
            let code = c.new_pairing()["code"].as_str().unwrap().to_string();
            c.pair(&pair_body(&code, name, key))
        };
        let id = |key: u8| nerve_transport::keys::node_id(&[key; 32]);
        assert!(nerve_proto::valid_node_name(&id(7)));
        assert_eq!(pair("box-1", 7).0, 200);
        // Another node's id, or its own.
        let told = pair(&id(7), 8);
        assert_eq!(
            told,
            (409, json!({"error": "this name is a node's id"})),
            "{told:?}"
        );
        assert_eq!(pair(&id(8), 8).0, 409);
        // A node whose id is another node's name.
        assert_eq!(pair(&id(9), 8).0, 200);
        let told = pair("box-9", 9);
        assert_eq!(
            told,
            (
                409,
                json!({"error": "another node is named like this node's id"})
            )
        );
        // A rename to a node's id, its own too; another name is fine.
        assert_eq!(
            c.rename(&id(8), &id(7)).unwrap_err(),
            "this name is a node's id"
        );
        assert!(c.rename(&id(8), &id(8)).is_err());
        c.rename(&id(8), "box-2").unwrap();
        assert_eq!(pair("box-9", 9).0, 200);
    }

    #[tokio::test]
    async fn changes_to_a_node_are_logged_under_its_name_and_id() {
        let dir = tempfile::tempdir().unwrap();
        let c = open(dir.path(), None);
        let code = c.new_pairing()["code"].as_str().unwrap().to_string();
        assert_eq!(c.pair(&pair_body(&code, "box-1", 7)).0, 200);
        let id = nerve_transport::keys::node_id(&[7; 32]);
        c.rename(&id, "web-1").unwrap();
        c.set_disabled(&id, true).unwrap();
        c.set_disabled(&id, false).unwrap();
        c.remove(&id).await.unwrap();

        let about: Vec<(Level, Option<String>, String)> = lines(&c)
            .into_iter()
            .filter(|e| e.node_id.as_deref() == Some(id.as_str()))
            .map(|e| (e.level, e.node, e.msg))
            .collect();
        let name = |n: &str| Some(n.to_string());
        assert_eq!(
            about[1],
            (
                Level::Info,
                name("web-1"),
                "the node was renamed from box-1".into()
            )
        );
        assert_eq!(about[2].1, name("web-1"));
        assert!(about[2].2.starts_with("the node was disabled"), "{about:?}");
        assert_eq!(about[3].2, "the node was enabled");
        // Removed, it is named as it was.
        assert_eq!(about.len(), 5);
        assert_eq!(about[4].1, name("web-1"));
        assert!(about[4].2.contains("removed by the owner"), "{about:?}");
        // The log still names a node the center forgot, for the view's list.
        let v = c.log_json(&Query {
            limit: 10,
            ..Query::default()
        });
        assert_eq!(
            v["nodes"],
            json!([{"id": id, "name": "web-1", "paired": false}])
        );
    }
}
