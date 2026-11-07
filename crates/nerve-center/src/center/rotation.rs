//! The rotation of the center's TLS key and of the nodes' keys
//! (docs/dev/spec/protocol.md §4.10).

use super::*;

impl Center {
    // ---- Key rotation (spec §4.10) ----

    /// Rotates the center's TLS key: a new key is made and kept beside the
    /// old one, which signs it; every node linked now that speaks rotation
    /// is told, and the others when they link. The old key is served until
    /// the grace ends ([`Center::sweep`]) or the owner ends it
    /// ([`Center::finish_key_rotation`]): a node that missed the rotation
    /// can still link and be told. The answer carries the new pin, which
    /// the owner sees once.
    pub async fn rotate_key(&self) -> Result<Value, String> {
        let out = self.start_rotation()?;
        let told = self.tell_rotation().await;
        let mut out = out;
        out["told"] = json!(told);
        Ok(out)
    }

    fn start_rotation(&self) -> Result<Value, String> {
        let _one = self.rotating.lock().unwrap();
        if self.read(|s| {
            s.key_rotation
                .as_ref()
                .is_some_and(|r| r.finished_ms.is_none())
        }) {
            return Err(
                "a rotation of the center's key is in its grace already; end it first".into(),
            );
        }
        let old = self.identity();
        let next = ServerIdentity::generate(&[self.public_url.host.clone(), host_name()])?;
        let new_spki = next.spki();
        let new_pin = nerve_transport::tls::pin_of_spki(&new_spki);
        let new_raw = nerve_transport::tls::decode_pin(&new_pin)?;
        let sig = old.sign(&nerve_proto::rotate_center_message(&self.id(), &new_raw))?;
        let next_path = self.dir.join(NEXT_IDENTITY_FILE);
        nerve_transport::files::write_private(&next_path, next.to_pem().as_bytes()).map_err(
            |e| {
                format!(
                    "cannot write {}: {e}; nothing was changed",
                    next_path.display()
                )
            },
        )?;
        let now = now_ms();
        let until = now + nerve_proto::ROTATE_GRACE_MS;
        let record = KeyRotation {
            started_ms: now,
            until_ms: until,
            old_spki: nerve_transport::tls::b64url(&old.spki()),
            new_spki: nerve_transport::tls::b64url(&new_spki),
            sig: nerve_transport::tls::b64url(&sig),
            finished_ms: None,
        };
        // Saved before anything is told: a rotation the state file does not
        // hold is dropped at the next start, with its key.
        let saved = {
            let mut st = self.store.lock().unwrap();
            let before = st.key_rotation.replace(record);
            st.key_rotations += 1;
            let r = self.write_snapshot(self.snapshot(&st));
            if r.is_err() {
                st.key_rotation = before;
                st.key_rotations -= 1;
            }
            r
        };
        if let Err(e) = saved {
            let _ = std::fs::remove_file(&next_path);
            return Err(format!(
                "cannot write the state file: {e}; nothing was changed"
            ));
        }
        let old_pin = old.pin();
        self.log.record(
            Level::Info,
            None,
            &format!(
                "the owner rotated the center's key: the new pin is {new_pin} (it was {old_pin}). Nodes are told; the old key is served for {} more, or until the owner ends that",
                util::span(Duration::from_millis(nerve_proto::ROTATE_GRACE_MS))
            ),
        );
        self.changed(Change::Nodes);
        Ok(json!({"pin": new_pin, "old_pin": old_pin, "until_ms": until}))
    }

    /// Ends the grace of the center's key rotation: the new key is served
    /// from now on, for every connection made from here. Links up now go
    /// on, and are told; a node that was not told cannot link any more and
    /// has to pair again. `why` goes to the log.
    pub async fn finish_key_rotation(&self, why: &str) -> Result<Value, String> {
        let out = self.end_rotation(why)?;
        self.tell_rotation().await;
        Ok(out)
    }

    fn end_rotation(&self, why: &str) -> Result<Value, String> {
        let _one = self.rotating.lock().unwrap();
        let Some(r) = self
            .read(|s| s.key_rotation.clone())
            .filter(|r| r.finished_ms.is_none())
        else {
            return Err("no rotation of the center's key is in its grace".into());
        };
        let next_path = self.dir.join(NEXT_IDENTITY_FILE);
        let next = std::fs::read_to_string(&next_path)
            .map_err(|e| e.to_string())
            .and_then(|t| ServerIdentity::from_pem(&t))
            .map_err(|e| {
                format!(
                    "cannot read the new key {}: {e}; the old key stays",
                    next_path.display()
                )
            })?;
        if nerve_transport::tls::b64url(&next.spki()) != r.new_spki {
            return Err(format!(
                "{} is not the key the rotation told the nodes; the old key stays",
                next_path.display()
            ));
        }
        let config = next.server_config()?;
        // The new key takes the old one's place; the old key is gone with
        // the file it was in.
        std::fs::rename(&next_path, self.dir.join(IDENTITY_FILE))
            .map_err(|e| format!("cannot put the new key in place: {e}; the old key stays"))?;
        let pin = next.pin();
        *self.server_config.lock().unwrap() = config;
        if self.public_url.tls {
            *self.pin.lock().unwrap() = Some(pin.clone());
        }
        *self.identity.lock().unwrap() = Arc::new(next);
        let now = now_ms();
        self.update(|s| {
            if let Some(r) = s.key_rotation.as_mut() {
                r.finished_ms = Some(now);
            }
        });
        self.log.record(
            Level::Info,
            None,
            &format!("the center serves its new key now ({why}); its pin is {pin}"),
        );
        self.changed(Change::Nodes);
        Ok(json!({"pin": pin}))
    }

    /// What `center.rotate` tells a node now: the last rotation, until no
    /// node can hold the old pin any more; the grace left, 0 once the new
    /// key is served.
    pub fn rotation_notice(&self) -> Option<Value> {
        let r = self.read(|s| s.key_rotation.clone())?;
        let now = now_ms();
        if now >= r.started_ms + nerve_proto::ROTATE_GRACE_MS && r.finished_ms.is_some() {
            return None;
        }
        let grace_ms = match r.finished_ms {
            Some(_) => 0,
            None => r.until_ms.saturating_sub(now),
        };
        serde_json::to_value(msg::CenterRotate {
            old_spki: r.old_spki,
            new_spki: r.new_spki,
            sig: r.sig,
            grace_ms,
        })
        .ok()
    }

    /// Tells every live link that speaks rotation; how many it told. Each
    /// is told in a task of its own: a link whose peer reads nothing cannot
    /// hold up the owner's request or the sweep.
    async fn tell_rotation(&self) -> usize {
        let Some(notice) = self.rotation_notice() else {
            return 0;
        };
        let links: Vec<Arc<Link>> = self
            .links
            .lock()
            .unwrap()
            .values()
            .filter(|l| !l.is_closed())
            .cloned()
            .collect();
        for l in &links {
            let (l, notice) = (l.clone(), notice.clone());
            tokio::spawn(async move { l.notify(msg::method::CENTER_ROTATE, notice).await });
        }
        links.len()
    }

    /// The state of the center's key for the web UI: its pin, and a
    /// rotation in its grace. The new pin is not in it: the owner saw it
    /// once, when the rotation was made, and the nodes get it signed.
    pub fn key_json(&self) -> Value {
        let r = self.read(|s| s.key_rotation.clone());
        json!({
            "pin": self.identity().pin(),
            "grace_until_ms": r.filter(|r| r.finished_ms.is_none()).map(|r| r.until_ms),
        })
    }

    /// Takes a node's new key (`key.rotate` on `link`): signed by the key
    /// it replaces and by itself. The old key is taken until the grace
    /// ends; a rotation in the grace of another drops that older key, which
    /// it also gives back so that a link opened with it ends. The new key is
    /// saved before it is told as taken: the node deletes its old key then.
    pub(crate) fn rotate_node_key(
        &self,
        link: &Link,
        p: &Map<String, Value>,
    ) -> (msg::KeyRotated, Option<String>) {
        let r: msg::KeyRotate = match nerve_proto::rpc::params(p) {
            Ok(r) => r,
            Err(e) => {
                return (
                    self.key_refused(
                        link,
                        String::new(),
                        format!("bad key.rotate: {}", e.message),
                    ),
                    None,
                );
            }
        };
        let new = r.public_key.clone();
        let Some(raw) = msg::unhex(&new).filter(|b| b.len() == 32) else {
            return (
                self.key_refused(
                    link,
                    new,
                    "public_key must be 32 bytes as 64 lowercase hex characters".into(),
                ),
                None,
            );
        };
        let message = nerve_proto::rotate_node_message(&self.id(), &raw);
        let verify = nerve_transport::keys::verify_node_signature;
        if !verify(&new, &message, &r.proof) {
            return (
                self.key_refused(link, new, "the new key did not sign the rotation".into()),
                None,
            );
        }
        let now = now_ms();
        // Sent again for the key the center took already (no answer reached
        // the node): taken, without a write, which could fail and have the
        // node drop the key the center holds. It was saved when it was taken.
        let held = self.read(|s| {
            s.nodes
                .get(&link.node_id)
                .is_some_and(|n| n.public_key == new)
        });
        let out = if held {
            Ok(None)
        } else {
            self.update_saved(|s| {
                if s.node_by_key(&new).is_some_and(|n| n.id != link.node_id) {
                    return Err("another node holds this key".to_string());
                }
                let n = s
                    .nodes
                    .get_mut(&link.node_id)
                    .ok_or("the node is no longer paired")?;
                if n.public_key == new {
                    return Ok(None);
                }
                if !verify(&n.public_key, &message, &r.sig) {
                    return Err("the rotation is not signed by the node's current key".to_string());
                }
                n.key_rotations += 1;
                let old = std::mem::replace(&mut n.public_key, new.clone());
                let dropped = n.old_key.replace(OldKey {
                    public_key: old.clone(),
                    until_ms: now + nerve_proto::ROTATE_GRACE_MS,
                });
                Ok(Some((old, dropped.map(|d| d.public_key))))
            })
        };
        match out {
            Err(why) => (self.key_refused(link, new, why), None),
            Ok(None) => {
                self.note(
                    Level::Debug,
                    Some(&link.node_id),
                    "the node sent its key rotation again; the center has its new key already",
                );
                (
                    msg::KeyRotated {
                        public_key: new,
                        error: None,
                    },
                    None,
                )
            }
            Ok(Some((old, dropped))) => {
                self.note(
                    Level::Info,
                    Some(&link.node_id),
                    format!(
                        "the node rotated its key: its new key is {new} (it was {old}); the old one is taken for {} more, or until the node ends that",
                        util::span(Duration::from_millis(nerve_proto::ROTATE_GRACE_MS))
                    ),
                );
                self.changed(Change::Nodes);
                (
                    msg::KeyRotated {
                        public_key: new,
                        error: None,
                    },
                    dropped,
                )
            }
        }
    }

    fn key_refused(&self, link: &Link, public_key: String, why: String) -> msg::KeyRotated {
        self.note(
            Level::Warn,
            Some(&link.node_id),
            format!("the node's key rotation was refused, its key stays: {why}"),
        );
        msg::KeyRotated {
            public_key,
            error: Some(why),
        }
    }

    /// Ends the grace of a node's old key (`key.retire` on `link`), signed
    /// by its current key. Also says whether `link` was opened with that old
    /// key: it ends with it.
    pub(crate) fn retire_node_key(
        &self,
        link: &Link,
        p: &Map<String, Value>,
    ) -> (msg::KeyRetired, bool) {
        let refused = |why: String| {
            self.note(
                Level::Warn,
                Some(&link.node_id),
                format!("the node's request to end the grace of its old key was refused: {why}"),
            );
            (msg::KeyRetired { error: Some(why) }, false)
        };
        let r: msg::KeyRetire = match nerve_proto::rpc::params(p) {
            Ok(r) => r,
            Err(e) => return refused(format!("bad key.retire: {}", e.message)),
        };
        let Some(raw) = msg::unhex(&r.public_key).filter(|b| b.len() == 32) else {
            return refused("public_key must be 32 bytes as 64 lowercase hex characters".into());
        };
        let message = nerve_proto::retire_node_message(&self.id(), &raw);
        let out = self.update_saved(|s| {
            let n = s
                .nodes
                .get_mut(&link.node_id)
                .ok_or("the node is no longer paired")?;
            if n.public_key != r.public_key
                || !nerve_transport::keys::verify_node_signature(&n.public_key, &message, &r.sig)
            {
                return Err("it is not signed by the node's current key".to_string());
            }
            Ok(n.old_key.take())
        });
        match out {
            Err(why) => refused(why),
            Ok(old) => {
                let opened_with_it = old
                    .as_ref()
                    .is_some_and(|o| o.public_key == link.auth_key());
                if let Some(o) = &old {
                    self.note(
                        Level::Info,
                        Some(&link.node_id),
                        format!(
                            "the node ended the grace of its old key {}; only its key {} is taken from now on",
                            o.public_key, r.public_key
                        ),
                    );
                    self.changed(Change::Nodes);
                }
                (msg::KeyRetired { error: None }, opened_with_it)
            }
        }
    }

    /// The keys a node's hello may be signed with now: its key, and its old
    /// one while the grace runs. `None` for a node that is not paired.
    pub(crate) fn node_keys(&self, node_id: &str) -> Option<(String, Option<OldKey>)> {
        self.read(|s| {
            s.nodes
                .get(node_id)
                .map(|n| (n.public_key.clone(), n.old_key.clone()))
        })
    }

    /// Ends what ran out: the grace of the center's rotation (the new key is
    /// served), the notices of a finished one, and nodes' old keys.
    pub async fn sweep(&self) {
        let now = now_ms();
        let due = self.read(|s| {
            s.key_rotation
                .as_ref()
                .is_some_and(|r| r.finished_ms.is_none() && now >= r.until_ms)
        });
        if due {
            match self.finish_key_rotation("its grace ended").await {
                Ok(_) => self.rotation_failed.store(false, Ordering::SeqCst),
                Err(e) => {
                    if !self.rotation_failed.swap(true, Ordering::SeqCst) {
                        self.log.record(
                            Level::Error,
                            None,
                            &format!("the grace of the center's key rotation ended, but the new key cannot be served: {e}"),
                        );
                    }
                }
            }
        }
        let expired: Vec<(String, String)> = self.read(|s| {
            s.nodes
                .values()
                .filter_map(|n| {
                    n.old_key
                        .as_ref()
                        .filter(|o| now >= o.until_ms)
                        .map(|o| (n.id.clone(), o.public_key.clone()))
                })
                .collect()
        });
        let stale = self.read(|s| {
            s.key_rotation.as_ref().is_some_and(|r| {
                r.finished_ms.is_some() && now >= r.started_ms + nerve_proto::ROTATE_GRACE_MS
            }) || s
                .nodes
                .values()
                .any(|n| n.old_key.as_ref().is_some_and(|o| now >= o.until_ms))
        });
        if stale {
            self.update(|s| {
                if s.key_rotation.as_ref().is_some_and(|r| {
                    r.finished_ms.is_some() && now >= r.started_ms + nerve_proto::ROTATE_GRACE_MS
                }) {
                    s.key_rotation = None;
                }
                for n in s.nodes.values_mut() {
                    if n.old_key.as_ref().is_some_and(|o| now >= o.until_ms) {
                        n.old_key = None;
                    }
                }
            });
        }
        // A link the old key opened during its grace ends with the grace.
        for (node_id, key) in expired {
            self.end_link_of_key(&node_id, &key);
        }
        // And whatever way a key stopped counting (the grace ended, the node
        // ended it, a newer rotation dropped it, or a link came up just
        // after), a link opened with it ends at the next sweep.
        let links: Vec<Arc<Link>> = self
            .links
            .lock()
            .unwrap()
            .values()
            .filter(|l| !l.is_closed())
            .cloned()
            .collect();
        for l in links {
            if !self.key_counts(&l.node_id, &l.auth_key()) {
                self.note(
                    Level::Info,
                    Some(&l.node_id),
                    "the link opened with the node's old key ends: that key no longer counts",
                );
                l.end(ByeReason::Replaced);
            }
        }
    }

    /// Whether a hello signed with `key` may hold a link of `node_id` now:
    /// the node's key, or its old one while the grace runs. A node that is
    /// not paired any more is left to its own end.
    pub(crate) fn key_counts(&self, node_id: &str, key: &str) -> bool {
        let now = now_ms();
        self.read(|s| match s.nodes.get(node_id) {
            None => true,
            Some(n) => {
                n.public_key == key
                    || n.old_key
                        .as_ref()
                        .is_some_and(|o| o.public_key == key && now < o.until_ms)
            }
        })
    }
}
