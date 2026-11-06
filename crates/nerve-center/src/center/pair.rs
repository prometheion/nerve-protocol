//! Pairing a node by a code (docs/dev/spec/protocol.md §3), and the log
//! of the codes that ran out.

use nerve_transport::sync::lock;

use super::*;

impl Center {
    // ---- Pairing (spec §3) ----

    /// A new pairing code and the link that carries it.
    pub fn new_pairing(&self) -> Value {
        let ttl = Duration::from_secs(u64::from(self.read(|st| st.pair_code_minutes)) * 60);
        let code = lock(&self.codes).create(Instant::now(), ttl);
        // The code is a secret until it is used, so it is not logged.
        self.log.record(
            Level::Info,
            None,
            &format!(
                "a pairing code was made; it is valid for {}",
                util::span(ttl)
            ),
        );
        let pin = self.pin();
        let link = PairLink {
            center: self.public_url.clone(),
            code: code.clone(),
            pin: pin.clone(),
        };
        json!({
            "code": code,
            "link": link.render(),
            "pin": pin,
            "center": self.public_url.to_string(),
            "expires_ms": now_ms() + ttl.as_millis() as u64,
        })
    }

    /// What became of a code from [`Center::new_pairing`], for the web UI:
    /// `open` while it can still pair a machine (a pairing in progress counts,
    /// it may fail), and once a machine used it, that machine as `node`.
    pub fn pairing_status(&self, code: &str) -> Value {
        let outcome = lock(&self.codes).outcome(code, Instant::now());
        match outcome {
            Outcome::Open => json!({"open": true, "node": null}),
            Outcome::Gone => json!({"open": false, "node": null}),
            Outcome::Paired(id) => {
                let name = self.read(|s| s.nodes.get(&id).map(|n| n.name.clone()));
                json!({"open": false, "node": name.map(|name| json!({"id": id, "name": name}))})
            }
        }
    }

    /// Answers `POST /nerve/v0/pair/check`: whether the code in the body
    /// could pair now, without using it or counting a try
    /// ([`crate::pairing::Codes::probe`]).
    pub fn pair_check(&self, body: &[u8]) -> (u16, Value) {
        let code = serde_json::from_slice::<Value>(body)
            .ok()
            .and_then(|v| v["code"].as_str().map(str::to_string))
            .filter(|c| nerve_proto::link::valid_code(c));
        let Some(code) = code else {
            return (
                400,
                json!({ "error": "the body is {\"code\": \"<pairing code>\"}" }),
            );
        };
        let probe = lock(&self.codes).probe(&code, Instant::now());
        self.log.record(
            Level::Debug,
            None,
            &format!("a node checked a pairing code: {}", probe.word()),
        );
        (200, json!({ "code": probe.word() }))
    }

    /// Answers `POST /nerve/v0/pair`: the status and the body.
    pub fn pair(&self, body: &[u8]) -> (u16, Value) {
        // A request without a code that works costs nothing to make, so a
        // refusal before the code is checked is detail, not news.
        let err = |s: u16, m: &str| {
            self.log.record(
                Level::Debug,
                None,
                &format!("a pairing request was refused ({s}): {m}"),
            );
            (s, json!({ "error": m }))
        };
        let req: PairRequest = match serde_json::from_slice(body) {
            Ok(r) => r,
            Err(e) => return err(400, &format!("bad pairing request: {e}")),
        };
        if !nerve_proto::valid_node_name(&req.name) {
            return err(
                400,
                "a node name is 1 to 32 characters of a-z, 0-9 and -, starting and ending with a letter or digit",
            );
        }
        if req.platform.is_empty()
            || req.platform.len() > 32
            || req.arch.is_empty()
            || req.arch.len() > 32
        {
            return err(400, "bad platform or arch");
        }
        let pk = match msg::unhex(&req.public_key) {
            Some(b) if b.len() == 32 => b,
            _ => {
                return err(
                    400,
                    "public_key must be 32 bytes as 64 lowercase hex characters",
                );
            }
        };
        let now = Instant::now();
        // Taken out in the same step as the check: the code is used up from
        // here on, and given back only if this pairing fails.
        let Ok(taken) = lock(&self.codes).take(&req.code, now) else {
            // Anyone who reaches the port can send these; one line now and
            // then says it happens.
            let quiet = lock(&self.pair_log).take(now);
            if let Some(more) = quiet {
                let also = if more > 0 {
                    format!(" ({more} more since the last line)")
                } else {
                    String::new()
                };
                self.log.record(
                    Level::Warn,
                    None,
                    &format!(
                        "pairing refused: the code is unknown, used, expired or out of tries{also}"
                    ),
                );
            }
            return (
                403,
                json!({ "error": "the pairing code is unknown, used, expired or out of tries" }),
            );
        };
        let node_id = nerve_transport::keys::node_id(&pk);
        // Kept before it is told: a node told it is paired stores the center
        // and dials it, and a pairing that is only in memory is gone at the
        // next start.
        let out = self.update_saved(|s| {
            if s.nodes.contains_key(&node_id) || s.node_by_key(&req.public_key).is_some() {
                return Err("this key is already paired".to_string());
            }
            if s.node_by_name(&req.name).is_some() {
                return Err("another node already has this name".to_string());
            }
            // `list` and `execute` find a node by its id or its name, so a
            // name is never a node's id: it would point at that node.
            if s.nodes.contains_key(&req.name) || req.name == node_id {
                return Err("this name is a node's id".to_string());
            }
            if s.node_by_name(&node_id).is_some() {
                return Err("another node is named like this node's id".to_string());
            }
            s.nodes.insert(
                node_id.clone(),
                NodeRecord {
                    id: node_id.clone(),
                    name: req.name.clone(),
                    public_key: req.public_key.clone(),
                    old_key: None,
                    key_rotations: 0,
                    platform: req.platform.clone(),
                    arch: req.arch.clone(),
                    paired_ms: now_ms(),
                    last_seen_ms: 0,
                    going_away: None,
                    descriptor: None,
                    catalog: Default::default(),
                    disabled: false,
                },
            );
            Ok(PairResponse {
                center_id: s.center_id.clone(),
                center_name: s.center_name.clone(),
                node_id: node_id.clone(),
            })
        });
        match out {
            Ok(resp) => {
                lock(&self.codes).done(taken, &node_id, Instant::now());
                self.log.record(
                    Level::Info,
                    Some((&req.name, &node_id)),
                    &format!(
                        "the node paired ({}/{}); its code is used up",
                        req.platform, req.arch
                    ),
                );
                self.changed(Change::Nodes);
                (200, serde_json::to_value(resp).unwrap_or_default())
            }
            Err(why) => {
                lock(&self.codes).fail(taken);
                let unwritable = why.starts_with(UNWRITABLE);
                self.log.record(
                    if unwritable {
                        Level::Error
                    } else {
                        Level::Warn
                    },
                    None,
                    &format!("pairing refused for the name {}: {why}", req.name),
                );
                (if unwritable { 500 } else { 409 }, json!({ "error": why }))
            }
        }
    }

    /// Notes the pairing codes that ran out unused. The center calls this now
    /// and then, so a log line is at most a few seconds behind the expiry.
    pub fn sweep_codes(&self) {
        // The wrong codes left out of a burst are counted when it is over.
        let left_out = lock(&self.pair_log).flush(Instant::now());
        if left_out > 0 {
            self.log.record(
                Level::Warn,
                None,
                &format!(
                    "{} left out since the last line: the code was unknown, used, expired or out of tries",
                    plural(left_out, "pairing refusal")
                ),
            );
        }
        let lost = lock(&self.codes).sweep(Instant::now());
        if lost.expired > 0 {
            self.log.record(
                Level::Info,
                None,
                &format!(
                    "{} expired without being used",
                    plural(lost.expired, "pairing code")
                ),
            );
        }
        if lost.out_of_tries > 0 {
            self.log.record(
                Level::Warn,
                None,
                &format!(
                    "{} ran out of tries on wrong codes",
                    plural(lost.out_of_tries, "pairing code")
                ),
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::center::tests::{lines, open, pair_body, said};

    /// A pairing the center cannot keep is refused, and nothing in memory
    /// says it was made: the code stays open, and pairing works once the
    /// disk takes it.
    #[cfg(unix)]
    #[test]
    fn a_pairing_that_cannot_be_written_is_refused() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let c = open(dir.path(), None);
        let code = c.new_pairing()["code"].as_str().unwrap().to_string();
        let body = json!({
            "code": code, "name": "box-1", "platform": "linux", "arch": "x86_64",
            "public_key": msg::hex(&[7; 32]),
        })
        .to_string();
        let mode = |m| std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(m));
        mode(0o500).unwrap();
        let (status, v) = c.pair(body.as_bytes());
        mode(0o700).unwrap();
        assert_eq!(status, 500, "{v}");
        assert!(v["error"].as_str().unwrap().starts_with(UNWRITABLE), "{v}");
        assert!(c.read(|s| s.nodes.is_empty()));
        assert_eq!(c.pairing_status(&code)["open"], true);
        assert_eq!(c.pair(body.as_bytes()).0, 200);
        assert_eq!(Store::load(dir.path()).unwrap().unwrap().nodes.len(), 1);
    }

    /// One code is good for one pairing, also when several nodes send it at
    /// the same moment.
    #[test]
    fn one_code_pairs_one_node_however_many_send_it_at_once() {
        let dir = tempfile::tempdir().unwrap();
        let center = open(dir.path(), None);
        let code = center.new_pairing()["code"].as_str().unwrap().to_string();
        let start = std::sync::Barrier::new(8);
        let statuses: Vec<u16> = std::thread::scope(|s| {
            let tries: Vec<_> = (0..8u8)
                .map(|i| {
                    let (center, code, start) = (&center, &code, &start);
                    s.spawn(move || {
                        let body = json!({
                            "code": code,
                            "name": format!("node-{i}"),
                            "platform": "linux",
                            "arch": "x86_64",
                            "public_key": msg::hex(&[i + 1; 32]),
                        });
                        start.wait();
                        center.pair(body.to_string().as_bytes()).0
                    })
                })
                .collect();
            tries.into_iter().map(|t| t.join().unwrap()).collect()
        });
        let paired = statuses.iter().filter(|s| **s == 200).count();
        assert_eq!(paired, 1, "statuses {statuses:?}");
        assert_eq!(center.read(|st| st.nodes.len()), 1);
        assert!(
            statuses.iter().all(|s| matches!(s, 200 | 403)),
            "{statuses:?}"
        );
    }

    /// A node's check before it pairs tells whether the code could pair,
    /// and the code stays as it was: still open, every try left.
    #[test]
    fn a_check_tells_the_code_open_and_uses_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let c = open(dir.path(), None);
        let code = c.new_pairing()["code"].as_str().unwrap().to_string();
        let check = |code: &str| c.pair_check(json!({ "code": code }).to_string().as_bytes());
        for _ in 0..20 {
            assert_eq!(check(&code), (200, json!({"code": "open"})));
        }
        assert_eq!(check("wrongwrong12"), (200, json!({"code": "gone"})));
        assert_eq!(c.pair_check(b"{}").0, 400);
        assert_eq!(c.pair(&pair_body(&code, "box-1", 7)).0, 200);
        assert_eq!(check(&code), (200, json!({"code": "used"})));
    }

    #[test]
    fn pairing_is_logged_and_no_code_is() {
        let dir = tempfile::tempdir().unwrap();
        let c = open(dir.path(), None);
        let made = c.new_pairing();
        let code = made["code"].as_str().unwrap().to_string();
        let link = made["link"].as_str().unwrap().to_string();
        // Wrong codes in a row make one line, not one each.
        for _ in 0..3 {
            assert_eq!(c.pair(&pair_body("wrongwrong12", "box-1", 1)).0, 403);
        }
        assert_eq!(c.pair(&pair_body(&code, "box-1", 7)).0, 200);
        // A right code that cannot pair: told, with the name that was asked for.
        let second = c.new_pairing()["code"].as_str().unwrap().to_string();
        assert_eq!(c.pair(&pair_body(&second, "box-2", 7)).0, 409);
        let id = nerve_transport::keys::node_id(&[7; 32]);

        assert_eq!(
            said(
                &c,
                Level::Info,
                "a pairing code was made; it is valid for 10 min"
            )
            .len(),
            2
        );
        assert_eq!(
            said(&c, Level::Warn, "pairing refused: the code is unknown").len(),
            1
        );
        let paired = said(&c, Level::Info, "the node paired (linux/x86_64)");
        assert_eq!(paired.len(), 1);
        assert_eq!(paired[0].node.as_deref(), Some("box-1"));
        assert_eq!(paired[0].node_id.as_deref(), Some(id.as_str()));
        assert_eq!(
            said(
                &c,
                Level::Warn,
                "pairing refused for the name box-2: this key is already paired"
            )
            .len(),
            1
        );
        // Neither a code, the link that carries one, nor a wrong code is in
        // the window or in the file.
        let file = std::fs::read_to_string(dir.path().join("log.jsonl")).unwrap();
        let window = serde_json::to_string(&lines(&c)).unwrap();
        for secret in [&code, &second, &link, "wrongwrong12"] {
            assert!(
                !file.contains(secret) && !window.contains(secret),
                "{secret}"
            );
        }
    }

    #[test]
    fn a_code_that_runs_out_unused_is_logged_once() {
        let dir = tempfile::tempdir().unwrap();
        let c = open(dir.path(), None);
        let short = Duration::from_millis(1);
        c.codes.lock().unwrap().create(Instant::now(), short);
        c.codes.lock().unwrap().create(Instant::now(), short);
        std::thread::sleep(Duration::from_millis(10));
        c.sweep_codes();
        c.sweep_codes();
        let expired = said(&c, Level::Info, "expired without being used");
        assert_eq!(expired.len(), 1);
        assert_eq!(expired[0].msg, "2 pairing codes expired without being used");
        // A code taken by wrong tries is a warning.
        c.codes
            .lock()
            .unwrap()
            .create(Instant::now(), Duration::from_secs(60));
        for _ in 0..crate::pairing::TRIES {
            assert_eq!(c.pair(&pair_body("wrongwrong12", "box-1", 1)).0, 403);
        }
        c.sweep_codes();
        assert_eq!(
            said(
                &c,
                Level::Warn,
                "1 pairing code ran out of tries on wrong codes"
            )
            .len(),
            1
        );
    }

    /// The wrong codes a burst leaves out of the log are counted once it is
    /// over, not only if another one comes later.
    #[test]
    fn a_burst_of_wrong_codes_is_counted_when_it_stops() {
        let dir = tempfile::tempdir().unwrap();
        let c = open(dir.path(), None);
        for _ in 0..5 {
            assert_eq!(c.pair(&pair_body("wrongwrong12", "box-1", 1)).0, 403);
        }
        assert_eq!(said(&c, Level::Warn, "pairing refused").len(), 1);
        // Inside the window the count waits.
        c.sweep_codes();
        assert!(said(&c, Level::Warn, "left out").is_empty());
        // Past it, the next sweep says how many there were, once.
        c.pair_log.lock().unwrap().last = Instant::now().checked_sub(QUIET_FOR * 2);
        c.sweep_codes();
        c.sweep_codes();
        let left = said(&c, Level::Warn, "left out");
        assert_eq!(left.len(), 1);
        assert!(
            left[0]
                .msg
                .starts_with("4 pairing refusals left out since the last line"),
            "{}",
            left[0].msg
        );
        // A single refusal after the quiet is a line of its own, with no count.
        assert_eq!(c.pair(&pair_body("wrongwrong12", "box-1", 1)).0, 403);
        let lines = said(&c, Level::Warn, "pairing refused");
        assert_eq!(lines.len(), 2);
        assert!(!lines[1].msg.contains("more since"), "{}", lines[1].msg);
    }
}
