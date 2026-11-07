//! The agents' sessions, and what each is offered of the nodes.

use nerve_transport::sync::lock;

use super::*;

impl Center {
    // ---- What the agent is offered ----

    /// The ids of the nodes with a live link, read before the state is
    /// locked (see `Inner::store`).
    fn online_ids(&self) -> BTreeSet<String> {
        lock(&self.links)
            .iter()
            .filter(|(_, l)| l.is_live())
            .map(|(id, _)| id.clone())
            .collect()
    }

    /// The nodes as `list()` shows them, each with the owner's note on it.
    pub fn listed_nodes(&self) -> Vec<listing::NodeLine> {
        let online = self.online_ids();
        self.read(|s| {
            s.nodes
                .values()
                .map(|n| {
                    let mut line = listing::line(n, online.contains(&n.id));
                    line.note = s
                        .checker
                        .nodes
                        .get(&n.id)
                        .map(|x| x.note.clone())
                        .filter(|t| !t.is_empty());
                    line
                })
                .collect()
        })
    }

    /// The node `given` (its name or id) with what it offers the agent, as
    /// `list(node)` shows it; none when there is no such node.
    pub fn offer(&self, given: &str) -> Option<listing::Offer> {
        let online = self.online_ids();
        self.read(|s| {
            let n = listing::find(&s.nodes, given)?;
            Some(listing::offer(n, online.contains(&n.id)))
        })
    }

    /// The names of the paired nodes, for an answer that names a node that
    /// is not there.
    pub fn node_names(&self) -> Vec<String> {
        self.read(|s| s.nodes.values().map(|n| n.name.clone()).collect())
    }

    /// Where `execute` of `unit` on the node `given` (its name or id) goes,
    /// with the unit to check the arguments against. `Ok(None)` when there
    /// is no such node.
    pub fn listed_unit(
        &self,
        given: &str,
        unit: &str,
    ) -> Result<Option<(Route, catalog::Unit)>, (String, listing::Miss)> {
        self.read(|s| {
            let Some(n) = listing::find(&s.nodes, given) else {
                return Ok(None);
            };
            let u = listing::unit(n, unit).map_err(|m| (n.name.clone(), m))?;
            let route = Route {
                node_id: n.id.clone(),
                node_name: n.name.clone(),
                cap: u.cap.clone(),
                action: u.action.clone(),
                effect: u.effect,
                kind: u.kind,
            };
            Ok(Some((route, u)))
        })
    }

    // ---- Sessions ----

    pub fn new_session(&self, transport: &str) -> Arc<Session> {
        let s = Arc::new(Session {
            id: format!("s-{}", nerve_transport::keys::random_token(20)),
            transport: transport.to_string(),
            client: Mutex::new(String::new()),
            started_ms: now_ms(),
            ended: AtomicBool::new(false),
            calls: AtomicU64::new(0),
            nodes: Mutex::new(BTreeSet::new()),
            tainted: AtomicBool::new(false),
            fetched: Mutex::new(Fetched::default()),
            jobs: Mutex::new(Jobs::default()),
            streams: Mutex::new(Streams::default()),
        });
        lock(&self.sessions).insert(s.id.clone(), s.clone());
        self.log.record(
            Level::Info,
            None,
            &format!("a harness session started over {transport} ({})", s.id),
        );
        self.changed(Change::Sessions);
        s
    }

    pub fn session(&self, id: &str) -> Option<Arc<Session>> {
        lock(&self.sessions).get(id).cloned()
    }

    /// Ends a session: every node it used gets `session.end`.
    pub async fn end_session(&self, id: &str) -> bool {
        let Some(s) = lock(&self.sessions).remove(id) else {
            return false;
        };
        s.ended.store(true, Ordering::SeqCst);
        // Its calls and jobs stop, and their results are dropped.
        let stops = lock(&s.jobs).end();
        for stop in stops {
            let _ = stop.send(Stop::SessionEnded);
        }
        // Its streams are dropped; one still running on its node stops.
        let closers = lock(&s.streams).end();
        for c in closers {
            c.close("the session ended");
        }
        self.log.record(
            Level::Info,
            None,
            &format!(
                "the harness session {} ended after {} calls",
                s.id,
                s.calls.load(Ordering::SeqCst)
            ),
        );
        let nodes: Vec<String> = lock(&s.nodes).iter().cloned().collect();
        for n in nodes {
            // A parked link gets it when it resumes.
            if let Some(l) = self.held(&n) {
                l.notify(msg::method::SESSION_END, json!({"session": s.id}))
                    .await;
            }
        }
        self.changed(Change::Sessions);
        true
    }

    pub fn sessions_json(&self) -> Value {
        let sessions: Vec<Arc<Session>> = lock(&self.sessions).values().cloned().collect();
        let list: Vec<Value> = sessions
            .iter()
            .map(|s| {
                // Copied out before the names are read: the state is never
                // locked under a session's lock (see `Inner::store`).
                let ids: Vec<String> = lock(&s.nodes).iter().cloned().collect();
                let nodes: Vec<String> = ids.iter().map(|n| self.node_name(n)).collect();
                json!({
                    "id": s.id,
                    "transport": s.transport,
                    "client": lock(&s.client).clone(),
                    "started_ms": s.started_ms,
                    "calls": s.calls.load(Ordering::SeqCst),
                    "nodes": nodes,
                    "tainted": s.tainted(),
                })
            })
            .collect();
        json!(list)
    }

    pub fn session_count(&self) -> usize {
        lock(&self.sessions).len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::center::tests::{node_record, open};

    /// A session remembers at most `FETCHED_MAX` shown units: past it the
    /// one shown longest ago is forgotten, and one shown again is new again.
    #[test]
    fn a_session_forgets_the_units_it_was_shown_longest_ago() {
        let dir = tempfile::tempdir().unwrap();
        let c = open(dir.path(), None);
        let s = c.new_session("test");
        assert_eq!(s.listed_hash("n1", "fs.read"), None);
        s.listed("n1", "fs.read", 1);
        s.listed("n2", "fs.read", 2);
        assert_eq!(s.listed_hash("n1", "fs.read"), Some(1));
        assert_eq!(s.listed_hash("n2", "fs.read"), Some(2));
        assert_eq!(s.listed_hash("n1", "fs.write"), None);
        // Shown again, with what it is now.
        s.listed("n1", "fs.read", 3);
        for i in 0..FETCHED_MAX - 2 {
            s.listed("n3", &format!("c{i}.a"), 0);
        }
        // n2's fs.read is the oldest now, and goes first.
        assert_eq!(s.listed_hash("n2", "fs.read"), Some(2));
        s.listed("n3", "last.a", 0);
        assert_eq!(s.listed_hash("n2", "fs.read"), None);
        assert_eq!(s.listed_hash("n1", "fs.read"), Some(3));
        s.listed("n3", "after.a", 0);
        assert_eq!(s.listed_hash("n1", "fs.read"), None);
        assert_eq!(s.listed_hash("n3", "c0.a"), Some(0));
        let f = s.fetched.lock().unwrap();
        assert_eq!((f.hashes.len(), f.order.len()), (FETCHED_MAX, FETCHED_MAX));
    }

    /// The web UI's node and session lists read at the same time (two
    /// overview polls) do not deadlock: the session list held a session's
    /// node set while it named the nodes from the state, the node list held
    /// the state while it read every session's node set, and two requests
    /// that met that way stopped every runtime worker for good (issue #150).
    /// Both lists still say who uses what.
    #[test]
    fn the_node_and_session_lists_read_together_do_not_deadlock() {
        let dir = tempfile::tempdir().unwrap();
        let c = open(dir.path(), None);
        let ids: Vec<String> = (0..16).map(|i| format!("n{i}")).collect();
        c.update(|s| {
            for id in &ids {
                s.nodes.insert(id.clone(), node_record(id, "linux"));
            }
        });
        let sessions: Vec<Arc<Session>> = (0..16).map(|_| c.new_session("test")).collect();
        for s in &sessions {
            s.nodes.lock().unwrap().extend(ids.iter().cloned());
        }
        let (done, finished) = std::sync::mpsc::channel();
        for i in 0..4 {
            let (c, done) = (c.clone(), done.clone());
            std::thread::spawn(move || {
                for _ in 0..300 {
                    if i % 2 == 0 {
                        c.nodes_json();
                    } else {
                        c.sessions_json();
                    }
                }
                let _ = done.send(());
            });
        }
        for _ in 0..4 {
            finished
                .recv_timeout(Duration::from_secs(60))
                .expect("the node and session lists deadlocked");
        }
        let nodes = c.nodes_json();
        assert_eq!(nodes[0]["sessions"].as_array().unwrap().len(), 16);
        let list = c.sessions_json();
        assert_eq!(list[0]["nodes"].as_array().unwrap().len(), 16);
        assert_eq!(list[0]["nodes"][0], "n0");
    }
}
