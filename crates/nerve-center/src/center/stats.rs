//! The statistics of the calls: per node and day, and in total.

use super::*;

impl Center {
    /// The log line and statistics of a call that worked or `failed`.
    pub(super) fn count_call(
        &self,
        sess: &Arc<Session>,
        route: &Route,
        failed: Option<&RpcError>,
        started: Instant,
    ) {
        let ms = started.elapsed().as_millis() as u64;
        // A call that returned outside content taints the session, so the
        // model's "only tainted sessions" scope and its state can take it in:
        // a result, or what a failed command printed (link::output_of).
        let outside = failed.is_none_or(|e| crate::link::output_of(e).is_some());
        if outside && self.checker().taint_on() && checker::taints(route.effect) {
            sess.set_tainted();
            self.changed(Change::Sessions);
        }
        let code = failed.map(|e| e.kind().as_str().to_string());
        // A call that worked is in the node's audit log, not here.
        if let Some(e) = failed {
            self.log_failed_call(route, e, started.elapsed());
        }
        self.update_soon(|s| {
            if !s.nodes.contains_key(&route.node_id) {
                return;
            }
            let d = s.day(&route.node_id, now_ms());
            let c = d
                .calls
                .entry(format!("{}.{}", route.cap, route.action))
                .or_default();
            c.count += 1;
            c.total_ms += ms;
            c.max_ms = c.max_ms.max(ms);
            if let Some(code) = &code {
                c.errors += 1;
                *d.errors.entry(code.clone()).or_default() += 1;
            }
        });
    }

    /// Statistics: per node (summed over the kept days) and in total.
    pub fn stats_json(&self) -> Value {
        self.read(|s| {
            let mut total = crate::store::DayStats::default();
            let mut nodes = Map::new();
            for (id, ns) in &s.stats {
                let mut sum = crate::store::DayStats::default();
                for d in ns.days.values() {
                    sum.add(d);
                }
                total.add(&sum);
                let name = s
                    .nodes
                    .get(id)
                    .map(|n| n.name.clone())
                    .unwrap_or_else(|| id.clone());
                nodes.insert(name, serde_json::to_value(&sum).unwrap_or_default());
            }
            json!({"retention_days": s.retention_days, "total": total, "nodes": nodes})
        })
    }
}
