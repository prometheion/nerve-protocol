//! The center's side of the action checker (issue #17,
//! docs/dev/action-checker.md): its settings, its rules against the catalog,
//! the local model and its install, and the audit of what it decided.

use nerve_transport::sync::lock;

use super::*;

/// Why a Save of the Action checker page was refused: the config changed
/// since the page loaded it.
pub const CHECKER_STALE: &str = "the action checker's settings changed since this page loaded them (another tab, or an allow rule from the Audit page); reload the page and make the change again";

/// While alive, the local model's files are being replaced or deleted and
/// the server stays down; dropping it lets `rebuild_checker` start it again.
struct FilesHeld(Center);

impl Drop for FilesHeld {
    fn drop(&mut self) {
        *lock(&self.0.files_held) = false;
    }
}

impl Center {
    // ---- Action checker (issue #17, docs/dev/action-checker.md) ----

    /// The checker as it is now.
    pub fn checker(&self) -> Arc<Checker> {
        lock(&self.checker).clone()
    }

    /// The file that holds the model endpoint's bearer token (a secret, so
    /// not in `state.json`), mode 0600 in the state folder.
    fn checker_token_path(&self) -> PathBuf {
        self.dir.join("checker-model.token")
    }

    /// The endpoint token, or `None` when none is set.
    pub fn checker_token(&self) -> Option<String> {
        std::fs::read_to_string(self.checker_token_path())
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
    }

    /// Whether an endpoint token is set (the UI never shows the token itself).
    pub fn checker_has_token(&self) -> bool {
        self.checker_token().is_some()
    }

    /// Sets or clears the endpoint token.
    pub fn set_checker_token(&self, token: Option<&str>) -> Result<(), String> {
        let path = self.checker_token_path();
        match token.map(str::trim).filter(|t| !t.is_empty()) {
            Some(t) => nerve_transport::files::write_private(&path, t.as_bytes())
                .map_err(|e| format!("cannot write the model token: {e}")),
            None => match std::fs::remove_file(&path) {
                Err(e) if e.kind() != std::io::ErrorKind::NotFound => {
                    Err(format!("cannot remove the model token: {e}"))
                }
                _ => Ok(()),
            },
        }
    }

    /// Rebuilds the checker from the stored config and the token, and brings
    /// the local model up or down to match. Called at start and after every
    /// change to the checker config.
    pub fn rebuild_checker(&self) {
        let cfg = self.read(|s| s.checker.clone());
        self.manage_local_model(&cfg);
        let checker = Checker::build(cfg, self.checker_token());
        for why in &checker.rejected {
            self.log.record(
                Level::Warn,
                None,
                &format!("the action checker left out a rule it could not parse: {why}"),
            );
        }
        *lock(&self.checker) = Arc::new(checker);
    }

    /// Starts, stops or keeps the local llama-server to match `cfg`. It runs
    /// only when the model is on (by the center's switch, or for a node by
    /// its own), its source is local, and the one-click
    /// install put the build and the chosen model in place. Keyed by the
    /// CPU/GPU choice and the model, so an unrelated change does not restart
    /// it.
    fn manage_local_model(&self, cfg: &CheckerConfig) {
        // Held for the whole run, so an install cannot take the files between
        // the check below and the start.
        let held = lock(&self.files_held);
        let installed = checker::install::installed(&self.dir, cfg.model.local_model);
        let want = cfg.model_wanted() && cfg.model.source == ModelSource::Local && installed;
        // An install is swapping the files (or Remove deleting them): start
        // nothing from them now. The install rebuilds when it is done, and
        // the empty signature makes that start the server.
        if want && *held {
            return;
        }
        let sig = if want {
            format!(
                "gpu={}|model={:?}",
                cfg.model.local_gpu, cfg.model.local_model
            )
        } else {
            String::new()
        };
        if *lock(&self.local_sig) == sig {
            return;
        }
        // Starting a server needs a runtime; without one (an off-runtime
        // open, as in a test) leave it for the next change inside the server.
        if want && tokio::runtime::Handle::try_current().is_err() {
            return;
        }
        // Drop the old one (its Drop ends the process), then start the new.
        *lock(&self.local_model) = None;
        if want {
            let bin = checker::install::server_bin(&self.dir);
            let model = checker::install::model_path(&self.dir, cfg.model.local_model);
            match bin
                .ok_or_else(|| "the local model is not installed".to_string())
                .and_then(|bin| {
                    LocalServer::start(
                        bin,
                        model,
                        &self.dir,
                        cfg.model.local_gpu,
                        cfg.model.timeout_ms,
                        checker::install::model_pin(cfg.model.local_model),
                    )
                }) {
                Ok(srv) => {
                    *lock(&self.local_model) = Some(Arc::new(srv));
                    // A question stored before the cap (or with an
                    // endpoint) is kept; the client refuses a call it
                    // pushes over the context, so say why.
                    let question = checker::config::question_len(&cfg.model);
                    if question > checker::config::QUESTION_MAX {
                        self.log.record(
                            Level::Warn,
                            None,
                            &format!(
                                "the action checker's model question is {question} bytes long, over the {} the local model's context is sized for: a long call beside it is refused as too long; shorten the question on the Action checker page",
                                checker::config::QUESTION_MAX
                            ),
                        );
                    }
                    self.log.record(
                        Level::Info,
                        None,
                        &format!(
                            "the action checker is starting its local decision model on the {}",
                            if cfg.model.local_gpu { "GPU" } else { "CPU" }
                        ),
                    );
                }
                Err(e) => self.log.record(
                    Level::Warn,
                    None,
                    &format!("the action checker cannot start its local model: {e}"),
                ),
            }
        }
        *lock(&self.local_sig) = sig;
    }

    /// The model endpoint to use now: the owner's endpoint, or the local
    /// server's once it is ready (or while it starts again after it ended
    /// on a call). `None` when the model is on but not
    /// reachable (the checker then fails closed, or logs, by its setting).
    pub(super) fn resolved_endpoint(&self, checker: &Checker) -> Option<Endpoint> {
        match checker.model_source() {
            ModelSource::Endpoint => checker.endpoint().cloned(),
            ModelSource::Local => {
                let srv = lock(&self.local_model).clone()?;
                // A server that ended while it read a call keeps its
                // endpoint while it starts again, so the client refuses the
                // calls of that window as lost, and allow-and-log
                // does not let them through as it does for a model that is
                // down (review T2 of #178).
                srv.takes_calls().then(|| srv.endpoint())
            }
        }
    }

    /// The local model's status for the UI, or `None` when there is no local
    /// server running.
    pub fn local_model_status(&self) -> Option<crate::checker::server::Status> {
        lock(&self.local_model).as_ref().map(|s| s.status())
    }

    /// Replaces the checker config (after the UI validated the change),
    /// saves it, rebuilds the checker and tells the UI. `clear_taint` clears
    /// every session's taint mark, for when taint is switched off.
    pub fn set_checker_config(&self, cfg: CheckerConfig, clear_taint: bool) {
        self.store_checker_config(cfg, clear_taint, None)
            .expect("a save without a version is never stale");
    }

    /// [`set_checker_config`](Self::set_checker_config), refused with
    /// [`CHECKER_STALE`] when `if_version` is given and the stored config is
    /// at another version: checked and written under one lock of the store.
    fn store_checker_config(
        &self,
        mut cfg: CheckerConfig,
        clear_taint: bool,
        if_version: Option<u64>,
    ) -> Result<(), String> {
        self.update(|s| {
            if if_version.is_some_and(|v| v != s.checker.version) {
                return Err(CHECKER_STALE.to_string());
            }
            cfg.version = s.checker.version + 1;
            s.checker = cfg;
            Ok(())
        })?;
        if clear_taint {
            for s in lock(&self.sessions).values() {
                s.tainted.store(false, Ordering::SeqCst);
            }
        }
        self.rebuild_checker();
        self.changed(Change::Nodes);
        self.changed(Change::Sessions);
        Ok(())
    }

    /// What the web UI's Action checker page reads: the config (no token),
    /// whether a token is set, whether the model is on anywhere (for the
    /// center or for a node, the rule that runs the local model), the
    /// default model and its licence, the one-click install's state and the
    /// running model's status, the platform/GPU support, and rules that did
    /// not parse.
    pub fn checker_json(&self) -> Value {
        let cfg = self.read(|s| s.checker.clone());
        json!({
            "config": cfg.view(),
            "model_wanted": cfg.model_wanted(),
            "has_token": self.checker_has_token(),
            "models": checker::install::MODELS,
            "default_blocklist": checker::config::default_blocklist(),
            "local": self.local_model_status(),
            "install": *lock(&self.install),
            "installed": checker::install::installed(&self.dir, cfg.model.local_model),
            "installed_models": checker::install::installed_models(&self.dir),
            "platform_supported": checker::install::platform_supported(),
            "gpu_hint": checker::install::gpu_hint(),
            "rejected": self.checker().rejected,
            "unpublished": self.read(|s| unpublished_rules(&s.checker, &s.nodes)),
            "stale": self.read(|s| stale_checker_rules(&s.checker, &s.nodes)),
            "fields": self.read(|s| rule_fields(&s.nodes)),
        })
    }

    /// The one-click install's current state.
    pub fn checker_install_status(&self) -> checker::install::Status {
        lock(&self.install).clone()
    }

    /// Starts the one-click install of llama.cpp and the chosen model on the
    /// CPU or GPU, in the background. On success it turns the local model on
    /// with the chosen device. Refused while an install is already running.
    /// Validates a posted checker config and, if it holds, saves it. Taint
    /// switched off clears every session's mark.
    pub fn apply_checker_config(&self, cfg: CheckerConfig) -> Result<(), String> {
        self.apply_checker_config_if(cfg, None)
    }

    /// [`apply_checker_config`](Self::apply_checker_config) for the page's
    /// Save: refused with [`CHECKER_STALE`] unless the stored config is
    /// still at `if_version`, the version the page loaded.
    pub fn apply_checker_config_if(
        &self,
        mut cfg: CheckerConfig,
        if_version: Option<u64>,
    ) -> Result<(), String> {
        // A rule the config adds has its conditions checked against the
        // schemas the machines publish; one it keeps stays, flagged where
        // its argument went since (`stale` in checker_json).
        let (old, nodes) = self.read(|s| (s.checker.clone(), s.nodes.clone()));
        for e in &cfg.blocklist {
            if !old
                .blocklist
                .iter()
                .any(|o| o.rule == e.rule && o.node_id == e.node_id)
            {
                checker_typed(&e.rule, e.node_id.as_deref(), &nodes)?;
                blocklist_typed(&e.rule, e.node_id.as_deref(), &nodes)?;
            }
        }
        for a in &cfg.allow_rules {
            if !old.allow_rules.contains(a) {
                checker_typed(&a.rule, a.node_id.as_deref(), &nodes)?;
            }
        }
        for e in &mut cfg.blocklist {
            Rule::parse(&e.rule)?;
            // An entry for one node is switched off as a whole; the
            // exceptions are for an entry of every node.
            if e.node_id.is_some() && !e.off_for.is_empty() {
                return Err(format!(
                    "the blocklist entry {} is for one node, so it cannot be switched off for single nodes; switch it off instead",
                    e.rule
                ));
            }
            e.off_for.sort();
            e.off_for.dedup();
        }
        for a in &cfg.allow_rules {
            Rule::parse(&a.rule)?;
        }
        if !(0.0..=1.0).contains(&cfg.model.threshold) {
            return Err("the threshold is between 0 and 1".into());
        }
        if cfg.model.timeout_ms < 100 {
            return Err("the model timeout is at least 100 ms".into());
        }
        if cfg.model.instructions.trim().is_empty() {
            return Err("the model question needs instructions".into());
        }
        // Only the local server's context is the center's to size; an
        // endpoint's model reads what its own machine holds.
        let question = checker::config::question_len(&cfg.model);
        if cfg.model.source == ModelSource::Local && question > checker::config::QUESTION_MAX {
            return Err(format!(
                "the model question (the instructions and both criteria) is {question} bytes long; at most {} fit",
                checker::config::QUESTION_MAX
            ));
        }
        // The owner's note is one line of a few sentences: `list()` gives it
        // to every harness on one line, and a long one would cost every
        // session the tokens.
        for (id, n) in &mut cfg.nodes {
            n.note = listing::one_line(&n.note);
            if n.note.len() > checker::config::NOTE_MAX {
                let name = Some(self.node_name(id)).filter(|n| !n.is_empty());
                return Err(format!(
                    "the note on machine {} is {} bytes long; at most {} fit",
                    name.as_deref().unwrap_or(id),
                    n.note.len(),
                    checker::config::NOTE_MAX
                ));
            }
        }
        // A node that follows the center in both and has no note is the
        // same as one with no settings: keep the state free of them.
        cfg.nodes.retain(|_, n| *n != NodeSettings::default());
        // Keep in memory what a restart reads back from the stored part.
        cfg.settle_blocklist();
        let clear_taint = self.read(|s| s.checker.taint_on) && !cfg.taint_on;
        self.store_checker_config(cfg, clear_taint, if_version)
    }

    /// Adds a saved allow rule, built for an audit button's `cap.action` and
    /// `target` (exact or wildcard, or with one argument pinned), for every
    /// node or one node.
    pub fn add_checker_allow(
        &self,
        cap: &str,
        action: &str,
        target: &str,
        wildcard: bool,
        pin: Option<(&str, &Value)>,
        node_id: Option<String>,
    ) -> Result<String, String> {
        let mut rule = audit_rule("allow", cap, action, target, wildcard, pin)?;
        // **Allow** saves the command line it was shown, and covers that line
        // alone: a pattern would also take more flags, operands or commands.
        if (cap, action) == ("exec", "run") && !wildcard && pin.is_none() {
            rule = format!("exec.run:exact:{}", target.trim());
        }
        self.read(|s| checker_typed(&rule, node_id.as_deref(), &s.nodes))?;
        let entry = AllowRule {
            rule: rule.clone(),
            node_id,
        };
        // Added to the stored config under its lock: a read, a push and a
        // write of the whole config would lose a change saved in between.
        let added = self.update(|s| {
            let new = !s.checker.allow_rules.contains(&entry);
            if new {
                s.checker.allow_rules.push(entry);
                s.checker.version += 1;
            }
            new
        });
        if added {
            self.rebuild_checker();
            self.changed(Change::Nodes);
            self.changed(Change::Sessions);
        }
        Ok(rule)
    }

    /// Takes the local model's files for an install's swap or a Remove: marks
    /// them held, so no config change starts the server from them, then stops
    /// the running server and waits for its process to exit, so the files are
    /// free to replace or delete (Windows refuses while it runs). The server
    /// stays down until the returned guard is dropped and the checker rebuilt.
    async fn hold_local_files(&self) -> FilesHeld {
        let server = {
            let mut held = lock(&self.files_held);
            *held = true;
            *lock(&self.local_sig) = String::new();
            lock(&self.local_model).take()
        };
        if let Some(srv) = server {
            srv.stop().await;
        }
        FilesHeld(self.clone())
    }

    /// Starts the one-click install of llama.cpp and `model` on the CPU or
    /// GPU, in the background. The running model keeps judging calls while
    /// the files download; it is stopped only for the swap at the end. On
    /// success it turns the local model on with the chosen model and device;
    /// for a GPU install it first checks the build really finds a device and
    /// falls back to the CPU with a note if not. Success or failure, the local
    /// server is then brought back in line with the config. Refused while an
    /// install is already running.
    pub async fn start_checker_install(&self, gpu: bool, model: LocalModel) -> Result<(), String> {
        if !checker::install::platform_supported() {
            return Err("this machine has no pinned local build; use the endpoint mode".into());
        }
        // Claim the install under the lock, so two requests cannot both start.
        {
            let mut st = lock(&self.install);
            if matches!(
                st.phase,
                checker::install::Phase::Downloading
                    | checker::install::Phase::Unpacking
                    | checker::install::Phase::Verifying
            ) {
                return Err("an install is already running".into());
            }
            *st = checker::install::Status {
                phase: checker::install::Phase::Downloading,
                gpu,
                model_id: model,
                ..Default::default()
            };
        }
        let cancel = Arc::new(AtomicBool::new(false));
        let from = lock(&self.install_from).clone();
        // Keep the slot locked while spawning, so the task's own check of
        // whether it is still current waits until its handle is stored.
        let mut slot = lock(&self.install_task);
        let (me, flag) = (self.clone(), cancel.clone());
        let task = tokio::spawn(async move { me.run_install(gpu, model, flag, from).await });
        *slot = Some(InstallTask { cancel, task });
        Ok(())
    }

    /// The body of an install task (see [`Center::start_checker_install`]).
    async fn run_install(
        &self,
        gpu: bool,
        model: LocalModel,
        cancel: Arc<AtomicBool>,
        from: Arc<checker::install::Sources>,
    ) {
        let r = async {
            let prepared =
                checker::install::prepare(&self.dir, gpu, model, &self.install, &cancel, &from)
                    .await?;
            // Only now take the server down: the files it runs from are
            // about to be replaced.
            let _held = self.hold_local_files().await;
            checker::install::commit(&self.dir, prepared)
        }
        .await;
        // A Remove took over (it also ends this task): drop the result.
        let current = lock(&self.install_task)
            .as_ref()
            .is_some_and(|t| Arc::ptr_eq(&t.cancel, &cancel));
        if !current {
            return;
        }
        match &r {
            Ok(()) => {
                // A GPU install only counts as GPU if the build finds a
                // device; otherwise fall back to the CPU and say so.
                let mut use_gpu = gpu;
                if gpu && !checker::install::gpu_available(&self.dir).await {
                    use_gpu = false;
                    self.note(
                        Level::Warn,
                        None,
                        "the action checker's GPU build found no device; running the model on the CPU. Reinstall on CPU to keep it off the GPU.",
                    );
                }
                self.update(|s| {
                    s.checker.local_installed(use_gpu, model);
                    s.checker.version += 1;
                });
                checker::install::finish(&self.install, &r);
                if gpu && !use_gpu {
                    lock(&self.install).message =
                        "no GPU device was found; running on the CPU".into();
                }
                self.note(
                    Level::Info,
                    None,
                    format!(
                        "the action checker's local model was installed ({})",
                        if use_gpu { "GPU" } else { "CPU" }
                    ),
                );
            }
            Err(e) => {
                checker::install::finish(&self.install, &r);
                self.note(
                    Level::Warn,
                    None,
                    format!("the action checker's local model install failed: {e}"),
                );
            }
        }
        // Start the new build, or the old one again after a failed swap (a
        // failed download never stopped it).
        self.rebuild_checker();
        self.changed(Change::Nodes);
    }

    /// Removes the installed local build and model, and turns the local model
    /// off. Ends a running install first and waits for its task, so nothing it
    /// does lands after this, then stops the server, so the delete does not
    /// fail while a file is in use. The model is turned off even when a file
    /// could not be deleted: it cannot run from a half-removed install, and
    /// left on it would refuse every call as unreachable.
    pub async fn remove_checker_model(&self) -> Result<(), String> {
        let running = lock(&self.install_task).take();
        if let Some(t) = running {
            t.cancel.store(true, Ordering::Relaxed);
            // A download waiting on a silent connection only sees the flag at
            // its next read; aborting ends it at once.
            t.task.abort();
            let _ = t.task.await;
        }
        *lock(&self.install) = checker::install::Status::default();
        let held = self.hold_local_files().await;
        // The server has exited; retry a couple of times for a late handle on
        // Windows.
        let mut last = Ok(());
        for _ in 0..3 {
            last = checker::install::remove(&self.dir);
            if last.is_ok() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(300)).await;
        }
        drop(held);
        // The model is off everywhere then: also for a node that had it on
        // by its own setting, which would otherwise refuse its every call
        // with no model to ask (fail closed).
        self.update(|s| {
            s.checker.version += 1;
            if s.checker.model.source == ModelSource::Local {
                s.checker.model_on = false;
                for n in s.checker.nodes.values_mut() {
                    if n.model == NodeSwitch::On {
                        n.model = NodeSwitch::Inherit;
                    }
                }
                s.checker.nodes.retain(|_, n| *n != NodeSettings::default());
            }
        });
        self.rebuild_checker();
        self.changed(Change::Nodes);
        match last {
            Ok(()) => {
                self.note(
                    Level::Info,
                    None,
                    "the action checker's local model was removed",
                );
                Ok(())
            }
            Err(e) => {
                let e = format!("the local model is off, but not every file could be deleted: {e}");
                self.note(Level::Warn, None, format!("the action checker: {e}"));
                Err(e)
            }
        }
    }

    /// Adds a checker audit entry (a center decision) to the feed and the log.
    /// `scope` says whether the entry, rule or switch behind it was the
    /// center's for every node or this node's own.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn audit_checker(
        &self,
        sess: &Arc<Session>,
        route: &Route,
        target: &str,
        decision: &str,
        layer: Layer,
        scope: Scope,
        detail: &str,
        args: &Map<String, Value>,
        marked: &[(String, PathMark)],
        params: &Value,
    ) {
        let node = self.node_name(&route.node_id);
        let mut e = Map::new();
        e.insert("ts".into(), json!(now_ms()));
        e.insert("cap".into(), json!(route.cap));
        e.insert("action".into(), json!(route.action));
        e.insert("target".into(), json!(target));
        e.insert("decision".into(), json!(decision));
        if decision == "forbidden" {
            e.insert("code".into(), json!("forbidden"));
        }
        e.insert("session".into(), json!(sess.id));
        e.insert("by".into(), json!("action checker"));
        e.insert("node_id".into(), json!(route.node_id));
        e.insert("node".into(), json!(node));
        e.insert(
            "checker".into(),
            json!({"layer": layer.as_str(), "scope": scope.as_str(), "detail": detail}),
        );
        // What its allow buttons may pin, as a node's entry has it, a path
        // argument as the checker matched it.
        // Only the arguments the schema names, as the node's entries have
        // them: an open schema lets junk keys through, and they would push
        // the real ones out of the choices.
        let args = nerve_policy::conditions::declared(
            params,
            &checker::blocklist::as_matched(args, marked),
            true,
        );
        if let Some(args) = nerve_policy::audit::pinnable_args(&route.cap, &route.action, &args) {
            e.insert("args".into(), Value::Object(args));
        }
        lock(&self.audit).push(Value::Object(e));
        self.changed(Change::Audit);
        let (level, verb) = if decision == "forbidden" {
            (Level::Warn, "refused")
        } else {
            (Level::Info, "allowed")
        };
        self.note(
            level,
            Some(&route.node_id),
            format!(
                "the action checker {verb} {}.{} by its {} {} ({detail})",
                route.cap,
                route.action,
                layer.as_str(),
                match scope {
                    Scope::Global => "for every node",
                    Scope::Node => "for this node",
                }
            ),
        );
    }
}

/// The owner's blocklist entries and allow rules that name a capability, or
/// an action of one, that no paired node publishes (the one node for a
/// rule of one node): they match no call now, which the checker page says,
/// since a misspelt name looks like a rule in force. An `fs`, `fs.read` or
/// `fs.write` blocklist entry also holds the path arguments of the other
/// capabilities, so it is in force where some capability has an argument
/// marked for it, `fs` published or not; an allow rule is matched against
/// the call's own target only, so it is not. Nothing is said while no node
/// has published anything, and the built-in entries name the node's own
/// capabilities.
fn unpublished_rules(cfg: &CheckerConfig, nodes: &BTreeMap<String, NodeRecord>) -> Vec<String> {
    if nodes.values().all(|n| n.descriptor.is_none()) {
        return Vec::new();
    }
    let publishes = |n: &NodeRecord, cap: &str, action: Option<&str>, by_path: bool| {
        let Some(d) = n.descriptor.as_ref() else {
            return false;
        };
        if d.capability(cap)
            .is_some_and(|c| action.is_none_or(|a| c.actions.contains_key(a)))
        {
            return true;
        }
        let held = |mark: PathMark| match action {
            None => true,
            Some("read") => mark == PathMark::Read,
            Some("write") => mark == PathMark::Write,
            Some(_) => false,
        };
        by_path
            && cap == "fs"
            && d.capabilities
                .iter()
                .flat_map(|c| c.actions.values())
                .flat_map(|a| nerve_proto::schema::path_args(&a.params))
                .any(|(_, mark)| held(mark))
    };
    let own = cfg.blocklist.iter().filter(|e| !e.builtin);
    let rules = own
        .map(|e| (&e.rule, &e.node_id, true))
        .chain(cfg.allow_rules.iter().map(|a| (&a.rule, &a.node_id, false)));
    let mut out: Vec<String> = Vec::new();
    for (rule, node, by_path) in rules {
        let scope = rule.split_once(':').map_or(rule.as_str(), |(s, _)| s);
        let (cap, action) = match scope.split_once('.') {
            Some((c, a)) => (c, Some(a)),
            None => (scope, None),
        };
        let known = match node {
            // A rule for a machine no longer paired is shown as such.
            Some(id) => nodes
                .get(id)
                .is_none_or(|n| publishes(n, cap, action, by_path)),
            None => nodes.values().any(|n| publishes(n, cap, action, by_path)),
        };
        if !known && !out.contains(rule) {
            out.push(rule.clone());
        }
    }
    out
}

/// The arguments schemas the machines publish for `cap.action`: of the one
/// machine `node`, or of every one that has it.
fn published_params(
    nodes: &BTreeMap<String, NodeRecord>,
    node: Option<&str>,
    unit: &str,
) -> Vec<(String, Value)> {
    nodes
        .iter()
        .filter(|(id, _)| node.is_none_or(|n| n == id.as_str()))
        .filter_map(|(_, n)| {
            n.catalog
                .unit(unit)
                .map(|u| (n.name.clone(), u.params.clone()))
        })
        .collect()
}

/// Checks the conditions of a checker rule as it is written, against the
/// schema the machine it is for publishes (for every machine: one that
/// publishes the action): an argument the action does not take, a value
/// not of its type, or an action no machine offers is refused. A rule
/// without conditions, or one that does not parse, is left to
/// [`Rule::parse`].
fn checker_typed(
    rule: &str,
    node: Option<&str>,
    nodes: &BTreeMap<String, NodeRecord>,
) -> Result<(), String> {
    if !nerve_policy::rules::has_conditions(rule) || Rule::parse(rule).is_err() {
        return Ok(());
    }
    let (scope, pattern) = rule.split_once(':').expect("has conditions");
    let found = published_params(nodes, node, scope);
    let mut first = None;
    for (_, params) in &found {
        match nerve_policy::conditions::check(scope, pattern, params) {
            Ok(()) => return Ok(()),
            Err(e) => {
                first.get_or_insert(e);
            }
        }
    }
    Err(match first {
        Some(e) => format!("rule {rule:?}: {e}"),
        None => format!(
            "rule {rule:?}: {} offers {scope} now, so its arguments cannot be checked; add the rule once it is offered",
            if node.is_some() {
                "this machine no longer"
            } else {
                "no machine"
            }
        ),
    })
}

/// Refuses a blocklist entry with a `!=` on a path from the home
/// (`notes.save:file!=~/inbox.md`): the center cannot tell a home, so the
/// entry would refuse every call of the action, the inbox's too. An absolute
/// path works.
fn blocklist_typed(
    rule: &str,
    node: Option<&str>,
    nodes: &BTreeMap<String, NodeRecord>,
) -> Result<(), String> {
    if !nerve_policy::rules::has_conditions(rule) {
        return Ok(());
    }
    let Some((scope, pattern)) = rule.split_once(':') else {
        return Ok(());
    };
    for (_, params) in published_params(nodes, node, scope) {
        if let Some(c) = nerve_policy::conditions::home_not_equal(pattern, &params) {
            return Err(format!(
                "rule {rule:?}: the center cannot tell the home in {c}, so the entry would refuse every call of {scope}; write the path in full (/home/…)"
            ));
        }
    }
    Ok(())
}

/// The arguments a rule may name for each action the machines publish
/// (`lamp.set` → `room (a string)`, …), for the checker page's forms: the
/// first machine's that has the action. An `fs` action and `exec.run` take
/// a path or a command line instead, and an action whose arguments a rule
/// cannot name is left out.
fn rule_fields(nodes: &BTreeMap<String, NodeRecord>) -> Value {
    let mut out = Map::new();
    for n in nodes.values() {
        for u in &n.catalog.units {
            if catalog::is_center(u)
                || out.contains_key(&u.name)
                || !nerve_policy::conditions::takes_conditions(&u.name)
            {
                continue;
            }
            let fields = nerve_policy::conditions::fields(&u.params);
            if !fields.is_empty() {
                out.insert(u.name.clone(), json!(fields));
            }
        }
    }
    Value::Object(out)
}

/// The owner's blocklist entries and allow rules whose conditions no longer
/// fit what a machine publishes for their action (an argument gone, or of
/// another type, a value it no longer takes), each with why: such a rule
/// no longer decides that machine's calls as written. A rule for every
/// machine is flagged where any one that publishes the action does not fit
/// it, naming that machine, for a blocklist entry there may refuse every
/// call. A rule whose action no machine publishes is [`unpublished_rules`]'.
fn stale_checker_rules(cfg: &CheckerConfig, nodes: &BTreeMap<String, NodeRecord>) -> Value {
    let own = cfg.blocklist.iter().filter(|e| !e.builtin);
    let rules = own.map(|e| (&e.rule, e.node_id.as_deref(), true)).chain(
        cfg.allow_rules
            .iter()
            .map(|a| (&a.rule, a.node_id.as_deref(), false)),
    );
    let mut out = Map::new();
    for (rule, node, blocks) in rules {
        if !nerve_policy::rules::has_conditions(rule) || out.contains_key(rule) {
            continue;
        }
        let (scope, pattern) = rule.split_once(':').expect("has conditions");
        let found = published_params(nodes, node, scope);
        if found.is_empty() {
            continue;
        }
        // A blocklist entry that types can still refuse every call: a `!=`
        // from the home on a field that became a path after the entry was
        // saved (the save checks only the schemas of its day).
        let misfit = found.iter().find_map(|(name, p)| {
            let err = nerve_policy::conditions::check(scope, pattern, p).err();
            let err = err.or_else(|| {
                blocks
                    .then(|| nerve_policy::conditions::home_not_equal(pattern, p))
                    .flatten()
                    .map(|c| {
                        format!(
                            "the center cannot tell the home in {c}, so the entry refuses every call of {scope}; write the path in full (/home/…)"
                        )
                    })
            });
            err.map(|e| (name, e))
        });
        if let Some((name, e)) = misfit {
            let why = if node.is_some() {
                e
            } else {
                format!("on {name}: {e}")
            };
            out.insert(rule.clone(), json!(why));
        }
    }
    Value::Object(out)
}

/// Why no audit button puts a command on a machine's sudo list.
pub const SUDO_LIST_OWNER_ONLY: &str =
    "only the machine's owner puts a command on the sudo list, on the machine itself";

/// The list and the rule an audit button means: the entry's `cap`, `action`
/// and `target`, the list (`allow` or `deny`; never `sudo`),
/// whether it is the wildcard form, and the argument it pins with its value
/// (one of the entry's `args`), if it pins one.
pub fn audit_rule(
    list: &str,
    cap: &str,
    action: &str,
    target: &str,
    wildcard: bool,
    pin: Option<(&str, &Value)>,
) -> Result<String, String> {
    // A cut target is no longer the call's, so no rule can be made from it.
    // Only a command line or a path is named by a rule; any other action's
    // rule is its `cap.action`, whatever its (path argument) target.
    if (cap == "fs" || (cap, action) == ("exec", "run"))
        && nerve_policy::audit::is_cut_target(target)
    {
        return Err("the target was cut to its start, so a rule cannot name it".into());
    }
    match list {
        "allow" | "deny" => nerve_policy::rules::rule_for(cap, action, target, wildcard, pin),
        // Its commands run as root, so the machine takes that list from its
        // owner only (nerve-policy's client_only); the Audit page says where.
        "sudo" => Err(SUDO_LIST_OWNER_ONLY.into()),
        _ => Err("the list is allow or deny".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::center::tests::{exec_route, node_record, online, open};

    /// The checker gate refuses a blocklisted command before the node, with a
    /// message that says the action checker did it; an ordinary command is
    /// not refused by it (it reaches the send instead, which fails on the
    /// test's link whose connection is gone). This is the whole point of the
    /// gate, so without it the blocklisted command would get the same end.
    #[tokio::test]
    async fn the_checker_refuses_a_blocklisted_command_before_the_node() {
        let dir = tempfile::tempdir().unwrap();
        let c = open(dir.path(), None);
        c.update(|s| {
            s.nodes.insert("n1".into(), node_record("n1", "linux"));
        });
        online(&c, "n1");
        let sess = c.new_session("test");
        let args = |cmd: &str| {
            let mut m = Map::new();
            m.insert("command".into(), json!(cmd));
            m
        };
        // Blocklisted: refused by the checker.
        let e = c
            .call(&sess, &exec_route("n1"), args("rm -rf /"))
            .await
            .unwrap_err();
        let CallError::Rpc(e) = e;
        assert_eq!(e.kind(), ErrorCode::Forbidden);
        assert!(e.message.contains("action checker"), "{}", e.message);
        // The refusal is in the audit feed, marked as the checker's.
        let last = c.audit().pop().unwrap();
        assert_eq!(last["by"], "action checker");
        assert_eq!(last["checker"]["layer"], "blocklist");
        // Ordinary work passes the checker and is sent.
        let e = c
            .call(&sess, &exec_route("n1"), args("git status"))
            .await
            .unwrap_err();
        let CallError::Rpc(e) = e;
        assert_eq!(e.kind(), ErrorCode::ConnectionLost);
    }

    /// The model is sent what the center's catalog says of the unit and the
    /// path the call names: a real call through `Center::call` to a fake
    /// System One endpoint, and the state it received is read back.
    #[tokio::test]
    async fn the_model_is_sent_a_provider_calls_effect_description_and_path() {
        use crate::tools::tests::{cap, desc};
        use std::io::{Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        listener.set_nonblocking(true).unwrap();
        let asked = std::thread::spawn(move || {
            // A call that never asks the model fails the test, not hangs it.
            let started = Instant::now();
            let mut conn = loop {
                match listener.accept() {
                    Ok((conn, _)) => break conn,
                    Err(_) if started.elapsed() < Duration::from_secs(10) => {
                        std::thread::sleep(Duration::from_millis(20));
                    }
                    Err(_) => return Value::Null,
                }
            };
            conn.set_nonblocking(false).unwrap();
            conn.set_read_timeout(Some(Duration::from_secs(10)))
                .unwrap();
            let mut got = Vec::new();
            let mut buf = [0u8; 4096];
            let body = loop {
                let n = conn.read(&mut buf).unwrap();
                got.extend_from_slice(&buf[..n]);
                let text = String::from_utf8_lossy(&got).into_owned();
                if let Some((head, body)) = text.split_once("\r\n\r\n") {
                    let want = head
                        .lines()
                        .find_map(|l| {
                            l.to_ascii_lowercase()
                                .strip_prefix("content-length: ")?
                                .parse()
                                .ok()
                        })
                        .unwrap_or(0usize);
                    if body.len() >= want {
                        break body.to_string();
                    }
                }
            };
            let answer = r#"{"answers":{"danger":{"type":"noul","noul":0.01}}}"#;
            let _ = write!(
                conn,
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{answer}",
                answer.len()
            );
            serde_json::from_str::<Value>(&body).unwrap()
        });
        let dir = tempfile::tempdir().unwrap();
        let c = open(dir.path(), None);
        let params = json!({"type": "object",
            "properties": {"path": {"type": "string", "x-nerve-path": "write"},
                           "text": {"type": "string"}}});
        let mut notes = cap(
            "notes",
            "notes",
            &[("save", nerve_proto::Effect::Write, params)],
        );
        notes.provider = "notesd".into();
        c.update(|s| {
            let mut n = node_record("n1", "linux");
            n.set_descriptor(desc("n1", vec![notes]));
            s.nodes.insert("n1".into(), n);
            s.checker.model_on = true;
            s.checker.model.source = ModelSource::Endpoint;
            s.checker.model.endpoint_url = format!("http://127.0.0.1:{port}");
        });
        c.rebuild_checker();
        online(&c, "n1");
        let sess = c.new_session("test");
        let route = Route {
            node_id: "n1".into(),
            node_name: "n1".into(),
            cap: "notes".into(),
            action: "save".into(),
            effect: nerve_proto::Effect::Write,
            kind: nerve_proto::UnitKind::Action,
        };
        let mut args = Map::new();
        args.insert("path".into(), json!("/home/me/notes/today.md"));
        args.insert("text".into(), json!("hello"));
        // The fake model scores it low, so the call goes on to the (test)
        // link, which is gone.
        let CallError::Rpc(e) = c.call(&sess, &route, args).await.unwrap_err();
        assert_eq!(e.kind(), ErrorCode::ConnectionLost, "{}", e.message);
        let body = asked.join().unwrap();
        let state = &body["state"];
        assert_eq!(state["capability"], "notes");
        assert_eq!(state["action"], "save");
        assert_eq!(state["effect"], "write");
        assert_eq!(state["description"], "save: save it (notes summary)");
        assert_eq!(state["target"], "/home/me/notes/today.md");
        assert!(state["args"].as_str().unwrap().contains("hello"), "{state}");
        let last = c.audit().pop().unwrap();
        assert_eq!(last["checker"]["layer"], "model");
        assert_eq!(last["target"], "/home/me/notes/today.md");
    }

    /// An `exec.run` command's working folder is a path it reads, so an
    /// `fs.read` entry on that folder refuses the command, and the audit
    /// still names the command.
    #[tokio::test]
    async fn a_commands_working_folder_meets_the_fs_read_entries() {
        use crate::tools::tests::{cap, desc};
        let dir = tempfile::tempdir().unwrap();
        let c = open(dir.path(), None);
        let params = json!({"type": "object",
            "properties": {"command": {"type": "string"},
                           "cwd": {"type": "string", "x-nerve-path": "read"}}});
        let exec = cap(
            "exec",
            "exec",
            &[("run", nerve_proto::Effect::Execute, params)],
        );
        c.update(|s| {
            let mut n = node_record("n1", "linux");
            n.set_descriptor(desc("n1", vec![exec]));
            s.nodes.insert("n1".into(), n);
            s.checker.blocklist.push(checker::BlockEntry {
                id: String::new(),
                rule: "fs.read:/srv/secret/*".into(),
                on: true,
                builtin: false,
                note: String::new(),
                node_id: None,
                off_for: Vec::new(),
            });
        });
        c.rebuild_checker();
        online(&c, "n1");
        let sess = c.new_session("test");
        let mut args = Map::new();
        args.insert("command".into(), json!("make test"));
        args.insert("cwd".into(), json!("/srv/secret/work"));
        let CallError::Rpc(e) = c.call(&sess, &exec_route("n1"), args).await.unwrap_err();
        assert_eq!(e.kind(), ErrorCode::Forbidden, "{}", e.message);
        assert!(
            e.message.contains("path argument /srv/secret/work"),
            "{}",
            e.message
        );
        let last = c.audit().pop().unwrap();
        assert_eq!(last["checker"]["layer"], "blocklist");
        assert_eq!(last["target"], "make test");
    }

    /// A pattern that cannot match anything is refused when the owner saves
    /// it, and one already stored is left out of the checker and reported.
    #[test]
    fn a_rule_that_cannot_match_is_refused_on_save_and_reported_when_stored() {
        let dir = tempfile::tempdir().unwrap();
        let c = open(dir.path(), None);
        let entry = |rule: &str| checker::BlockEntry {
            id: String::new(),
            rule: rule.into(),
            on: true,
            builtin: false,
            note: String::new(),
            node_id: None,
            off_for: Vec::new(),
        };
        let mut cfg = c.read(|s| s.checker.clone());
        cfg.blocklist.push(entry("lamp.set:office"));
        let why = c.apply_checker_config(cfg).unwrap_err();
        assert!(why.contains("comes =, !=, <, <=, >, >= or ~"), "{why}");
        let mut cfg = c.read(|s| s.checker.clone());
        cfg.allow_rules.push(AllowRule {
            rule: "exec:rm *".into(),
            node_id: None,
        });
        let why = c.apply_checker_config(cfg).unwrap_err();
        assert!(why.contains("exec.run:rm *"), "{why}");
        // Stored by an older center: out of force, and named on the page.
        c.update(|s| s.checker.blocklist.push(entry("lamp.set:office")));
        c.rebuild_checker();
        let rejected = c.checker_json()["rejected"].clone();
        assert_eq!(rejected.as_array().unwrap().len(), 1, "{rejected}");
        assert!(rejected[0].as_str().unwrap().contains("lamp.set:office"));
        assert!(c.checker().rejected[0].contains("lamp.set:office"));
    }

    /// A blocklist entry `!=` a path from the home is refused when it is
    /// written: the center cannot tell a home, so it would refuse every call
    /// of the action. An absolute path is taken, and so is the same on a
    /// plain string argument.
    #[test]
    fn a_blocklist_entry_the_center_cannot_tell_is_refused_on_save() {
        use crate::tools::tests::{cap, desc};
        let dir = tempfile::tempdir().unwrap();
        let c = open(dir.path(), None);
        let params = json!({"type": "object",
            "properties": {"file": {"type": "string", "x-nerve-path": "write"},
                           "tag": {"type": "string"}}});
        let notes = cap(
            "notes",
            "notes",
            &[("save", nerve_proto::Effect::Write, params)],
        );
        c.update(|s| {
            let mut n = node_record("n1", "linux");
            n.set_descriptor(desc("n1", vec![notes]));
            s.nodes.insert("n1".into(), n);
        });
        let add = |rule: &str| {
            let mut cfg = c.read(|s| s.checker.clone());
            cfg.blocklist.push(checker::BlockEntry {
                id: String::new(),
                rule: rule.into(),
                on: true,
                builtin: false,
                note: String::new(),
                node_id: None,
                off_for: Vec::new(),
            });
            c.apply_checker_config(cfg)
        };
        let e = add("notes.save:file!=~/inbox.md").unwrap_err();
        assert!(e.contains("cannot tell the home"), "{e}");
        add("notes.save:file!=/home/me/inbox.md").unwrap();
        add("notes.save:tag!=~/x").unwrap();
    }

    /// A blocklist entry saved while its field was plain text is flagged
    /// once the field becomes a path, for it would refuse every call then.
    #[test]
    fn a_blocklist_entry_a_later_path_makes_blind_is_flagged() {
        use crate::tools::tests::{cap, desc};
        let dir = tempfile::tempdir().unwrap();
        let c = open(dir.path(), None);
        let publish = |tag: Value| {
            let params = json!({"type": "object", "properties": {"tag": tag}});
            let notes = cap(
                "notes",
                "notes",
                &[("save", nerve_proto::Effect::Write, params)],
            );
            c.update(|s| {
                let mut n = node_record("n1", "linux");
                n.set_descriptor(desc("n1", vec![notes]));
                s.nodes.insert("n1".into(), n);
            });
        };
        publish(json!({"type": "string"}));
        let mut cfg = c.read(|s| s.checker.clone());
        cfg.blocklist.push(checker::BlockEntry {
            id: String::new(),
            rule: "notes.save:tag!=~/drafts".into(),
            on: true,
            builtin: false,
            note: String::new(),
            node_id: None,
            off_for: Vec::new(),
        });
        c.apply_checker_config(cfg).unwrap();
        assert_eq!(c.checker_json()["stale"], json!({}));
        publish(json!({"type": "string", "x-nerve-path": "write"}));
        let stale = c.checker_json()["stale"].clone();
        let why = stale["notes.save:tag!=~/drafts"].as_str().unwrap_or("");
        assert!(why.contains("cannot tell the home"), "{stale:?}");
    }

    /// **Allow** on an audited command saves that line exactly: its rule
    /// covers no other line. **Allow as wildcard** saves the program and
    /// `*`.
    #[test]
    fn the_allow_button_saves_the_exact_command_line() {
        let dir = tempfile::tempdir().unwrap();
        let c = open(dir.path(), None);
        let rule = c
            .add_checker_allow("exec", "run", "  git status  ", false, None, None)
            .unwrap();
        assert_eq!(rule, "exec.run:exact:git status");
        let rule = c
            .add_checker_allow("exec", "run", "git status", true, None, None)
            .unwrap();
        assert_eq!(rule, "exec.run:git *");
        let saved: Vec<String> = c.read(|s| {
            s.checker
                .allow_rules
                .iter()
                .map(|a| a.rule.clone())
                .collect()
        });
        assert_eq!(saved, ["exec.run:exact:git status", "exec.run:git *"]);
        let exact = Rule::parse("exec.run:exact:git status").unwrap();
        let at = |line: &'static str| crate::checker::blocklist::Call {
            cap: "exec",
            action: "run",
            target: line,
            args: None,
            marked: &[],
        };
        assert!(exact.matches(&at("git status")));
        assert!(!exact.matches(&at("git status; rm -rf ~")));
        assert!(Rule::parse("exec.run:exact:  ").is_err());
    }

    /// A checker rule with conditions is checked against the schema the
    /// machines publish as it is written: an argument the action does not
    /// take, a value not of its type, or an action no machine (or not the
    /// rule's machine) offers is refused, from the page and from an audit
    /// button. A stored rule whose argument went since is flagged.
    #[test]
    fn a_checker_rules_conditions_are_typed_against_the_catalog() {
        use crate::tools::tests::{cap, desc};
        let dir = tempfile::tempdir().unwrap();
        let c = open(dir.path(), None);
        let lamp = |props: Value| {
            cap(
                "lamp",
                "lamp",
                &[(
                    "set",
                    nerve_proto::Effect::Actuate,
                    json!({"type": "object", "properties": props}),
                )],
            )
        };
        let full = json!({"room": {"type": "string"}, "brightness": {"type": "integer"}});
        c.update(|s| {
            let mut n = node_record("n1", "linux");
            n.set_descriptor(desc("n1", vec![lamp(full.clone())]));
            s.nodes.insert("n1".into(), n);
            s.nodes.insert("n2".into(), node_record("n2", "linux"));
        });
        let add = |rule: &str, node: Option<&str>| {
            let mut cfg = c.read(|s| s.checker.clone());
            cfg.blocklist.push(checker::BlockEntry {
                id: String::new(),
                rule: rule.into(),
                on: true,
                builtin: false,
                note: String::new(),
                node_id: node.map(str::to_string),
                off_for: Vec::new(),
            });
            c.apply_checker_config(cfg)
        };
        add("lamp.set:room=office,brightness>50", None).unwrap();
        add("lamp.set:room=office", Some("n1")).unwrap();
        for (rule, node, why) in [
            (
                "lamp.set:size=2",
                None,
                "lamp.set has no argument size; it takes brightness, room",
            ),
            ("lamp.set:brightness=high", None, "is an integer"),
            (
                "lamp.off:room=office",
                None,
                "no machine offers lamp.off now",
            ),
            (
                "lamp.set:room=hall",
                Some("n2"),
                "this machine no longer offers lamp.set",
            ),
        ] {
            let e = add(rule, node).unwrap_err();
            assert!(e.contains(why), "{rule}: {e}");
        }
        let one = json!("hall");
        let e = c
            .add_checker_allow("lamp", "off", "lamp.off", false, Some(("room", &one)), None)
            .unwrap_err();
        assert!(e.contains("no machine offers lamp.off now"), "{e}");
        assert_eq!(
            c.add_checker_allow("lamp", "set", "lamp.set", false, Some(("room", &one)), None)
                .unwrap(),
            "lamp.set:room=hall"
        );
        assert_eq!(c.checker_json()["stale"], json!({}));
        // The machine publishes the action without `room` now: the rules
        // that name it are flagged, and the config still saves as it is.
        c.update(|s| {
            let n = s.nodes.get_mut("n1").unwrap();
            n.set_descriptor(desc(
                "n1",
                vec![lamp(json!({"brightness": {"type": "integer"}}))],
            ));
        });
        let stale = c.checker_json()["stale"].clone();
        let stale = stale.as_object().unwrap();
        assert_eq!(
            stale.keys().collect::<Vec<_>>(),
            [
                "lamp.set:room=hall",
                "lamp.set:room=office",
                "lamp.set:room=office,brightness>50"
            ],
            "{stale:?}"
        );
        assert!(
            stale["lamp.set:room=office"]
                .as_str()
                .unwrap()
                .contains("no argument room")
        );
        c.apply_checker_config(c.read(|s| s.checker.clone()))
            .unwrap();
        // A rule for every machine that one of them no longer fits is
        // flagged, naming that machine, while another still fits it.
        c.update(|s| {
            let mut n = node_record("n2", "linux");
            n.set_descriptor(desc("n2", vec![lamp(full.clone())]));
            s.nodes.insert("n2".into(), n);
        });
        let stale = c.checker_json()["stale"].clone();
        assert_eq!(
            stale["lamp.set:room=office,brightness>50"],
            json!("on n1: lamp.set has no argument room; it takes brightness"),
            "{stale}"
        );
        assert_eq!(
            stale["lamp.set:room=office"],
            json!("lamp.set has no argument room; it takes brightness"),
            "{stale}"
        );
    }

    /// An `fs` entry holds the path arguments of other capabilities, so it
    /// is not called dead where a program takes a path for it, `fs`
    /// published or not; a typo and an entry no path argument can meet are.
    #[test]
    fn an_fs_entry_is_in_force_where_a_program_takes_a_path() {
        use crate::tools::tests::{cap, desc};
        let dir = tempfile::tempdir().unwrap();
        let c = open(dir.path(), None);
        let entry = |rule: &str| checker::BlockEntry {
            id: String::new(),
            rule: rule.into(),
            on: true,
            builtin: false,
            note: String::new(),
            node_id: None,
            off_for: Vec::new(),
        };
        let params = json!({"type": "object",
            "properties": {"path": {"type": "string", "x-nerve-path": "write"}}});
        let mut notes = cap(
            "notes",
            "notes",
            &[("save", nerve_proto::Effect::Write, params)],
        );
        notes.provider = "notesd".into();
        c.update(|s| {
            let mut n = node_record("n1", "linux");
            n.set_descriptor(desc("n1", vec![notes]));
            s.nodes.insert("n1".into(), n);
            s.checker.blocklist.extend([
                entry("fs.write:/home/*/.config/autostart/*"),
                entry("fs:/srv/*"),
                entry("fs.read:/srv/secret/*"),
                entry("fs.wirte:/etc/*"),
            ]);
            // An allow rule is matched against a call's own target only, so
            // a path argument does not put it in force.
            s.checker.allow_rules.push(AllowRule {
                rule: "fs.write:/home/*/notes/*".into(),
                node_id: None,
            });
        });
        // The program writes a path; nothing reads one, and `fs` is not
        // published here.
        assert_eq!(
            c.checker_json()["unpublished"],
            json!([
                "fs.read:/srv/secret/*",
                "fs.wirte:/etc/*",
                "fs.write:/home/*/notes/*"
            ])
        );
    }

    /// The checker page is told which of the owner's rules name a
    /// capability or action no paired node publishes (for a rule of one
    /// node, that node), and none while no node has published anything.
    #[test]
    fn a_rule_naming_a_capability_no_node_publishes_is_warned_about() {
        use crate::tools::tests::{cap, desc};
        let dir = tempfile::tempdir().unwrap();
        let c = open(dir.path(), None);
        let rule = |r: &str, node: Option<&str>| AllowRule {
            rule: r.into(),
            node_id: node.map(str::to_string),
        };
        c.update(|s| {
            s.nodes.insert("n1".into(), node_record("n1", "linux"));
            s.nodes.insert("n2".into(), node_record("n2", "linux"));
            s.checker.allow_rules = vec![
                rule("lamp.set", None),
                rule("lamp.sett", None),
                rule("lamp", Some("n2")),
                rule("notes", None),
                rule("exec.run:make *", None),
            ];
            s.checker.blocklist.push(checker::BlockEntry {
                id: String::new(),
                rule: "fs.wirte:/etc/*".into(),
                on: true,
                builtin: false,
                note: String::new(),
                node_id: None,
                off_for: Vec::new(),
            });
        });
        assert_eq!(c.checker_json()["unpublished"], json!([]));
        let lamp = cap(
            "lamp",
            "lamp",
            &[("set", nerve_proto::Effect::Actuate, json!({}))],
        );
        let exec = cap(
            "exec",
            "exec",
            &[("run", nerve_proto::Effect::Execute, json!({}))],
        );
        c.update(|s| {
            let n1 = s.nodes.get_mut("n1").unwrap();
            n1.set_descriptor(desc("n1", vec![lamp, exec]));
        });
        assert_eq!(
            c.checker_json()["unpublished"],
            json!(["fs.wirte:/etc/*", "lamp.sett", "lamp", "notes"])
        );
    }

    /// A question longer than every model's context holds beside the
    /// largest state is refused at the save with the local source (#178),
    /// counted as the model reads it: a control character as its six-byte
    /// escape.
    #[test]
    fn a_question_too_long_for_the_context_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let c = open(dir.path(), None);
        let with = |instructions: String| {
            let mut cfg = c.read(|s| s.checker.clone());
            cfg.model.instructions = instructions;
            cfg
        };
        let m = c.read(|s| s.checker.model.clone());
        let criteria = m.criteria_true.len() + m.criteria_false.len();
        let fits = checker::config::QUESTION_MAX - criteria;
        c.apply_checker_config(with("x".repeat(fits))).unwrap();
        let e = c
            .apply_checker_config(with("x".repeat(fits + 1)))
            .unwrap_err();
        assert!(e.contains("at most 2000 fit"), "{e}");
        assert_eq!(c.read(|s| s.checker.model.instructions.len()), fits);
        let e = c
            .apply_checker_config(with(format!("{}\u{1}", "x".repeat(fits - 5))))
            .unwrap_err();
        assert!(e.contains("is 2001 bytes"), "{e}");
        // An endpoint's context is not the center's: a longer question
        // saves there (review r2), and other settings with it.
        let mut cfg = with("x".repeat(fits + 1000));
        cfg.model.source = ModelSource::Endpoint;
        cfg.model_on = !cfg.model_on;
        c.apply_checker_config(cfg).unwrap();
        assert_eq!(c.read(|s| s.checker.model.instructions.len()), fits + 1000);
    }

    /// A block entry for one node and a global entry switched off for
    /// another: each node gets what the owner set for it, and the audit says
    /// whether the entry was the global one or the node's. A posted config
    /// with an exception on a one-node entry is refused, and nodes that only
    /// inherit are not kept.
    #[tokio::test]
    async fn per_node_block_entries_are_audited_with_their_scope() {
        let dir = tempfile::tempdir().unwrap();
        let c = open(dir.path(), None);
        c.update(|s| {
            s.nodes.insert("n1".into(), node_record("n1", "linux"));
            s.nodes.insert("n2".into(), node_record("n2", "linux"));
        });
        online(&c, "n1");
        online(&c, "n2");
        let mut cfg = c.read(|s| s.checker.clone());
        let mut tf = cfg.blocklist[0].clone();
        tf.rule = "exec.run:terraform destroy".into();
        tf.builtin = false;
        tf.node_id = Some("n1".into());
        cfg.blocklist.push(tf.clone());
        cfg.blocklist
            .iter_mut()
            .find(|e| e.rule == "exec.run:rm -rf /")
            .unwrap()
            .off_for = vec!["n2".into(), "n2".into()];
        cfg.nodes.insert("n2".into(), NodeSettings::default());
        // An exception on a one-node entry is refused as a whole.
        let mut bad = cfg.clone();
        bad.blocklist.last_mut().unwrap().off_for.push("n2".into());
        assert!(c.apply_checker_config(bad).is_err());
        c.apply_checker_config(cfg).unwrap();
        let kept = c.read(|s| s.checker.clone());
        assert!(kept.nodes.is_empty(), "{:?}", kept.nodes);
        assert_eq!(
            kept.blocklist
                .iter()
                .find(|e| e.rule == "exec.run:rm -rf /")
                .unwrap()
                .off_for,
            ["n2"]
        );
        let sess = c.new_session("test");
        let run = |node: &'static str, cmd: &'static str| {
            let c = &c;
            let sess = &sess;
            async move {
                let mut m = Map::new();
                m.insert("command".into(), json!(cmd));
                let CallError::Rpc(e) = c.call(sess, &exec_route(node), m).await.unwrap_err();
                e
            }
        };
        let e = run("n1", "terraform destroy").await;
        assert_eq!(e.kind(), ErrorCode::Forbidden);
        assert!(
            e.message.contains("this node's own blocklist"),
            "{}",
            e.message
        );
        let last = c.audit().pop().unwrap();
        assert_eq!(last["checker"]["scope"], "node");
        assert_eq!(last["checker"]["detail"], "exec.run:terraform destroy");
        let e = run("n1", "rm -rf /").await;
        assert_eq!(e.kind(), ErrorCode::Forbidden);
        assert_eq!(c.audit().pop().unwrap()["checker"]["scope"], "global");
        // n2: no entry of its own, and `rm -rf /` switched off for it, so
        // both are sent to the node.
        assert_eq!(
            run("n2", "terraform destroy").await.kind(),
            ErrorCode::ConnectionLost
        );
        assert_eq!(
            run("n2", "rm -rf /").await.kind(),
            ErrorCode::ConnectionLost
        );
    }

    /// What the Action checker page reads: whether the model is on anywhere,
    /// also when only one machine has it on (so the page tells "its server
    /// is not running" from "turn the model on"), and the whole blocklist
    /// with the built-ins in full. A post of that config is taken back as is
    /// and saved as the owner's part only.
    #[test]
    fn the_checker_page_reads_the_model_on_for_one_machine_and_the_whole_list() {
        let dir = tempfile::tempdir().unwrap();
        let c = open(dir.path(), None);
        let v = c.checker_json();
        assert_eq!(v["model_wanted"], false);
        let list = v["config"]["blocklist"].as_array().unwrap();
        assert_eq!(list.len(), checker::config::default_blocklist().len());
        assert_eq!(list[0]["id"], "rm-root");
        assert_eq!(list[0]["builtin"], true);

        c.update(|s| {
            s.checker.nodes.insert(
                "n1".into(),
                NodeSettings {
                    blocklist: NodeSwitch::Inherit,
                    model: NodeSwitch::On,
                    ..Default::default()
                },
            );
        });
        let v = c.checker_json();
        assert_eq!(v["config"]["model_on"], false);
        assert_eq!(v["model_wanted"], true);

        // The page posts the list back with one built-in switched off.
        let mut config = v["config"].clone();
        config["blocklist"][0]["on"] = json!(false);
        let cfg: CheckerConfig = serde_json::from_value(config).unwrap();
        c.apply_checker_config(cfg).unwrap();
        let v = c.checker_json();
        assert_eq!(v["config"]["blocklist"][0]["on"], false);
        let saved: Value =
            serde_json::from_slice(&std::fs::read(dir.path().join("state.json")).unwrap()).unwrap();
        assert_eq!(
            saved["checker"]["blocklist"],
            json!({"builtins": {"rm-root": {"on": false}}})
        );
    }

    /// A command line nested too deeply for the splitter is refused by the
    /// gate (fail closed), not passed to the node (review r1, finding 1).
    #[tokio::test]
    async fn the_checker_refuses_a_command_line_it_cannot_take_apart() {
        let dir = tempfile::tempdir().unwrap();
        let c = open(dir.path(), None);
        c.update(|s| {
            s.nodes.insert("n1".into(), node_record("n1", "linux"));
        });
        online(&c, "n1");
        let sess = c.new_session("test");
        let mut args = Map::new();
        args.insert(
            "command".into(),
            json!(format!("echo {}", "$(".repeat(50_000))),
        );
        let e = c.call(&sess, &exec_route("n1"), args).await.unwrap_err();
        let CallError::Rpc(e) = e;
        assert_eq!(e.kind(), ErrorCode::Forbidden);
        assert!(e.message.contains("nests more than"), "{}", e.message);
    }

    /// With the model on but no endpoint set, the checker fails closed: a
    /// write call is refused because the model is unreachable.
    #[tokio::test]
    async fn the_model_fails_closed_when_it_cannot_be_reached() {
        let dir = tempfile::tempdir().unwrap();
        let c = open(dir.path(), None);
        c.update(|s| {
            s.nodes.insert("n1".into(), node_record("n1", "linux"));
            s.checker.model_on = true;
            // An endpoint source with no URL: nothing to reach.
            s.checker.model.source = ModelSource::Endpoint;
            s.checker.model.endpoint_url = String::new();
        });
        c.rebuild_checker();
        online(&c, "n1");
        let sess = c.new_session("test");
        let mut args = Map::new();
        args.insert("command".into(), json!("echo hi > out.txt"));
        let e = c.call(&sess, &exec_route("n1"), args).await.unwrap_err();
        let CallError::Rpc(e) = e;
        assert_eq!(e.kind(), ErrorCode::Forbidden);
        assert!(e.message.contains("reach"), "{}", e.message);
    }

    /// A fake release server for the install: the one connection it takes
    /// gets a head that promises 1000 bytes and ten of them, then nothing
    /// until the returned sender fires, when the connection is closed (so the
    /// download fails as cut short).
    #[cfg(unix)]
    fn held_download() -> (String, std::sync::mpsc::Sender<()>) {
        use std::io::{Read, Write};
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        let (tx, rx) = std::sync::mpsc::channel::<()>();
        std::thread::spawn(move || {
            if let Some(Ok(mut c)) = l.incoming().next() {
                let mut buf = [0u8; 4096];
                let _ = c.read(&mut buf);
                let _ = c.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 1000\r\n\r\n0123456789");
                let _ = rx.recv_timeout(Duration::from_secs(25));
            }
        });
        (format!("http://127.0.0.1:{port}"), tx)
    }

    /// An installed CPU build that is the fake `llama-server` (it answers as
    /// a decision model), with a d1-2B file it ignores.
    #[cfg(unix)]
    fn install_fake_build(state: &Path) {
        let bin = checker::install::llama_dir(state).join("bin");
        std::fs::create_dir_all(&bin).unwrap();
        checker::server::fake::fake_llama_server(&bin);
        std::fs::write(bin.parent().unwrap().join("variant"), "cpu").unwrap();
        let model = checker::install::model_path(state, LocalModel::D1_2b);
        std::fs::create_dir_all(model.parent().unwrap()).unwrap();
        std::fs::write(model, b"x").unwrap();
    }

    /// Waits up to 20 s for `f`.
    #[cfg(unix)]
    async fn until(what: &str, mut f: impl FnMut() -> bool) {
        let deadline = Instant::now() + Duration::from_secs(20);
        while !f() {
            assert!(Instant::now() < deadline, "timed out waiting for {what}");
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    #[cfg(unix)]
    fn local_ready(c: &Center) -> bool {
        c.local_model_status()
            .is_some_and(|s| s.phase == checker::server::Phase::Ready)
    }

    /// A center with the fake build installed and the local model on and
    /// ready.
    #[cfg(unix)]
    async fn center_with_a_running_model(dir: &Path) -> Center {
        install_fake_build(dir);
        let c = open(dir, None);
        c.update(|s| {
            s.checker.model_on = true;
            s.checker.model.source = ModelSource::Local;
        });
        c.rebuild_checker();
        until("the model to be ready", || local_ready(&c)).await;
        c
    }

    /// A local model that ended on a call keeps its endpoint while it starts
    /// again, so the client refuses the calls of that window; one that is
    /// merely down has none, and allow-and-log applies (review T2 of #178).
    #[cfg(unix)]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_local_model_that_ended_on_a_call_keeps_its_endpoint_while_it_starts_again() {
        tokio::time::timeout(Duration::from_secs(60), async {
            let dir = tempfile::tempdir().unwrap();
            let c = center_with_a_running_model(dir.path()).await;
            let checker = c.checker();
            assert!(c.resolved_endpoint(&checker).is_some());
            let pid =
                std::fs::read_to_string(checker::install::llama_dir(dir.path()).join("bin/pid"))
                    .unwrap();
            let killed = std::process::Command::new("kill")
                .args(["-9", pid.trim()])
                .status()
                .unwrap();
            assert!(killed.success());
            until("the model to end", || !local_ready(&c)).await;
            // Down, with no call lost: no endpoint.
            assert!(c.resolved_endpoint(&checker).is_none());
            let srv = c.local_model.lock().unwrap().clone().unwrap();
            srv.endpoint().budget.unwrap().die_on_call();
            assert!(c.resolved_endpoint(&checker).is_some());
            until("the model to be ready again", || local_ready(&c)).await;
            assert!(!srv.died_on_call());
        })
        .await
        .expect("the test did not finish within 60 s");
    }

    /// The local model runs when only a node has the model on, and Remove
    /// switches it off there too, so that node does not refuse every call
    /// for want of a model.
    #[cfg(unix)]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_node_with_the_model_on_runs_the_local_model_until_remove() {
        tokio::time::timeout(Duration::from_secs(60), async {
            let dir = tempfile::tempdir().unwrap();
            install_fake_build(dir.path());
            let c = open(dir.path(), None);
            c.update(|s| {
                s.checker.model_on = false;
                s.checker.model.source = ModelSource::Local;
                s.checker.nodes.insert(
                    "n1".into(),
                    NodeSettings {
                        blocklist: NodeSwitch::Off,
                        model: NodeSwitch::On,
                        ..Default::default()
                    },
                );
            });
            c.rebuild_checker();
            until("the model to be ready", || local_ready(&c)).await;
            c.remove_checker_model().await.unwrap();
            assert!(c.local_model_status().is_none());
            let n1 = c.read(|s| s.checker.nodes.get("n1").cloned());
            assert_eq!(
                n1,
                Some(NodeSettings {
                    blocklist: NodeSwitch::Off,
                    model: NodeSwitch::Inherit,
                    ..Default::default()
                })
            );
        })
        .await
        .expect("the test did not finish within 60 s");
    }

    /// A config save that only toggles taint.
    #[cfg(unix)]
    fn save_unrelated_change(c: &Center) {
        let mut cfg = c.read(|s| s.checker.clone());
        cfg.taint_on = !cfg.taint_on;
        c.apply_checker_config(cfg).unwrap();
    }

    /// An install keeps the running model judging calls while it downloads,
    /// a config save meanwhile does not disturb it, and a failed install
    /// leaves the working model installed and running (review r3, findings 2
    /// and 3).
    #[cfg(unix)]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_install_keeps_the_model_running_until_its_swap() {
        tokio::time::timeout(Duration::from_secs(60), async {
            let dir = tempfile::tempdir().unwrap();
            let c = center_with_a_running_model(dir.path()).await;
            let (base, release) = held_download();
            *c.install_from.lock().unwrap() = Arc::new(checker::install::Sources::at(&base));
            // The switch to the GPU build starts downloading.
            c.start_checker_install(true, LocalModel::D1_2b)
                .await
                .unwrap();
            until("the download to start", || {
                c.checker_install_status().llama.done >= 10
            })
            .await;
            assert!(local_ready(&c), "the model was stopped for the download");
            save_unrelated_change(&c);
            assert!(local_ready(&c), "a config save disturbed the running model");
            // The download fails: the CPU build is kept and still runs.
            release.send(()).unwrap();
            until("the install to fail", || {
                c.checker_install_status().phase == checker::install::Phase::Failed
            })
            .await;
            assert_eq!(checker::install::installed_variant(dir.path()), Some(false));
            until("the model to run again", || local_ready(&c)).await;
        })
        .await
        .expect("the test did not finish within 60 s");
    }

    /// A fake Hugging Face that answers each of two downloads with `body`.
    #[cfg(unix)]
    fn serve_model(body: &'static [u8]) -> String {
        use std::io::{Read, Write};
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        std::thread::spawn(move || {
            for c in l.incoming().take(2) {
                let Ok(mut c) = c else { continue };
                let mut buf = [0u8; 4096];
                let _ = c.read(&mut buf);
                let head = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                let _ = c.write_all(head.as_bytes());
                let _ = c.write_all(body);
            }
        });
        format!("http://127.0.0.1:{port}")
    }

    /// An install that reaches its swap brings the local server back: after
    /// a successful switch it runs the new model, and after a swap that fails
    /// the model it had (review r4, finding 6). The install stopped the
    /// server for the swap, so only its closing rebuild starts it again.
    #[cfg(unix)]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_install_brings_the_model_back_after_its_swap() {
        tokio::time::timeout(Duration::from_secs(60), async {
            let dir = tempfile::tempdir().unwrap();
            let c = center_with_a_running_model(dir.path()).await;
            const MODEL: &[u8] = b"a small stand-in for the model file";
            let base = serve_model(MODEL);
            *c.install_from.lock().unwrap() =
                Arc::new(checker::install::Sources::with_model(&base, MODEL));
            let phase = |c: &Center| c.checker_install_status().phase;
            // The switch to Kev-4B keeps the CPU build and swaps the model.
            c.start_checker_install(false, LocalModel::Kev4b)
                .await
                .unwrap();
            until("the install to finish", || {
                phase(&c) == checker::install::Phase::Done
            })
            .await;
            assert_eq!(c.read(|s| s.checker.model.local_model), LocalModel::Kev4b);
            assert!(!checker::install::model_path(dir.path(), LocalModel::D1_2b).exists());
            until("the new model to run", || local_ready(&c)).await;
            // A swap that fails: something is in the way where d1-2B's file
            // goes.
            let d1 = checker::install::model_path(dir.path(), LocalModel::D1_2b);
            std::fs::create_dir_all(d1.join("in-the-way")).unwrap();
            c.start_checker_install(false, LocalModel::D1_2b)
                .await
                .unwrap();
            until("the install to fail", || {
                phase(&c) == checker::install::Phase::Failed
            })
            .await;
            let st = c.checker_install_status();
            assert!(
                st.message.contains("put the model in place"),
                "{}",
                st.message
            );
            assert_eq!(c.read(|s| s.checker.model.local_model), LocalModel::Kev4b);
            until("the model it had to run again", || local_ready(&c)).await;
        })
        .await
        .expect("the test did not finish within 60 s");
    }

    /// While an install swaps the files (or Remove deletes them), a config
    /// save does not start the server from them; it starts again once they
    /// are free (review r3, finding 3).
    #[cfg(unix)]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_config_save_does_not_start_the_model_while_its_files_are_held() {
        tokio::time::timeout(Duration::from_secs(60), async {
            let dir = tempfile::tempdir().unwrap();
            let c = center_with_a_running_model(dir.path()).await;
            let held = c.hold_local_files().await;
            assert!(c.local_model_status().is_none());
            save_unrelated_change(&c);
            assert!(
                c.local_model_status().is_none(),
                "a config save started the server during the swap"
            );
            drop(held);
            c.rebuild_checker();
            until("the model to run again", || local_ready(&c)).await;
        })
        .await
        .expect("the test did not finish within 60 s");
    }

    /// Remove during a stalled download ends the install at once, and
    /// nothing of that install lands afterwards: its status stays reset and
    /// no file comes back (review r3, finding 5).
    #[cfg(unix)]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn remove_ends_a_stalled_install_for_good() {
        tokio::time::timeout(Duration::from_secs(60), async {
            let dir = tempfile::tempdir().unwrap();
            let c = open(dir.path(), None);
            let (base, release) = held_download();
            *c.install_from.lock().unwrap() = Arc::new(checker::install::Sources::at(&base));
            c.start_checker_install(false, LocalModel::D1_2b)
                .await
                .unwrap();
            until("the download to start", || {
                c.checker_install_status().llama.done >= 10
            })
            .await;
            let t = Instant::now();
            c.remove_checker_model().await.unwrap();
            assert!(t.elapsed() < Duration::from_secs(5), "{:?}", t.elapsed());
            assert_eq!(
                c.checker_install_status().phase,
                checker::install::Phase::Idle
            );
            // A second install starts while the first one's connection is
            // still open and silent.
            let (base2, release2) = held_download();
            *c.install_from.lock().unwrap() = Arc::new(checker::install::Sources::at(&base2));
            c.start_checker_install(false, LocalModel::D1_2b)
                .await
                .unwrap();
            until("the second download to start", || {
                c.checker_install_status().llama.done >= 10
            })
            .await;
            // The first connection now ends. A first task still waiting on it
            // would fail, clean up the staging folder the second one is
            // using, and could write its failure into the second's status.
            let _ = release.send(());
            tokio::time::sleep(Duration::from_millis(500)).await;
            let st = c.checker_install_status();
            assert_eq!(
                st.phase,
                checker::install::Phase::Downloading,
                "{}",
                st.message
            );
            let staging = checker::install::llama_dir(dir.path()).with_extension("staging");
            assert!(
                staging.exists(),
                "the first install removed the second's files"
            );
            let _ = release2.send(());
            until("the second install to end", || {
                c.checker_install_status().phase == checker::install::Phase::Failed
            })
            .await;
        })
        .await
        .expect("the test did not finish within 60 s");
    }
}
