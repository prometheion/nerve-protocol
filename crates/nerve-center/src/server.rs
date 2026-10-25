//! Starting the center: the node listener, the web UI, the HTTP MCP
//! endpoint and the attach socket. `main` and the end-to-end tests both go
//! through [`start`].

use std::net::SocketAddr;
use std::time::Duration;

use nerve_transport::log::Level;
use tokio::task::JoinHandle;

use crate::attach::Lock;
use crate::center::{Center, Options};
use crate::config::{Args, McpMode, is_loopback};
use crate::listen::{self, Server};
use crate::mcp::HttpMcp;
use crate::store::Store;
use crate::ui::Ui;

/// A running center. Dropping it stops its listeners; call
/// [`Running::stop`] to close the links cleanly first.
pub struct Running {
    pub center: Center,
    /// Where nodes reach the center.
    pub nodes: SocketAddr,
    pub ui: Option<SocketAddr>,
    pub mcp: Option<SocketAddr>,
    tasks: Vec<JoinHandle<()>>,
    _lock: Lock,
}

impl Running {
    /// Says bye to every node and stops the listeners.
    pub async fn stop(self) {
        self.center.shutdown().await;
        for t in &self.tasks {
            t.abort();
        }
        self.center
            .log()
            .record(Level::Info, None, "the center stopped");
    }
}

impl Drop for Running {
    fn drop(&mut self) {
        for t in &self.tasks {
            t.abort();
        }
    }
}

/// Opens the center in `args.state_dir()` (whose lock the caller holds) and
/// starts its listeners. MCP over stdio is not started here; the caller
/// runs [`crate::mcp::serve_stdio`] itself.
pub async fn start(args: &Args, lock: Lock) -> Result<Running, String> {
    let ui_addr = (!args.ui_off()).then(|| args.ui.clone());
    let token = args.harness_token.clone().filter(|t| !t.is_empty());
    // The web UI logs in with a harness token. Beyond loopback it must, and
    // then it also needs TLS, since the token and the session cookie cross the
    // network. On loopback it does once a token exists, unless the owner
    // switched the login off; a center without any token yet is open to this
    // machine so that the first token can be made in the UI. All of this is
    // settled before anything is bound or written.
    let state = args.state_dir();
    let has_token = token.is_some()
        || Store::load(&state)
            .map_err(|e| e.to_string())?
            .is_some_and(|s| !s.harness_tokens.is_empty());
    if let Some(a) = ui_addr.as_deref().filter(|a| !is_loopback(a)) {
        if args.ui_no_login {
            return Err(format!(
                "the web UI at {a} is beyond loopback, where it always needs a login; drop --ui-no-login or use --ui 127.0.0.1:<port>"
            ));
        }
        if !has_token {
            return Err(format!(
                "the web UI at {a} is beyond loopback and logs in with a harness token, but there is none; set --harness-token (NERVE_HARNESS_TOKEN) or use --ui 127.0.0.1:<port>"
            ));
        }
    }
    let ui_login = has_token && !args.ui_no_login;

    let node_listener = listen::tcp(&args.listen).await?;
    let nodes = node_listener.local_addr().map_err(|e| e.to_string())?;
    let center = Center::open(Options {
        state_dir: state,
        name: args.name.clone(),
        public_url: args.public_url(nodes.port()),
        log: nerve_transport::log::global(),
        log_level: args.log,
    })?;
    center.set_call_wait(args.call_wait);
    // Whatever else a message carries, this token is never in the log.
    center.log().set_secret("harness-token", token.as_deref());

    let mut tasks = Vec::new();

    let node_server = Server::from_listener(node_listener, &center, args.plain_loopback)?;
    tasks.push(tokio::spawn(listen::serve_nodes(
        center.clone(),
        node_server,
    )));

    let mut ui = None;
    if let Some(a) = ui_addr {
        let tls = !is_loopback(&a);
        let server = Server::bind(&a, &center, !tls).await?;
        ui = Some(server.local_addr());
        tasks.push(tokio::spawn(
            Ui::new(&center, token.clone(), ui_login, tls).serve(server),
        ));
    }

    let mut mcp = None;
    if args.mcp == McpMode::Http {
        let tls = !is_loopback(&args.mcp_listen);
        let server = Server::bind(&args.mcp_listen, &center, !tls).await?;
        mcp = Some(server.local_addr());
        if !has_token {
            center.log().record(
                Level::Warn,
                None,
                "no harness token yet: the HTTP MCP endpoint refuses every client until one is made in the web UI or set with NERVE_HARNESS_TOKEN",
            );
        }
        tasks.push(tokio::spawn(HttpMcp::new(&center, token).serve(server)));
    }

    #[cfg(unix)]
    {
        let listener = crate::attach::bind(&args.state_dir())?;
        tasks.push(tokio::spawn(crate::attach::serve(center.clone(), listener)));
    }

    // State changes are batched; this writes them out now and then, notes
    // the pairing codes that ran out, and ends the graces of key rotations.
    let c = center.clone();
    tasks.push(tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(5));
        loop {
            tick.tick().await;
            c.flush();
            c.sweep_codes();
            c.sweep().await;
        }
    }));

    // The address of the web UI stays last: the end-to-end tests read it from
    // this line.
    center.log().record(
        Level::Info,
        None,
        &format!(
            "nerve-center {}: center {} ({}) for nodes at {}{}",
            env!("CARGO_PKG_VERSION"),
            center.name(),
            center.id(),
            center.public_url(),
            ui.map(|u| format!(
                ", web UI at {}://{u}",
                if is_loopback(&u.to_string()) {
                    "http"
                } else {
                    "https"
                }
            ))
            .unwrap_or_default()
        ),
    );
    Ok(Running {
        center,
        nodes,
        ui,
        mcp,
        tasks,
        _lock: lock,
    })
}

/// Runs `nerve-center` as `main` does: owner or attached, until stdin ends or
/// a signal.
pub async fn run(args: Args) -> Result<(), String> {
    nerve_transport::init_crypto();
    let state = args.state_dir();
    let Some(lock) = crate::attach::try_lock(&state)? else {
        // Another nerve-center owns this state folder.
        if args.mcp != McpMode::Stdio {
            return Err(format!(
                "another nerve-center already runs the center in {}; only a --mcp stdio instance can attach to it",
                state.display()
            ));
        }
        #[cfg(unix)]
        {
            tracing::info!("attaching to the center that runs in {}", state.display());
            return crate::attach::relay(&state).await;
        }
        #[cfg(not(unix))]
        return Err(format!(
            "another nerve-center already runs the center in {}",
            state.display()
        ));
    };
    let running = start(&args, lock).await?;
    match args.mcp {
        McpMode::Stdio => {
            crate::mcp::serve_stdio(running.center.clone()).await;
            // The harness that started us is gone; harnesses that attached
            // keep the center until they end too.
            while running.center.session_count() > 0 {
                tokio::select! {
                    _ = tokio::time::sleep(Duration::from_secs(1)) => {}
                    _ = signal() => break,
                }
            }
        }
        McpMode::Http | McpMode::None => signal().await,
    }
    running.stop().await;
    Ok(())
}

async fn signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        let mut term = signal(SignalKind::terminate()).expect("a SIGTERM handler");
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = term.recv() => {}
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}
