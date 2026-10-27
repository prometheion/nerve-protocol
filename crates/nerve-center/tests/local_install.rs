//! An `#[ignore]` end-to-end test of the one-click local install
//! (`checker::install`) against the real pinned llama.cpp release: it
//! downloads the CPU build through the center's own downloader (SHA-256
//! checked), unpacks it, and starts d1-3B with it on the CPU.
//!
//! The 1.7 GB model is not downloaded again: `NERVE_TEST_D1_MODEL` names a
//! local copy, which is linked (or copied) into the test state folder, where
//! the install finds it and only checks its hash.
//!
//! ```sh
//! NERVE_TEST_D1_MODEL=/path/to/d1-3B-Q4_K_M.gguf \
//!     cargo test -p nerve-center --test local_install -- --ignored --nocapture
//! ```

use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde_json::Map;

use nerve_center::checker::config::{CheckerConfig, LocalModel, ModelConfig};
use nerve_center::checker::install::{self, Phase as InstallPhase, Status};
use nerve_center::checker::server::{LocalServer, Phase};
use nerve_center::checker::{CallInfo, Checker, Decision};
use nerve_proto::Effect;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "downloads the real pinned llama.cpp CPU build; needs NERVE_TEST_D1_MODEL"]
async fn the_real_cpu_build_installs_and_runs_d1() {
    let d1 = PathBuf::from(
        std::env::var("NERVE_TEST_D1_MODEL").expect("set NERVE_TEST_D1_MODEL to the d1-3B GGUF"),
    );
    let state = tempfile::tempdir().unwrap();
    let model = install::model_path(state.path(), LocalModel::D1_3b);
    std::fs::create_dir_all(model.parent().unwrap()).unwrap();
    if std::fs::hard_link(&d1, &model).is_err() {
        std::fs::copy(&d1, &model).unwrap();
    }

    let shared = Arc::new(Mutex::new(Status::default()));
    let started = Instant::now();
    let cancel = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    install::install(
        state.path().to_path_buf(),
        false,
        LocalModel::D1_3b,
        shared.clone(),
        cancel,
    )
    .await
    .expect("the install");
    let st = shared.lock().unwrap().clone();
    println!(
        "install done in {:?}: llama {} of {} bytes, phase {:?}",
        started.elapsed(),
        st.llama.done,
        st.llama.total,
        st.phase
    );
    assert_eq!(st.phase, InstallPhase::Done);
    assert!(
        st.llama.total > 1_000_000,
        "the CPU build was really fetched"
    );
    assert!(install::installed(state.path(), LocalModel::D1_3b));
    assert_eq!(install::installed_variant(state.path()), Some(false));

    let bin = install::server_bin(state.path()).unwrap();
    println!("llama-server at {}", bin.display());
    let server = LocalServer::start(bin, model, false, 8000).expect("start the server");
    let deadline = Instant::now() + Duration::from_secs(180);
    while Instant::now() < deadline && !server.ready() {
        let s = server.status();
        assert_ne!(s.phase, Phase::Failed, "server failed: {s:?}");
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    assert!(server.ready(), "never ready: {:?}", server.status());

    // A small VM may need more than the product default per call; the test
    // takes a longer timeout from the environment so it measures the model,
    // not the machine.
    let timeout_ms = std::env::var("NERVE_TEST_TIMEOUT_MS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(8000);
    let checker = Checker::build(
        CheckerConfig {
            blocklist_on: false,
            model_on: true,
            model: ModelConfig {
                timeout_ms,
                ..Default::default()
            },
            ..Default::default()
        },
        None,
    );
    let args = Map::new();
    let call = |target: &'static str| CallInfo {
        cap: "exec",
        action: "run",
        effect: Effect::Execute,
        description: "",
        target,
        paths: &[],
        args: &args,
        node_id: "n1",
        os: std::env::consts::OS,
        tainted: false,
    };
    let endpoint = server.endpoint();
    let t = Instant::now();
    let refused = checker.check(&call("rm -rf /"), Some(&endpoint)).await;
    println!("rm -rf / -> {refused:?} in {:?}", t.elapsed());
    // Refused by the model's score, not by a timeout (fail closed).
    assert!(
        matches!(&refused, Decision::Refuse { detail, .. } if detail.starts_with("score")),
        "{refused:?}"
    );
    let t = Instant::now();
    let allowed = checker.check(&call("git status"), Some(&endpoint)).await;
    println!("git status -> {allowed:?} in {:?}", t.elapsed());
    assert!(matches!(allowed, Decision::Allowed { .. }), "{allowed:?}");
}

/// The center end to end with the real pinned build: install on the CPU, wait
/// for the model to be ready, optionally switch to the GPU build while it runs
/// (`NERVE_TEST_GPU_SWITCH=1`, for a machine whose GPUs may be used; on one
/// without a device it must fall back to the CPU), then Remove while it runs.
/// On Windows a running `llama-server.exe` holds its files, so Remove and the
/// switch only work if the center stops it first (review r2, finding 1).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "downloads the real pinned llama.cpp build; needs NERVE_TEST_D1_MODEL"]
async fn the_center_installs_switches_and_removes_a_running_model() {
    use nerve_center::center::{Center, Options};
    let d1 = PathBuf::from(
        std::env::var("NERVE_TEST_D1_MODEL").expect("set NERVE_TEST_D1_MODEL to the d1-3B GGUF"),
    );
    let state = tempfile::tempdir().unwrap();
    let model = install::model_path(state.path(), LocalModel::D1_3b);
    std::fs::create_dir_all(model.parent().unwrap()).unwrap();
    if std::fs::hard_link(&d1, &model).is_err() {
        std::fs::copy(&d1, &model).unwrap();
    }
    nerve_transport::init_crypto();
    let c = Center::open(Options {
        state_dir: state.path().to_path_buf(),
        name: None,
        public_url: "http://127.0.0.1:7443".into(),
        log: None,
        log_level: None,
    })
    .unwrap();
    // Ready once the install has ended and the model it put in place runs
    // (the old model keeps running while a switch downloads).
    let wait_ready = |c: Center, what: &'static str| async move {
        let deadline = Instant::now() + Duration::from_secs(600);
        loop {
            let inst = c.checker_install_status();
            assert_ne!(inst.phase, InstallPhase::Failed, "{what}: {}", inst.message);
            if inst.phase != InstallPhase::Done {
                assert!(Instant::now() < deadline, "{what}: the install never ended");
                tokio::time::sleep(Duration::from_millis(500)).await;
                continue;
            }
            if let Some(s) = c.local_model_status() {
                assert_ne!(s.phase, Phase::Failed, "{what}: {s:?}");
                if s.phase == Phase::Ready {
                    return;
                }
            }
            assert!(Instant::now() < deadline, "{what}: never ready");
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    };

    c.start_checker_install(false, LocalModel::D1_3b)
        .await
        .unwrap();
    wait_ready(c.clone(), "CPU install").await;
    println!("installed and ready on the CPU");

    if std::env::var("NERVE_TEST_GPU_SWITCH").is_ok() {
        c.start_checker_install(true, LocalModel::D1_3b)
            .await
            .unwrap();
        // The running model keeps judging calls during the download, and a
        // config save meanwhile (here taint toggled twice) must not start a
        // server from the files the switch is about to replace (review r3,
        // findings 2 and 3).
        for _ in 0..2 {
            let mut cfg = c.read(|s| s.checker.clone());
            cfg.taint_on = !cfg.taint_on;
            c.apply_checker_config(cfg).unwrap();
            if let Some(s) = c.local_model_status() {
                println!("during the switch the model is {:?}", s.phase);
            }
            tokio::time::sleep(Duration::from_millis(300)).await;
        }
        wait_ready(c.clone(), "GPU switch").await;
        let gpu = c.read(|s| s.checker.model.local_gpu);
        println!(
            "switched while running; running on the {} ({})",
            if gpu { "GPU" } else { "CPU" },
            c.checker_install_status().message
        );
        assert_eq!(install::installed_variant(state.path()), Some(true));
    }

    // Remove while the model runs.
    c.remove_checker_model()
        .await
        .expect("remove while running");
    assert!(!state.path().join("checker").exists(), "files left behind");
    assert!(!c.read(|s| s.checker.model_on));
    assert!(c.local_model_status().is_none());
    println!("removed while running");
}
