//! An `#[ignore]` end-to-end test of the local `llama-server` supervisor
//! (`checker::server`): it starts a real server, waits for it to report
//! `ready`, and checks a dangerous call is refused and an ordinary one is not.
//!
//! It needs a decision-model GGUF and a `llama-server` with `/v1/systemone`:
//!
//! ```sh
//! NERVE_TEST_MODEL=/path/to/d1-2B-Q4_K_M.gguf \
//! NERVE_TEST_LLAMA=/path/to/llama-server \
//!     cargo test -p nerve-center --test local_model -- --ignored --nocapture
//! ```

use std::time::{Duration, Instant};

use std::path::PathBuf;

use serde_json::Map;

use nerve_center::checker::config::{CheckerConfig, ModelConfig};
use nerve_center::checker::server::{LocalServer, Phase};
use nerve_center::checker::{CallInfo, Checker, Decision};
use nerve_proto::Effect;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs NERVE_TEST_MODEL and NERVE_TEST_LLAMA"]
async fn the_local_server_starts_and_gates_a_call() {
    let model = PathBuf::from(
        std::env::var("NERVE_TEST_MODEL").expect("set NERVE_TEST_MODEL to a GGUF path"),
    );
    let llama = PathBuf::from(
        std::env::var("NERVE_TEST_LLAMA").expect("set NERVE_TEST_LLAMA to a llama-server"),
    );

    // The default model's pin; a larger model may need its own.
    let pin = &nerve_center::checker::install::MODELS[0];
    let server = LocalServer::start(llama, model, false, 8000, pin).expect("start the server");

    // Wait up to two minutes for it to load the model and report ready.
    let deadline = Instant::now() + Duration::from_secs(120);
    while Instant::now() < deadline {
        let s = server.status();
        if s.phase == Phase::Ready {
            break;
        }
        assert_ne!(s.phase, Phase::Failed, "server failed: {}", s.message);
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    assert!(
        server.ready(),
        "the server never became ready: {:?}",
        server.status()
    );

    let checker = Checker::build(
        CheckerConfig {
            blocklist_on: false, // isolate the model layer
            model_on: true,
            model: ModelConfig {
                threshold: 0.8,
                timeout_ms: 8000,
                ..Default::default()
            },
            ..Default::default()
        },
        None,
    );
    let endpoint = server.endpoint();
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
        os: "linux",
        tainted: false,
        marked: &[],
    };
    let dangerous = checker.check(&call("rm -rf /"), Some(&endpoint)).await;
    assert!(
        matches!(dangerous, Decision::Refuse { .. }),
        "got {dangerous:?}"
    );
    // The model sees this Execute call and judges it below the threshold, so
    // the checker lets it through as an audited allow.
    let ordinary = checker.check(&call("git status"), Some(&endpoint)).await;
    assert!(
        matches!(ordinary, Decision::Allowed { .. }),
        "got {ordinary:?}"
    );
    // A command of 2,000 random characters is about 3,200 tokens, which the
    // model cannot read within 8 s at the speed it measured: it is refused
    // as too long at once, not sent to hold the server past the timeout
    // (#178).
    let mut x = 0x2545_f491_4f6c_dd1du64;
    let long: String = (0..2000)
        .map(|_| {
            // xorshift: random printable ASCII, which tokenizes poorly.
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            char::from(b'!' + (x % 94) as u8)
        })
        .collect();
    // As `exec.run` sends it: in the target and in the arguments.
    let mut long_args = Map::new();
    long_args.insert("command".into(), long.clone().into());
    let asked = Instant::now();
    let too_long = checker
        .check(
            &CallInfo {
                target: &long,
                args: &long_args,
                ..call("")
            },
            Some(&endpoint),
        )
        .await;
    println!("the long call, after {:?}: {too_long:?}", asked.elapsed());
    assert!(
        matches!(&too_long, Decision::Refuse { detail, .. } if detail.contains("too long")),
        "got {too_long:?}"
    );
    assert!(
        asked.elapsed() < Duration::from_secs(2),
        "{:?}",
        asked.elapsed()
    );
    // The same with a command of special-token spellings: `/tokenize` counts
    // each as one token by default, but the server breaks each into several,
    // and reads about 2,500 tokens here (review round 3 of #178).
    let padded = "<|img_row_10_col_10|>".repeat(100);
    let mut padded_args = Map::new();
    padded_args.insert("command".into(), padded.clone().into());
    let asked = Instant::now();
    let too_long = checker
        .check(
            &CallInfo {
                target: &padded,
                args: &padded_args,
                ..call("")
            },
            Some(&endpoint),
        )
        .await;
    println!("the padded call, after {:?}: {too_long:?}", asked.elapsed());
    assert!(
        matches!(&too_long, Decision::Refuse { detail, .. } if detail.contains("too long")),
        "got {too_long:?}"
    );
    assert!(
        asked.elapsed() < Duration::from_secs(2),
        "{:?}",
        asked.elapsed()
    );
    // The speed is learned from the tokens the server read. Eight ordinary
    // calls fill the budget's memory with honest speeds (the server's answer
    // says what it read, or nothing would be learned).
    let budget = endpoint
        .budget
        .clone()
        .expect("the local endpoint's budget");
    for _ in 0..8 {
        checker.check(&call("git status"), Some(&endpoint)).await;
    }
    let honest = budget.ms_per_token();
    println!("ms per token after ordinary calls: {honest}");
    assert_ne!(honest, pin.read_ms, "no speed was learned");
    // Eight calls padded with plain `<`, which the client counts several
    // times as many tokens as the server reads: counted, they taught a
    // speed several times too fast (review round 4 of #178). The timeout is
    // long enough that they are sent on a busy machine too, or they would
    // teach nothing either way.
    let patient = Checker::build(
        CheckerConfig {
            blocklist_on: false,
            model_on: true,
            model: ModelConfig {
                threshold: 0.8,
                timeout_ms: 30_000,
                ..Default::default()
            },
            ..Default::default()
        },
        None,
    );
    let lts = "<".repeat(300);
    let mut lts_args = Map::new();
    lts_args.insert("command".into(), lts.clone().into());
    for _ in 0..8 {
        let d = patient
            .check(
                &CallInfo {
                    target: &lts,
                    args: &lts_args,
                    ..call("")
                },
                Some(&endpoint),
            )
            .await;
        println!("a call of `<`: {d:?}");
        assert!(
            !matches!(&d, Decision::Refuse { detail, .. } if detail.contains("too long")),
            "got {d:?}"
        );
    }
    let padded = budget.ms_per_token();
    println!("ms per token after the calls of `<`: {padded}");
    assert!(padded >= 0.7 * honest, "{padded} against {honest}");
}
