# Building and checks

## Build

Needs Rust 1.88 or newer (`rust-version` in `Cargo.toml`). Only 1.99.0, the
toolchain of CI and the release, is tested; nothing checks 1.88.

```sh
cargo build --release
# target/release/nerve-center and target/release/nerve-node
```

`target/release/nerve-node-desktop` is the node with its desktop app
(`crates/nerve-node-desktop`). On Linux it needs the fontconfig headers to build
(`libfontconfig1-dev` on Debian and Ubuntu), and glibc: it is no static musl
program. Its UI is in `crates/nerve-node-desktop/ui/`, its colours, type and spaces
in `ui/theme.slint`. Screenshots of every page, light and dark:

```sh
NERVE_DESKTOP_SHOTS=/tmp/shots cargo test -p nerve-node-desktop --test shots -- --ignored
```

Started from `target/`, the app shows its installer: it opens its pages only
from its installed place. `tests/real.rs` installs, controls, updates and
removes it through the app's code; run it on a test machine only, as root (on
Windows as an elevated administrator):

```sh
NERVE_DESKTOP_REAL=/path/to/nerve-node-desktop cargo test -p nerve-node-desktop --test real -- --ignored
```

## Checks

```sh
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
```

The release workflow runs the same three with `--locked --workspace` before it
builds anything ([releasing](releasing.md)).

The `CI` workflow (`.github/workflows/ci.yml`) runs on every pull request and on
every push to `main`. Its Linux job and its Windows job each run fmt, clippy and
`cargo test --workspace`, so the tests that are compiled only on Windows (grants,
the integrity level, the service steps, the job object, Windows paths) run on
a Windows runner. Most of the AppContainer and grant end-to-end tests are
skipped there for now, because they fail on the hosted runner (issues
[#105](https://github.com/prometheion/nerve-protocol/issues/105) and
[#106](https://github.com/prometheion/nerve-protocol/issues/106)): run them by
hand on the Windows test machine. The same job skips
`a_cancel_ends_a_chain_of_processes_that_hand_over_and_exit`, a timing flake
([#107](https://github.com/prometheion/nerve-protocol/issues/107)). Both use the toolchain of the release
and a cargo cache keyed by `Cargo.lock`, so a change to the lock file builds
once from scratch.

A test that needs more than a hosted runner has (the node installed as a
service, an administrator account, a virtual disk, the system keyring) is
`#[ignore = "<reason>"]`: every run lists it as ignored with its reason, and it
is run by hand on a test machine with `cargo test -- --ignored`. The `keyring`
job runs two of them, in `crates/nerve-node/tests/real_account.rs`, as root on
hosted Ubuntu 22.04 and 24.04 runners (`.github/scripts/keyring-end-to-end.sh`):
the installed node with its keys in the keyring, and `folder` mode as
`nerve-run`. The Windows job also skips by name the tests that fail on Windows
today; the comment in the workflow says which and why, and the skip goes when
the test is fixed.

The action checker's tests that need a real model or download are
`#[ignore]` too, and name what they need
([action-checker](action-checker.md)):

| Test | Needs | Does |
|---|---|---|
| `tests/local_install.rs` | `NERVE_TEST_D1_MODEL`, a local copy of the d1-3B GGUF; the network. `NERVE_TEST_TIMEOUT_MS` (8000 by default) for a slow machine | Downloads the pinned llama.cpp CPU build through the center, starts d1-3B with it and checks a call each way. The second test drives the center: install, switch to the GPU (only with `NERVE_TEST_GPU_SWITCH=1`), Remove |
| `tests/local_model.rs` | `NERVE_TEST_MODEL` (a decision-model GGUF) and `NERVE_TEST_LLAMA` (a `llama-server` with `/v1/systemone`) | Starts the server through the checker's supervisor and checks a call each way |
| `tests/checker_eval.rs` | `NERVE_CHECKER_ENDPOINT`, a System One endpoint; `NERVE_CHECKER_TOKEN`, `NERVE_CHECKER_MODEL` and `NERVE_CHECKER_TIMEOUT_MS` are optional | The evaluation: sends the cases of `tests/data/checker-eval.json` and prints, per threshold, how many dangerous and benign cases were refused and the latency |

```sh
NERVE_TEST_D1_MODEL=<d1-3B-Q4_K_M.gguf> \
    cargo test -p nerve-center --test local_install -- --ignored --nocapture
llama-server -m <model.gguf> -ngl 0 --host 127.0.0.1 --port 19931 &
NERVE_CHECKER_ENDPOINT=http://127.0.0.1:19931 \
    cargo test -p nerve-center --test checker_eval -- --ignored --nocapture
```

`cargo test` runs the unit tests, the integration tests and the
[conformance suite](spec/conformance.md). The end-to-end tests, which
start the real `nerve-center` and `nerve-node`, run on Unix. To run only the
suite:

```sh
cargo test -p nerve-conformance
```

To run the end-to-end tests against programs you built elsewhere (the release
workflow does this with the binaries it releases), name them:

```sh
NERVE_CENTER_BIN=/path/to/nerve-center NERVE_NODE_BIN=/path/to/nerve-node \
  cargo test -p nerve-conformance
```

## Static Linux binaries

Needs the musl target and clang:

```sh
rustup target add x86_64-unknown-linux-musl
CC_x86_64_unknown_linux_musl=clang cargo build --release --target x86_64-unknown-linux-musl
```

The programs are in `target/x86_64-unknown-linux-musl/release/`. For ARM, use
the target `aarch64-unknown-linux-musl` and the variable
`CC_aarch64_unknown_linux_musl`.

## Windows binaries from Linux

Use `cargo-xwin`. The static C runtime avoids a missing `vcruntime140.dll`:

```sh
rustup target add x86_64-pc-windows-msvc
CARGO_TARGET_X86_64_PC_WINDOWS_MSVC_RUSTFLAGS="-C target-feature=+crt-static" \
  cargo xwin build --release --target x86_64-pc-windows-msvc
```

The programs are in `target/x86_64-pc-windows-msvc/release/`.
