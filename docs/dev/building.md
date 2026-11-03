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
every push to `main`, with the toolchain of the release and a cargo cache keyed
by `Cargo.lock` (a change to the lock file builds once from scratch). Its jobs:

| Job | Runs |
|---|---|
| `linux` | fmt, clippy and `cargo test --workspace` on Ubuntu 24.04, as the runner's account with a systemd user session; then the tests that need root, as root: root's backup file (`tests/backup_caller.rs`), root's start (`tests/root_start.rs`) and four ACL tests of uninstall and revoked grants |
| `musl` | the folder walk of install and uninstall (`service::tests::chown`) on musl, the C library of the released Linux programs |
| `keyring` | the node installed on Ubuntu 22.04 and 24.04 (`.github/scripts/keyring-end-to-end.sh`): the real tests below, `setup` with the keys moved into GNOME Keyring, the keyring test as `nerve`, restarts of the keyring's session and of the node, the web UI, `uninstall --purge`; then the center as a service (`.github/scripts/center-service-end-to-end.sh`) |
| `desktop-real` | the desktop app's own install, control, update and uninstall on Ubuntu 24.04, as root (`crates/nerve-node-desktop/tests/real.rs`) |
| `windows` | fmt, clippy and `cargo test --workspace` on Windows, so the tests compiled only there run (grants, the integrity level, the service steps, the job object, the AppContainer, Windows paths) |

A test that cannot run on a machine returns early and prints why
(`skipped: needs root`). The `linux` and `windows` jobs run the tests with
`--show-output`, and `.github/scripts/skips.py` fails the job on a skip that
`.github/test-skips.txt` does not let that job have: a runner that loses
Landlock, user namespaces or its user session turns the job red instead of
passing with less tested. The `linux` and `keyring` jobs also fail when the
kernel has less Landlock than they expect (`.github/scripts/landlock-abi.py`).

A test that needs more than a hosted runner has (the node installed as a
service, an administrator account, a virtual disk, the system keyring) is
`#[ignore = "<reason>"]`: every run lists it as ignored with its reason. The
`keyring` and `desktop-real` jobs run these of them:

| Test | Does |
|---|---|
| `real_account.rs` `folder_mode_runs_as_nerve_run_on_this_machine` | install, `nerve-run`, folder grants as ACLs, uninstall |
| `real_account.rs` `the_owners_program_attaches_and_is_held_to_the_folders` | a provider of the owner's, held to the folders |
| `real_account.rs` `a_config_capability_runs_as_nerve_run_in_a_folder_pairing` | capabilities of `node.toml` as `nerve-run` |
| `real_account.rs` `argument_rules_decide_a_config_capability_on_the_installed_node` | rules on a capability's arguments |
| `real_account.rs` `a_command_is_held_to_its_limits_on_the_installed_node` | the limits per command in the service's cgroup |
| `real_account.rs` `the_installed_node_with_its_keys_in_the_keyring_runs_folder_commands_as_nerve_run` | the keys in the keyring, and folder mode |
| `real_root_owner.rs` (both) | root as the owner, a program of root as a provider |
| `keyring.rs` `the_keys_move_into_the_system_keyring_and_back` | a node's keys into the keyring of `nerve` and back |
| `nerve-node-desktop` `real.rs` | the desktop app's install on Linux |

Not run by CI, by hand on a test machine:

- every test on a kernel without Landlock (a container or LXC guest), and on
  a distribution's own older kernel (CI's runners have GitHub's newer ones);
- the Windows tests marked `#[ignore]` (the installed service, an
  administrator, a virtual disk, Credential Manager), the desktop app's
  `real.rs` on Windows, and the Windows tests the `windows` job skips by
  name: they fail on the hosted runner today, and the comment in the workflow
  says which and why; each skip goes when its test is fixed;
- the action checker's tests with a real model (below).

The action checker's tests that need a real model or download are
`#[ignore]` too, and name what they need
([action-checker](action-checker.md)):

| Test | Needs | Does |
|---|---|---|
| `tests/local_install.rs` | `NERVE_TEST_D1_MODEL`, a local copy of the d1-2B GGUF; the network. `NERVE_TEST_TIMEOUT_MS` (8000 by default) for a slow machine | Downloads the pinned llama.cpp CPU build through the center, starts d1-2B with it and checks a call each way. The second test drives the center with a model file and a build no pin names in the checker folder: install (which deletes them), switch to the GPU (only with `NERVE_TEST_GPU_SWITCH=1`), Remove |
| `tests/local_model.rs` | `NERVE_TEST_MODEL` (a decision-model GGUF) and `NERVE_TEST_LLAMA` (a `llama-server` with `/v1/systemone`) | Starts the server through the checker's supervisor and checks a call each way |
| `tests/checker_eval.rs` | `NERVE_CHECKER_ENDPOINT`, a System One endpoint; `NERVE_CHECKER_TOKEN`, `NERVE_CHECKER_MODEL`, `NERVE_CHECKER_TIMEOUT_MS`, `NERVE_EVAL_STRIDE` and `NERVE_EVAL_DUMP` are optional | The evaluation: sends the cases of `tests/data/checker-eval.json` and prints, per threshold, how many dangerous and benign cases were refused and the latency |

```sh
NERVE_TEST_D1_MODEL=<d1-2B-Q4_K_M.gguf> \
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

## Dependencies

The `Dependencies` workflow (`.github/workflows/deny.yml`) runs
[cargo-deny](https://github.com/EmbarkStudios/cargo-deny) against `deny.toml`
on every pull request, on `main`, and every Monday, since an advisory can come
out for a crate nobody changed. It fails on:

- a licence that is not in `deny.toml`'s list (licences that fit the Apache
  License 2.0); Slint's Royalty-free licence is allowed for Slint's crates and
  the desktop app only, and Slint may be linked by the desktop app alone;
- an advisory of the RustSec database, an unmaintained or unsound crate too,
  that `deny.toml` does not name with its reason;
- a second version of a crate that `deny.toml` does not name with its reason;
- a crate from anywhere but crates.io, a wildcard version, OpenSSL.

To run it here, get the release named in `deny.yml` and:

```sh
cargo deny --locked check
```

An advisory that a newer patch release fixes is fixed with
`cargo update -p <crate>`; one that cannot be fixed yet goes into `deny.toml`
with why Nerve is not reached, and comes out again with the fix.

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
