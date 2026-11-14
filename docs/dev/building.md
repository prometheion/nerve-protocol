# Building and checks

## Build

Needs Rust 1.89 or newer (`rust-version` in `Cargo.toml`). Only 1.99.0, the
toolchain of CI and the release, is tested; nothing checks 1.89.

```sh
cargo build --release
# target/release/nerve-center and target/release/nerve-node
```

A debug build keeps line tables only (`[profile.dev]` in `Cargo.toml`), as
CI builds: enough for a backtrace, and a far smaller `target/`. For a
debugger, build with `CARGO_PROFILE_DEV_DEBUG=true`.

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
| `linux` | fmt, that every script of the web UIs parses (`node --check`), clippy, a check of the runner's Landlock ABI (`landlock-abi.py`) and `cargo test --workspace` on Ubuntu 24.04, as the runner's account with a systemd user session; then the tests that need root, as root: root's backup file (`tests/backup_caller.rs`), root's start (`tests/root_start.rs`), six unit tests of uninstall, revoked grants and mounted drives, and the root test of `tests/own_proc.rs`; last the tests of a command's own `/proc` (`tests/own_proc.rs`) with user namespaces opened. After each run `skips.py` fails the job on a skipped test the list does not allow |
| `musl` | on x86_64 and arm64: the folder walk of install and uninstall (`service::tests::chown`) on musl, the C library of the released Linux programs; then `nerve-node` and `nerve-center` built as the release builds them, and the real tests' programs |
| `installed` | those static programs installed on Ubuntu 22.04 and 24.04 (x86_64, and arm64 on 24.04), and on Ubuntu 26.04, Debian 12 and Debian 13, each a container with systemd on an Ubuntu 24.04 runner (`.github/workflows/installed.yml`): `.github/scripts/keyring-end-to-end.sh` runs the real tests below, `setup` with the keys moved into GNOME Keyring, the keyring test as `nerve`, restarts of the keyring's session and of the node, the web UI, `uninstall --purge`; then `.github/scripts/center-service-end-to-end.sh` installs the center as a service, drives it over MCP, updates and uninstalls it. On the x86_64 Ubuntu runners both scripts also open every page of the node's and the center's web UI in headless Chrome. The release runs the same on the binaries it publishes |
| `desktop-real` | the desktop app's own install, control, update and uninstall on Ubuntu 24.04, as root (`crates/nerve-node-desktop/tests/real.rs`) |
| `windows` | fmt, clippy and `cargo test --workspace` on Windows, so the tests compiled only there run (grants, the integrity level, the service steps, the job object, the AppContainer, Windows paths). No test is skipped by name: the tests marked `#[ignore]` are listed as ignored with their reason, and `skips.py` fails the job on one that returns early. Then the debug programs and the test programs of `windows-installed` (`.github/scripts/windows-test-programs.sh`) |
| `windows-installed` | the Windows tests marked `#[ignore]` that need a machine of their own, on a windows-2025 runner (`.github/workflows/installed-windows.yml`, [below](#windows-tests-on-an-installed-node)). The release runs the same on the release-profile programs it is about to publish, and its `publish` job waits for it |

A test that fails now and then is shown fixed (or caught) by the `Repeat tests`
workflow (`.github/workflows/repeat.yml`): it runs chosen tests of one package
again and again on a hosted runner, and with `load` workers keeps the runner
as busy as the whole `windows` or `linux` job does, which is what makes the
tests that wait on a process start fail. Start it from the Actions tab, or by
pushing a branch `repeat/<name>` that has a `.github/repeat.env`
(`os`, `package`, `filter`, `count`, `load`, one `key=value` a line).

The web UIs' smoke test (`.github/scripts/web-ui-smoke.mjs`) needs only
Chrome and Node.js 22 or newer: it signs in with a token on the login page,
opens every page of the sidebar, and fails on a script error, an error in the
console, an answer of 500 or more, or an empty page. To run it against a
center or node of your own:

```sh
node .github/scripts/web-ui-smoke.mjs "$(command -v google-chrome)" http://127.0.0.1:7480/ <token>
```

A test that cannot run on a machine returns early and prints why
(`skipped: needs root`). The `linux` and `windows` jobs run the tests with
`--show-output`, and `.github/scripts/skips.py` fails the job on a skip that
`.github/test-skips.txt` does not let that job have: a runner that loses
Landlock, user namespaces or its user session turns the job red instead of
passing with less tested. The `linux` and `installed` jobs also fail when the
kernel has less Landlock than they expect (`.github/scripts/landlock-abi.py`).

A test that needs more than a hosted runner has (the node installed as a
service, an administrator account, a virtual disk, the system keyring) is
`#[ignore = "<reason>"]`: every run lists it as ignored with its reason. The
`installed` and `desktop-real` jobs run these of them, and fail when one skips:

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
- the Windows tests marked `#[ignore]` that `windows-installed` does not
  name: the UAC broker with another administrator
  (`nerve-node-desktop/tests/broker_users.rs`), the open WMI gap
  (`exec::tests::a_cancel_ends_a_process_started_through_wmi`), the slow wait
  for a recycled shell id (`a_shell_pid_given_to_another_command_reaches_no_other_job`)
  and the PowerShell diagnostic of `nerve-sandbox`;
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

## Windows: tests on an installed node

The tests that need a Windows machine of their own carry
`#[ignore = "<reason>"]`. CI's `windows-installed` job
(`.github/workflows/installed-windows.yml`) runs them on a fresh
`windows-2025` runner, with the debug programs and test programs the
`windows` job built; the release runs it too, on the release-profile programs
it built, with the same debug test programs of the same commit. The job:

- checks that the runner is Windows Server 2025
  (`.github/scripts/windows-runner.ps1`);
- makes an administrator account and a standard account with random
  passwords, and their profiles by a logon that loads them, as nobody signs
  in on a runner;
- has the app install, start, stop, restart, update and uninstall Nerve
  (`nerve-node-desktop/tests/real.rs`);
- installs over a folder in `C:\ProgramData\Nerve` that the standard account
  made first: the install refuses before it changes anything, and names the
  account and what to do;
- installs the node again with the administrator account as its owner (the sudo
  test below needs an administrator). The install
  makes `nerve-run`, its profile (by a logon that loads it) and the service
  `nerve-run-profile`, which the job checks. Then it reads what the install
  put on the machine as Windows reads it: the Start menu link, the handler of
  `nerve://` links, the entry in Apps & features;
- runs, one by one, with `--ignored --exact`: the sudo switch
  (`nerve-node/tests/win_sudo.rs`), a provider on the provider pipe
  (`win_provider.rs`), the keys and a proxy's password in the service's
  Credential Manager through backup and restore (`win_vault.rs`), the limits per
  command (`win_limits.rs`), and the command account
  (`win_account.rs`: a command in its folder works and one outside is refused
  and audited; one pairing reaches neither another's folders, nor its home,
  nor its processes; a folder without flags inside a `w` folder is closed;
  `nerve-run` opens neither the node's config and state folders, nor the
  owner's registry, nor the node's pipes; with the network off a connection
  and a sudo command are refused), smaller tests of it (a command the folder
  sync refuses in the audit log, a granted folder that becomes a link to
  another machine, a capability's value that is one argument), the
  administrator's batch logon, a folder on a virtual disk mounted in a folder,
  a backup's folder on a FAT32 virtual disk and a folder reached over the
  machine's own share. A test name that matches nothing fails the job;
- stops the service, gives its state folder to the standard account, and
  expects the service not to start on it, and the manager to start it again
  once the administrators own the folder;
- installs the node again for a local owner whose name has a blank and an
  umlaut, a standard account, and runs the test of that owner's folder and
  commands;
- installs the center as a service and runs `win_service.rs`: its `status`,
  its restart actions (and a restart after its process is killed), its web UI
  in Chrome (`.github/scripts/web-ui-smoke.mjs`), what the standard account
  cannot read or take, what the administrator's other account and a pipe the
  standard account made get from a second center, a second center that
  attaches to a first, a backup and a restore into the service, `update` (a
  program that is not the center, another build) and `uninstall --purge`;
- runs the Apps & features entry's quiet uninstall, which keeps the data, and
  `--silent`, which installs again without a question;
- uninstalls with `--purge`, which removes `nerve-run` and `nerve-run-profile`
  too, and fails on a test that skipped.

After a failure the job prints the node's log, the Event Log entries, the
folder grants and the permission lists of the test folders. The `windows` job
also keeps the debug `nerve-node-desktop.exe` and `nerve-center.exe` as the
artifact `windows-programs` for three days, to try a change on a Windows test
machine as a person would.

## Dependencies

The `Dependencies` workflow (`.github/workflows/deny.yml`) runs
[cargo-deny](https://github.com/EmbarkStudios/cargo-deny) against `deny.toml`
on every pull request, on `main`, and every Monday, since an advisory can come
out for a crate nobody changed. It fails on:

- a licence that is not in `deny.toml`'s list (licences that fit the Apache
  License 2.0); Slint's Royalty-free licence is allowed for Slint's crates and
  the desktop app only, and Slint may be linked by the desktop app alone;
- an advisory of the RustSec database, an unmaintained or unsound crate too,
  that `deny.toml` does not name with its reason (on a pull request this step
  only warns; on `main` and the weekly run it fails);
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

CI and the release build them on a Windows runner ([releasing](releasing.md));
to build them here, use `cargo-xwin`. The static C runtime avoids a missing `vcruntime140.dll`:

```sh
rustup target add x86_64-pc-windows-msvc
CARGO_TARGET_X86_64_PC_WINDOWS_MSVC_RUSTFLAGS="-C target-feature=+crt-static" \
  cargo xwin build --release --target x86_64-pc-windows-msvc
```

The programs are in `target/x86_64-pc-windows-msvc/release/`.
