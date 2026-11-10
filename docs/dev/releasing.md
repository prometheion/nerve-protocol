# Releasing

Releases are made by the `Release` workflow (`.github/workflows/release.yml`).
The owner starts it by hand: **Actions, Release, Run workflow**. Leave "Use
workflow from" on `main` and fill in the inputs below. A pre-release of a
branch that changes the release workflow itself picks that branch under "Use
workflow from" too: GitHub takes the workflow file from there, not from
`branch`.

| Input | Meaning |
|---|---|
| `branch` | The branch to build from. Default `main` |
| `kind` | `pre-release` or `release` |
| `version` | `x.y.z`, the version of `nerve-center`, `nerve-node` and `nerve-node-desktop` in the workspace `Cargo.toml` |
| `windows` | Build and publish the Windows programs too. Off by default |

Windows comes with 0.1.0: until then a release publishes the Linux programs
only, and the `windows` input stays off. 0.1.0 turns it on.

## Rules

- A **release** comes from `main` only. Any other branch stops the run in its
  first job. Its tag is `v<version>`. If that tag exists, the run fails. Tags
  are never moved or reused, so a new release needs a new version.
- A **pre-release** may come from any branch. Its tag is `pre<N>-v<version>`,
  where `N` is one more than the highest `pre<N>-v<version>` so far (`pre1`
  first, then `pre2`). It is only for a version that is not released yet. If
  `v<version>` exists, the run fails, because the pre-release would come after
  the release, with newer code, under a name that says it is older. Raise the
  version on the branch first.
- The version must equal the one in `Cargo.toml`.
- A release needs a `## <version>` section with entries in `CHANGELOG.md`. The
  section becomes its release notes. A pre-release never reads that file. Its
  text is one line about the binaries and their checksums.
- The run builds the commit the branch is at when it starts. It tags that
  commit in its last job, after the checks and every build passed.
- One run at a time. A second run waits for the first. While one run waits, a
  third start replaces it, because GitHub keeps one waiting run per group.

## What a run does

1. Checks the inputs, the version and the tag (for a release, also the notes).
   Then it runs `cargo fmt --check`,
   `cargo clippy --locked --workspace --all-targets -- -D warnings` and
   `cargo test --locked --workspace` with the pinned toolchain.
2. Builds `nerve-center` and `nerve-node` for `x86_64-unknown-linux-musl` and
   `aarch64-unknown-linux-musl` (static). Each Linux binary must be static.
   Each binary must print its version from `--version`, and it must equal the
   one given. It also builds the desktop app `nerve-node-desktop` for Linux
   x86_64 on Ubuntu 22.04, the oldest runner (it links glibc and fontconfig,
   so it runs where glibc is 2.35 or newer; the run's summary says the glibc
   it needs). It must print `nerve-node-desktop <version>`. With `windows`,
   the `windows` job also builds `nerve-center` and `nerve-node-desktop` for
   `x86_64-pc-windows-msvc` (static C runtime); without it that job is
   skipped.
3. Runs the conformance suite (`cargo test -p nerve-conformance`) against the
   Linux binaries that were just built, the ones to be released, with
   `NERVE_CENTER_BIN` and `NERVE_NODE_BIN` set to them. `x86_64` runs on an
   x86_64 runner and `aarch64` on an arm64 runner. Then it installs them on
   Ubuntu 22.04 and 24.04 (x86_64, and arm64 on 24.04) and Debian 12, and
   runs the real-machine tests, the keyring path and the center as a service
   there, as CI does (`.github/workflows/installed.yml`,
   [building](building.md#checks)). Windows binaries, with `windows`, are
   built but not run by the workflow.
4. Publishes a GitHub Release with `SHA256SUMS` and the five Linux binaries:
   `nerve-center` and `nerve-node` for each machine, and
   `nerve-node-desktop-x86_64-linux`, which also comes as
   `nerve-node-desktop_<version>_amd64.deb` and
   `nerve-node-desktop-<version>.x86_64.rpm`: packed from that program with
   `dpkg-deb` and `rpmbuild` (`.github/scripts/desktop-packages.sh`) and
   installed on Ubuntu 22.04 and 24.04 and Fedora in containers first
   (`desktop-packages-test`). With `windows` there are two more:
   `nerve-center-x86_64-windows.exe` and
   `nerve-node-desktop-x86_64-windows.exe` too (Windows has no `nerve-node` of
   its own: the desktop app is the node there). The release text ends with a
   footer that names the programs it has. The desktop app's update takes its
   own file from there, as `nerve-node update` takes `nerve-node-*`. A release
   is marked latest. A pre-release is marked as a pre-release.

The programs' help links to the user guide (`--help`, both web UIs, the
desktop app) name the git ref in `NERVE_GUIDE_REF`: the run sets it to
`v<version>` for a release, whose tag exists once the run is over, and to
`main` for a pre-release. A build without it, such as `cargo build`, links
`main`, so no link leads to a tag that does not exist (`crates/nerve-transport/build.rs`).

The binaries are not signed. The workflow uses no secrets. Only its last job
may write to the repository.

## A failed run

A failed run leaves no tag and no release. It deletes the draft release and the
tag it made itself, found by the id and the tag object it recorded. A draft you
wrote by hand for the same tag stays. It deletes them only when GitHub says
the tag has no published release.

If the last call published the release and only its answer was lost, the run is
red, the release and its tag stay as they are, and nothing needs doing.

If GitHub cannot be asked, nothing is deleted and the log has a warning. Look at
**Releases** and **Tags**, and delete a leftover draft or tag by hand before you
run again.

## Make a release

1. Set the version in the workspace `Cargo.toml`, in the `version` of the path
   dependencies in `[workspace.dependencies]`, and in `Cargo.lock` (run
   `cargo build`). Rename the `## Unreleased` section of `CHANGELOG.md`, where
   the changes since the last release collect, to `## <version>`. Until 0.1.0
   the Windows items stay under `## Unreleased`, as the release has no Windows
   program.
2. Merge that to `main`.
3. Run the workflow with kind `release` and that version.

The version is raised only by the release chore of step 1, right before the
release: never with the first change toward it. A pre-release of a version
that is not released yet needs that version on its branch, in a commit of its
own. Every change between releases collects under `## Unreleased`.
