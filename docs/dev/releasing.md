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
| `version` | `x.y.z`, the version of `nerve-center`, `nerve-node` and `nerve` in the workspace `Cargo.toml` |

Every run builds and publishes the Linux and the Windows programs.

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
- `update --pre` on a machine takes the newest release, pre-releases too
  (GitHub's API names it), and `update --tag pre<N>-v<version>` that one, from
  `releases/download/<tag>/`; plain `update` takes `releases/latest/`, which
  skips pre-releases. A pre-release and its release of one version are
  different programs: `update` takes the release over the pre-release. The
  desktop app's **Settings › App › Pre-releases** passes `--pre`.
- The run builds the commit the branch is at when it starts. It tags that
  commit in its last job, after the checks and every build passed.
- One run at a time. A second run waits for the first. While one run waits, a
  third start replaces it, because GitHub keeps one waiting run per group.

## What a run does

1. Checks the inputs, the version and the tag (for a release, also the notes).
   Then it waits until CI (`ci.yml`: fmt, clippy and the whole test suite on
   Linux and Windows, musl, the installed tests) has passed on that very
   commit, at most two hours; a commit with no CI run, or a failed one, is
   not released. A pre-release of a branch needs the branch's pull request
   to have run CI on that commit.
2. Builds `nerve-center` and `nerve-node` for `x86_64-unknown-linux-musl` and
   `aarch64-unknown-linux-musl` (static). Each Linux binary must be static.
   Each binary must print its version from `--version`, and it must equal the
   one given. It also builds the desktop app `nerve` for Linux
   x86_64 on Ubuntu 22.04, the oldest runner (it links glibc and fontconfig,
   so it runs where glibc is 2.35 or newer; the run's summary says the glibc
   it needs). It must print `nerve <version>`. The `windows`
   job builds `nerve-center` and `nerve` for
   `x86_64-pc-windows-msvc` (static C runtime), with no Visual C++ runtime
   and the version given.
3. Runs the conformance suite (`cargo test -p nerve-conformance`) against the
   Linux binaries that were just built, the ones to be released, with
   `NERVE_CENTER_BIN` and `NERVE_NODE_BIN` set to them. `x86_64` runs on an
   x86_64 runner and `aarch64` on an arm64 runner. Then it installs them on
   Ubuntu 22.04 and 24.04 (x86_64, and arm64 on 24.04), Ubuntu 26.04 and
   Debian 12 and 13, and runs the real-machine tests, the keyring path and
   the center as a service there, as CI does
   (`.github/workflows/installed.yml`, [building](building.md#checks)).
   `windows-installed` does the same with the Windows programs it built, as CI's `windows-installed` does with debug ones
   (`.github/workflows/installed-windows.yml`); its test programs are debug
   builds of the same commit (`.github/scripts/windows-test-programs.sh`).
   The release's Windows tests are these installed ones, not the whole
   `cargo test --workspace` of CI's `windows` job.
4. Publishes, only once every job above passed, a GitHub Release with
   `SHA256SUMS` and nine files. The eight Linux files:
   `nerve-center` and `nerve-node` for each machine, and
   `nerve-x86_64-linux`, the app, which also comes as
   `nerve_<version>_amd64.deb`,
   `nerve-<version>.x86_64.rpm` and
   `nerve-<version>-1-x86_64.pkg.tar.zst`. The `.deb` and the `.rpm` are
   packed from that program with `dpkg-deb` and `rpmbuild`
   (`.github/scripts/desktop-packages.sh`) and installed on Ubuntu 22.04
   and 24.04 and Fedora in containers first (`desktop-packages-test`). The
   Arch package is built with `makepkg` from `packaging/arch/PKGBUILD` in an
   archlinux container (`.github/scripts/arch-package.sh`, job
   `desktop-arch-package`) and installed there with `pacman -U`, started
   with `--version`, upgraded and removed
   (`desktop-arch-package-test`). There is no AUR package. The ninth file
   is `nerve-x86_64-windows.exe`, the app, which is the node or the center
   there (the Windows job builds `nerve-center.exe` for the install test
   only). The release text ends with a
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
   the changes since the last release collect, to `## <version>`.
2. Merge that to `main`.
3. Run the workflow with kind `release` and that version.

The version is raised only by the release chore of step 1, right before the
release: never with the first change toward it. A pre-release of a version
that is not released yet needs that version on its branch, in a commit of its
own. Every change between releases collects under `## Unreleased`.
