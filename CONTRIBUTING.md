# Contributing

Thank you for helping. A pull request against `main` is the way in; for a
bigger change, open an issue first so the design is agreed before the work.

- **Build and checks:** [docs/dev/building.md](docs/dev/building.md). Before
  you push, `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`
  and `cargo test` pass, and so does `cargo deny --locked check` when you
  changed a dependency. CI runs them on Linux and Windows.
- **How it is built:** [docs/dev/architecture.md](docs/dev/architecture.md),
  and the [spec](docs/dev/spec/README.md) for anything on the wire.
- **A change comes with a test that fails without it**, and with the user doc
  it changes (`docs/user/`) and a line in `CHANGELOG.md` under `## Unreleased`.
- **No new dependency** without a reason in the pull request: every one is
  code that runs on the machines Nerve guards.
- **Licence:** Nerve is under the [Apache License 2.0](LICENSE). By sending a
  contribution you agree it is under that licence too (section 5 of the
  licence); there is no CLA and no sign-off line.
- **A security hole is not an issue or a pull request.** Report it as
  [SECURITY.md](SECURITY.md) says.
