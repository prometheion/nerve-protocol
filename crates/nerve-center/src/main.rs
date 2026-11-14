//! `nerve-center`: started by a harness from its MCP configuration, or by
//! the owner with one of its commands (crate::entry).

fn main() -> std::process::ExitCode {
    nerve_center::entry::main(std::env::args_os().collect())
}
