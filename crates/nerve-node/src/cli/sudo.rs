//! `nerve-node sudo`: whether the commands on a center's sudo list run
//! with sudo, and the password they use.

use super::*;

/// `nerve-node sudo`, `sudo on|off`. The password lives in the running
/// daemon only, so `on` needs one; `off` without a daemon edits the file.
/// On Windows the CLI talks to it over its control pipe (crate::winsudo).
pub(super) async fn sudo_cmd(
    paths: &NodePaths,
    c: Option<SudoCmd>,
    out: &mut dyn Write,
) -> Result<(), String> {
    let Some(c) = c else {
        let on = sudo_is_on(paths).await?;
        let mut p = page(if on { "sudo on" } else { "sudo off" });
        match on {
            true => p.note("Only commands the sudo list names run with sudo."),
            false => p.next("Turn it on", "nerve-node sudo on"),
        };
        show(out, &p);
        return Ok(());
    };
    #[cfg(unix)]
    {
        use nerve_transport::ctl::{NOT_RUNNING, call};
        let w = |out: &mut dyn Write, s: &str| {
            let _ = writeln!(out, "{s}");
        };
        let sock = paths.ctl_socket();
        match c {
            SudoCmd::On => {
                // Fail before asking for the password when nothing can take it.
                match call(&sock, "status", json!({})).await {
                    Ok(_) => {}
                    Err(e) if e == NOT_RUNNING => {
                        return Err(
                            "sudo on needs the running daemon: it keeps the password in memory only"
                                .into(),
                        );
                    }
                    Err(e) => return Err(e),
                }
                let password = read_password(out, "sudo password: ")?;
                call(&sock, "sudo.on", json!({"password": password})).await?;
                w(
                    out,
                    "sudo: on (only commands the sudo allow list names run with sudo)",
                );
            }
            SudoCmd::Off => {
                match call(&sock, "sudo.off", json!({})).await {
                    Ok(_) => {}
                    Err(e) if e == NOT_RUNNING => {
                        edit(paths, |c| {
                            c.machine.sudo = nerve_policy::config::Sudo::Off;
                            Ok(())
                        })
                        .await?;
                    }
                    Err(e) => return Err(e),
                }
                w(out, "sudo: off");
            }
        }
        Ok(())
    }
    #[cfg(windows)]
    {
        use crate::win_host::WinHost;
        let call = async |m: &str, p: Value| node_call(paths, m, p).await;
        match c {
            SudoCmd::On => {
                let installed = crate::service::is_service_node(paths);
                crate::winsudo::on(&WinHost, installed, call, out).await
            }
            SudoCmd::Off => crate::winsudo::off(paths, &WinHost, call, out).await,
        }
    }
}

/// `nerve-node password`: the owner's Windows password to the running
/// node, which checks it and stores it for the commands that run as the
/// owner (crate::winsvc::save_owner_password). Only Windows keeps one.
pub(super) async fn owner_password(paths: &NodePaths, out: &mut dyn Write) -> Result<(), String> {
    #[cfg(not(windows))]
    {
        let _ = (paths, out);
        Err("only the node on Windows keeps its owner's password".into())
    }
    #[cfg(windows)]
    {
        use crate::winsvc::WinSystem;
        let password = crate::win_host::WinHost.read_password("Your Windows password: ", out)?;
        let v = node_call(paths, "owner.password", json!({"password": password})).await?;
        let _ = writeln!(
            out,
            "the node has the password of {}: commands that run as you run",
            v["owner"].as_str().unwrap_or_default()
        );
        Ok(())
    }
}

/// Whether sudo is on: the running node holds the password; one that does
/// not run holds none.
pub(super) async fn sudo_is_on(paths: &NodePaths) -> Result<bool, String> {
    #[cfg(unix)]
    {
        match nerve_transport::ctl::call(&paths.ctl_socket(), "sudo.status", json!({})).await {
            Ok(v) => Ok(v["sudo"] == "on"),
            // A node that does not run holds no password.
            Err(e) if e == nerve_transport::ctl::NOT_RUNNING => Ok(false),
            Err(e) => Err(e),
        }
    }
    #[cfg(windows)]
    {
        crate::winsudo::status(paths, async |m: &str, p: Value| {
            node_call(paths, m, p).await
        })
        .await
    }
}

/// Reads a password: from the terminal without echo, else one line of stdin.
#[cfg(unix)]
pub(super) fn read_password(out: &mut dyn Write, prompt: &str) -> Result<String, String> {
    use std::os::fd::AsRawFd;
    let stdin = std::io::stdin();
    let fd = stdin.as_raw_fd();
    // SAFETY: plain termios calls on stdin with a zeroed struct to fill.
    let mut old: libc::termios = unsafe { std::mem::zeroed() };
    let tty = unsafe { libc::isatty(fd) == 1 && libc::tcgetattr(fd, &mut old) == 0 };
    if tty {
        let _ = write!(out, "{prompt}");
        let _ = out.flush();
        let mut quiet = old;
        quiet.c_lflag &= !libc::ECHO;
        // SAFETY: as above; restored below.
        unsafe { libc::tcsetattr(fd, libc::TCSANOW, &quiet) };
    }
    let mut line = String::new();
    let r = stdin.lock().read_line(&mut line);
    if tty {
        // SAFETY: restores what tcgetattr returned.
        unsafe { libc::tcsetattr(fd, libc::TCSANOW, &old) };
        let _ = writeln!(out);
    }
    r.map_err(|e| e.to_string())?;
    let password = line.strip_suffix('\n').unwrap_or(&line);
    let password = password.strip_suffix('\r').unwrap_or(password).to_string();
    line.clear();
    if password.is_empty() {
        return Err("no password given".into());
    }
    Ok(password)
}
