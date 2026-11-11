//! `nerve-node proxy`: the HTTP proxy the node reaches its centers
//! through, with its header values and password in the keyring.

use super::*;

/// `proxy set|rm|ls`. The header values, and a user name and password given
/// in an `http://` URL, go into the system keyring ([`crate::secrets`]);
/// `node.toml` keeps the URL without them and the header names. The
/// installed node on Windows refuses them, as the service does not read the
/// keyring of the account that runs this. The password of an `https://`
/// proxy, a relay token, is kept with the node's own keys instead, where
/// `machine.secret_storage` says, and its user name in `connection.login`.
/// Nothing here prints, logs or audits a value.
pub(super) async fn proxy_cmd(
    paths: &NodePaths,
    c: Option<ProxyCmd>,
    out: &mut dyn Write,
) -> Result<(), String> {
    let Some(c) = c else {
        return show_proxy(paths, out).await;
    };
    match c {
        ProxyCmd::Set {
            url,
            pin,
            mut headers,
        } => {
            // `-` takes the URL or relay link from the first line of stdin,
            // as `center add -` takes its link: a relay link holds the
            // relay token, which in an argument every account could read in
            // the process list. What else comes on stdin follows that line.
            let url = given_url(&url)?;
            // A URL with a user name and no password takes the password from
            // stdin (asked without echo at a terminal), and `--header -`
            // the headers, one a line after it: neither shows in the
            // process list.
            let headers_stdin = headers.iter().any(|h| h == "-");
            headers.retain(|h| h != "-");
            let password_stdin = proxy_wants_password(&url);
            let mut stdin_password = None;
            if headers_stdin {
                let mut text = String::new();
                std::io::Read::read_to_string(&mut std::io::stdin(), &mut text)
                    .map_err(|e| format!("cannot read stdin: {e}"))?;
                let (password, more) = stdin_secrets(&text, password_stdin, true);
                stdin_password = password;
                headers.extend(more);
            } else if password_stdin {
                stdin_password = Some(proxy_password(out)?);
            }
            if stdin_password.as_ref().is_some_and(String::is_empty) {
                return Err("no password given: the first line of stdin is empty".into());
            }
            // A relay's link holds the proxy URL with this node's login and
            // the pin: one paste (docs/dev/node-link.md).
            let (url, pin) =
                if nerve_proto::link::strip_prefix_ci(url.trim(), "nerve://relay").is_some() {
                    let link = nerve_proto::link::RelayLink::parse(&url)?;
                    if pin.as_ref().is_some_and(|p| *p != link.pin) {
                        return Err("the relay link carries the pin; give no other --pin".into());
                    }
                    (link.proxy_url(), Some(link.pin))
                } else {
                    (url, pin)
                };
            let mut hs: Vec<(String, String)> = Vec::new();
            for (i, h) in headers.iter().enumerate() {
                // Not echoed: without its colon the whole line may be the secret.
                let (k, v) = h
                    .split_once(':')
                    .ok_or_else(|| format!("--header number {} is not `Name: value`", i + 1))?;
                let k = k.trim().to_string();
                if hs.iter().any(|(n, _)| n.eq_ignore_ascii_case(&k)) {
                    return Err(format!("the header {k} is given twice"));
                }
                hs.push((k, v.trim().to_string()));
            }
            let (url, mut login) = split_credentials(&url)?;
            if let Some(password) = stdin_password
                && let Some((_, p)) = &mut login
                && p.is_empty()
            {
                *p = password;
            }
            let https = url.to_ascii_lowercase().starts_with("https://");
            let (now, _) = read_config(paths).await?;
            let storage = now.machine.secret_storage;
            // An https:// proxy's login is the node's own secret.
            let (login, kept) = match login {
                Some((user, password)) if https => {
                    if !nerve_policy::config::valid_login(&user) {
                        return Err("the proxy URL has an empty or bad user name".into());
                    }
                    if hs
                        .iter()
                        .any(|(n, _)| n.eq_ignore_ascii_case(PROXY_AUTHORIZATION))
                    {
                        return Err(format!(
                            "give the proxy's user name and password either in the URL or as a {PROXY_AUTHORIZATION} header, not both"
                        ));
                    }
                    (None, Some((user, password)))
                }
                other => (other, None),
            };
            if let Some((user, password)) = login {
                if hs
                    .iter()
                    .any(|(n, _)| n.eq_ignore_ascii_case(PROXY_AUTHORIZATION))
                {
                    return Err(format!(
                        "give the proxy's user name and password either in the URL or as a {PROXY_AUTHORIZATION} header, not both"
                    ));
                }
                use base64::Engine;
                let basic =
                    base64::engine::general_purpose::STANDARD.encode(format!("{user}:{password}"));
                hs.push((PROXY_AUTHORIZATION.into(), format!("Basic {basic}")));
            }
            nerve_transport::net::Proxy::parse(&url, hs.clone())?.pinned(pin.clone())?;
            let names: Vec<String> = hs.iter().map(|(k, _)| k.clone()).collect();
            // The relay token goes where the node's keys are; where that is
            // a keyring that does not answer, this fails as for any key of
            // the node, and nothing is changed.
            match &kept {
                Some((_, password)) => crate::secrets::store_proxy_login(paths, storage, password)?,
                None if now.connection.login.is_some() => {
                    let _ = crate::secrets::remove_proxy_login(paths, storage);
                }
                None => {}
            }
            // The keyring first: when it cannot take the values, node.toml
            // stays as it was rather than name headers nobody can send. A
            // proxy without headers leaves the keyring alone, unless the one
            // before had some: their entry would only linger.
            if !hs.is_empty() {
                crate::secrets::store_proxy_headers(paths, &hs)?;
            } else if !now.connection.headers.is_empty() {
                let _ = crate::secrets::remove_proxy_headers(paths);
            }
            let user = kept.as_ref().map(|(u, _)| u.clone());
            edit(paths, |c| {
                c.connection.proxy = Some(url.clone());
                c.connection.pin = pin.clone();
                c.connection.login = user.clone();
                c.connection.headers = names.clone();
                Ok(())
            })
            .await?;
            let _ = writeln!(out, "proxy {url}");
            if let Some(p) = &pin {
                let _ = writeln!(out, "pin {p}");
            }
            if let Some(u) = &user {
                let _ = writeln!(
                    out,
                    "login {u} (its password is kept with the node's keys: {})",
                    keys_place(storage)
                );
            }
            for n in &names {
                let _ = writeln!(out, "header {n} (its value is in the system keyring)");
            }
            Ok(())
        }
        ProxyCmd::Off => {
            let (cfg, _) = read_config(paths).await?;
            edit(paths, |c| {
                c.connection.proxy = None;
                c.connection.pin = None;
                c.connection.login = None;
                c.connection.headers.clear();
                Ok(())
            })
            .await?;
            let _ = writeln!(out, "no proxy");
            if cfg.connection.login.is_some()
                && let Err(e) =
                    crate::secrets::remove_proxy_login(paths, cfg.machine.secret_storage)
            {
                return Err(format!("the proxy is removed, but {e}"));
            }
            // A proxy without headers has no entry; where there is no
            // keyring, asking for one would only fail.
            if cfg.connection.headers.is_empty() {
                return Ok(());
            }
            match crate::secrets::remove_proxy_headers(paths) {
                Ok(true) => {
                    let _ = writeln!(out, "deleted the header values from the system keyring");
                }
                Ok(false) => {}
                Err(e) => return Err(format!("the proxy is removed, but {e}")),
            }
            Ok(())
        }
    }
}

/// `proxy`: the proxy that is set and the names of its headers, never
/// their values.
async fn show_proxy(paths: &NodePaths, out: &mut dyn Write) -> Result<(), String> {
    let (cfg, _) = read_config(paths).await?;
    let Some(url) = &cfg.connection.proxy else {
        let _ = writeln!(out, "no proxy");
        return Ok(());
    };
    let _ = writeln!(out, "proxy {url}");
    if let Some(p) = &cfg.connection.pin {
        let _ = writeln!(out, "pin {p}");
    }
    if let Some(u) = &cfg.connection.login {
        let storage = cfg.machine.secret_storage;
        match crate::secrets::proxy_login(paths, storage) {
            Ok(_) => {
                let _ = writeln!(
                    out,
                    "login {u} (its password is kept with the node's keys: {})",
                    keys_place(storage)
                );
            }
            Err(e) => {
                let _ = writeln!(out, "login {u}");
                let _ = writeln!(out, "the link cannot use this proxy: {e}");
            }
        }
    }
    // The keyring is asked whether it holds every value; only the
    // names are shown.
    let names = &cfg.connection.headers;
    match crate::secrets::proxy_headers(paths, names) {
        Ok(_) => {
            for n in names {
                let _ = writeln!(out, "header {n} (its value is in the system keyring)");
            }
        }
        Err(e) => {
            for n in names {
                let _ = writeln!(out, "header {n}");
            }
            let _ = writeln!(out, "the link cannot use this proxy: {e}");
        }
    }
    Ok(())
}

/// The password of a proxy URL with a user name and no password: asked
/// without echo at a terminal (a console on Windows, as `sudo on` asks), else
/// the first line of stdin.
pub fn proxy_password(out: &mut dyn Write) -> Result<String, String> {
    #[cfg(unix)]
    return read_password(out, "proxy password: ");
    #[cfg(windows)]
    return crate::winsvc::WinSystem::read_password(
        &crate::win_host::WinHost,
        "proxy password: ",
        out,
    );
}

pub(super) const PROXY_AUTHORIZATION: &str = "Proxy-Authorization";

/// Where the node's keys are, in words.
pub(super) fn keys_place(storage: SecretStorage) -> &'static str {
    match storage {
        SecretStorage::File => "a file in the config folder",
        SecretStorage::Keyring => "the system keyring",
    }
}

/// Splits a user name and password off a proxy URL
/// (`http://user:pass@host:port`), percent-escapes decoded. Errors never quote
/// the URL once it holds an `@`.
/// What `proxy set` reads from stdin: with `password`, the first line is
/// the password; with `headers`, every other line that is not empty is a
/// header.
fn stdin_secrets(text: &str, password: bool, headers: bool) -> (Option<String>, Vec<String>) {
    let mut lines = text.lines().map(|l| l.trim_end_matches('\r'));
    let pw = if password {
        Some(lines.next().unwrap_or_default().to_string())
    } else {
        None
    };
    let hs = if headers {
        lines
            .filter(|l| !l.trim().is_empty())
            .map(str::to_string)
            .collect()
    } else {
        Vec::new()
    };
    (pw, hs)
}

/// The URL of `proxy set`: the one given, or for `-` the first line of
/// stdin.
fn given_url(url: &str) -> Result<String, String> {
    if url != "-" {
        return Ok(url.to_string());
    }
    let mut line = String::new();
    std::io::stdin()
        .lock()
        .read_line(&mut line)
        .map_err(|e| format!("cannot read the proxy URL: {e}"))?;
    let line = line.trim();
    if line.is_empty() {
        return Err(
            "proxy set -: the first line of stdin is empty, not a proxy URL or relay link".into(),
        );
    }
    Ok(line.to_string())
}

/// Whether `proxy set` reads the password of `url`: a URL with a user name
/// and no password (`http://user@host:port`).
pub fn proxy_wants_password(url: &str) -> bool {
    !url.trim().to_ascii_lowercase().starts_with("nerve://")
        && matches!(split_credentials(url), Ok((_, Some((_, p)))) if p.is_empty())
}

fn split_credentials(url: &str) -> Result<(String, Option<(String, String)>), String> {
    let Some(at) = url.rfind('@') else {
        return Ok((url.to_string(), None));
    };
    let scheme_end = url
        .find("://")
        .filter(|i| *i < at)
        .ok_or("a proxy URL with a user name starts with http://")?;
    let (scheme, info, rest) = (
        &url[..scheme_end + 3],
        &url[scheme_end + 3..at],
        &url[at + 1..],
    );
    let (user, password) = info.split_once(':').unwrap_or((info, ""));
    let decode = |s: &str| {
        pct_decode(s).ok_or("the user name or password in the proxy URL has a bad %-escape")
    };
    let (user, password) = (decode(user)?, decode(password)?);
    if user.is_empty() || user.contains(':') {
        return Err("the proxy URL has an empty or bad user name".into());
    }
    Ok((format!("{scheme}{rest}"), Some((user, password))))
}

/// `%XX` escapes decoded; `None` for a broken escape or text that is not UTF-8.
fn pct_decode(s: &str) -> Option<String> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' {
            let hex = std::str::from_utf8(b.get(i + 1..i + 3)?).ok()?;
            out.push(u8::from_str_radix(hex, 16).ok()?);
            i += 3;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    String::from_utf8(out).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::tests::{load, run, setup};

    #[test]
    fn proxy_secrets_come_from_stdin() {
        let text = "s3cret pass\r\nProxy-Authorization: Bearer x\n\nX-Team: a\n";
        assert_eq!(
            stdin_secrets(text, true, true),
            (
                Some("s3cret pass".into()),
                vec!["Proxy-Authorization: Bearer x".into(), "X-Team: a".into()]
            )
        );
        assert_eq!(stdin_secrets("X-A: 1\nX-B: 2", false, true).1.len(), 2);
        assert_eq!(
            stdin_secrets("pw\nX-A: 1", true, false),
            (Some("pw".into()), vec![])
        );
        assert_eq!(stdin_secrets("", true, false).0.as_deref(), Some(""));
    }

    /// What the test keyring holds for the node at `paths`.
    fn keyring_entry(paths: &NodePaths) -> Option<String> {
        let entry = crate::secrets::Entry::proxy(paths);
        crate::secrets::store::get(entry.account()).unwrap()
    }

    #[test]
    fn proxy_set_keeps_header_values_in_the_keyring_not_in_node_toml() {
        let (_d, paths) = setup(&["home"]);
        let out = run(
            &paths,
            &[
                "proxy",
                "set",
                "http://127.0.0.1:3128",
                "--header",
                "X-Key: s3cret-value",
                "--header",
                "X-Other:  two words ",
            ],
        )
        .unwrap();
        assert!(
            out.contains("header X-Key") && out.contains("header X-Other"),
            "{out}"
        );
        assert!(!out.contains("s3cret"), "{out}");
        let file = std::fs::read_to_string(paths.config_file()).unwrap();
        assert!(
            !file.contains("s3cret") && !file.contains("two words"),
            "{file}"
        );
        let cfg = load(&paths);
        assert_eq!(
            cfg.connection.proxy.as_deref(),
            Some("http://127.0.0.1:3128")
        );
        assert_eq!(cfg.connection.headers, ["X-Key", "X-Other"]);
        let held: std::collections::BTreeMap<String, String> =
            serde_json::from_str(&keyring_entry(&paths).unwrap()).unwrap();
        assert_eq!(held["X-Key"], "s3cret-value");
        assert_eq!(held["X-Other"], "two words");
        // A proxy without headers needs no entry; the old one goes.
        run(&paths, &["proxy", "set", "http://127.0.0.1:3129"]).unwrap();
        assert_eq!(keyring_entry(&paths), None);
        assert!(load(&paths).connection.headers.is_empty());
    }

    #[test]
    fn a_user_and_password_in_the_url_go_to_the_keyring() {
        let (_d, paths) = setup(&["home"]);
        let out = run(
            &paths,
            &["proxy", "set", "http://alice:pa%40ss-w0rd@127.0.0.1:3128"],
        )
        .unwrap();
        assert!(!out.contains("pa%40ss") && !out.contains("alice"), "{out}");
        let file = std::fs::read_to_string(paths.config_file()).unwrap();
        assert!(
            !file.contains("alice") && !file.contains("pa%40ss"),
            "{file}"
        );
        let cfg = load(&paths);
        assert_eq!(
            cfg.connection.proxy.as_deref(),
            Some("http://127.0.0.1:3128")
        );
        assert_eq!(cfg.connection.headers, [PROXY_AUTHORIZATION]);
        use base64::Engine;
        let basic = base64::engine::general_purpose::STANDARD.encode("alice:pa@ss-w0rd");
        assert!(!file.contains(&basic), "{file}");
        let held: std::collections::BTreeMap<String, String> =
            serde_json::from_str(&keyring_entry(&paths).unwrap()).unwrap();
        assert_eq!(held[PROXY_AUTHORIZATION], format!("Basic {basic}"));
        // Both ways at once is refused, and so is a bad URL, without quoting it.
        let both = [
            "proxy",
            "set",
            "http://alice:s3cret@127.0.0.1:3128",
            "--header",
            "proxy-authorization: Basic x",
        ];
        assert!(run(&paths, &both).unwrap_err().contains("not both"));
        for bad in [
            "alice:s3cret@127.0.0.1:3128",
            "http://alice:s3cret@127.0.0.1:3128/path",
            "https://alice:s3cret@127.0.0.1:3128/path",
            "http://alice:s3cr%zzet@127.0.0.1:3128",
        ] {
            let e = run(&paths, &["proxy", "set", bad]).unwrap_err();
            assert!(!e.contains("s3cr"), "{bad}: {e}");
        }
        // A --header without its colon is not quoted either.
        let e = run(
            &paths,
            &["proxy", "set", "http://127.0.0.1:1", "--header", "s3cret"],
        )
        .unwrap_err();
        assert!(!e.contains("s3cret"), "{e}");
    }

    #[test]
    fn a_node_toml_with_header_values_is_refused_with_run_proxy_set_again() {
        let d = tempfile::tempdir().unwrap();
        let paths = NodePaths::new(d.path().join("c"), d.path().join("s"));
        std::fs::create_dir_all(&paths.config_dir).unwrap();
        std::fs::write(
            paths.config_file(),
            "[connection]\nproxy = \"http://127.0.0.1:3128\"\nheaders = { X-Key = \"s3cret-value\" }\n",
        )
        .unwrap();
        for args in [&["proxy"][..], &["status"]] {
            let e = run(&paths, args).unwrap_err();
            assert!(e.contains("run `nerve-node proxy set` again"), "{e}");
            assert!(!e.contains("s3cret"), "{e}");
        }
    }

    /// The login of an https:// proxy, a relay token, is kept where the
    /// node keeps its keys: its file by default, the keyring with
    /// `keyring`, which refuses clearly when it does not answer; never in
    /// node.toml, and `proxy off` deletes it.
    #[test]
    fn an_https_proxy_login_is_kept_with_the_node_keys() {
        let pin = "A".repeat(43);
        let url = "https://lab:t0ken-value@127.0.0.1:7490";
        for storage in [SecretStorage::File, SecretStorage::Keyring] {
            let (_d, paths) = setup(&["home"]);
            if storage == SecretStorage::Keyring {
                let mut cfg = load(&paths);
                cfg.machine.secret_storage = storage;
                cfg.save(&paths.config_file()).unwrap();
            }
            let out = run(&paths, &["proxy", "set", url, "--pin", &pin]).unwrap();
            assert!(
                out.contains(&format!(
                    "pin {pin}\nlogin lab (its password is kept with the node's keys"
                )),
                "{out}"
            );
            assert!(!out.contains("t0ken"), "{out}");
            let cfg = load(&paths);
            assert_eq!(
                cfg.connection.proxy.as_deref(),
                Some("https://127.0.0.1:7490")
            );
            assert_eq!(cfg.connection.login.as_deref(), Some("lab"));
            assert!(cfg.connection.headers.is_empty());
            let toml = std::fs::read_to_string(paths.config_file()).unwrap();
            assert!(!toml.contains("t0ken"), "{toml}");
            assert_eq!(keyring_entry(&paths), None, "the header entry stays empty");
            let entry = crate::secrets::Entry::proxy_login(&paths);
            let in_keyring = crate::secrets::store::get(entry.account()).unwrap();
            let in_file = std::fs::read_to_string(paths.proxy_login_file()).ok();
            match storage {
                SecretStorage::File => {
                    assert_eq!(in_file.as_deref().map(str::trim), Some("t0ken-value"));
                    assert_eq!(in_keyring, None);
                }
                SecretStorage::Keyring => {
                    assert_eq!(in_keyring.as_deref(), Some("t0ken-value"));
                    assert_eq!(in_file, None);
                }
            }
            let ls = run(&paths, &["proxy"]).unwrap();
            assert!(ls.contains("login lab (its password is kept"), "{ls}");
            run(&paths, &["proxy", "off"]).unwrap();
            assert_eq!(crate::secrets::store::get(entry.account()).unwrap(), None);
            assert!(!paths.proxy_login_file().exists());
            assert_eq!(load(&paths).connection, Default::default());
        }
        // With the keys in a keyring that does not answer, it refuses and
        // changes nothing, as for any key of the node.
        let (_d, paths) = setup(&["home"]);
        let mut cfg = load(&paths);
        cfg.machine.secret_storage = SecretStorage::Keyring;
        cfg.save(&paths.config_file()).unwrap();
        run(&paths, &["status"]).unwrap();
        crate::secrets::store::set_unreachable(true);
        let r = run(&paths, &["proxy", "set", url, "--pin", &pin]);
        crate::secrets::store::set_unreachable(false);
        let e = r.unwrap_err();
        assert!(e.contains("system keyring"), "{e}");
        assert!(!e.contains("t0ken"), "{e}");
        assert_eq!(load(&paths).connection, Default::default());
        assert!(!paths.proxy_login_file().exists());
        // A pin is for an https:// proxy only.
        let e = run(
            &paths,
            &["proxy", "set", "http://127.0.0.1:3128", "--pin", &pin],
        )
        .unwrap_err();
        assert!(e.contains("https"), "{e}");
    }

    #[test]
    fn proxy_ls_and_rm_with_and_without_a_keyring_entry() {
        let (_d, paths) = setup(&["home"]);
        let set = [
            "proxy",
            "set",
            "http://127.0.0.1:3128",
            "--header",
            "X-Key: s3cret-value",
        ];
        // With the entry: ls says the value is there, rm deletes it.
        run(&paths, &set).unwrap();
        let ls = run(&paths, &["proxy"]).unwrap();
        assert_eq!(
            ls,
            "proxy http://127.0.0.1:3128\nheader X-Key (its value is in the system keyring)\n"
        );
        let rm = run(&paths, &["proxy", "off"]).unwrap();
        assert!(rm.contains("deleted the header values"), "{rm}");
        assert_eq!(keyring_entry(&paths), None);
        assert_eq!(run(&paths, &["proxy"]).unwrap(), "no proxy\n");

        // Without it: ls names the entry the link misses, rm still works.
        run(&paths, &set).unwrap();
        let entry = crate::secrets::Entry::proxy(&paths);
        crate::secrets::store::delete(entry.account()).unwrap();
        let ls = run(&paths, &["proxy"]).unwrap();
        assert!(ls.contains("header X-Key\n"), "{ls}");
        assert!(ls.contains(&format!("no entry {entry}")), "{ls}");
        let rm = run(&paths, &["proxy", "off"]).unwrap();
        assert_eq!(
            rm,
            format!("no proxy\nthe change is in node.toml; it {NEXT_START}\n")
        );
        assert_eq!(load(&paths).connection, Default::default());

        // A proxy without headers never needs the keyring, reachable or not.
        crate::secrets::store::set_unreachable(true);
        let plain = run(&paths, &["proxy", "set", "http://127.0.0.1:3128"]);
        let ls = run(&paths, &["proxy"]);
        let rm = run(&paths, &["proxy", "off"]);
        crate::secrets::store::set_unreachable(false);
        let next = format!("the change is in node.toml; it {NEXT_START}\n");
        assert_eq!(
            plain.unwrap(),
            format!("proxy http://127.0.0.1:3128\n{next}")
        );
        assert_eq!(ls.unwrap(), "proxy http://127.0.0.1:3128\n");
        assert_eq!(rm.unwrap(), format!("no proxy\n{next}"));
    }

    #[test]
    fn without_a_keyring_proxy_set_refuses_and_writes_no_value() {
        let (_d, paths) = setup(&["home"]);
        let before = std::fs::read_to_string(paths.config_file()).unwrap();
        crate::secrets::store::set_unreachable(true);
        let r = run(
            &paths,
            &[
                "proxy",
                "set",
                "http://alice:pa55w0rd@127.0.0.1:3128",
                "--header",
                "X-Key: s3cret-value",
            ],
        );
        crate::secrets::store::set_unreachable(false);
        let e = r.unwrap_err();
        assert!(
            e.contains("cannot store the proxy's header values in the system keyring"),
            "{e}"
        );
        assert!(e.contains(crate::secrets::store::NO_SERVICE), "{e}");
        assert!(!e.contains("s3cret") && !e.contains("pa55w0rd"), "{e}");
        // Nothing changed, and no value went to any file of the node.
        assert_eq!(
            std::fs::read_to_string(paths.config_file()).unwrap(),
            before
        );
        assert_eq!(keyring_entry(&paths), None);
        for dir in [&paths.config_dir, &paths.state_dir] {
            for f in files_below(dir) {
                let bytes = std::fs::read(&f).unwrap();
                let text = String::from_utf8_lossy(&bytes);
                assert!(
                    !text.contains("s3cret") && !text.contains("pa55w0rd"),
                    "{f:?}"
                );
            }
        }
    }

    /// On the installed node on Windows `proxy set` of an administrator puts
    /// a header value and a password into the Credential Manager of the
    /// service's account, through the running service, never its own; a
    /// proxy that needs neither takes the entry away again.
    #[test]
    fn on_the_installed_node_on_windows_proxy_set_keeps_its_values_in_the_services_vault() {
        let (_d, paths) = setup(&["home"]);
        crate::secrets::for_tests::pretend_windows_service(&paths);
        crate::secrets::for_tests::pretend_service_runs(&paths, true);
        run(
            &paths,
            &[
                "proxy",
                "set",
                "http://alice:pa55w0rd@127.0.0.1:3129",
                "--header",
                "X-Key: s3cret-value",
            ],
        )
        .unwrap();
        let cfg = load(&paths);
        assert_eq!(cfg.connection.headers.len(), 2, "{:?}", cfg.connection);
        let held = keyring_entry(&paths).expect("the service's vault holds them");
        assert!(
            held.contains("s3cret-value") && held.contains("Basic "),
            "{held}"
        );
        let toml = std::fs::read_to_string(paths.config_file()).unwrap();
        assert!(
            !toml.contains("s3cret") && !toml.contains("pa55w0rd"),
            "{toml}"
        );
        let ls = run(&paths, &["proxy"]).unwrap();
        assert!(ls.contains("its value is in the system keyring"), "{ls}");
        assert!(!ls.contains("s3cret"), "{ls}");
        run(&paths, &["proxy", "set", "http://127.0.0.1:3129"]).unwrap();
        assert_eq!(keyring_entry(&paths), None);
        run(&paths, &["proxy", "off"]).unwrap();
    }

    fn files_below(dir: &Path) -> Vec<PathBuf> {
        let mut out = Vec::new();
        for e in std::fs::read_dir(dir).into_iter().flatten().flatten() {
            let p = e.path();
            if p.is_dir() {
                out.extend(files_below(&p));
            } else {
                out.push(p);
            }
        }
        out
    }
}
