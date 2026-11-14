//! `nerve-node relay`: other nodes reach this node's centers through it.

use super::*;

/// `relay`, `relay on|off|add|set|token|rm` (crate::relay). A token is
/// shown once, by `add` or `token`; `node.toml` keeps only its hash. Each
/// change says when it is in force ([`relay_in_force`]).
pub(super) async fn relay_cmd(
    paths: &NodePaths,
    c: Option<RelayCmd>,
    out: &mut dyn Write,
) -> Result<(), String> {
    let w = |out: &mut dyn Write, s: String| {
        let _ = writeln!(out, "{s}");
    };
    let Some(c) = c else {
        return show_relay(paths, out).await;
    };
    match c {
        RelayCmd::On {
            address,
            max_links,
            max_links_per_node,
            max_opens_per_minute,
        } => {
            if address.parse::<std::net::SocketAddr>().is_err() {
                return Err(format!(
                    "relay.listen {address:?}: an address and a port, like 0.0.0.0:7490 or [::]:7490"
                ));
            }
            let (now, _) = read_config(paths).await?;
            let (pin, made) = relay_pin(paths, &now, Some(&address))?;
            let cfg = edit(paths, |c| {
                c.relay.listen = Some(address.clone());
                c.relay.pin = Some(pin.clone());
                if let Some(n) = max_links {
                    c.relay.max_links = n;
                }
                if let Some(n) = max_links_per_node {
                    c.relay.max_links_per_node = n;
                }
                if let Some(n) = max_opens_per_minute {
                    c.relay.max_opens_per_minute = n;
                }
                Ok(())
            })
            .await?;
            w(
                out,
                format!(
                    "relay on {address}: at most {} tunnels, {} per node, {} opened a minute per node",
                    cfg.relay.max_links,
                    cfg.relay.max_links_per_node,
                    cfg.relay.max_opens_per_minute
                ),
            );
            w(out, format!("its TLS certificate has the pin {pin}"));
            if made && now.relay.pin.is_some() {
                w(
                    out,
                    "that is a new certificate: the relayed nodes need the new pin in `proxy set --pin`".into(),
                );
            }
            if cfg.relay.nodes.is_empty() {
                w(
                    out,
                    "no node may use it yet: `nerve-node relay add <name>` makes a token".into(),
                );
            }
            relay_in_force(paths, out, None).await;
            Ok(())
        }
        RelayCmd::Off => {
            edit(paths, |c| {
                c.relay.listen = None;
                Ok(())
            })
            .await?;
            w(out, "relay off".into());
            relay_in_force(
                paths,
                out,
                Some("the relay stops listening, and every tunnel ends"),
            )
            .await;
            Ok(())
        }
        RelayCmd::Add {
            name,
            centers,
            address,
        } => {
            if !nerve_proto::valid_node_name(&name) {
                return Err(format!(
                    "{name:?} is not a relay node name: 1 to 32 characters of a-z, 0-9 and -, starting and ending with a letter or digit"
                ));
            }
            let (now, _) = read_config(paths).await?;
            relay_centers(&now, &centers)?;
            let at = link_address(now.relay.listen.as_deref(), address.as_deref())?;
            let (pin, made) = relay_pin(paths, &now, now.relay.listen.as_deref())?;
            let (token, hash) = crate::relay::new_token();
            let cfg = edit(paths, |c| {
                if c.relay.node(&name).is_some() {
                    return Err(format!(
                        "the relay knows a node {name} already; `nerve-node relay rm {name}` takes its token away first"
                    ));
                }
                relay_centers(c, &centers)?;
                c.relay.pin = Some(pin.clone());
                c.relay.nodes.push(nerve_policy::config::RelayNode {
                    name: name.clone(),
                    token_sha256: hash.clone(),
                    centers: centers.clone(),
                    max_links: None,
                    max_opens_per_minute: None,
                });
                Ok(())
            })
            .await?;
            if made && now.relay.pin.is_some() {
                w(
                    out,
                    format!(
                        "the relay's TLS key was gone or did not match its pin, so it has a new certificate (pin {pin}): the relayed nodes need the new pin in `proxy set --pin`"
                    ),
                );
            }
            w(
                out,
                format!("relay node {name} added; its link, shown only now:"),
            );
            relay_link(out, &name, &token, &at, &pin, address.is_none());
            w(out, format!("it may reach {}", reach_of(&centers)));
            json::also(
                "token",
                link_json(
                    &name,
                    &token,
                    &at,
                    &pin,
                    &centers,
                    made && now.relay.pin.is_some(),
                    cfg.relay.listen.is_none(),
                ),
            );
            if cfg.relay.listen.is_none() {
                w(
                    out,
                    "the relay is off: `nerve-node relay on <address>` turns it on".into(),
                );
            }
            relay_in_force(paths, out, None).await;
            Ok(())
        }
        RelayCmd::Set {
            name,
            centers,
            max_links,
            max_opens_per_minute,
        } => {
            // `relay set 0.0.0.0:7490` was how the relay was turned on.
            if name.parse::<std::net::SocketAddr>().is_ok() || name.contains(':') {
                return Err(format!(
                    "{name:?} is an address, not a relayed node: turn the relay on with `nerve-node relay on {name}`"
                ));
            }
            if centers.is_empty() && max_links.is_none() && max_opens_per_minute.is_none() {
                return Err(
                    "name what to change: --to CENTER (`*` for every one), --max-links N or --max-opens-per-minute N (`default` for the relay's)"
                        .into(),
                );
            }
            let every = centers.iter().any(|c| c == "*");
            if every && centers.len() > 1 {
                return Err("--to '*' is every center; give no other --to with it".into());
            }
            let reach: Option<Vec<String>> = match () {
                _ if every => Some(Vec::new()),
                _ if centers.is_empty() => None,
                _ => Some(centers.clone()),
            };
            let limit = |what: &str, v: &Option<String>| -> Result<Option<Option<u32>>, String> {
                match v.as_deref() {
                    None => Ok(None),
                    Some("default") => Ok(Some(None)),
                    Some(n) => n
                        .parse()
                        .map(|n| Some(Some(n)))
                        .map_err(|_| format!("--{what} {n}: a number, or default")),
                }
            };
            let links_limit = limit("max-links", &max_links)?;
            let opens_limit = limit("max-opens-per-minute", &max_opens_per_minute)?;
            let cfg = edit(paths, |c| {
                if let Some(reach) = &reach {
                    relay_centers(c, reach)?;
                }
                let node = c
                    .relay
                    .nodes
                    .iter_mut()
                    .find(|n| n.name == name)
                    .ok_or_else(|| format!("the relay knows no node {name}"))?;
                if let Some(reach) = &reach {
                    node.centers = reach.clone();
                }
                if let Some(n) = links_limit {
                    node.max_links = n;
                }
                if let Some(n) = opens_limit {
                    node.max_opens_per_minute = n;
                }
                Ok(())
            })
            .await?;
            let node = cfg.relay.node(&name).expect("set above");
            if let Some(reach) = &reach {
                w(
                    out,
                    format!("relay node {name} may reach {}", reach_of(reach)),
                );
            }
            if links_limit.is_some() || opens_limit.is_some() {
                let links = node.links(&cfg.relay);
                let mut line = format!(
                    "relay node {name}: at most {links} tunnels at once, {} opened a minute",
                    node.opens(&cfg.relay)
                );
                if cfg.relay.max_links < links {
                    line.push_str(&format!(
                        " (the relay's {} tunnels in all bound it; `relay on <address> --max-links N` raises that)",
                        cfg.relay.max_links
                    ));
                }
                w(out, line);
            }
            let ends = reach
                .is_some()
                .then_some("its tunnels to other centers end");
            relay_in_force(paths, out, ends).await;
            Ok(())
        }
        RelayCmd::Token { name, address } => {
            let (now, _) = read_config(paths).await?;
            let at = link_address(now.relay.listen.as_deref(), address.as_deref())?;
            let (pin, made) = relay_pin(paths, &now, now.relay.listen.as_deref())?;
            let (token, hash) = crate::relay::new_token();
            let cfg = edit(paths, |c| {
                c.relay.pin = Some(pin.clone());
                let node = c
                    .relay
                    .nodes
                    .iter_mut()
                    .find(|n| n.name == name)
                    .ok_or_else(|| {
                        format!("the relay knows no node {name}; `relay add {name}` makes one")
                    })?;
                node.token_sha256 = hash.clone();
                Ok(())
            })
            .await?;
            if made && now.relay.pin.is_some() {
                w(
                    out,
                    format!(
                        "the relay's TLS key was gone or did not match its pin, so it has a new certificate (pin {pin}): the relayed nodes need the new pin in `proxy set --pin`"
                    ),
                );
            }
            let node = cfg.relay.node(&name).expect("set above");
            // Whether the old token is dead is the running node's to say
            // (`relay_in_force`): on Windows it takes the change at its next
            // start.
            w(
                out,
                format!("relay node {name} has a new token; its link, shown only now:"),
            );
            relay_link(out, &name, &token, &at, &pin, address.is_none());
            w(out, format!("it may reach {}", reach_of(&node.centers)));
            json::also(
                "token",
                link_json(
                    &name,
                    &token,
                    &at,
                    &pin,
                    &node.centers,
                    made && now.relay.pin.is_some(),
                    cfg.relay.listen.is_none(),
                ),
            );
            if cfg.relay.listen.is_none() {
                w(
                    out,
                    "the relay is off: `nerve-node relay on <address>` turns it on".into(),
                );
            }
            relay_in_force(
                paths,
                out,
                Some("the old token no longer works, and its tunnels end"),
            )
            .await;
            Ok(())
        }
        RelayCmd::Rm { name } => {
            edit(paths, |c| {
                let before = c.relay.nodes.len();
                c.relay.nodes.retain(|n| n.name != name);
                if c.relay.nodes.len() == before {
                    return Err(format!("the relay knows no node {name}"));
                }
                Ok(())
            })
            .await?;
            w(out, format!("relay node {name} removed"));
            relay_in_force(
                paths,
                out,
                Some("its token no longer works, and its tunnels end"),
            )
            .await;
            Ok(())
        }
    }
}

/// `relay`: the relay, the nodes that may use it and, on a running node,
/// who is connected.
async fn show_relay(paths: &NodePaths, out: &mut dyn Write) -> Result<(), String> {
    let (cfg, _) = read_config(paths).await?;
    let r = &cfg.relay;
    // Only a node that is not there means no node runs; any other error
    // is said, not taken for "no tunnel".
    let live = match node_call(paths, "status", json!({})).await {
        Ok(v) => Some(v["relay"].clone()),
        Err(e) if crate::cli::no_node(paths, &e) => None,
        Err(e) => return Err(format!("cannot ask the running node: {e}")),
    };
    let mut p = match &r.listen {
        Some(listen) => {
            let mut p = page("relay on");
            p.row("Listens on", listen.clone());
            if let Some(v) = &live {
                p.row("State", v["status"].as_str().unwrap_or("not known"));
            }
            p
        }
        None => {
            let mut p = page("relay off");
            p.next("Turn it on", "nerve-node relay on 0.0.0.0:7490");
            p
        }
    };
    if let Some(pin) = &r.pin {
        p.row("Pin", pin.clone());
    }
    p.row(
        "Limits",
        format!(
            "{} tunnels · {} per node · {} opened a minute per node",
            r.max_links, r.max_links_per_node, r.max_opens_per_minute
        ),
    );
    let nodes = r
        .nodes
        .iter()
        .map(|n| {
            let mut row = vec![n.name.clone(), reach_of(&n.centers)];
            if n.max_links.is_some() || n.max_opens_per_minute.is_some() {
                row.push(format!(
                    "own limits: {} tunnels · {} a minute",
                    n.links(r),
                    n.opens(r)
                ));
            }
            row
        })
        .collect::<Vec<_>>();
    if nodes.is_empty() {
        p.row("Nodes", "none may use it");
        p.next("Let one in", "nerve-node relay add <name>");
    }
    p.list(Some("Nodes"), nodes);
    match live {
        Some(v) => {
            let now = crate::now_ms();
            let tunnels = v["tunnels"]
                .as_array()
                .into_iter()
                .flatten()
                .map(|t| {
                    let since = t["since_ms"].as_u64().unwrap_or(now);
                    vec![
                        t["node"].as_str().unwrap_or_default().to_string(),
                        format!("from {}", t["from"].as_str().unwrap_or_default()),
                        format!("to {}", t["center"].as_str().unwrap_or_default()),
                        format!(
                            "for {}",
                            nerve_transport::log::span(std::time::Duration::from_millis(
                                now.saturating_sub(since)
                            ))
                        ),
                    ]
                })
                .collect();
            p.list(Some("Tunnels"), tunnels);
        }
        None if r.listen.is_some() => {
            p.note("No node runs here, so no tunnel is open.");
        }
        None => {}
    }
    show(out, &p);
    Ok(())
}

/// Says when a relay change is in force. A running node that took it
/// applies it at once: `now` says what that does ("its tunnels end"), for
/// the changes that take something away. With no node running there is
/// nothing to say.
async fn relay_in_force(paths: &NodePaths, out: &mut dyn Write, now: Option<&str>) {
    if daemon_answers(paths).await
        && let Some(what) = now
    {
        let _ = writeln!(out, "{what} now");
    }
}

/// Refuses a `--center` list that names a center this node is not paired
/// with, or one twice.
fn relay_centers(cfg: &NodeConfig, centers: &[String]) -> Result<(), String> {
    for (i, c) in centers.iter().enumerate() {
        let Some(entry) = cfg.center(c) else {
            return Err(format!("no center named {c} is paired here"));
        };
        if centers[..i].contains(c) {
            return Err(format!("--center {c} is given twice"));
        }
        // A tunnel reaches a host and port, not a center: a center there
        // that is not on the list would be reached as well.
        let at = |url: &str| {
            nerve_proto::link::CenterUrl::parse(url)
                .ok()
                .map(|u| (u.host, u.port))
        };
        let same = |a: Option<(String, u16)>, b: Option<(String, u16)>| match (a, b) {
            (Some((ha, pa)), Some((hb, pb))) => pa == pb && crate::relay::same_host(&ha, &hb),
            _ => false,
        };
        if let Some(other) = cfg.centers.iter().find(|o| {
            o.name != entry.name && !centers.contains(&o.name) && same(at(&o.url), at(&entry.url))
        }) {
            return Err(format!(
                "the centers {c} and {} share one host and port, and a tunnel reaches the host and port, so the relay cannot keep them apart: name both or neither",
                other.name
            ));
        }
    }
    Ok(())
}

/// What a relay node's center list allows, in words.
fn reach_of(centers: &[String]) -> String {
    if centers.is_empty() {
        "every https center of this node".into()
    } else {
        format!("the centers {}", centers.join(", "))
    }
}

/// The pin of the relay's TLS certificate, and whether it was made now: one
/// is made when the relay has none, or its key is gone or is not the one
/// `relay.pin` names. The key goes where the node keeps its keys
/// (`machine.secret_storage`), before the config names its pin; where that
/// is a keyring that does not answer, this fails as for any of its keys.
fn relay_pin(
    paths: &NodePaths,
    cfg: &NodeConfig,
    address: Option<&str>,
) -> Result<(String, bool), String> {
    let storage = cfg.machine.secret_storage;
    if let Some(pin) = &cfg.relay.pin
        && let Ok(Some(id)) = crate::secrets::relay_tls(paths, storage)
        && id.pin() == *pin
    {
        return Ok((pin.clone(), false));
    }
    let names: Vec<String> = address
        .and_then(|a| a.parse::<std::net::SocketAddr>().ok())
        .filter(|a| !a.ip().is_unspecified())
        .map(|a| a.ip().to_string())
        .into_iter()
        .collect();
    let id = nerve_transport::tls::ServerIdentity::generate(&names)?;
    crate::secrets::store_relay_tls(paths, storage, &id)?;
    Ok((id.pin(), true))
}

/// The port a relay link names when the relay has no address to listen on
/// yet: the one docs/dev/node-link.md uses.
const RELAY_PORT: u16 = 7490;

/// Where a relayed node finds the relay, for its link: `given` (with the
/// relay's port when it names none), else the address the relay listens on,
/// else this machine's host name, at the port it listens on.
pub fn link_address(listen: Option<&str>, given: Option<&str>) -> Result<String, String> {
    use nerve_proto::link::valid_host_port;
    let listen = listen.and_then(|l| l.parse::<std::net::SocketAddr>().ok());
    let port = listen.map_or(RELAY_PORT, |a| a.port());
    let at = match given.map(str::trim) {
        Some(g) if valid_host_port(g) => g.to_string(),
        Some(g) if g.parse::<std::net::Ipv6Addr>().is_ok() => format!("[{g}]:{port}"),
        Some(g) => format!("{g}:{port}"),
        None => match listen {
            Some(a) if !a.ip().is_unspecified() => a.to_string(),
            _ => format!("{}:{port}", crate::descriptor::host_name()),
        },
    };
    if let Some(g) = given
        && !valid_host_port(&at)
    {
        return Err(format!(
            "--address {g:?}: a host name or address, with or without :PORT"
        ));
    }
    Ok(at)
}

/// The lines that hand a relayed node its link: the link, and how the other
/// node takes it. `guessed`: the address is this program's guess, which the
/// owner may need to give.
fn relay_link(out: &mut dyn Write, name: &str, token: &str, at: &str, pin: &str, guessed: bool) {
    let link = nerve_proto::link::RelayLink {
        address: at.into(),
        node: name.into(),
        token: token.into(),
        pin: pin.into(),
    }
    .render();
    let _ = writeln!(out, "  {link}");
    // `-` reads the link from stdin: as an argument the token would be in
    // the process list while `proxy set` runs, and in the shell's history.
    let _ = writeln!(
        out,
        "on {name}, paste it in the desktop app (Relay, Connect), or run this and paste it on the next line:"
    );
    let _ = writeln!(out, "  nerve-node proxy set -");
    if guessed {
        let _ = writeln!(
            out,
            "the link reaches this machine as {at}; if {name} knows it by another name or address, make a new link with `relay token {name} --address <it>`"
        );
    }
}

/// What `relay add` and `relay token` give a program besides their lines.
fn link_json(
    name: &str,
    token: &str,
    at: &str,
    pin: &str,
    centers: &[String],
    new_pin: bool,
    relay_off: bool,
) -> Value {
    let link = nerve_proto::link::RelayLink {
        address: at.into(),
        node: name.into(),
        token: token.into(),
        pin: pin.into(),
    };
    json!({
        "node": name,
        "token": token,
        "address": at,
        "link": link.render(),
        "proxy": link.proxy_url(),
        "pin": pin,
        "reach": reach_of(centers),
        "new_pin": new_pin,
        "relay_off": relay_off,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::tests::{entry, has_row, load, run, setup};

    /// `relay add` shows a node's token once, with the line its node runs
    /// (an https:// proxy with the relay's pin), and `node.toml` keeps only
    /// the token's hash; the relay's TLS key is kept with the node's keys;
    /// `set`, `set-centers`, `rm` and `off` change the relay and nothing
    /// else.
    #[test]
    fn relay_add_shows_the_token_once_and_keeps_only_its_hash() {
        let (_d, paths) = setup(&["home", "work"]);
        // home and its neighbour share one address, behind one proxy.
        let mut cfg = load(&paths);
        cfg.centers[0].url = "https://h.example/a".into();
        cfg.centers[1].url = "https://w.example".into();
        let mut neighbour = entry("home-b");
        neighbour.url = "https://H.example:443/b".into();
        cfg.centers.push(neighbour);
        cfg.save(&paths.config_file()).unwrap();
        let paired = load(&paths).centers;
        let out = run(&paths, &["relay", "on", "0.0.0.0:7490", "--max-links", "8"]).unwrap();
        let pin = load(&paths).relay.pin.expect("a pin");
        assert!(
            out.starts_with(&format!(
                "relay on 0.0.0.0:7490: at most 8 tunnels, 4 per node, 30 opened a minute per node\nits TLS certificate has the pin {pin}\nno node may use it yet"
            )),
            "{out}"
        );
        let id = crate::secrets::relay_tls(&paths, SecretStorage::File)
            .unwrap()
            .expect("the relay's TLS key");
        assert_eq!(id.pin(), pin);
        assert!(paths.relay_tls_file().exists());
        // Again: the same certificate.
        run(
            &paths,
            &[
                "relay",
                "on",
                "0.0.0.0:7491",
                "--max-opens-per-minute",
                "300",
            ],
        )
        .unwrap();
        assert_eq!(load(&paths).relay.max_opens_per_minute, 300);
        assert!(
            run(
                &paths,
                &["relay", "on", "0.0.0.0:7491", "--max-opens-per-minute", "0"]
            )
            .is_err()
        );
        assert_eq!(load(&paths).relay.pin.as_deref(), Some(pin.as_str()));
        let e = run(&paths, &["relay", "on", "relay.example:7490"]).unwrap_err();
        assert!(e.contains("relay.listen"), "{e}");
        assert_eq!(load(&paths).relay.listen.as_deref(), Some("0.0.0.0:7491"));

        let out = run(&paths, &["relay", "add", "lab-pc"]).unwrap();
        // One link holds all the other node needs: the relay's address (the
        // host name here, as the relay listens on every address), the
        // node's name and token, and the pin.
        let link = out.lines().nth(1).unwrap().trim().to_string();
        let parsed = nerve_proto::link::RelayLink::parse(&link).unwrap();
        let token = parsed.token.clone();
        assert_eq!(token.len(), 43, "{out}");
        assert_eq!(parsed.node, "lab-pc");
        assert_eq!(parsed.pin, pin);
        let host = crate::descriptor::host_name();
        assert_eq!(parsed.address, format!("{host}:7491"));
        assert!(
            out.contains(&format!(
                "on lab-pc, paste it in the desktop app (Relay, Connect), or run this and paste it on the next line:\n  nerve-node proxy set -\nthe link reaches this machine as {host}:7491;"
            )),
            "{out}"
        );
        assert!(
            out.contains("it may reach every https center of this node\n"),
            "{out}"
        );
        let file = std::fs::read_to_string(paths.config_file()).unwrap();
        assert!(!file.contains(&token), "{file}");
        let cfg = load(&paths);
        let node = cfg.relay.node("lab-pc").unwrap();
        assert_eq!(node.token_sha256, crate::relay::token_hash(&token));
        assert!(node.centers.is_empty());
        assert_eq!(cfg.centers, paired);
        let e = run(&paths, &["relay", "add", "lab-pc"]).unwrap_err();
        assert!(e.contains("relay rm lab-pc"), "{e}");
        assert!(run(&paths, &["relay", "add", "Lab PC"]).is_err());

        // A node limited to some centers; only paired ones can be named.
        // A list that splits one address is refused: the relay cannot keep
        // the two apart.
        let e = run(&paths, &["relay", "add", "lab-2", "--to", "home"]).unwrap_err();
        assert!(e.contains("home and home-b share one host and port"), "{e}");
        assert!(load(&paths).relay.node("lab-2").is_none());
        let out = run(&paths, &["relay", "add", "lab-2", "--to", "work"]).unwrap();
        assert!(out.contains("it may reach the centers work\n"), "{out}");
        assert_eq!(load(&paths).relay.node("lab-2").unwrap().centers, ["work"]);
        let e = run(&paths, &["relay", "add", "lab-3", "--to", "elsewhere"]).unwrap_err();
        assert!(e.contains("no center named elsewhere"), "{e}");
        assert!(load(&paths).relay.node("lab-3").is_none());
        let out = run(
            &paths,
            &[
                "relay", "set", "lab-2", "--to", "work", "--to", "home", "--to", "home-b",
            ],
        )
        .unwrap();
        assert!(
            out.starts_with("relay node lab-2 may reach the centers work, home, home-b\n"),
            "{out}"
        );
        assert!(run(&paths, &["relay", "set", "nobody", "--to", "home"]).is_err());

        // A node of its own limits, for a relay behind this one.
        let out = run(
            &paths,
            &[
                "relay",
                "set",
                "lab-2",
                "--max-links",
                "12",
                "--max-opens-per-minute",
                "300",
            ],
        )
        .unwrap();
        assert!(
            out.starts_with("relay node lab-2: at most 12 tunnels at once, 300 opened a minute (the relay's 8 tunnels in all bound it;"),
            "{out}"
        );
        let node = load(&paths).relay.node("lab-2").unwrap().clone();
        assert_eq!(
            (node.max_links, node.max_opens_per_minute),
            (Some(12), Some(300))
        );
        // One flag sets that limit and keeps the other, as `relay on` does.
        run(&paths, &["relay", "set", "lab-2", "--max-links", "20"]).unwrap();
        let node = load(&paths).relay.node("lab-2").unwrap().clone();
        assert_eq!(
            (node.max_links, node.max_opens_per_minute),
            (Some(20), Some(300))
        );
        run(&paths, &["relay", "set", "lab-2", "--max-links", "12"]).unwrap();
        // A new token keeps the node's centers and limits; the old one
        // stops working.
        let before = load(&paths).relay.node("lab-2").unwrap().clone();
        let out = run(
            &paths,
            &["relay", "token", "lab-2", "--address", "relay.example"],
        )
        .unwrap();
        let link = nerve_proto::link::RelayLink::parse(out.lines().nth(1).unwrap()).unwrap();
        let token2 = link.token.clone();
        assert_eq!(token2.len(), 43, "{out}");
        // The address given, at the relay's port; no guess to warn about.
        assert_eq!(link.address, "relay.example:7491");
        assert!(!out.contains("make a new link"), "{out}");
        assert!(
            out.contains("it may reach the centers work, home, home-b\n"),
            "{out}"
        );
        let after = load(&paths).relay.node("lab-2").unwrap().clone();
        assert_eq!(after.token_sha256, crate::relay::token_hash(&token2));
        assert_ne!(after.token_sha256, before.token_sha256);
        assert_eq!(
            (&after.centers, after.max_links, after.max_opens_per_minute),
            (
                &before.centers,
                before.max_links,
                before.max_opens_per_minute
            )
        );
        assert!(
            !std::fs::read_to_string(paths.config_file())
                .unwrap()
                .contains(&token2)
        );
        assert!(run(&paths, &["relay", "token", "nobody"]).is_err());
        // The flag's help sends a chain to `relay set`, not to the
        // relay-wide budget.
        let help = Cli::command()
            .find_subcommand_mut("relay")
            .unwrap()
            .find_subcommand_mut("on")
            .unwrap()
            .render_long_help()
            .to_string();
        assert!(help.contains("relay set <name>"), "{help}");
        assert!(!help.contains("more for a relay behind this one"), "{help}");
        assert_eq!(
            load(&paths).relay.max_links_per_node,
            4,
            "the relay's stays"
        );
        assert!(run(&paths, &["relay", "set", "lab-2", "--max-links", "0"]).is_err());
        assert!(run(&paths, &["relay", "set", "nobody", "--max-links", "2"]).is_err());
        let ls = run(&paths, &["relay"]).unwrap();
        assert!(
            has_row(
                &ls,
                "lab-2 the centers work, home, home-b own limits: 12 tunnels · 300 a minute"
            ),
            "{ls}"
        );
        // Nothing named to change is an error; `default` gives the relay's
        // limits again, and an address names no relayed node.
        let e = run(&paths, &["relay", "set", "lab-2"]).unwrap_err();
        assert!(e.contains("name what to change"), "{e}");
        let e = run(&paths, &["relay", "set", "0.0.0.0:7490"]).unwrap_err();
        assert!(e.contains("`nerve-node relay on 0.0.0.0:7490`"), "{e}");
        run(
            &paths,
            &[
                "relay",
                "set",
                "lab-2",
                "--max-links",
                "default",
                "--max-opens-per-minute",
                "default",
            ],
        )
        .unwrap();
        let node = load(&paths).relay.node("lab-2").unwrap().clone();
        assert_eq!((node.max_links, node.max_opens_per_minute), (None, None));

        let ls = run(&paths, &["relay"]).unwrap();
        assert!(
            ls.ends_with(&format!(
                " · relay on

  Listens on   0.0.0.0:7491
  Pin          {pin}
  Limits       8 tunnels · 4 per node · 300 opened a minute per node

  Nodes
    lab-pc   every https center of this node
    lab-2    the centers work, home, home-b

Note  No node runs here, so no tunnel is open.
"
            )),
            "{ls}"
        );
        assert!(!ls.contains(&token), "{ls}");
        assert!(
            run(
                &paths,
                &["relay", "set", "lab-2", "--to", "*", "--to", "work"]
            )
            .is_err()
        );
        run(&paths, &["relay", "set", "lab-2", "--to", "*"]).unwrap();
        assert!(load(&paths).relay.node("lab-2").unwrap().centers.is_empty());

        // A lost TLS key: relay add makes a new certificate and says so.
        std::fs::remove_file(paths.relay_tls_file()).unwrap();
        let out = run(&paths, &["relay", "add", "lab-4"]).unwrap();
        let new_pin = load(&paths).relay.pin.unwrap();
        assert_ne!(new_pin, pin);
        assert!(
            out.starts_with(&format!(
                "the relay's TLS key was gone or did not match its pin, so it has a new certificate (pin {new_pin})"
            )),
            "{out}"
        );
        let out = run(&paths, &["relay", "add", "lab-5"]).unwrap();
        assert!(!out.contains("new certificate"), "{out}");

        let out = run(&paths, &["relay", "rm", "lab-pc"]).unwrap();
        assert!(out.starts_with("relay node lab-pc removed"), "{out}");
        assert!(load(&paths).relay.node("lab-pc").is_none());
        assert!(run(&paths, &["relay", "rm", "lab-pc"]).is_err());
        let out = run(&paths, &["relay", "off"]).unwrap();
        assert!(out.starts_with("relay off\n"), "{out}");
        let cfg = load(&paths);
        assert_eq!(cfg.relay.listen, None);
        assert_eq!(cfg.relay.max_links, 8);
        assert!(run(&paths, &["relay"]).unwrap().contains(" · relay off\n"));
    }
}
