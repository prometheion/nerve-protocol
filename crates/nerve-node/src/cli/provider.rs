//! `nerve-node provider`: the programs that may add capabilities.

use super::*;

/// `provider add`: allows a program to offer capabilities.
pub(super) async fn add_provider(
    paths: NodePaths,
    name: String,
    exe: String,
    out: &mut dyn Write,
) -> Result<(), String> {
    if !nerve_policy::config::valid_provider_name(&name) {
        return Err(format!(
            "{name:?} cannot name a provider: 1 to 32 of a-z, 0-9 and -, starting and ending with a letter or digit, and not node, config or center-added"
        ));
    }
    if !Path::new(&exe).is_absolute() {
        return Err(format!(
            "{exe}: give the program by its full path, as the node compares it"
        ));
    }
    edit(&paths, |c| {
        match c.providers.allowed.iter_mut().find(|p| p.name == name) {
            Some(p) => p.exe = exe.clone(),
            None => c
                .providers
                .allowed
                .push(nerve_policy::config::AllowedProvider {
                    name: name.clone(),
                    exe: exe.clone(),
                }),
        }
        Ok(())
    })
    .await?;
    w(out, format!("provider {name} added: {exe}"));
    Ok(())
}

/// `provider rm`: a program no longer offers capabilities.
pub(super) async fn rm_provider(
    paths: NodePaths,
    name: String,
    out: &mut dyn Write,
) -> Result<(), String> {
    edit(&paths, |c| {
        let before = c.providers.allowed.len();
        c.providers.allowed.retain(|p| p.name != name);
        if c.providers.allowed.len() == before {
            return Err(format!(
                "no provider {name} is allowed; `nerve-node provider` lists them"
            ));
        }
        Ok(())
    })
    .await?;
    w(out, format!("provider {name} removed"));
    Ok(())
}

/// A bare `provider`: the allowed programs and what they offer.
pub(super) async fn show_providers(paths: NodePaths, out: &mut dyn Write) -> Result<(), String> {
    let (cfg, _) = read_config(&paths).await?;
    let v = cap_listing(&paths, &cfg).await?;
    for l in program_lines(&v) {
        w(out, l);
    }
    Ok(())
}

/// The lines of `provider`: each program allowed, and whether it is
/// attached.
pub(super) fn program_lines(v: &Value) -> Vec<String> {
    let programs = v["programs"].as_array().cloned().unwrap_or_default();
    if programs.is_empty() {
        return vec!["no program is allowed as a provider".into()];
    }
    programs
        .iter()
        .map(|p| {
            let state = match p["attached"].as_bool() {
                Some(true) => "attached",
                Some(false) => "not attached",
                None => "the node does not run",
            };
            format!(
                "program {}: {}, {state}",
                p["name"].as_str().unwrap_or_default(),
                p["exe"].as_str().unwrap_or_default()
            )
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::tests::{json_of, program_path, run, setup};

    /// `provider add` names a program, again to replace it, `rm`
    /// takes it off, and `ls` shows them; a bad name or a relative path is
    /// refused.
    #[test]
    fn provider_adds_lists_and_removes_programs() {
        let (_d, paths) = setup(&["home"]);
        let (a, b, lamp) = (
            program_path("usr/bin/a"),
            program_path("usr/bin/b"),
            program_path("opt/lamp"),
        );
        let said = run(&paths, &["provider", "add", "desk", &a]).unwrap();
        // A stopped node takes it at its next start, and is told so.
        assert!(
            said.starts_with(&format!("provider desk added: {a}\n")),
            "{said}"
        );
        run(&paths, &["provider", "add", "desk", &b]).unwrap();
        run(&paths, &["provider", "add", "lamp-2", &lamp]).unwrap();
        let cfg =
            NodeConfig::parse(&std::fs::read_to_string(paths.config_file()).unwrap()).unwrap();
        let allowed: Vec<(&str, &str)> = cfg
            .providers
            .allowed
            .iter()
            .map(|p| (p.name.as_str(), p.exe.as_str()))
            .collect();
        assert_eq!(allowed, [("desk", b.as_str()), ("lamp-2", lamp.as_str())]);
        assert_eq!(
            run(&paths, &["provider"]).unwrap(),
            format!(
                "program desk: {b}, the node does not run\nprogram lamp-2: {lamp}, the node does \
                 not run\n"
            )
        );
        let v = json_of(&paths, &["provider"]);
        assert_eq!(v["programs"][1]["name"], "lamp-2", "{v}");
        assert_eq!(v["running"], false, "{v}");
        for (bad, why) in [
            (
                &["provider", "add", "Desk", &a][..],
                "cannot name a provider",
            ),
            (&["provider", "add", "node", &a], "cannot name a provider"),
            (&["provider", "add", "config", &a], "cannot name a provider"),
            (&["provider", "add", "desk", "bin/a"], "by its full path"),
            (&["provider", "rm", "nope"], "no provider nope"),
        ] {
            let e = run(&paths, bad).unwrap_err();
            assert!(e.contains(why), "{bad:?}: {e}");
        }
        let said = run(&paths, &["provider", "rm", "desk"]).unwrap();
        assert!(said.starts_with("provider desk removed\n"), "{said}");
        let v = json_of(&paths, &["provider"]);
        assert_eq!(v["programs"].as_array().unwrap().len(), 1, "{v}");
        run(&paths, &["provider", "rm", "lamp-2"]).unwrap();
        assert_eq!(
            run(&paths, &["provider"]).unwrap(),
            "no program is allowed as a provider\n"
        );
    }
}
