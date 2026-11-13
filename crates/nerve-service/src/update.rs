//! `update` of an installed service, the node's and the center's: the new
//! program (the latest release, checked against its `SHA256SUMS`, or a file
//! the owner gives) replaces the installed one, the service's files (its
//! unit, and the node's polkit files and helper) are written as the new
//! program has them, and the service restarts. A program that does not run
//! here, or is older than the installed one, is refused; when the new one
//! does not start, the old program and the old files go back.

use std::io::Write;
use std::path::{Path, PathBuf};

use crate::{System, write_file};

/// The longest program a download takes.
const PROGRAM_MAX: usize = 256 * 1024 * 1024;
/// The longest `SHA256SUMS` a download takes.
const SUMS_MAX: usize = 64 * 1024;
/// The largest list of releases read from GitHub's API: a few releases,
/// each with its files.
const LIST_MAX: usize = 4 * 1024 * 1024;

/// The steps a command did, shown as they are done; the node audits them at
/// its end.
pub struct Steps<'a> {
    pub done: Vec<String>,
    pub out: &'a mut dyn Write,
}

impl<'a> Steps<'a> {
    pub fn new(out: &'a mut dyn Write) -> Steps<'a> {
        Steps {
            done: Vec::new(),
            out,
        }
    }

    pub fn did(&mut self, step: impl Into<String>) {
        let step = step.into();
        let _ = writeln!(self.out, "{step}");
        self.done.push(step);
    }
}

/// The system account `name` of a service, which `install` makes (`what`
/// says what it is for the steps, "the user"; `made_by` the command that
/// makes it): one there already that carries `mark` is taken, any other is
/// refused.
pub fn system_account(
    sys: &dyn System,
    name: &str,
    home: &Path,
    mark: &str,
    what: &str,
    made_by: &str,
    steps: &mut Steps<'_>,
) -> Result<crate::Account, String> {
    match sys.account(name)? {
        Some(a) if a.comment == mark => {
            steps.did(format!("{what} {name}, is there already"));
            Ok(a)
        }
        Some(_) => Err(format!(
            "an account {name} exists already, and {made_by} did not make it; the service needs it for itself"
        )),
        None => {
            sys.add_account(name, home, mark)?;
            let a = sys
                .account(name)?
                .ok_or_else(|| format!("useradd made no account {name}"))?;
            steps.did(format!("made {what} {name} (uid {})", a.uid));
            Ok(a)
        }
    }
}

/// The last steps of `install`: the unit `text` at `unit`, and the service
/// `name`, which runs as `user`, enabled and started again with it;
/// `started` waits until it answers.
pub fn start_unit(
    sys: &dyn System,
    unit: &Path,
    text: &str,
    name: &str,
    user: &str,
    started: &dyn Fn() -> Result<(), String>,
    steps: &mut Steps<'_>,
) -> Result<(), String> {
    write_file(unit, text.as_bytes(), 0o644)?;
    steps.did(format!("wrote the service unit {}", unit.display()));
    sys.systemctl(&["daemon-reload"])?;
    sys.systemctl(&["enable", name])?;
    sys.systemctl(&["restart", name])?;
    started()?;
    steps.did(format!(
        "the service {name} runs as {user} and starts with the machine"
    ));
    Ok(())
}

/// A version as `<program> --version` prints it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Version(u64, u64, u64);

impl Version {
    /// The version in what `program --version` said; none when another
    /// program said it.
    pub fn parse_of(program: &str, said: &str) -> Option<Version> {
        let v = said.trim().strip_prefix(program)?.strip_prefix(' ')?;
        let mut parts = v.split('.').map(|p| p.parse::<u64>().ok());
        let v = Version(parts.next()??, parts.next()??, parts.next()??);
        parts.next().is_none().then_some(v)
    }
}

impl std::fmt::Display for Version {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{}.{}", self.0, self.1, self.2)
    }
}

/// The installed program `update` replaces.
pub struct Program<'a> {
    /// Its name: the first word of its `--version`.
    pub name: &'a str,
    pub bin: &'a Path,
    /// Where the programs of the latest release and their `SHA256SUMS` are.
    pub release: &'a str,
    /// Its release file for this machine, or why there is none.
    pub asset: Result<String, String>,
    /// The service's user, and the mark `install` gives it.
    pub user: &'a str,
    pub mark: &'a str,
    /// The systemd unit.
    pub unit: &'a str,
    /// What makes the service again where its user is missing.
    pub install: &'a str,
    /// What `<program> service-files` is asked besides that word: what the
    /// service's files depend on here (the node's owner, the polkit found).
    pub files_args: Vec<String>,
    /// Where each file `service-files` names by its role goes, and its mode.
    pub places: Vec<Place>,
    /// What the new files need before the service restarts (the node loads
    /// its AppArmor profile). It says in `steps` what it did and does not
    /// fail the update.
    pub before_restart: &'a dyn Fn(&mut Steps<'_>),
    /// Where a package manager put the new program at `bin` already (the
    /// desktop app from a .deb or .rpm): the update leaves the file to it.
    pub placed: Option<Placed>,
}

/// The program as it was before a package manager put the new one in its
/// place ([`Program::placed`]). The service may still run it, so the
/// update restarts the service even where nothing else changed.
#[derive(Debug, Clone, Default)]
pub struct Placed {
    /// Its bytes, which go back where the new one does not start; none
    /// where the package manager ran before the update did.
    pub old: Option<Vec<u8>>,
    pub version: Option<Version>,
}

/// Where the file of a role goes, and its mode.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Place {
    pub role: &'static str,
    pub path: PathBuf,
    pub mode: u32,
}

/// The word that makes a program print its service's files.
pub const SERVICE_FILES: &str = "service-files";

/// What `<program> service-files` prints: each file of the service by its
/// role, its text, or `null` for one that must not be there. A role it
/// leaves out stays as it is.
pub fn files_text(files: &[(&str, Option<String>)]) -> String {
    let map: serde_json::Map<String, serde_json::Value> = files
        .iter()
        .map(|(role, text)| (role.to_string(), serde_json::json!(text)))
        .collect();
    serde_json::Value::Object(map).to_string()
}

/// The files `said` names (what `service-files` printed), each at its
/// place; and the roles there is no place for here.
pub fn files_from(said: &str, places: &[Place]) -> Result<(Vec<ServiceFile>, Vec<String>), String> {
    let v: serde_json::Value = serde_json::from_str(said).map_err(|e| format!("not JSON: {e}"))?;
    let map = v.as_object().ok_or("not an object")?;
    let mut files = Vec::new();
    let mut unknown = Vec::new();
    for (role, text) in map {
        let Some(p) = places.iter().find(|p| p.role == role) else {
            unknown.push(role.clone());
            continue;
        };
        let text = match text {
            serde_json::Value::Null => None,
            serde_json::Value::String(t) => Some(t.clone()),
            _ => return Err(format!("{role}: neither a text nor null")),
        };
        files.push(ServiceFile {
            path: p.path.clone(),
            text,
            mode: p.mode,
        });
    }
    Ok((files, unknown))
}

/// A file of the service besides its program, as the new program has it:
/// its text, written with `mode`, or `None` for one that must not be there.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceFile {
    pub path: PathBuf,
    pub text: Option<String>,
    pub mode: u32,
}

/// A file as it was before `update` changed it: its bytes and mode, or none.
struct Before {
    path: PathBuf,
    was: Option<(Vec<u8>, u32)>,
}

/// Replaces the program `p` with the new one and restarts its service, with
/// the service's files as the new program has them (`service-files`, asked of
/// it as root with an empty environment; `--version` runs as the service's
/// user). `started` waits until the restarted service
/// answers. `Ok(false)`: the installed program is that one already, its
/// files are as it has them, and nothing changed.
pub async fn update(
    p: &Program<'_>,
    sys: &dyn System,
    from: Option<&Path>,
    started: &dyn Fn() -> Result<(), String>,
    steps: &mut Steps<'_>,
) -> Result<bool, String> {
    let name = p.name;
    let account = sys
        .account(p.user)?
        .filter(|a| a.comment == p.mark)
        .ok_or_else(|| {
            format!(
                "the user {} is missing; `{}` makes it again",
                p.user, p.install
            )
        })?;
    let new = match from {
        // The package manager's program, at its place.
        _ if p.placed.is_some() => {
            std::fs::read(p.bin).map_err(|e| format!("{}: {e}", p.bin.display()))?
        }
        Some(f) => {
            let b = std::fs::read(f).map_err(|e| format!("{}: {e}", f.display()))?;
            steps.did(format!("read the new program from {}", f.display()));
            b
        }
        None => {
            let asset = p.asset.clone()?;
            let b = fetch_release(p.release, &asset).await?;
            steps.did(format!(
                "downloaded {asset} from {} and checked it against its SHA256SUMS",
                p.release
            ));
            b
        }
    };
    let old = match &p.placed {
        Some(placed) => placed.old.clone(),
        None => Some(std::fs::read(p.bin).map_err(|e| format!("{}: {e}", p.bin.display()))?),
    };
    // A program the package manager placed is never the same: the service
    // still runs the one before it.
    let same = p.placed.is_none() && old.as_deref() == Some(&new[..]);
    let placed = p.placed.is_some();
    // Staged beside the program, so the rename that puts it in place does
    // not cross file systems.
    let staged = p.bin.with_file_name(format!(".{name}.new"));
    let stage = !same && !placed;
    if stage {
        write_file(&staged, &new, 0o755)?;
    }
    // Where the program is the installed one already, it still has the
    // files: an `update` brings those a program left behind, as the update
    // that installed it did not know them.
    let from_program = if stage { &staged } else { p.bin };
    let checked = (|| {
        let old_v = match &p.placed {
            Some(placed) => placed.version,
            None => sys
                .version_of(p.bin, &account)
                .ok()
                .and_then(|s| Version::parse_of(name, &s)),
        };
        let mut new_v = old_v;
        if !same {
            let said = sys.version_of(from_program, &account)?;
            let v = Version::parse_of(name, &said)
                .ok_or_else(|| format!("the new program is not {name}: it says {said:?}"))?;
            // The package manager's program is in place already; the
            // node refused an older package before it ran.
            if let Some(o) = old_v
                && v < o
                && !placed
            {
                return Err(format!(
                    "the new program is {name} {v}, older than the installed {o}; nothing changed"
                ));
            }
            new_v = Some(v);
        }
        // The new program's own unit and files: it runs under what it
        // was made for, not under what the installed one wrote. Root asks
        // for them, not the service's user: the files root writes must not
        // come from a process that the service's other processes can reach.
        let mut args = vec![SERVICE_FILES];
        args.extend(p.files_args.iter().map(String::as_str));
        let want = sys
            .output_of(from_program, None, &args)
            .and_then(|said| files_from(&said, &p.places))
            .map_err(|e| format!("the new program does not say its service's files: {e}"))?;
        Ok((old_v, new_v, want))
    })();
    let (old_v, new_v, (want, unknown)) = match checked {
        Ok(v) => v,
        Err(e) => {
            if stage {
                let _ = std::fs::remove_file(&staged);
            }
            return Err(e);
        }
    };
    let shown = |v: Option<Version>| v.map_or_else(|| "?".to_string(), |v| v.to_string());
    if !same {
        if stage {
            std::fs::rename(&staged, p.bin).map_err(|e| format!("{}: {e}", p.bin.display()))?;
        }
        steps.did(match old_v {
            // The package manager replaced it before this update ran.
            None if placed => format!("{name} {} from its package is in place", shown(new_v)),
            _ => format!("replaced {name} {} with {}", shown(old_v), shown(new_v)),
        });
    }
    let mut before = Vec::new();
    let put = put_files(&want, &mut before, steps);
    if put.is_ok() && same && before.is_empty() {
        steps.did(
            "the installed program and its service's files are those already; nothing to update",
        );
        return Ok(false);
    }
    let start = put
        .and_then(|()| reload(sys, &before))
        .and_then(|()| {
            (p.before_restart)(steps);
            sys.systemctl(&["restart", p.unit])
        })
        .and_then(|()| started());
    if let Err(e) = start {
        // A placed program whose old bytes are unknown stays.
        let program_back = !same && old.is_some();
        if let (true, Some(old)) = (program_back, &old) {
            write_file(p.bin, old, 0o755)?;
        }
        let files_back = put_back(&before).and_then(|()| reload(sys, &before));
        let back = files_back
            .and_then(|()| sys.systemctl(&["restart", p.unit]))
            .and_then(|()| started());
        let what = match (program_back, before.is_empty()) {
            (true, true) => format!("{name} {}", shown(old_v)),
            (true, false) => format!("{name} {} and its service's files", shown(old_v)),
            (false, _) => "the service's files".to_string(),
        };
        steps.did(format!("put {what} back"));
        let new = if same {
            "the service did not start with its new files"
        } else {
            "the new program did not start"
        };
        return Err(match back {
            Ok(()) => format!("{new} ({e}); the old one runs again"),
            Err(e2) => format!("{new} ({e}), and the old one does not either ({e2})"),
        });
    }
    steps.did(format!("restarted the service {}", p.unit));
    if !unknown.is_empty() {
        steps.did(format!(
            "Warning: the new program has files this update cannot place ({}): `{}` puts them in place",
            unknown.join(", "),
            p.install
        ));
    }
    Ok(true)
}

/// Writes or removes each of `want` that differs from what is there, and
/// keeps in `before` what it was.
fn put_files(
    want: &[ServiceFile],
    before: &mut Vec<Before>,
    steps: &mut Steps<'_>,
) -> Result<(), String> {
    for f in want {
        let was = match std::fs::read(&f.path) {
            Ok(b) => Some((b, mode_of(&f.path))),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(e) => return Err(format!("{}: {e}", f.path.display())),
        };
        let same = match (&was, &f.text) {
            (Some((b, _)), Some(t)) => b == t.as_bytes(),
            (None, None) => true,
            _ => false,
        };
        if same {
            continue;
        }
        before.push(Before {
            path: f.path.clone(),
            was,
        });
        match &f.text {
            Some(t) => {
                write_file(&f.path, t.as_bytes(), f.mode)?;
                steps.did(format!("wrote {}", f.path.display()));
            }
            None => {
                std::fs::remove_file(&f.path).map_err(|e| format!("{}: {e}", f.path.display()))?;
                steps.did(format!("removed {}", f.path.display()));
            }
        }
    }
    Ok(())
}

/// Puts back what [`put_files`] changed.
fn put_back(before: &[Before]) -> Result<(), String> {
    for b in before {
        match &b.was {
            Some((bytes, mode)) => write_file(&b.path, bytes, *mode)?,
            None => match std::fs::remove_file(&b.path) {
                Err(e) if e.kind() != std::io::ErrorKind::NotFound => {
                    return Err(format!("{}: {e}", b.path.display()));
                }
                _ => {}
            },
        }
    }
    Ok(())
}

/// systemd reads the unit again where a file changed.
fn reload(sys: &dyn System, before: &[Before]) -> Result<(), String> {
    if before.is_empty() {
        return Ok(());
    }
    sys.systemctl(&["daemon-reload"])
}

fn mode_of(path: &Path) -> u32 {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::metadata(path).map_or(0o644, |m| m.permissions().mode() & 0o7777)
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        0o644
    }
}

/// Downloads `asset` from the release at `base` and checks it against the
/// release's `SHA256SUMS`.
pub async fn fetch_release(base: &str, asset: &str) -> Result<Vec<u8>, String> {
    fetch_release_where(base, asset, &|name| name == asset)
        .await
        .map(|(_, b)| b)
}

/// Which release `update` takes: the latest (GitHub's latest leaves the
/// pre-releases out), the newest one with the pre-releases (`--pre`), or the
/// one of a tag (`--tag`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum Release {
    #[default]
    Latest,
    Pre,
    Tag(String),
}

/// The end of where the latest release's files are, after the repository.
const LATEST: &str = "/releases/latest/download";

impl Release {
    /// The release `--pre` and `--tag` choose.
    pub fn of(pre: bool, tag: Option<String>) -> Release {
        match (pre, tag) {
            (_, Some(t)) => Release::Tag(t),
            (true, None) => Release::Pre,
            (false, None) => Release::Latest,
        }
    }

    /// Where this release's files are, from `latest`, where the latest
    /// release's are (`<repository>/releases/latest/download`): a tag's in
    /// `<repository>/releases/download/<tag>`; with the pre-releases, the
    /// newest release's, which GitHub's API names.
    pub async fn base(&self, latest: &str) -> Result<String, String> {
        match self {
            Release::Latest => Ok(latest.to_string()),
            Release::Tag(t) => tag_base(latest, t),
            Release::Pre => {
                nerve_transport::init_crypto();
                let list = download(&api_of(latest)?, LIST_MAX)
                    .await
                    .map_err(|e| refused_list(&e))?;
                tag_base(latest, &newest_tag(&list)?)
            }
        }
    }
}

/// Where the files of the release `tag` are, beside the latest's.
fn tag_base(latest: &str, tag: &str) -> Result<String, String> {
    let ok = !tag.is_empty()
        && tag.len() <= 100
        && !tag.contains("..")
        && tag
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "._-+".contains(c));
    if !ok {
        return Err(format!(
            "{tag:?} is no release tag: letters, digits, `.`, `-`, `_` and `+`, like pre2-v0.1.0"
        ));
    }
    let repo = latest
        .strip_suffix(LATEST)
        .ok_or_else(|| format!("{latest} is not where a release's files are"))?;
    Ok(format!("{repo}/releases/download/{tag}"))
}

/// The list of the releases, newest first, of the repository whose latest
/// release's files are at `latest`: GitHub's API for a repository there;
/// elsewhere (a mirror, a test's server) `<repository>/api/releases`.
fn api_of(latest: &str) -> Result<String, String> {
    let repo = latest
        .strip_suffix(LATEST)
        .ok_or_else(|| format!("{latest} is not where a release's files are"))?;
    Ok(match repo.strip_prefix("https://github.com/") {
        Some(path) => format!("https://api.github.com/repos/{path}/releases?per_page=5"),
        None => format!("{repo}/api/releases"),
    })
}

/// The tag of the newest release in GitHub's list of releases (newest
/// first), pre-releases too; drafts are left out.
fn newest_tag(list: &[u8]) -> Result<String, String> {
    let v: serde_json::Value = serde_json::from_slice(list)
        .map_err(|e| format!("GitHub's list of releases is no JSON: {e}"))?;
    v.as_array()
        .into_iter()
        .flatten()
        .filter(|r| r["draft"] != true)
        .find_map(|r| r["tag_name"].as_str())
        .map(str::to_string)
        .ok_or_else(|| "GitHub's list of releases names none".to_string())
}

/// What a refused list of the releases means. Without a login GitHub's API
/// answers a machine 60 times an hour, then 403 or 429.
fn refused_list(e: &str) -> String {
    if e.contains("HTTP 403") || e.contains("HTTP 429") {
        return "GitHub did not say which release is the newest: it answers 60 such questions an hour from a machine without a login. Try again later, or name the release with --tag <tag> (its releases page lists them)".into();
    }
    format!("cannot ask GitHub for the newest release: {e}")
}

/// [`fetch_release`] of the first file `SHA256SUMS` lists that `pick`
/// takes (a package, whose name holds the release's version): its name
/// and bytes. `what` names it where the list has none.
pub async fn fetch_release_where(
    base: &str,
    what: &str,
    pick: &dyn Fn(&str) -> bool,
) -> Result<(String, Vec<u8>), String> {
    nerve_transport::init_crypto();
    // A tag with no release (`--tag` mistyped) has no SHA256SUMS either.
    let sums = download(&format!("{base}/SHA256SUMS"), SUMS_MAX)
        .await
        .map_err(|e| match e.contains("HTTP 404") {
            true => format!("no release is at {base}: {e}"),
            false => e,
        })?;
    let (asset, want) = String::from_utf8_lossy(&sums)
        .lines()
        .find_map(|l| {
            let (hash, name) = l.split_once(char::is_whitespace)?;
            let name = name.trim_start();
            let name = name.strip_prefix('*').unwrap_or(name);
            pick(name).then(|| (name.to_string(), hash.to_ascii_lowercase()))
        })
        .ok_or_else(|| format!("the release's SHA256SUMS lists no {what}"))?;
    let program = download(&format!("{base}/{asset}"), PROGRAM_MAX).await?;
    let got = nerve_transport::keys::sha256_hex(&program);
    if got != want {
        return Err(format!(
            "the downloaded {asset} does not match its line in SHA256SUMS; nothing changed"
        ));
    }
    Ok((asset, program))
}

/// `GET url`, following redirects (never from https to http), through the
/// proxy `HTTPS_PROXY` names: the download the center's one-click model
/// install shares (`nerve_transport::download`). Errors name the host, not
/// the whole address, which may hold a signed query.
async fn download(url: &str, max: usize) -> Result<Vec<u8>, String> {
    let mut body = Vec::new();
    let opts = nerve_transport::download::Options {
        max: max as u64,
        idle: nerve_transport::http::HEAD_TIMEOUT,
        // Five redirects, as the node's own loop followed before.
        hops: 5,
        cancel: None,
    };
    nerve_transport::download::fetch(url, &mut body, &opts, &mut |_, _| {}).await?;
    Ok(body)
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::fake::Fake;
    use std::os::unix::fs::PermissionsExt;

    /// `--tag` takes the files of that release, beside the latest's;
    /// `--pre` the newest release's that the list of releases names, a
    /// pre-release too and no draft (#213). A tag that is not one is
    /// refused, and a refused list says how to go on.
    #[tokio::test]
    async fn a_release_is_the_latest_a_tag_or_the_newest_with_the_pre_releases() {
        let latest = "https://github.com/o/r/releases/latest/download";
        assert_eq!(Release::Latest.base(latest).await.unwrap(), latest);
        assert_eq!(
            Release::of(false, Some("pre2-v0.1.0".into()))
                .base(latest)
                .await
                .unwrap(),
            "https://github.com/o/r/releases/download/pre2-v0.1.0"
        );
        for bad in ["", "../x", "a..b", "a/b", "v1 2", "x?y"] {
            assert!(tag_base(latest, bad).is_err(), "{bad:?}");
        }
        assert_eq!(
            api_of(latest).unwrap(),
            "https://api.github.com/repos/o/r/releases?per_page=5"
        );
        assert!(api_of("https://example.org/files").is_err());
        let list = br#"[{"tag_name": "pre3-v0.1.1", "draft": true, "prerelease": true},
                        {"tag_name": "pre2-v0.1.1", "draft": false, "prerelease": true},
                        {"tag_name": "v0.1.0", "draft": false, "prerelease": false}]"#;
        assert_eq!(newest_tag(list).unwrap(), "pre2-v0.1.1");
        assert!(newest_tag(b"[]").is_err());
        assert!(newest_tag(b"{\"message\": \"x\"}").is_err());
        assert!(refused_list("api.github.com answered HTTP 403").contains("--tag <tag>"));
        // `--pre` asks the list and takes the newest tag's files.
        use nerve_transport::http::{Response, read_request};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            while let Ok((mut io, _)) = listener.accept().await {
                let req = read_request(&mut io, 0).await.unwrap();
                let r = match req.path.as_str() {
                    "/o/r/api/releases" => Response::new(200, "application/json", &list[..]),
                    _ => Response::text(404, "no"),
                };
                let _ = r.write(&mut io).await;
            }
        });
        let here = format!("http://127.0.0.1:{port}/o/r/releases/latest/download");
        assert_eq!(
            Release::Pre.base(&here).await.unwrap(),
            format!("http://127.0.0.1:{port}/o/r/releases/download/pre2-v0.1.1")
        );
    }

    struct At {
        _dir: tempfile::TempDir,
        bin: PathBuf,
        unit: PathBuf,
        helper: PathBuf,
        rule: PathBuf,
    }

    /// A service installed by version 1.0.0 in a temporary folder: its
    /// program, its unit and a rule; no helper yet.
    fn installed(sys: &Fake) -> At {
        let d = tempfile::tempdir().unwrap();
        let at = At {
            bin: d.path().join("bin/svc"),
            unit: d.path().join("systemd/svc.service"),
            helper: d.path().join("lib/svc/helper"),
            rule: d.path().join("polkit/svc.rules"),
            _dir: d,
        };
        write_file(&at.bin, b"svc 1.0.0\n", 0o755).unwrap();
        write_file(&at.unit, b"old unit", 0o644).unwrap();
        write_file(&at.rule, b"old rule", 0o644).unwrap();
        sys.add_account("svc", Path::new("/var/lib/svc"), "Svc")
            .unwrap();
        at
    }

    fn program(at: &At) -> Program<'_> {
        Program {
            name: "svc",
            bin: &at.bin,
            release: "https://releases.invalid",
            asset: Err("no release here".into()),
            user: "svc",
            mark: "Svc",
            unit: "svc.service",
            install: "sudo svc install",
            files_args: vec!["--owner".into(), "alice".into()],
            places: vec![
                Place {
                    role: "unit",
                    path: at.unit.clone(),
                    mode: 0o644,
                },
                Place {
                    role: "helper",
                    path: at.helper.clone(),
                    mode: 0o755,
                },
                Place {
                    role: "rule",
                    path: at.rule.clone(),
                    mode: 0o644,
                },
            ],
            before_restart: &|_| {},
            placed: None,
        }
    }

    /// Version 1.1.0, whose unit changed, which has a helper and no rule,
    /// and a file of a role this version does not know.
    fn newer(at: &At) -> PathBuf {
        let p = at.bin.with_file_name("new");
        let files = files_text(&[
            ("unit", Some("new unit".into())),
            ("helper", Some("helper".into())),
            ("rule", None),
            ("later", Some("x".into())),
        ]);
        std::fs::write(&p, format!("svc 1.1.0\n{files}\n")).unwrap();
        p
    }

    fn read(p: &Path) -> Option<String> {
        std::fs::read_to_string(p).ok()
    }

    /// The same version from another release (a pre-release of 0.1.0, then
    /// the release) is another program, and is taken; an older one stays
    /// refused (#213).
    #[tokio::test]
    async fn the_same_version_of_another_release_is_taken_an_older_one_not() {
        let sys = Fake::new("svc", "Svc", "/var/lib/svc");
        let at = installed(&sys);
        let files = files_text(&[("unit", Some("new unit".into()))]);
        let same = at.bin.with_file_name("same");
        std::fs::write(&same, format!("svc 1.0.0\n{files}\n")).unwrap();
        let mut out = Vec::new();
        let mut steps = Steps::new(&mut out);
        let r = update(
            &program(&at),
            &sys,
            Some(&same),
            &|| sys.started(),
            &mut steps,
        )
        .await;
        assert_eq!(r, Ok(true), "{:?}", steps.done);
        assert!(
            steps
                .done
                .iter()
                .any(|d| d == "replaced svc 1.0.0 with 1.0.0"),
            "{:?}",
            steps.done
        );
        assert_eq!(read(&at.bin), read(&same));
        let older = at.bin.with_file_name("older");
        std::fs::write(&older, format!("svc 0.9.0\n{files}\n")).unwrap();
        let mut out = Vec::new();
        let mut steps = Steps::new(&mut out);
        let e = update(
            &program(&at),
            &sys,
            Some(&older),
            &|| sys.started(),
            &mut steps,
        )
        .await
        .unwrap_err();
        assert!(e.contains("older than the installed 1.0.0"), "{e}");
        assert_eq!(read(&at.bin), read(&same));
    }

    /// `update` writes the unit and the other files as the new program
    /// says them, reloads systemd before the restart, and says which files
    /// it cannot place.
    #[tokio::test]
    async fn the_new_programs_files_come_with_it() {
        let sys = Fake::new("svc", "Svc", "/var/lib/svc");
        let at = installed(&sys);
        let new = newer(&at);
        let mut out = Vec::new();
        let mut steps = Steps::new(&mut out);
        let r = update(
            &program(&at),
            &sys,
            Some(&new),
            &|| sys.started(),
            &mut steps,
        )
        .await;
        assert_eq!(r, Ok(true), "{:?}", steps.done);
        assert_eq!(
            read(&at.bin).unwrap(),
            std::fs::read_to_string(&new).unwrap()
        );
        assert_eq!(read(&at.unit).as_deref(), Some("new unit"));
        assert_eq!(read(&at.helper).as_deref(), Some("helper"));
        let mode = std::fs::metadata(&at.helper).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o755);
        assert!(!at.rule.exists());
        assert_eq!(
            sys.calls(),
            [
                "useradd svc /var/lib/svc",
                "systemctl daemon-reload",
                "systemctl restart svc.service"
            ]
        );
        assert!(
            sys.runs
                .borrow()
                .iter()
                .any(|r| r == "service-files --owner alice")
        );
        let last = steps.done.last().unwrap();
        assert!(
            last.contains("(later)") && last.contains("sudo svc install"),
            "{last}"
        );
    }

    /// A new program that does not start goes, and so do its files: the old
    /// program, unit and rule are back, the helper it brought is gone, and
    /// systemd reads them again before the old one starts.
    #[tokio::test]
    async fn the_old_files_go_back_with_the_old_program() {
        let sys = Fake::new("svc", "Svc", "/var/lib/svc");
        let at = installed(&sys);
        let new = newer(&at);
        sys.next_start.set(Some(false));
        let mut out = Vec::new();
        let mut steps = Steps::new(&mut out);
        let e = update(
            &program(&at),
            &sys,
            Some(&new),
            &|| sys.started(),
            &mut steps,
        )
        .await
        .unwrap_err();
        assert!(e.contains("the old one runs again"), "{e}");
        assert_eq!(read(&at.bin).as_deref(), Some("svc 1.0.0\n"));
        assert_eq!(read(&at.unit).as_deref(), Some("old unit"));
        assert_eq!(read(&at.rule).as_deref(), Some("old rule"));
        assert!(!at.helper.exists());
        let reloads = sys
            .calls()
            .iter()
            .filter(|c| *c == "systemctl daemon-reload")
            .count();
        assert_eq!(reloads, 2, "{:?}", sys.calls());
        assert!(
            steps
                .done
                .iter()
                .any(|s| s.contains("and its service's files back"))
        );
    }

    /// The same program is no update: nothing is written or restarted.
    #[tokio::test]
    async fn the_same_program_changes_nothing() {
        let sys = Fake::new("svc", "Svc", "/var/lib/svc");
        let at = installed(&sys);
        let same = at.bin.with_file_name("same");
        std::fs::copy(&at.bin, &same).unwrap();
        let mut out = Vec::new();
        let mut steps = Steps::new(&mut out);
        let r = update(
            &program(&at),
            &sys,
            Some(&same),
            &|| sys.started(),
            &mut steps,
        )
        .await;
        assert_eq!(r, Ok(false));
        assert_eq!(read(&at.unit).as_deref(), Some("old unit"));
        assert_eq!(sys.calls(), ["useradd svc /var/lib/svc"]);
    }

    /// A program a package manager put in place: the update does not write
    /// it, restarts the service with it even where it and its files are the
    /// ones there already (the service may run the one before), and puts
    /// the old one back where the new one does not start.
    #[tokio::test]
    async fn a_program_the_package_manager_placed_restarts_the_service() {
        let sys = Fake::new("svc", "Svc", "/var/lib/svc");
        let at = installed(&sys);
        let old = std::fs::read(&at.bin).unwrap();
        // Placed before the update ran: nothing to put back, but restarted.
        let mut p = program(&at);
        p.placed = Some(Placed::default());
        let mut out = Vec::new();
        let mut steps = Steps::new(&mut out);
        let r = update(&p, &sys, None, &|| sys.started(), &mut steps).await;
        assert_eq!(r, Ok(true), "{:?}", steps.done);
        assert_eq!(sys.calls().last().unwrap(), "systemctl restart svc.service");
        assert!(
            steps
                .done
                .iter()
                .any(|s| s == "svc 1.0.0 from its package is in place"),
            "{:?}",
            steps.done
        );
        // The same bytes as before (the package again): restarted all the
        // same.
        p.placed = Some(Placed {
            old: Some(old.clone()),
            version: Version::parse_of("svc", "svc 1.0.0"),
        });
        let restarts = |sys: &Fake| sys.calls().iter().filter(|c| c.contains("restart")).count();
        let before = restarts(&sys);
        let mut out = Vec::new();
        let mut steps = Steps::new(&mut out);
        let r = update(&p, &sys, None, &|| sys.started(), &mut steps).await;
        assert_eq!(r, Ok(true), "{:?}", steps.done);
        assert_eq!(restarts(&sys), before + 1);
        // Placed by the update itself, which knows the old one.
        std::fs::copy(newer(&at), &at.bin).unwrap();
        p.placed = Some(Placed {
            old: Some(old.clone()),
            version: Version::parse_of("svc", "svc 1.0.0"),
        });
        let mut out = Vec::new();
        let mut steps = Steps::new(&mut out);
        let r = update(&p, &sys, None, &|| sys.started(), &mut steps).await;
        assert_eq!(r, Ok(true), "{:?}", steps.done);
        assert!(
            steps
                .done
                .iter()
                .any(|s| s == "replaced svc 1.0.0 with 1.1.0")
        );
        assert_eq!(read(&at.unit).as_deref(), Some("new unit"));
        assert!(!at.bin.with_file_name(".svc.new").exists());
        // One that does not start: the old one goes back.
        write_file(&at.unit, b"old unit", 0o644).unwrap();
        std::fs::copy(newer(&at), &at.bin).unwrap();
        sys.next_start.set(Some(false));
        let mut out = Vec::new();
        let mut steps = Steps::new(&mut out);
        let e = update(&p, &sys, None, &|| sys.started(), &mut steps)
            .await
            .unwrap_err();
        assert!(e.contains("the old one runs again"), "{e}");
        assert_eq!(std::fs::read(&at.bin).unwrap(), old);
        assert_eq!(read(&at.unit).as_deref(), Some("old unit"));
    }

    /// An installed program whose files were not written by the update that
    /// put it there (the one before it did not know them): the same program
    /// again still brings them, and a start that fails puts them back.
    #[tokio::test]
    async fn the_same_program_still_brings_the_files_it_has() {
        for starts in [true, false] {
            let sys = Fake::new("svc", "Svc", "/var/lib/svc");
            let at = installed(&sys);
            let files = files_text(&[("unit", Some("new unit".into())), ("rule", None)]);
            write_file(&at.bin, format!("svc 1.0.0\n{files}\n").as_bytes(), 0o755).unwrap();
            let same = at.bin.with_file_name("same");
            std::fs::copy(&at.bin, &same).unwrap();
            sys.next_start.set(Some(starts));
            let mut out = Vec::new();
            let mut steps = Steps::new(&mut out);
            let r = update(
                &program(&at),
                &sys,
                Some(&same),
                &|| sys.started(),
                &mut steps,
            )
            .await;
            if starts {
                assert_eq!(r, Ok(true), "{:?}", steps.done);
                assert_eq!(read(&at.unit).as_deref(), Some("new unit"));
                assert!(!at.rule.exists());
                assert_eq!(
                    sys.calls(),
                    [
                        "useradd svc /var/lib/svc",
                        "systemctl daemon-reload",
                        "systemctl restart svc.service"
                    ]
                );
            } else {
                let e = r.unwrap_err();
                assert!(e.contains("did not start with its new files"), "{e}");
                assert_eq!(read(&at.unit).as_deref(), Some("old unit"));
                assert_eq!(read(&at.rule).as_deref(), Some("old rule"));
                assert!(
                    steps
                        .done
                        .iter()
                        .any(|s| s == "put the service's files back")
                );
            }
            // The program itself stayed.
            assert!(read(&at.bin).unwrap().starts_with("svc 1.0.0\n"));
        }
    }

    #[tokio::test]
    async fn the_download_follows_five_redirects_and_no_more() {
        use nerve_transport::http::{Response, read_request};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        // `/rN` redirects to `/r(N+1)` up to `/r6`, which answers.
        tokio::spawn(async move {
            while let Ok((mut io, _)) = listener.accept().await {
                let req = read_request(&mut io, 0).await.unwrap();
                let n: u8 = req.path.trim_start_matches("/r").parse().unwrap_or(9);
                let r = if n >= 6 {
                    Response::text(200, "end")
                } else {
                    Response::new(302, "text/plain", "")
                        .with_header("Location", &format!("/r{}", n + 1))
                };
                let _ = r.write(&mut io).await;
            }
        });
        let url = |n: u8| format!("http://127.0.0.1:{port}/r{n}");
        assert_eq!(download(&url(1), 1024).await.unwrap(), b"end");
        let e = download(&url(0), 1024).await.unwrap_err();
        assert!(e.contains("too many redirects"), "{e}");
    }

    #[test]
    fn versions() {
        assert_eq!(
            Version::parse_of("svc", "svc 1.2.3").unwrap().to_string(),
            "1.2.3"
        );
        assert!(Version::parse_of("svc", "other 1.2.3").is_none());
        assert!(Version::parse_of("svc", "svc 1.2").is_none());
        assert!(Version::parse_of("svc", "svc 0.0.9") < Version::parse_of("svc", "svc 0.0.10"));
    }
}
