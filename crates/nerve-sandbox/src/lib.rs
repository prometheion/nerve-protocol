//! Confinement for the commands a node runs (docs/dev/policy-engine.md).
//!
//! The sandbox confines with Landlock on Linux, in `folders` mode: a command reads
//! the system directories and the folders flagged `r`, writes only the `w`
//! folders, and runs programs only from the system directories and the `x`
//! folders. The rules are applied in a small shim, `nerve-node __exec-shim`,
//! which the node starts per command: Landlock restricts the calling process,
//! and doing that between `fork` and `exec` of a multi-threaded async node is
//! not safe, while the shim is single-threaded.
//!
//! On Windows a `folders` command runs in an AppContainer, one per pairing
//! ([`appcontainer`]): a process there opens only what carries a grant for the
//! container's SID, and what Windows opens to every AppContainer (the system
//! folders and Program Files, for reading and running). The node puts grants
//! on the center's folders for their flags ([`acl`]), passes them down to what
//! is below a folder as far as they change it ([`inherit`]), and takes them
//! off when a folder goes. The shim starts the command in the container and
//! waits for it.
//!
//! Neither limits a command's memory, CPU or processes: on Linux the node
//! runs each command in a cgroup of its own for that (`nerve-node`'s
//! `cgroup` module).

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

pub mod inherit;
#[cfg(target_os = "linux")]
pub mod net_filter;
#[cfg(target_os = "linux")]
pub mod own_proc;

/// The argument that selects the shim in the `nerve-node` binary. Hidden from
/// `--help`.
pub const SHIM_ARG: &str = "__exec-shim";

/// What a confined command may touch.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LandlockSpec {
    pub read: Vec<PathBuf>,
    /// Writable, and nothing more: a folder that is also to be read is in
    /// `read` as well.
    pub write: Vec<PathBuf>,
    /// Programs below these may run. The files there can be read by name too
    /// (see `landlock_rules::prepare`), the folders not listed.
    pub exec: Vec<PathBuf>,
    /// No TCP connection and no listening port ([`LANDLOCK_NETWORK`]), where
    /// the kernel has the rules for them: a second layer under the node's
    /// filter ([`net_filter`]), which holds the command off the network by
    /// itself.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub no_network: bool,
    /// With `no_network`, where the kernel can tell them apart
    /// ([`LANDLOCK_RESOLVE_UNIX`]): the command reaches a unix socket by its
    /// path only below these, the pairing's own and granted folders and the
    /// system's sockets ([`kept_sockets`]). A program behind another socket
    /// could reach the network for it.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub unix: Vec<PathBuf>,
}

/// What the node sends the shim on its stdin.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ShimSpec {
    pub program: PathBuf,
    pub args: Vec<String>,
    /// The node's pid: a shim whose parent already changed exits at once.
    pub parent: u32,
    #[serde(default)]
    pub landlock: Option<LandlockSpec>,
    /// Windows: run the command in this AppContainer.
    #[serde(default)]
    pub container: Option<ContainerSpec>,
    /// Linux: run the command in a PID namespace with a `/proc` of its own
    /// ([`own_proc`]), so it sees only its own processes.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub own_proc: bool,
    /// The folder the command starts in, which the shim enters first, as
    /// the account it runs as. Windows: the node starts the shim of another
    /// account elsewhere, as Windows checks the folder a process starts in
    /// as the one that starts it, and the node's own account may not look
    /// into the command's folder (a pairing's home in the container's
    /// folder, the owner's folders).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cwd: Option<PathBuf>,
}

/// What a PowerShell command in an AppContainer starts with. PowerShell
/// checks every folder above its working folder when it takes that as its
/// location, and the container may not look at them (`C:\`, `C:\Users`),
/// so it would stand somewhere else and start programs there. A drive
/// `Work:` rooted at the working folder puts it where it belongs; paths
/// below it work, relative or under `Work:\`, and so do whole paths to
/// files.
///
/// `cd` (`Set-Location`) and `pushd` (`Push-Location`) to a whole path, or
/// up out of such a drive, would check the folders above it all the same.
/// So functions stand in for the cmdlets: a folder below one of these
/// drives is taken as a path on that drive, and any other folder the
/// command can see gets a drive `Work2:`, `Work3:`, … of its own. The
/// drives open nothing: the container still decides what the command reads
/// and writes. A folder the command cannot see goes to the cmdlet as a
/// whole path and fails as before, also when `..` named it: the cmdlet
/// would stop `..` at the drive's root and stay there without an error.
/// A path with a wildcard has the part before its first wildcard resolved
/// so; the rest goes on with the wildcard. The cmdlet's errors are the
/// function's, so a failed `cd` sets `$?` and the exit code as the cmdlet
/// does, whatever the error action. Other commands keep `..` on the drive.
/// The text has no `"`, which the Windows command line would escape.
///
/// It first imports Windows PowerShell's two core modules by name. In a
/// container on some machines (GitHub's Windows Server 2025 image among
/// them) PowerShell reads every module but does not load one on its own
/// when a command names a cmdlet, so `New-PSDrive`, `Get-Content` and
/// `Out-File` were "not recognized" (#105, #106). After the import they are
/// there; other modules still load on their own where that works.
pub const POWERSHELL_START: &str = concat!(
    r"Import-Module Microsoft.PowerShell.Management, Microsoft.PowerShell.Utility -ErrorAction Stop; ",
    r"$null = New-PSDrive -Name Work -PSProvider FileSystem ",
    r"-Root ([Environment]::CurrentDirectory) -Scope Global -ErrorAction Stop; ",
    r"Set-Location Work:\ -ErrorAction Stop; ",
    // Whether the folder `full` is `root` or below it.
    r"function global:NerveUnder([string]$full, [string]$root) { ",
    r"$f = $full.TrimEnd('\', '/'); $r = $root.TrimEnd('\', '/'); ",
    r"$f -eq $r -or $f.StartsWith($r + '\', 'OrdinalIgnoreCase') }; ",
    // The path on a Work drive for the folder `p` names literally, the
    // whole path of a folder the command cannot see, or nothing where the
    // cmdlet takes `p` as it is: another drive or provider, `~`, `\`, `-`
    // and `+`. A relative path is resolved here as well, since the cmdlet
    // would keep its `..` on the drive (`..\app` on `Work:\` is `Work:\app`).
    r"function global:NerveFolder([string]$p) { ",
    r"$p = $p -replace '^(Microsoft\.PowerShell\.Core\\)?FileSystem::', ''; ",
    r"if ($p -match '^([A-Za-z]:[\\/]|[\\/][\\/])') { $base = '' } ",
    r"elseif ($p -notmatch '^(~|[\\/])|^[+-]$|:' -and $PWD.Provider.Name -eq 'FileSystem') { ",
    r"$base = $PWD.ProviderPath } ",
    r"else { return $null }; ",
    r"try { $full = [IO.Path]::GetFullPath([IO.Path]::Combine($base, $p)) } catch { return $null }; ",
    r"$best = $null; ",
    r"foreach ($d in Get-PSDrive -PSProvider FileSystem) { ",
    r"if ($d.Name -match '^Work\d*$' -and (NerveUnder $full $d.Root) -and ",
    r"(-not $best -or $d.Root.Length -gt $best.Root.Length)) { $best = $d } }; ",
    r"if (-not $best) { ",
    r"if (-not [IO.Directory]::Exists($full)) { return $full }; ",
    // `Ignore`, not `SilentlyContinue`: that would leave an error in `$Error`.
    r"$n = 2; while (Get-PSDrive -Name ('Work' + $n) -ErrorAction Ignore) { $n++ }; ",
    r"try { $best = New-PSDrive -Name ('Work' + $n) -PSProvider FileSystem -Root $full ",
    r"-Scope Global -ErrorAction Stop } catch { return $full } }; ",
    r"$best.Name + ':\' + $full.TrimEnd('\', '/').Substring($best.Root.TrimEnd('\', '/').Length).TrimStart('\', '/') }; ",
    // Runs the cmdlet `cmd` with the parameters `bound`, its path moved
    // onto a Work drive where NerveFolder finds one. A `-Path` loses its
    // escapes (`` b`[1`] `` is the folder `b[1]`); one with a wildcard is
    // moved up to its first wildcard and keeps the rest, unless all before
    // it is `\` or `/`, the root of the drive it stands on. The cmdlet always
    // writes its errors, so that the function can write them again under
    // the caller's error action: one the cmdlet keeps quiet leaves `$?`
    // true. An object other than a string `piped` to the untyped `Path` is
    // bound as the cmdlet binds it: its `Path`, or else its `PSPath` as
    // `-LiteralPath` (a folder from `Get-ChildItem` would otherwise be its
    // bare name).
    r"function global:NerveGo([string]$cmd, $bound, [bool]$piped) { ",
    r"$a = @{}; foreach ($k in $bound.Keys) { $a[$k] = $bound[$k] }; ",
    r"$o = $a['Path']; if ($piped -and $null -ne $o -and $o -isnot [string]) { ",
    r"$q = $o.PSObject.Properties; if ($q['Path']) { $a['Path'] = $q['Path'].Value } ",
    r"else { foreach ($n in 'PSPath', 'LiteralPath', 'LP') { if ($q[$n]) { ",
    r"$null = $a.Remove('Path'); $a['LiteralPath'] = [string]$q[$n].Value; break } } } }; ",
    r"foreach ($k in 'Path', 'LiteralPath') { if (-not $a[$k]) { continue }; ",
    r"$v = [string]$a[$k]; $tail = $null; ",
    r"if ($k -eq 'Path') { $s = $v -split '[\\/]'; $i = 0; ",
    r"while ($i -lt $s.Count -and ",
    r"-not [Management.Automation.WildcardPattern]::ContainsWildcardCharacters($s[$i])) { $i++ }; ",
    r"if ($i -lt $s.Count) { if ($i -eq 0 -or ($i -eq 1 -and $s[0] -eq '')) { continue }; ",
    r"$v = $s[0..($i - 1)] -join '\'; $tail = $s[$i..($s.Count - 1)] -join '\' }; ",
    r"$v = [Management.Automation.WildcardPattern]::Unescape($v) }; ",
    r"$m = NerveFolder $v; ",
    r"if ($m) { $a.Remove('Path'); $a.Remove('LiteralPath'); ",
    r"if ($null -ne $tail) { $a['Path'] = ",
    r"[Management.Automation.WildcardPattern]::Escape($m.TrimEnd('\', '/')) + '\' + $tail } ",
    r"else { $a['LiteralPath'] = $m } } }; ",
    r"$a['ErrorAction'] = 'Continue'; & $cmd @a }; ",
    // The cmdlets' own parameters, as Windows PowerShell 5.1 and PowerShell
    // 7 have them; the aliases `cd`, `chdir`, `sl` and `pushd` find these
    // functions before the cmdlets. An error a command inside a function
    // writes leaves `$?` true, so the cmdlet's errors are written again as
    // the function's own. `Path` has no type: `[string]` would turn `$null`,
    // which Windows PowerShell 5.1 refuses, into `''`, which it ignores.
    r"function global:Set-Location { [CmdletBinding(DefaultParameterSetName = 'Path')] param(",
    r"[Parameter(ParameterSetName = 'Path', Position = 0, ValueFromPipeline = $true, ",
    r"ValueFromPipelineByPropertyName = $true)] $Path, ",
    r"[Parameter(ParameterSetName = 'LiteralPath', Mandatory = $true, ",
    r"ValueFromPipelineByPropertyName = $true)] [Alias('PSPath', 'LP')] [string]$LiteralPath, ",
    r"[switch]$PassThru, ",
    r"[Parameter(ParameterSetName = 'Stack', ValueFromPipelineByPropertyName = $true)] [string]$StackName) ",
    r"process { NerveGo 'Microsoft.PowerShell.Management\Set-Location' $PSBoundParameters ",
    r"$PSCmdlet.MyInvocation.ExpectingInput 2>&1 | ",
    r"ForEach-Object { if ($_ -is [Management.Automation.ErrorRecord]) { $PSCmdlet.WriteError($_) } ",
    r"else { $_ } } } }; ",
    r"function global:Push-Location { [CmdletBinding(DefaultParameterSetName = 'Path')] param(",
    r"[Parameter(ParameterSetName = 'Path', Position = 0, ValueFromPipeline = $true, ",
    r"ValueFromPipelineByPropertyName = $true)] $Path, ",
    r"[Parameter(ParameterSetName = 'LiteralPath', Mandatory = $true, ",
    r"ValueFromPipelineByPropertyName = $true)] [Alias('PSPath', 'LP')] [string]$LiteralPath, ",
    r"[switch]$PassThru, ",
    r"[Parameter(ValueFromPipelineByPropertyName = $true)] [string]$StackName) ",
    r"process { NerveGo 'Microsoft.PowerShell.Management\Push-Location' $PSBoundParameters ",
    r"$PSCmdlet.MyInvocation.ExpectingInput 2>&1 | ",
    r"ForEach-Object { if ($_ -is [Management.Automation.ErrorRecord]) { $PSCmdlet.WriteError($_) } ",
    r"else { $_ } } } }; ",
);

/// The AppContainer a Windows command runs in. Its SID is derived from the
/// name, so the node's grants and the shim's process agree on it without a
/// profile.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContainerSpec {
    pub name: String,
    /// The owner's network switch: the container gets none of its network
    /// capabilities, and Windows keeps it off every network.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub no_network: bool,
    /// The command's home and its programs' settings are the container's
    /// own ([`acl::container_home`]): each pairing has its own, and none is
    /// the account's, which every pairing's commands share.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub home: bool,
    /// Variables the command gets besides its account's own
    /// (`machine.command_env`): names and the values of the node's.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub env: Vec<(String, String)>,
}

impl ContainerSpec {
    /// The container `name`, with the network, the account's home and
    /// nothing added.
    pub fn new(name: impl Into<String>) -> ContainerSpec {
        ContainerSpec {
            name: name.into(),
            no_network: false,
            home: false,
            env: Vec::new(),
        }
    }
}

/// The largest spec the shim reads.
const MAX_SPEC: u64 = 1 << 20;

/// Exit code of a shim that could not set up the command.
pub const SHIM_FAILED: i32 = 126;

/// Runs the shim: reads its [`ShimSpec`] (JSON) from stdin up to its end,
/// confines itself, and replaces itself with the command, whose stdin is then
/// `/dev/null`. Returns only on failure, with the exit code to use. Must run
/// before any thread starts in the process.
///
/// The spec comes on stdin rather than in argv so it does not show in
/// `/proc/<pid>/cmdline`.
pub fn shim_main() -> i32 {
    use std::io::Read;
    let mut json = Vec::new();
    if std::io::stdin()
        .lock()
        .take(MAX_SPEC)
        .read_to_end(&mut json)
        .is_err()
    {
        eprintln!("nerve-node: the exec shim got no spec");
        return SHIM_FAILED;
    }
    match serde_json::from_slice::<ShimSpec>(&json) {
        Ok(spec) => {
            if let Some(cwd) = &spec.cwd
                && let Err(e) = std::env::set_current_dir(cwd)
            {
                eprintln!("nerve-node: cannot enter {}: {e}", cwd.display());
                return SHIM_FAILED;
            }
            imp::run(spec)
        }
        Err(e) => {
            eprintln!("nerve-node: bad exec shim spec: {e}");
            SHIM_FAILED
        }
    }
}

/// The lowest Landlock ABI a node run by hand confines commands with. Below
/// it the kernel does not handle `truncate(2)` (ABI 3, Linux 6.2), so a
/// command held to its folders could still cut any file of the owner's
/// outside them to nothing: such a node takes that Landlock as none and
/// runs no command of folder mode ([`Confinement::by_hand`]). The installed
/// node keeps it: without Landlock its commands would run as its account
/// with no confinement at all.
pub const LANDLOCK_FLOOR: i32 = 3;

/// The Landlock ABI that rules the network (Linux 6.7): from it a command
/// can be kept from making TCP connections and from listening on a TCP
/// port. It rules nothing else of the network: UDP, raw and other sockets
/// stay open, and so do unix sockets by path; abstract unix sockets close
/// from [`LANDLOCK_WANTED`] on. The node's filter ([`net_filter`]) is what
/// holds a command off the network; these rules are a second layer.
pub const LANDLOCK_NETWORK: i32 = 4;

/// The Landlock ABI that rules unix sockets by path (Linux 7.1): from it a
/// command whose network is off reaches only the sockets below its rules
/// ([`LandlockSpec::unix`]). Below it every such socket the command may see
/// stays open to it, and a program that answers there may reach the network
/// for it.
pub const LANDLOCK_RESOLVE_UNIX: i32 = 9;

/// The Landlock ABI the node asks for (Linux 6.12): from it every guard the
/// node sets is held, and the commands of the installed node's pairings, all
/// of one account, are kept apart from each other.
pub const LANDLOCK_WANTED: i32 = 6;

/// What Landlock at `abi` does not guard of what the node asks for
/// ([`LANDLOCK_WANTED`]): empty from that ABI on.
pub fn landlock_gaps(abi: i32) -> Vec<&'static str> {
    let mut gaps = Vec::new();
    if abi < 3 {
        gaps.push("truncating files");
    }
    if abi < 5 {
        gaps.push("device ioctls");
    }
    if abi < 6 {
        gaps.push("signals to other processes of the account");
        gaps.push("abstract unix sockets");
    }
    gaps
}

/// How this machine can confine commands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Confinement {
    /// The kernel's Landlock ABI version; `None` when Landlock is missing or
    /// off, and on a node run by hand below [`LANDLOCK_FLOOR`].
    pub landlock_abi: Option<i32>,
    /// Windows: commands run in an AppContainer. Every Windows the node
    /// runs on (10 and later) has them.
    pub appcontainer: bool,
}

impl Confinement {
    pub fn detect() -> Confinement {
        Confinement {
            landlock_abi: landlock_abi(),
            appcontainer: cfg!(windows),
        }
    }

    /// This confinement as a node run by hand takes it: Landlock below
    /// [`LANDLOCK_FLOOR`] counts as none.
    pub fn by_hand(self) -> Confinement {
        Confinement {
            landlock_abi: self.landlock_abi.filter(|v| *v >= LANDLOCK_FLOOR),
            ..self
        }
    }

    /// Whether `folders` mode can confine commands.
    pub fn available(&self) -> bool {
        self.landlock_abi.is_some() || self.appcontainer
    }

    /// The `confinement` string of the `exec` state.
    pub fn describe(&self) -> String {
        match self.landlock_abi {
            Some(v) => format!("landlock v{v}"),
            None if self.appcontainer => "appcontainer".into(),
            None => "none".into(),
        }
    }
}

/// Directories every confined command may read and run programs from, each
/// at its real place (`/bin` is a link to `/usr/bin` on many systems): the
/// shim opens a rule's path without following a link ([`landlock_rules`]).
pub fn system_dirs() -> Vec<PathBuf> {
    resolved(&[
        "/usr",
        "/bin",
        "/sbin",
        "/lib",
        "/lib32",
        "/lib64",
        "/etc",
        "/opt",
        "/nix/store",
        "/proc",
        "/sys",
        "/dev",
        "/run",
    ])
}

/// The paths of `names` that exist, each at its real place, once.
fn resolved(names: &[&str]) -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = Vec::new();
    for p in names.iter().filter_map(|p| std::fs::canonicalize(p).ok()) {
        if !out.contains(&p) {
            out.push(p);
        }
    }
    out
}

/// The system's sockets a command whose network is off still reaches by
/// path ([`LandlockSpec::unix`]): the system bus, the system log
/// (`/dev/log`), systemd-resolved's and nscd's. Programs need them to look
/// up names and accounts, to log and to talk to the system's services. Only
/// those that are there, each at its real place (`/dev/log` is a link on
/// systemd systems); the system bus where `DBUS_SYSTEM_BUS_ADDRESS` puts
/// it, else at its usual place.
pub fn kept_sockets() -> Vec<PathBuf> {
    let bus = std::env::var("DBUS_SYSTEM_BUS_ADDRESS").ok();
    let mut out = bus_sockets(bus.as_deref());
    out.extend(
        [
            "/dev/log",
            "/run/systemd/resolve/io.systemd.Resolve",
            "/run/nscd/socket",
            "/var/run/nscd/socket",
        ]
        .iter()
        .map(PathBuf::from),
    );
    let mut kept: Vec<PathBuf> = Vec::new();
    for p in out.iter().filter_map(|p| std::fs::canonicalize(p).ok()) {
        if !kept.contains(&p) {
            kept.push(p);
        }
    }
    kept
}

/// The sockets of a D-Bus address (`unix:path=...`, several separated by
/// `;`), the default system bus where there is none. Other transports have
/// no path to keep.
fn bus_sockets(address: Option<&str>) -> Vec<PathBuf> {
    let Some(address) = address.filter(|a| !a.trim().is_empty()) else {
        return vec![PathBuf::from("/run/dbus/system_bus_socket")];
    };
    address
        .split(';')
        .filter_map(|a| a.strip_prefix("unix:"))
        .flat_map(|keys| keys.split(','))
        .filter_map(|kv| kv.strip_prefix("path="))
        .map(|v| PathBuf::from(unescape_bus(v)))
        .collect()
}

/// A D-Bus address value with its `%XX` escapes undone.
fn unescape_bus(v: &str) -> String {
    let b = v.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        let hex = b
            .get(i + 1..i + 3)
            .and_then(|h| std::str::from_utf8(h).ok())
            .and_then(|h| u8::from_str_radix(h, 16).ok());
        match (b[i], hex) {
            (b'%', Some(x)) => {
                out.push(x);
                i += 3;
            }
            (c, _) => {
                out.push(c);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// The terminals of the machine's users under `/dev`: the pseudo-terminals
/// (`pts`), the console and every device the kernel's tty layer lists
/// (`/sys/class/tty`: the text consoles and serial lines, but also the
/// hypervisor consoles `hvc*`, which are no `tty*`). A command of a node
/// run by hand runs as the owner, who owns the terminal they work in, so it
/// must not read these by name: what the owner types there would reach the
/// command. A program that makes a terminal of its own needs none of them:
/// `ptmx` stays, and a pseudo-terminal's slave is reached through the
/// master's descriptor.
pub fn terminal_devices() -> Vec<PathBuf> {
    terminals_in(Path::new("/dev"), Path::new("/sys/class/tty"))
}

/// [`terminal_devices`] for a `/dev` and the kernel's list of tty devices.
/// A name that starts with `tty` counts also where the list does not have
/// it. The list writes `/dev/3270/tty1` as `3270!tty1`.
fn terminals_in(dev: &Path, tty_class: &Path) -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = ["pts", "console"]
        .iter()
        .map(|n| dev.join(n))
        .filter(|p| p.exists())
        .collect();
    let mut named: Vec<PathBuf> = Vec::new();
    if let Ok(entries) = std::fs::read_dir(dev) {
        named.extend(
            entries
                .flatten()
                .filter(|e| e.file_name().to_string_lossy().starts_with("tty"))
                .map(|e| e.path()),
        );
    }
    if let Ok(entries) = std::fs::read_dir(tty_class) {
        named.extend(
            entries
                .flatten()
                .map(|e| e.file_name().to_string_lossy().replace('!', "/"))
                .filter(|n| n != "ptmx")
                .map(|n| dev.join(n))
                .filter(|p| p.exists()),
        );
    }
    named.sort();
    named.dedup();
    let seen = out.clone();
    out.extend(named.into_iter().filter(|p| !seen.contains(p)));
    out
}

/// Files every confined command may write: the null devices, nothing else
/// outside its folders. Not `/dev/tty`: a confined command has no
/// controlling terminal, and the one it had would be the owner's.
pub fn system_writable() -> Vec<PathBuf> {
    resolved(&["/dev/null", "/dev/zero", "/dev/full"])
}

#[cfg(target_os = "linux")]
fn landlock_abi() -> Option<i32> {
    landlock_rules::abi_version()
}

#[cfg(not(target_os = "linux"))]
fn landlock_abi() -> Option<i32> {
    None
}

#[cfg(target_os = "linux")]
mod imp {
    use super::{SHIM_FAILED, ShimSpec};
    use std::os::unix::process::CommandExt;
    use std::process::{Command, Stdio};

    pub fn run(spec: ShimSpec) -> i32 {
        // SAFETY: prctl and getppid with plain integer arguments.
        unsafe {
            // The command dies with the node instead of running on unseen.
            libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0);
            if libc::getppid() as u32 != spec.parent {
                return SHIM_FAILED;
            }
        }
        if spec.container.is_some() {
            eprintln!("nerve-node: AppContainers are Windows'");
            return SHIM_FAILED;
        }
        // Before Landlock, which forbids the mount of the new /proc; the
        // rules then name that /proc, opened in the namespace.
        if spec.own_proc {
            match super::own_proc::enter() {
                Ok(super::own_proc::Entered::Inside) => {}
                Ok(super::own_proc::Entered::Ended(code)) => return code,
                Err(e) => {
                    eprintln!("nerve-node: cannot give the command a /proc of its own: {e}");
                    return SHIM_FAILED;
                }
            }
        }
        // The profile that let the shim make the namespace stays with the
        // shim: whatever it starts leaves it (Landlock, below, forbids the
        // write, and the shim is any account's to run).
        if let Err(e) = super::own_proc::leave_profile() {
            eprintln!(
                "nerve-node: cannot take the command out of the node's AppArmor profile: {e}"
            );
            return SHIM_FAILED;
        }
        if let Some(l) = &spec.landlock {
            let applied = super::landlock_rules::prepare(l)
                .and_then(|r| super::landlock_rules::enforce(r).map_err(|e| e.to_string()));
            if let Err(e) = applied {
                eprintln!("nerve-node: cannot confine the command: {e}");
                return SHIM_FAILED;
            }
        }
        let e = Command::new(&spec.program)
            .args(&spec.args)
            .stdin(Stdio::null())
            .exec();
        eprintln!("nerve-node: cannot start {}: {e}", spec.program.display());
        127
    }
}

#[cfg(windows)]
mod imp {
    use super::{SHIM_FAILED, ShimSpec};
    use std::process::{Command, Stdio};

    /// Takes Ctrl+C and Ctrl+Break as handled, so the shim lives on.
    unsafe extern "system" fn outlast(event: u32) -> windows_sys::core::BOOL {
        use windows_sys::Win32::System::Console::{CTRL_BREAK_EVENT, CTRL_C_EVENT};
        (event == CTRL_C_EVENT || event == CTRL_BREAK_EVENT).into()
    }

    pub fn run(spec: ShimSpec) -> i32 {
        if spec.landlock.is_some() || spec.own_proc {
            return SHIM_FAILED;
        }
        // A stop sends Ctrl+C to the command's console, which the shim shares
        // with the command (nerve-node's win_stop). The shim waits for the
        // command and passes on its exit code rather than end first. A
        // handler is not inherited, so the command still hears it.
        // SAFETY: a handler that only compares its argument.
        unsafe {
            windows_sys::Win32::System::Console::SetConsoleCtrlHandler(Some(outlast), 1);
        }
        // The node runs the shim in a job object of the command's own, which
        // holds this process and what it starts, the container's processes
        // too.
        if let Some(c) = &spec.container {
            return match super::appcontainer::run(&spec.program, &spec.args, c) {
                Ok(code) => code as i32,
                Err(e) => {
                    eprintln!(
                        "nerve-node: cannot start {} in its AppContainer: {e}",
                        spec.program.display()
                    );
                    SHIM_FAILED
                }
            };
        }
        match Command::new(&spec.program)
            .args(&spec.args)
            .stdin(Stdio::null())
            .status()
        {
            Ok(st) => st.code().unwrap_or(255),
            Err(e) => {
                eprintln!("nerve-node: cannot start {}: {e}", spec.program.display());
                127
            }
        }
    }
}

#[cfg(target_os = "linux")]
pub mod landlock_rules {
    //! Landlock rules for a `folders` command. Every filesystem access is
    //! handled (so denied unless a rule allows it). Where the kernel supports
    //! it, the command also cannot signal processes outside its sandbox or
    //! reach abstract sockets.

    use super::LandlockSpec;
    use landlock::{
        ABI, Access, AccessFs, AccessNet, BitFlags, PathBeneath, Ruleset, RulesetAttr,
        RulesetCreated, RulesetCreatedAttr, RulesetError, RulesetStatus, Scope,
    };
    use std::ffi::CString;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::os::unix::ffi::OsStrExt;
    use std::path::{Component, Path, PathBuf};

    /// `openat` with `O_PATH`: a handle on the place, no more.
    fn open_at(dir: i32, name: &CString, flags: i32) -> std::io::Result<OwnedFd> {
        // SAFETY: a plain openat on a descriptor and a terminated name; the
        // new descriptor is ours alone.
        let fd = unsafe {
            libc::openat(
                dir,
                name.as_ptr(),
                libc::O_PATH | libc::O_CLOEXEC | libc::O_NOFOLLOW | flags,
            )
        };
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        // SAFETY: `fd` is a descriptor just returned by openat.
        Ok(unsafe { OwnedFd::from_raw_fd(fd) })
    }

    /// The place at `path` (absolute, as the node resolved it), opened part
    /// by part without following a link: a rule opened by its name would
    /// follow one that has replaced a part since the node judged the path,
    /// and grant the folder's flags where the link leads. A part that is a
    /// link now fails the open (`ELOOP`, `ENOTDIR`).
    fn open_unlinked(path: &Path) -> std::io::Result<OwnedFd> {
        let bad = || std::io::Error::from(std::io::ErrorKind::InvalidInput);
        let mut parts = path.components();
        if parts.next() != Some(Component::RootDir) {
            return Err(bad());
        }
        let root = CString::new("/").map_err(|_| bad())?;
        let mut at = open_at(libc::AT_FDCWD, &root, libc::O_DIRECTORY)?;
        let mut parts = parts.peekable();
        while let Some(part) = parts.next() {
            let Component::Normal(name) = part else {
                return Err(bad());
            };
            let name = CString::new(name.as_bytes()).map_err(|_| bad())?;
            let last = parts.peek().is_none();
            // O_PATH with O_NOFOLLOW yields the link itself, so a part
            // before the last must be a folder (O_DIRECTORY) and the last is
            // looked at.
            at = open_at(
                at.as_raw_fd(),
                &name,
                if last { 0 } else { libc::O_DIRECTORY },
            )?;
            if last {
                // SAFETY: fstat on our descriptor into a zeroed buffer.
                let mut st: libc::stat = unsafe { std::mem::zeroed() };
                if unsafe { libc::fstat(at.as_raw_fd(), &mut st) } != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                if st.st_mode & libc::S_IFMT == libc::S_IFLNK {
                    return Err(std::io::Error::from_raw_os_error(libc::ELOOP));
                }
            }
        }
        Ok(at)
    }

    /// The rules of `paths` with `access`, as `landlock::path_beneath_rules`
    /// makes them but each path opened by [`open_unlinked`]. A path that is
    /// not there is left out (a command has no access to what is not there);
    /// so is one that is a link now, and the command is told.
    fn rules<'a>(
        paths: &'a [PathBuf],
        access: BitFlags<AccessFs>,
    ) -> impl Iterator<Item = Result<PathBeneath<OwnedFd>, RulesetError>> + 'a {
        paths.iter().filter_map(move |p| match open_unlinked(p) {
            Ok(fd) => Some(Ok(PathBeneath::new(fd, access))),
            Err(e) => {
                if matches!(e.raw_os_error(), Some(libc::ELOOP | libc::ENOTDIR)) {
                    eprintln!(
                        "nerve-node: {} is, or lies behind, a link now and is left out of the command's sandbox",
                        p.display()
                    );
                }
                None
            }
        })
    }

    /// Best effort up to this ABI: older kernels enforce what they know.
    const ABI_WANTED: ABI = ABI::V6;

    pub fn prepare(spec: &LandlockSpec) -> Result<RulesetCreated, String> {
        let e = |e: landlock::RulesetError| e.to_string();
        // Running a program is its own right, granted only where `exec` says.
        // The kernel opens a program for reading as well as for execution, so
        // Landlock refuses the exec of a file it may not read: an `exec`
        // folder therefore also lets a command read the files in it by name.
        // It cannot list the folder (no ReadDir), and `read` stays the set
        // that grants whole trees.
        let mut read = AccessFs::from_read(ABI_WANTED);
        read.remove(AccessFs::Execute);
        // A folder that may be written may be read too (nerve-policy reads
        // `w` as `rw`), so the write set carries the read rights as well.
        let write = AccessFs::from_write(ABI_WANTED) | read;
        let handled = AccessFs::from_all(ABI_WANTED);
        let mut rs = Ruleset::default().handle_access(handled).map_err(e)?;
        if !Scope::from_all(ABI_WANTED).is_empty() {
            rs = rs.scope(Scope::from_all(ABI_WANTED)).map_err(e)?;
        }
        // No TCP connection or listening port, with no rule to allow one,
        // where the kernel has the rules (best effort): the node's filter
        // (crate::net_filter) holds the command off the network without
        // them, and these are a second layer under it.
        // And no unix socket by path but below `unix`, where the kernel
        // tells them apart (ABI 9, best effort): a program that answers on
        // another could reach the network for the command. Older kernels
        // leave them open; the docs say so.
        if spec.no_network {
            rs = rs
                .handle_access(AccessNet::from_all(ABI::V4))
                .map_err(e)?
                .handle_access(AccessFs::ResolveUnix)
                .map_err(e)?;
        }
        let rs = rs
            .create()
            .map_err(e)?
            .add_rules(rules(&spec.read, read))
            .map_err(e)?
            .add_rules(rules(&spec.write, write))
            .map_err(e)?
            .add_rules(rules(&spec.exec, AccessFs::Execute | AccessFs::ReadFile))
            .map_err(e)?;
        if !spec.no_network {
            return Ok(rs);
        }
        rs.add_rules(rules(&spec.unix, AccessFs::ResolveUnix.into()))
            .map_err(e)
    }

    /// Restricts the calling process and what it runs. Fails (so the command
    /// does not run) when the kernel enforces nothing.
    pub fn enforce(rs: RulesetCreated) -> std::io::Result<()> {
        let st = rs.restrict_self().map_err(std::io::Error::other)?;
        if st.ruleset == RulesetStatus::NotEnforced {
            return Err(std::io::Error::other("Landlock is not enforced"));
        }
        Ok(())
    }

    /// The kernel's Landlock ABI version, `None` when Landlock is off or
    /// missing.
    pub fn abi_version() -> Option<i32> {
        const LANDLOCK_CREATE_RULESET_VERSION: u32 = 1;
        // SAFETY: the version query takes no ruleset and returns an integer.
        let v = unsafe {
            libc::syscall(
                libc::SYS_landlock_create_ruleset,
                std::ptr::null::<libc::c_void>(),
                0usize,
                LANDLOCK_CREATE_RULESET_VERSION,
            )
        };
        (v > 0).then_some(v as i32)
    }
}

pub mod acl {
    //! The rights a folder's flags give a Windows AppContainer, as the access
    //! masks of the grants on the folder: one for the folder and the folders
    //! below it, one for the files below it. Plain values, so they are
    //! tested on every platform.
    //!
    //! As on Linux, `w` reads too (nerve-policy reads `w` as `rw`) and also
    //! deletes and renames, and `x` runs and reads files by name but lists
    //! nothing (a program cannot run from a file it may not read, and a
    //! script is read by its interpreter). No flag gives a right on the
    //! access list or the owner, so a command cannot widen its own grants.
    //!
    //! Windows grants a move by the same right as a delete, and a moved
    //! object keeps its own access list until a change on its new folder
    //! passes that folder's entries down to it; a command moves only what
    //! it may read, so no move makes something readable that was not. A
    //! granted folder or file itself has no `DELETE` ([`entries`]): a
    //! command deletes, renames or moves it only where the folder above it
    //! gives that, as on Linux.

    use crate::inherit::Gets;

    pub const READ_DATA: u32 = 0x1; // FILE_LIST_DIRECTORY on a folder
    pub const WRITE_DATA: u32 = 0x2; // FILE_ADD_FILE
    pub const APPEND_DATA: u32 = 0x4; // FILE_ADD_SUBDIRECTORY
    pub const READ_EA: u32 = 0x8;
    pub const WRITE_EA: u32 = 0x10;
    pub const EXECUTE: u32 = 0x20; // FILE_TRAVERSE
    pub const DELETE_CHILD: u32 = 0x40;
    pub const READ_ATTRIBUTES: u32 = 0x80;
    pub const WRITE_ATTRIBUTES: u32 = 0x100;
    pub const DELETE: u32 = 0x1_0000;
    pub const READ_CONTROL: u32 = 0x2_0000;
    pub const WRITE_DAC: u32 = 0x4_0000;
    #[cfg(test)]
    pub const WRITE_OWNER: u32 = 0x8_0000;
    pub const SYNCHRONIZE: u32 = 0x10_0000;

    /// What every flag gives: waiting on a handle and reading the
    /// attributes and the access list, as `stat` does on Linux.
    const BASE: u32 = SYNCHRONIZE | READ_ATTRIBUTES | READ_CONTROL;

    #[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
    pub struct Masks {
        /// The folder itself and every folder below it.
        pub dir: u32,
        /// Every file below it (or the path itself, when it is a file).
        pub file: u32,
        /// Denied, not allowed: a folder closed inside one the container
        /// is granted ([`closed`]).
        pub deny: bool,
    }

    /// Every right a file or folder has (FILE_ALL_ACCESS).
    pub const ALL: u32 = 0x1F_01FF;

    /// The masks of a folder without a flag inside a folder the container
    /// is granted: every right denied to it there and below, whatever it
    /// inherits from the folder around, which Windows passes into every
    /// folder below (nerve-node's grants). Denied entries come first.
    pub fn closed() -> Masks {
        Masks {
            dir: ALL,
            file: ALL,
            deny: true,
        }
    }

    /// The masks for a folder with these flags; both 0 without a flag.
    /// `write` reads too.
    pub fn masks(read: bool, write: bool, execute: bool) -> Masks {
        let mut m = Masks::default();
        if read || write {
            m.dir |= BASE | READ_DATA | READ_EA | EXECUTE;
            m.file |= BASE | READ_DATA | READ_EA;
        }
        if write {
            m.dir |= WRITE_DATA | APPEND_DATA | WRITE_EA | WRITE_ATTRIBUTES;
            m.file |= WRITE_DATA | APPEND_DATA | WRITE_EA | WRITE_ATTRIBUTES;
            m.dir |= DELETE_CHILD | DELETE;
            m.file |= DELETE;
        }
        if execute {
            m.dir |= BASE | EXECUTE;
            // FILE_GENERIC_READ, as a script's interpreter opens it.
            m.file |= BASE | EXECUTE | READ_DATA | READ_EA;
        }
        m
    }

    pub const OBJECT_INHERIT: u32 = 0x1;
    pub const CONTAINER_INHERIT: u32 = 0x2;
    pub const INHERIT_ONLY: u32 = 0x8;
    pub const INHERITED: u8 = 0x10;

    /// The most an AppContainer may have on a file with more than one name
    /// (hard links) whose names lie under different grants: read it, run
    /// it, and look at it, as on Linux such a file keeps its own, usually
    /// readable, rights (#149).
    pub const READ_AND_EXECUTE: u32 = BASE | READ_DATA | READ_EA | EXECUTE;

    /// What a name of such a file under a grant with these flags allows
    /// the file, within [`READ_AND_EXECUTE`].
    pub fn file_cap(read: bool, write: bool, execute: bool) -> u32 {
        masks(read, write, execute).file & READ_AND_EXECUTE
    }

    /// The kinds of entries of an access list (`ACE_HEADER::AceType`) that
    /// [`capped`] tells apart.
    pub const ALLOWED: u8 = 0;
    pub const DENIED: u8 = 1;
    const ALLOWED_COMPOUND: u8 = 4;
    const ALLOWED_OBJECT: u8 = 5;
    const ALLOWED_CALLBACK: u8 = 9;
    const ALLOWED_CALLBACK_OBJECT: u8 = 11;

    /// An entry of an access list, as [`capped`] looks at it.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct Ace {
        pub kind: u8,
        pub flags: u8,
        pub mask: u32,
        /// Its SID as text (`S-1-…`), for the kinds that have it right
        /// after the mask (allowed and denied, also with a condition).
        pub sid: Option<String>,
    }

    /// One entry of a list [`capped`] gives.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum Capped {
        /// The entry at this place of the list it was given, with this mask.
        Entry(usize, u32),
        /// A denying entry of the node's own, for the SID at this place of
        /// the caps, with this mask.
        Deny(usize, u32),
        /// An allowing entry of the node's own, for the SID at this place of
        /// the caps, with this mask.
        Allow(usize, u32),
        /// An allowing entry of the node's own of [`READ_AND_EXECUTE`] for
        /// the account the walk acts as ([`readable_by`]).
        Reads,
    }

    /// A generic right of an entry written out as the rights of a file,
    /// as Windows maps them; the rights an entry on a file cannot give
    /// (the system list, the most allowed) go.
    fn mapped(mask: u32) -> u32 {
        const GENERIC_READ: u32 = 0x8000_0000;
        const GENERIC_WRITE: u32 = 0x4000_0000;
        const GENERIC_EXECUTE: u32 = 0x2000_0000;
        const GENERIC_ALL: u32 = 0x1000_0000;
        let mut m = mask & ALL;
        for (generic, rights) in [
            (GENERIC_READ, BASE | READ_DATA | READ_EA),
            (
                GENERIC_WRITE,
                BASE | WRITE_DATA | APPEND_DATA | WRITE_EA | WRITE_ATTRIBUTES,
            ),
            (GENERIC_EXECUTE, BASE | EXECUTE),
            (GENERIC_ALL, ALL),
        ] {
            if mask & generic != 0 {
                m |= rights;
            }
        }
        m
    }

    /// Whether `sid` (as text) is the SID of an app package as Windows
    /// derives it from a container's name: `S-1-15-2-` and seven numbers,
    /// as the node's containers have. Not the groups every container is in
    /// (`ALL APPLICATION PACKAGES`, `S-1-15-2-1`, and `ALL RESTRICTED
    /// APPLICATION PACKAGES`, `S-1-15-2-2`), which other programs list on
    /// purpose, nor a capability (`S-1-15-3-…`).
    pub fn package_sid(sid: &str) -> bool {
        let Some(rest) = sid
            .get(..9)
            .is_some_and(|p| p.eq_ignore_ascii_case("S-1-15-2-"))
            .then(|| &sid[9..])
        else {
            return false;
        };
        let parts: Vec<&str> = rest.split('-').collect();
        parts.len() == 7
            && parts
                .iter()
                .all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()))
    }

    /// The access list `aces` of a file with more than one name, as `caps`
    /// says for each SID (as text) and with no more than
    /// [`READ_AND_EXECUTE`] for every other AppContainer and capability
    /// (`S-1-15-…`): an entry that allows more is cut down to that, one that
    /// allows nothing then goes. The node's own entries for the SIDs of
    /// `caps` (its allowing and denying ones, inherited too) are worked out
    /// anew from `caps` alone, not from what the list holds now: a SID that
    /// [`Gets::Rights`] gets an allowing entry of those and a denying one of
    /// every other right, a closed one a denying entry of every right, and
    /// one that is [`Gets::Unheld`] none. So it gets the same whichever
    /// name's folder the list was worked out under. Its denying entry, first
    /// in the list, stays when Windows passes a folder's list down to the
    /// file again (as Explorer and `icacls` do), but it does not hold a
    /// container back (Windows checks a container by the entries that allow
    /// it something): the file inherits the folder's whole entry again,
    /// which [`capped_within`] does not count as capped, so the next sync
    /// caps it again. The node's allowing entries come after the
    /// other explicit ones and before the inherited ones, as Windows orders
    /// a list. Every other entry stays as it is.
    pub fn capped(aces: &[Ace], caps: &[(String, Gets)]) -> Vec<Capped> {
        let listed = |sid: &str| caps.iter().position(|(s, _)| s.eq_ignore_ascii_case(sid));
        let any_app = |sid: &str| {
            sid.get(..7)
                .is_some_and(|p| p.eq_ignore_ascii_case("S-1-15-"))
        };
        // The cap of an entry's SID, where it has one.
        let cap_of = |sid: &str| match listed(sid).map(|j| caps[j].1) {
            Some(Gets::Closed) => Some(0),
            Some(Gets::Rights(c)) => Some(c & READ_AND_EXECUTE),
            Some(Gets::Unheld) | None => any_app(sid).then_some(READ_AND_EXECUTE),
        };
        let mut out = Vec::new();
        // Where the inherited entries start in `out`.
        let mut first_inherited = None;
        for (i, a) in aces.iter().enumerate() {
            let explicit = a.flags & INHERITED == 0;
            let j = a.sid.as_deref().and_then(listed);
            let cap = a.sid.as_deref().and_then(cap_of);
            let entry = match (a.kind, j, cap) {
                // The node's own, worked out again below: also one the file
                // inherited, since its list is no longer worked out under a
                // folder's (see `Volume::cap`).
                (ALLOWED | DENIED, Some(_), _) => None,
                (ALLOWED | ALLOWED_CALLBACK, _, Some(cap)) => {
                    let m = mapped(a.mask) & cap;
                    (m != 0).then_some(Capped::Entry(i, m))
                }
                // The SID of these does not follow the mask: whoever it is,
                // it gets no more than read and execute.
                (ALLOWED_COMPOUND | ALLOWED_OBJECT | ALLOWED_CALLBACK_OBJECT, _, _) => {
                    let m = mapped(a.mask) & READ_AND_EXECUTE;
                    (m != 0).then_some(Capped::Entry(i, m))
                }
                _ => Some(Capped::Entry(i, a.mask)),
            };
            if let Some(e) = entry {
                if !explicit && first_inherited.is_none() {
                    first_inherited = Some(out.len());
                }
                out.push(e);
            }
        }
        let denies = caps.iter().enumerate().filter_map(|(j, (_, g))| match g {
            Gets::Closed => Some(Capped::Deny(j, ALL)),
            Gets::Rights(c) => Some(Capped::Deny(j, ALL & !(c & READ_AND_EXECUTE))),
            Gets::Unheld => None,
        });
        let allows = caps.iter().enumerate().filter_map(|(j, (_, g))| match g {
            Gets::Rights(c) if c & READ_AND_EXECUTE != 0 => {
                Some(Capped::Allow(j, c & READ_AND_EXECUTE))
            }
            _ => None,
        });
        let at = first_inherited.unwrap_or(out.len());
        let inherited = out.split_off(at);
        denies.chain(out).chain(allows).chain(inherited).collect()
    }

    /// `out`, a list [`capped`] gave for `aces`, with an allowing entry of
    /// [`READ_AND_EXECUTE`] for `reader` (a SID as text), after the other
    /// explicit entries and before the node's allowing ones: where
    /// [`capped`] keeps it on the next walk, which may look at the file
    /// then and gives no reader, so that walk leaves the list as it is. For the account the
    /// walk acts as (the owner) on a file its list did not let it look at:
    /// one a command linked from its own store into a granted folder keeps
    /// the store's list, which names only the command account, its
    /// container and the system, so without it the owner could not open
    /// what an agent installed in their project. Read, not more, as on
    /// Linux, where the owner reads such a file by its mode. Such an entry
    /// that the list holds already (an earlier walk's) goes first, so a
    /// walk that gives it again leaves the list as it is too; the reader's
    /// other entries stay.
    pub fn readable_by(out: Vec<Capped>, aces: &[Ace], reader: &str) -> Vec<Capped> {
        let ours = |i: usize| {
            let a = &aces[i];
            a.kind == ALLOWED
                && a.flags & INHERITED == 0
                && a.mask == READ_AND_EXECUTE
                && a.sid
                    .as_deref()
                    .is_some_and(|s| s.eq_ignore_ascii_case(reader))
        };
        let after_explicit = |e: &Capped| match *e {
            Capped::Allow(..) => true,
            Capped::Entry(i, _) => aces[i].flags & INHERITED != 0,
            Capped::Deny(..) | Capped::Reads => false,
        };
        let mut out: Vec<Capped> = out
            .into_iter()
            .filter(|e| !matches!(*e, Capped::Entry(i, _) if ours(i)))
            .collect();
        let at = out.iter().position(after_explicit).unwrap_or(out.len());
        out.insert(at, Capped::Reads);
        out
    }

    /// The access list `aces` of a file with more than one name that
    /// changes as any file ([`crate::inherit::Linked::Full`]): without the
    /// node's own entries for the SIDs `listed` (as text), which an earlier
    /// cap gave it ([`capped`]). Every other entry stays as it is.
    pub fn uncapped(aces: &[Ace], listed: &[String]) -> Vec<Capped> {
        aces.iter()
            .enumerate()
            .filter(|(_, a)| {
                !(a.flags & INHERITED == 0
                    && matches!(a.kind, ALLOWED | DENIED)
                    && a.sid
                        .as_deref()
                        .is_some_and(|sid| listed.iter().any(|l| l.eq_ignore_ascii_case(sid))))
            })
            .map(|(i, a)| Capped::Entry(i, a.mask))
            .collect()
    }

    /// Whether `have`, a container's explicit entries (kind, ACE flags,
    /// mask) on a granted file with more than one name, are those
    /// [`capped`] gives it under a grant of `m`: a denying entry of every
    /// right it does not allow, and an allowing one of no more than the
    /// grant gives within [`READ_AND_EXECUTE`], or none (closed). The node
    /// caps such a file in place of the grant's own entry (#149): it counts
    /// as granted, so a sync does not put it on again each time. Not while
    /// the file inherits an entry that allows the container something
    /// (`inherits`): Windows does not hold a container to a denying entry,
    /// so a tool that passed the folder's list down again (Explorer,
    /// `icacls`) reopened the file, and [`capped`] takes that entry off on
    /// the next sync.
    pub fn capped_within(have: &[(u8, u32, u32)], m: Masks, inherits: bool) -> bool {
        if m.deny || inherits {
            return false;
        }
        let mut have = have.to_vec();
        have.sort_unstable();
        match have[..] {
            [(DENIED, 0, d)] => d == ALL,
            [(ALLOWED, 0, c), (DENIED, 0, d)] => {
                c != 0 && c & !(m.file & READ_AND_EXECUTE) == 0 && d == ALL & !c
            }
            _ => false,
        }
    }

    /// The entries a grant of `m` is on a folder (`is_dir`) or a file, as
    /// (ACE flags, mask): for the folder itself, for the folders below it,
    /// and for the files below it. The granted folder or file itself has no
    /// `DELETE`, so a command deletes, renames or moves it only through the
    /// folder above it; what is below it has `DELETE` by the flags.
    pub fn entries(is_dir: bool, m: Masks) -> Vec<(u32, u32)> {
        if m.deny {
            let inherit = if is_dir {
                CONTAINER_INHERIT | OBJECT_INHERIT
            } else {
                0
            };
            return vec![(inherit, m.dir)];
        }
        let all = if !is_dir {
            vec![(0, m.file & !DELETE)]
        } else if m.dir & DELETE == 0 {
            vec![
                (CONTAINER_INHERIT, m.dir),
                (OBJECT_INHERIT | INHERIT_ONLY, m.file),
            ]
        } else {
            vec![
                (0, m.dir & !DELETE),
                (CONTAINER_INHERIT | INHERIT_ONLY, m.dir),
                (OBJECT_INHERIT | INHERIT_ONLY, m.file),
            ]
        };
        all.into_iter().filter(|(_, mask)| *mask != 0).collect()
    }

    /// Whether the entries of two access lists, each as the bytes of its
    /// ACEs one after the other, give the same access: equal but for the
    /// order within a run of allowing entries of the same kind (its own or
    /// inherited), which Windows reads as one, since allowed rights only add
    /// up. Two grants on one folder swap their places when one of them is
    /// put on again, and a walk that compared in order rewrote every file
    /// below it twice (#40, node-1). Bytes that are not whole ACEs compare
    /// as they are.
    pub fn same_entries(a: &[u8], b: &[u8]) -> bool {
        match (runs(a), runs(b)) {
            (Some(a), Some(b)) => a == b,
            _ => a == b,
        }
    }

    /// The ACEs of `bytes` in runs: one ACE alone, or the allowing ones of
    /// one kind that follow each other, sorted. `None` when they are not
    /// whole ACEs.
    fn runs(mut bytes: &[u8]) -> Option<Vec<Vec<&[u8]>>> {
        let mut out: Vec<Vec<&[u8]>> = Vec::new();
        let mut last: Option<u8> = None;
        while !bytes.is_empty() {
            let size = usize::from(u16::from_le_bytes([*bytes.get(2)?, *bytes.get(3)?]));
            if size < 4 || size > bytes.len() {
                return None;
            }
            let (ace, rest) = bytes.split_at(size);
            bytes = rest;
            let kind = (ace[0] == ALLOWED).then_some(ace[1] & INHERITED);
            match (kind, last, out.last_mut()) {
                (Some(k), Some(l), Some(run)) if k == l => run.push(ace),
                _ => out.push(vec![ace]),
            }
            last = kind;
        }
        for run in &mut out {
            run.sort_unstable();
        }
        Some(out)
    }

    /// Whether two Windows paths name the same place by the same names, as
    /// NTFS compares them: in either case, by either separator, with or
    /// without the `\\?\` prefix.
    pub fn same_path(a: &str, b: &str) -> bool {
        // Whether it is a share's (`\\host\…`), and its names.
        fn parts(s: &str) -> (bool, Vec<String>) {
            let (unc, rest) = match s.strip_prefix(r"\\?\") {
                Some(r) => match r.strip_prefix(r"UNC\") {
                    Some(u) => (true, u),
                    None => (false, r),
                },
                None => (s.starts_with(r"\\"), s),
            };
            let names = rest
                .split(['\\', '/'])
                .filter(|c| !c.is_empty())
                .map(str::to_lowercase)
                .collect();
            (unc, names)
        }
        parts(a) == parts(b)
    }

    /// Which file or folder carries a grant, whatever its name: the serial
    /// number of its volume and its file ID there. A move or a rename on the
    /// volume keeps both, and keeps the object's own access list, grants
    /// and all. Written as `<volume>:<file>` in hex.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct FileId {
        pub volume: u64,
        pub file: [u8; 16],
    }

    impl std::fmt::Display for FileId {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "{:016x}:", self.volume)?;
            self.file.iter().try_for_each(|b| write!(f, "{b:02x}"))
        }
    }

    impl std::str::FromStr for FileId {
        type Err = String;

        fn from_str(s: &str) -> Result<FileId, String> {
            let bad = || format!("not a file ID: {s}");
            let (volume, file) = s.split_once(':').ok_or_else(bad)?;
            if volume.len() != 16 || file.len() != 32 || !file.is_ascii() {
                return Err(bad());
            }
            let volume = u64::from_str_radix(volume, 16).map_err(|_| bad())?;
            let mut out = [0u8; 16];
            for (i, b) in out.iter_mut().enumerate() {
                *b = u8::from_str_radix(&file[2 * i..2 * i + 2], 16).map_err(|_| bad())?;
            }
            Ok(FileId { volume, file: out })
        }
    }

    /// Why a change of a grant changed nothing at all: it was refused
    /// before it wrote anything, or nothing was at its path. Marked on the
    /// error ([`untouched`]): only such a change may be taken for one that
    /// did not happen. An error from anywhere else may come after a part of
    /// the change was written, whatever its kind.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum Untouched {
        Refused,
        Gone,
    }

    #[derive(Debug)]
    struct Marked {
        why: Untouched,
        message: String,
    }

    impl std::fmt::Display for Marked {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str(&self.message)
        }
    }

    impl std::error::Error for Marked {}

    /// `e`, of its kind and with its message, marked as a change that
    /// changed nothing (`why`).
    pub fn untouched(why: Untouched, e: std::io::Error) -> std::io::Error {
        std::io::Error::new(
            e.kind(),
            Marked {
                why,
                message: e.to_string(),
            },
        )
    }

    /// What `e` is marked as ([`untouched`]), if anything.
    pub fn untouched_by(e: &std::io::Error) -> Option<Untouched> {
        e.get_ref()?.downcast_ref::<Marked>().map(|m| m.why)
    }

    /// Where an object of a [`FileId`] is now.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum Found {
        /// At this path.
        At(std::path::PathBuf),
        /// Nowhere: it was deleted, and its grants with it.
        Gone,
        /// Its volume is not on this machine now (a drive taken away), so
        /// nothing reaches it; it may come back.
        Away,
    }

    /// The command line that hands `args` to `program` so that it reads
    /// them back as they are (`CommandLineToArgvW`'s rules, as Rust's own
    /// `Command` writes it on Windows): an argument with a space or a tab, or
    /// an empty one, goes in quotes, a quote in it gets a backslash, and the
    /// backslashes before a quote are doubled. The program is always quoted.
    pub fn command_line(program: &str, args: &[String]) -> String {
        let mut out = format!("\"{program}\"");
        for a in args {
            out.push(' ');
            let quote = a.is_empty() || a.contains([' ', '\t']);
            if quote {
                out.push('"');
            }
            let mut backslashes = 0;
            for c in a.chars() {
                if c == '\\' {
                    backslashes += 1;
                } else {
                    if c == '"' {
                        out.extend(std::iter::repeat_n('\\', backslashes + 1));
                    }
                    backslashes = 0;
                }
                out.push(c);
            }
            if quote {
                out.extend(std::iter::repeat_n('\\', backslashes));
                out.push('"');
            }
        }
        out
    }

    /// The environment a command starts with in the container, from this
    /// process's `vars`: Windows PowerShell gets a module path of its own
    /// folders only, `%ProgramFiles%\WindowsPowerShell\Modules` and
    /// `%SystemRoot%\system32\WindowsPowerShell\v1.0\Modules`, which every
    /// AppContainer reads, and no module analysis cache of the machine's
    /// (`PSModuleAnalysisCachePath`). A machine's module path often holds
    /// more: PowerShell 7's folders, which break Windows PowerShell's own
    /// cmdlets, folders of tools (SQL Server, Azure) and of other accounts.
    /// A container reads few of them, and its PowerShell then took half a
    /// minute to start and found none of its own cmdlets (#105, #106). The
    /// rest of the environment stays as it is.
    pub fn container_env(
        vars: impl IntoIterator<Item = (std::ffi::OsString, std::ffi::OsString)>,
    ) -> Vec<(std::ffi::OsString, std::ffi::OsString)> {
        let vars: Vec<_> = vars.into_iter().collect();
        let named = |name: &str| {
            vars.iter()
                .find(|(k, _)| k.to_string_lossy().eq_ignore_ascii_case(name))
                .map(|(_, v)| v.to_string_lossy().trim_end_matches('\\').to_string())
                .filter(|v| !v.is_empty())
        };
        let programs = named("ProgramFiles").unwrap_or_else(|| r"C:\Program Files".into());
        let windows = named("SystemRoot").unwrap_or_else(|| r"C:\Windows".into());
        let modules = format!(
            r"{programs}\WindowsPowerShell\Modules;{windows}\system32\WindowsPowerShell\v1.0\Modules"
        );
        let mut out: Vec<_> = vars
            .into_iter()
            .filter(|(k, _)| {
                let k = k.to_string_lossy();
                !k.eq_ignore_ascii_case("PSModulePath")
                    && !k.eq_ignore_ascii_case("PSModuleAnalysisCachePath")
            })
            .collect();
        out.push(("PSModulePath".into(), modules.into()));
        out
    }

    /// The variables that make `ac`, the container's own folder (`AC` of
    /// its profile), the command's home: `USERPROFILE`, `HOME`,
    /// `HOMEDRIVE` and `HOMEPATH` name `ac\home`, `APPDATA` the
    /// `AppData\Roaming` there. So programs that keep settings below the
    /// home (git, ssh, npm, pip, PowerShell's `~`) keep the pairing's own,
    /// and what one pairing leaves there steers no other: every pairing's
    /// commands run as one account. `LOCALAPPDATA`, `TEMP` and `TMP`
    /// Windows points at `ac` itself. Programs that ask Windows for the
    /// profile folder (the known-folder API, OpenSSH's `known_hosts`) still
    /// get the account's, which the container cannot write.
    ///
    /// git trusts the repositories the command reaches, as on Linux: they
    /// are the owner's, given to it, and git refuses another account's
    /// otherwise ("dubious ownership").
    pub fn container_home(ac: &std::path::Path) -> Vec<(String, String)> {
        // Windows paths, also where the tests run elsewhere.
        let text = format!("{}\\home", ac.display());
        // `C:` and the rest, as Windows splits a home on a drive.
        let (drive, path) = match text.get(..2) {
            Some(d) if d.ends_with(':') => (d.to_string(), text[2..].to_string()),
            _ => (String::new(), text.clone()),
        };
        vec![
            ("USERPROFILE".into(), text.clone()),
            ("HOME".into(), text.clone()),
            ("HOMEDRIVE".into(), drive),
            ("HOMEPATH".into(), path),
            ("APPDATA".into(), format!("{text}\\AppData\\Roaming")),
            ("GIT_CONFIG_COUNT".into(), "1".into()),
            ("GIT_CONFIG_KEY_0".into(), "safe.directory".into()),
            ("GIT_CONFIG_VALUE_0".into(), "*".into()),
        ]
    }

    /// What a container's command gets set besides the environment it
    /// inherits: `env`, the variables the owner passes on, then its home
    /// (`ac`, its container's folder, [`container_home`]), which wins, as
    /// on Linux a pairing's own home does.
    pub fn command_set(
        ac: Option<&std::path::Path>,
        env: &[(String, String)],
    ) -> Vec<(String, String)> {
        let mut set = env.to_vec();
        set.extend(ac.map(container_home).unwrap_or_default());
        set
    }

    /// `vars` with each of `set` in place of a variable of its name
    /// (Windows' names know no case); of two in `set` with one name, the
    /// later.
    pub fn with_vars(
        vars: Vec<(std::ffi::OsString, std::ffi::OsString)>,
        set: &[(String, String)],
    ) -> Vec<(std::ffi::OsString, std::ffi::OsString)> {
        let set: Vec<&(String, String)> = set
            .iter()
            .enumerate()
            .filter(|(i, (k, _))| !set[i + 1..].iter().any(|(l, _)| l.eq_ignore_ascii_case(k)))
            .map(|(_, v)| v)
            .collect();
        let mut out: Vec<_> = vars
            .into_iter()
            .filter(|(k, _)| {
                let k = k.to_string_lossy();
                !set.iter().any(|(s, _)| s.eq_ignore_ascii_case(&k))
            })
            .collect();
        out.extend(set.iter().map(|(k, v)| (k.into(), v.into())));
        out
    }
}

#[cfg(windows)]
pub mod appcontainer {
    //! The AppContainer of a Windows `folders` command: the grants on its
    //! folders ([`set`]) and the process in it ([`run`]).
    //!
    //! The container's SID is derived from its name, so the node puts grants
    //! on folders for it without asking anything of Windows. To start a
    //! process in it, Windows wants its profile; the shim makes that for the
    //! user it runs as ([`ensure_profile`]), and the node removes it with the
    //! container's last grant ([`remove_profile`]). The container has the
    //! network (`internetClient`, `internetClientServer`,
    //! `privateNetworkClientServer`), which Landlock leaves open too, but not
    //! the machine's own loopback address, which Windows keeps from every
    //! AppContainer.

    use std::ffi::{OsStr, c_void};
    use std::io;
    use std::os::windows::ffi::{OsStrExt, OsStringExt};
    use std::os::windows::io::{AsRawHandle, FromRawHandle};
    use std::path::{Path, PathBuf};
    use std::ptr::{null, null_mut};

    use windows_sys::Wdk::Foundation::OBJECT_ATTRIBUTES;
    use windows_sys::Wdk::Storage::FileSystem::{
        FILE_LINK_ENTRY_FULL_ID_INFORMATION, FILE_LINK_ENTRY_INFORMATION,
        FILE_LINKS_FULL_ID_INFORMATION, FILE_LINKS_INFORMATION, FILE_OPEN_FOR_BACKUP_INTENT,
        FILE_OPEN_REPARSE_POINT, FILE_SYNCHRONOUS_IO_NONALERT, FileHardLinkFullIdInformation,
        FileHardLinkInformation, NtOpenFile, NtQueryInformationFile,
    };
    use windows_sys::Win32::Foundation::{
        CloseHandle, ERROR_ACCESS_DENIED, ERROR_INSUFFICIENT_BUFFER, ERROR_INVALID_LEVEL,
        ERROR_INVALID_PARAMETER, ERROR_NO_MORE_FILES, ERROR_NO_TOKEN, ERROR_NOT_SUPPORTED,
        GENERIC_ALL, HANDLE, HANDLE_FLAG_INHERIT, INVALID_HANDLE_VALUE, LocalFree, NTSTATUS,
        RtlNtStatusToDosError, STATUS_BUFFER_OVERFLOW, STATUS_BUFFER_TOO_SMALL,
        STATUS_DELETE_PENDING, STATUS_INVALID_INFO_CLASS, STATUS_INVALID_PARAMETER,
        STATUS_NOT_SUPPORTED, STATUS_OBJECT_NAME_NOT_FOUND, SetHandleInformation, UNICODE_STRING,
    };
    use windows_sys::Win32::Security::Authorization::{
        ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
        ConvertStringSidToSidW, GetSecurityInfo, SDDL_REVISION_1, SE_FILE_OBJECT, SE_WINDOW_OBJECT,
        SetSecurityInfo,
    };
    use windows_sys::Win32::Security::Isolation::{
        CreateAppContainerProfile, DeleteAppContainerProfile,
        DeriveAppContainerSidFromAppContainerName,
    };
    use windows_sys::Win32::Security::{
        ACCESS_ALLOWED_ACE, ACE_HEADER, ACL, ACL_REVISION_DS, ACL_SIZE_INFORMATION,
        AclSizeInformation, AddAccessAllowedAceEx, AddAccessDeniedAceEx, AddAce,
        CONTAINER_INHERIT_ACE, ConvertToAutoInheritPrivateObjectSecurity,
        CreatePrivateObjectSecurityEx, CreateWellKnownSid, DACL_SECURITY_INFORMATION,
        DestroyPrivateObjectSecurity, EqualSid, FreeSid, GENERIC_MAPPING,
        GROUP_SECURITY_INFORMATION, GetAce, GetAclInformation, GetKernelObjectSecurity,
        GetLengthSid, GetSecurityDescriptorControl, GetSecurityDescriptorDacl,
        GetSecurityDescriptorGroup, GetSecurityDescriptorLength, GetSecurityDescriptorOwner,
        GetTokenInformation, INHERIT_ONLY_ACE, INHERITED_ACE, ImpersonateLoggedOnUser,
        InitializeAcl, InitializeSecurityDescriptor, MakeSelfRelativeSD, OBJECT_INHERIT_ACE,
        OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID, RevertToSelf,
        SE_DACL_AUTO_INHERIT_REQ, SE_DACL_AUTO_INHERITED, SE_DACL_PROTECTED, SECURITY_ATTRIBUTES,
        SECURITY_CAPABILITIES, SECURITY_DESCRIPTOR, SEF_AVOID_OWNER_CHECK,
        SEF_AVOID_PRIVILEGE_CHECK, SEF_DACL_AUTO_INHERIT, SID_AND_ATTRIBUTES,
        SetKernelObjectSecurity, SetSecurityDescriptorControl, SetSecurityDescriptorDacl,
        SetSecurityDescriptorGroup, SetSecurityDescriptorOwner, TOKEN_IMPERSONATE, TOKEN_QUERY,
        TOKEN_USER, TokenUser, WinCapabilityInternetClientServerSid,
        WinCapabilityInternetClientSid, WinCapabilityPrivateNetworkClientServerSid,
    };
    use windows_sys::Win32::Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, ExtendedFileIdType, FILE_ALL_ACCESS, FILE_ATTRIBUTE_DIRECTORY,
        FILE_ATTRIBUTE_REPARSE_POINT, FILE_ATTRIBUTE_TAG_INFO, FILE_FLAG_BACKUP_SEMANTICS,
        FILE_FULL_DIR_INFO, FILE_GENERIC_EXECUTE, FILE_GENERIC_READ, FILE_GENERIC_WRITE,
        FILE_ID_128, FILE_ID_DESCRIPTOR, FILE_ID_DESCRIPTOR_0, FILE_ID_EXTD_DIR_INFO, FILE_ID_INFO,
        FILE_LIST_DIRECTORY, FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE, FILE_SHARE_READ,
        FILE_SHARE_WRITE, FILE_STANDARD_INFO, FileAttributeTagInfo, FileFullDirectoryInfo,
        FileIdExtdDirectoryInfo, FileIdInfo, FileStandardInfo, FindFirstVolumeW, FindNextVolumeW,
        FindVolumeClose, GetFileInformationByHandle, GetFileInformationByHandleEx,
        GetFinalPathNameByHandleW, GetLogicalDrives, GetLongPathNameW, OpenFileById, READ_CONTROL,
        SYNCHRONIZE, WRITE_DAC,
    };
    use windows_sys::Win32::System::IO::IO_STATUS_BLOCK;
    use windows_sys::Win32::System::Threading::{
        CREATE_UNICODE_ENVIRONMENT, CreateProcessW, DeleteProcThreadAttributeList,
        EXTENDED_STARTUPINFO_PRESENT, GetCurrentProcess, GetCurrentThread, GetExitCodeProcess,
        INFINITE, InitializeProcThreadAttributeList, LPPROC_THREAD_ATTRIBUTE_LIST,
        OpenProcessToken, OpenThreadToken, PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
        PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES, PROCESS_INFORMATION, STARTF_USESTDHANDLES,
        STARTUPINFOEXW, SetThreadToken, UpdateProcThreadAttribute, WaitForSingleObject,
    };

    use super::acl::{self, FileId, Found, Masks, command_line, entries};
    use crate::inherit::{self, Derived, Kind, Linked, Objects, Walk, Walked};

    // The flags of `acl::entries` are Windows' own.
    const _: () = assert!(
        acl::OBJECT_INHERIT == OBJECT_INHERIT_ACE
            && acl::CONTAINER_INHERIT == CONTAINER_INHERIT_ACE
            && acl::INHERIT_ONLY == INHERIT_ONLY_ACE
    );

    const ACCESS_ALLOWED_ACE_TYPE: u8 = 0;
    const ACCESS_DENIED_ACE_TYPE: u8 = 1;
    const SE_GROUP_ENABLED: u32 = 4;

    fn wide(s: &OsStr) -> Vec<u16> {
        s.encode_wide().chain(std::iter::once(0)).collect()
    }

    fn check(ok: i32) -> io::Result<()> {
        if ok == 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }

    /// The SID of the container `name`, or of the account whose SID `name`
    /// is in text (`S-1-5-…`): the command account gets entries on the
    /// folders as well as each container (nerve-node's grants). Whether
    /// Windows allocated it with LocalAlloc.
    pub struct Sid(PSID, bool);

    impl Sid {
        /// The SID, for a call that takes one; it lives as long as `self`.
        pub fn as_ptr(&self) -> PSID {
            self.0
        }

        pub fn derive(name: &str) -> io::Result<Sid> {
            if name.starts_with("S-1-") {
                let mut sid: PSID = null_mut();
                // SAFETY: a NUL-terminated string; the SID the call
                // allocates is freed with LocalFree.
                check(unsafe { ConvertStringSidToSidW(wide(OsStr::new(name)).as_ptr(), &mut sid) })
                    .map_err(|e| io::Error::new(e.kind(), format!("the SID {name}: {e}")))?;
                return Ok(Sid(sid, true));
            }
            let n = wide(OsStr::new(name));
            let mut sid: PSID = null_mut();
            // SAFETY: a NUL-terminated name; the call sets `sid` to a SID it
            // allocated, freed with FreeSid.
            let hr = unsafe { DeriveAppContainerSidFromAppContainerName(n.as_ptr(), &mut sid) };
            if hr < 0 || sid.is_null() {
                return Err(io::Error::other(format!(
                    "cannot derive the AppContainer SID of {name} ({hr:#x})"
                )));
            }
            Ok(Sid(sid, false))
        }
    }

    impl Drop for Sid {
        fn drop(&mut self) {
            // SAFETY: the SID came from ConvertStringSidToSidW or from
            // DeriveAppContainerSidFromAppContainerName.
            unsafe {
                if self.1 {
                    LocalFree(self.0);
                } else {
                    FreeSid(self.0);
                }
            }
        }
    }

    /// Memory Windows allocated with LocalAlloc, freed when dropped.
    struct Local(*mut c_void);

    impl Drop for Local {
        fn drop(&mut self) {
            // SAFETY: the pointer came from LocalAlloc (or is null).
            unsafe { LocalFree(self.0) };
        }
    }

    /// The ACEs of `dacl`, each from its header.
    fn aces(dacl: *mut ACL) -> io::Result<Vec<*const ACE_HEADER>> {
        let mut info = ACL_SIZE_INFORMATION::default();
        // SAFETY: a valid ACL and a buffer of the size given.
        check(unsafe {
            GetAclInformation(
                dacl,
                &mut info as *mut _ as *mut c_void,
                size_of::<ACL_SIZE_INFORMATION>() as u32,
                AclSizeInformation,
            )
        })?;
        (0..info.AceCount)
            .map(|i| {
                let mut ace: *mut c_void = null_mut();
                // SAFETY: `i` is below the ACE count; the ACE lies in `dacl`.
                check(unsafe { GetAce(dacl, i, &mut ace) })?;
                Ok(ace as *const ACE_HEADER)
            })
            .collect()
    }

    /// Whether `ace` is an entry of the list's own (not inherited) that
    /// allows or denies something to `sid`.
    ///
    /// SAFETY: `ace` points to an ACE of a valid list.
    unsafe fn own_for(ace: *const ACE_HEADER, sid: &Sid) -> bool {
        // SAFETY: every ACE starts with its header.
        let h = unsafe { &*ace };
        if u32::from(h.AceFlags) & INHERITED_ACE != 0 {
            return false;
        }
        matches!(h.AceType, ACCESS_ALLOWED_ACE_TYPE | ACCESS_DENIED_ACE_TYPE)
            // SAFETY: an allowed or denied ACE has its SID at SidStart.
            && unsafe {
                let a = ace as *const ACCESS_ALLOWED_ACE;
                EqualSid(&raw const (*a).SidStart as PSID, sid.0) != 0
            }
    }

    /// `path` opened for `access` alone, a folder as well as a file, while
    /// others may keep it open for anything.
    fn open(path: &Path, access: u32) -> io::Result<std::fs::File> {
        use std::os::windows::fs::OpenOptionsExt;
        std::fs::OpenOptions::new()
            .access_mode(access)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
            .open(path)
    }

    fn id_of(f: &std::fs::File) -> io::Result<FileId> {
        id_by(f.as_raw_handle())
    }

    fn id_by(h: HANDLE) -> io::Result<FileId> {
        let mut info = FILE_ID_INFO::default();
        // SAFETY: an open handle and a buffer of the size given.
        check(unsafe {
            GetFileInformationByHandleEx(
                h,
                FileIdInfo,
                &mut info as *mut _ as *mut c_void,
                size_of::<FILE_ID_INFO>() as u32,
            )
        })?;
        Ok(FileId {
            volume: info.VolumeSerialNumber,
            file: info.FileId.Identifier,
        })
    }

    /// Which object is at `path` now (the tests'; the node asks by the
    /// handle it holds, [`handle_id`]).
    #[cfg(test)]
    pub fn file_id(path: &Path) -> io::Result<FileId> {
        id_of(&open(path, FILE_READ_ATTRIBUTES)?)
    }

    /// Which object the open handle `h` is on.
    pub fn handle_id(h: &impl AsRawHandle) -> io::Result<FileId> {
        id_by(h.as_raw_handle())
    }

    /// `path` without the `\\?\` prefix, as the policy compares paths.
    fn plain(path: Vec<u16>) -> PathBuf {
        let w = |s: &str| s.encode_utf16().collect::<Vec<u16>>();
        let out = if let Some(rest) = path.strip_prefix(&w(r"\\?\UNC\")[..]) {
            [w(r"\\"), rest.to_vec()].concat()
        } else if let Some(rest) = path.strip_prefix(&w(r"\\?\")[..]) {
            rest.to_vec()
        } else {
            path
        };
        PathBuf::from(std::ffi::OsString::from_wide(&out))
    }

    /// What is at `path` (its [`FileId`], `None` where the volume gives
    /// none), and whether its own entries for the container `name` are
    /// exactly those [`set`] puts on for `masks` (on a file with more than
    /// one name, or the cap [`set_below`] gives it in their place:
    /// [`acl::capped_within`]). NotFound when nothing is there.
    pub fn look(path: &Path, name: &str, masks: Masks) -> io::Result<(Option<FileId>, bool)> {
        let sid = Sid::derive(name)?;
        let f = open(path, READ_CONTROL | FILE_READ_ATTRIBUTES)?;
        let id = id_of(&f).ok();
        let is_dir = f.metadata()?.is_dir();
        let mut dacl: *mut ACL = null_mut();
        let mut sd: PSECURITY_DESCRIPTOR = null_mut();
        // SAFETY: an open handle and out pointers to locals; the descriptor
        // is freed with LocalFree, and `dacl` points into it.
        let e = unsafe {
            GetSecurityInfo(
                f.as_raw_handle(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                null_mut(),
                null_mut(),
                &mut dacl,
                null_mut(),
                &mut sd,
            )
        };
        if e != 0 {
            return Err(io::Error::from_raw_os_error(e as i32));
        }
        let _sd = Local(sd);
        if dacl.is_null() {
            return Ok((id, false));
        }
        let mut have = Vec::new();
        // An entry it inherits that allows the container something: a
        // folder closed to it is not closed while it has one ([`closing`]),
        // as where a tool passed the list of the folder around it down.
        let mut opened = false;
        for ace in aces(dacl)? {
            // SAFETY: the ACE lies in `dacl`, valid while `_sd` lives; an
            // allowed or denied ACE has its mask after the header and its
            // SID at SidStart.
            unsafe {
                let a = ace as *const ACCESS_ALLOWED_ACE;
                if own_for(ace, &sid) {
                    have.push(((*ace).AceType, u32::from((*ace).AceFlags), (*a).Mask));
                } else if (*ace).AceType == ACCESS_ALLOWED_ACE_TYPE
                    && EqualSid(&raw const (*a).SidStart as PSID, sid.0) != 0
                {
                    opened = true;
                }
            }
        }
        if masks.deny && opened {
            return Ok((id, false));
        }
        let kind = if masks.deny {
            ACCESS_DENIED_ACE_TYPE
        } else {
            ACCESS_ALLOWED_ACE_TYPE
        };
        let mut want: Vec<_> = entries(is_dir, masks)
            .into_iter()
            .map(|(flags, mask)| (kind, flags, mask))
            .collect();
        have.sort_unstable();
        want.sort_unstable();
        if have == want || is_dir {
            return Ok((id, have == want));
        }
        // A file with more than one name gets the node's cap in place of
        // the grant's entry ([`set_below`]).
        let mut info = BY_HANDLE_FILE_INFORMATION::default();
        // SAFETY: an open handle and a buffer for the answer.
        check(unsafe { GetFileInformationByHandle(f.as_raw_handle(), &mut info) })?;
        Ok((
            id,
            info.nNumberOfLinks > 1 && acl::capped_within(&have, masks, opened),
        ))
    }

    /// The path of the object open as `f`: by its drive or the folder its
    /// volume is mounted in, or else by the volume's own name
    /// (`\\?\Volume{…}\…`), which reaches it too.
    fn final_path(f: &std::fs::File) -> io::Result<PathBuf> {
        const VOLUME_NAME_GUID: u32 = 1;
        named_path(f, 0).or_else(|_| named_path(f, VOLUME_NAME_GUID))
    }

    fn named_path(f: &std::fs::File, how: u32) -> io::Result<PathBuf> {
        let mut buf = vec![0u16; 512];
        loop {
            // SAFETY: an open handle and a buffer of the length given.
            let n = unsafe {
                GetFinalPathNameByHandleW(
                    f.as_raw_handle(),
                    buf.as_mut_ptr(),
                    buf.len() as u32,
                    how,
                )
            } as usize;
            if n == 0 {
                return Err(io::Error::last_os_error());
            }
            if n < buf.len() {
                buf.truncate(n);
                return Ok(PathBuf::from(std::ffi::OsString::from_wide(&buf)));
            }
            // Too short: `n` is the length it needs.
            buf.resize(n, 0);
        }
    }

    /// The root of every volume on the machine, by its own name
    /// (`\\?\Volume{…}\`): also those without a drive letter.
    fn volumes() -> Vec<PathBuf> {
        let mut out = Vec::new();
        let mut buf = [0u16; 260];
        // SAFETY: a buffer of the length given.
        let h = unsafe { FindFirstVolumeW(buf.as_mut_ptr(), buf.len() as u32) };
        if h == INVALID_HANDLE_VALUE {
            return out;
        }
        loop {
            let n = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
            out.push(PathBuf::from(std::ffi::OsString::from_wide(&buf[..n])));
            // SAFETY: the search handle from above and a buffer of the length
            // given.
            if unsafe { FindNextVolumeW(h, buf.as_mut_ptr(), buf.len() as u32) } == 0 {
                break;
            }
        }
        // SAFETY: the search handle from above, closed once.
        unsafe { FindVolumeClose(h) };
        out
    }

    /// Where the object `id` is now ([`Found`]). Its volume is looked for at
    /// each folder of `near`, a path it had (one may be where a volume is
    /// mounted), then among all the volumes on the machine, and at every
    /// drive letter. Away only when none of them is its volume.
    pub fn locate(id: &FileId, near: &Path) -> io::Result<Found> {
        let mut roots: Vec<PathBuf> = near.ancestors().map(Path::to_path_buf).collect();
        roots.extend(volumes());
        // SAFETY: no arguments.
        let drives = unsafe { GetLogicalDrives() };
        roots.extend(
            (0..26u8)
                .filter(|i| drives & (1 << i) != 0)
                .map(|i| PathBuf::from(format!("{}:\\", char::from(b'A' + i)))),
        );
        for root in roots {
            let Ok(r) = open(&root, FILE_READ_ATTRIBUTES) else {
                continue;
            };
            if id_of(&r).ok().map(|v| v.volume) != Some(id.volume) {
                continue;
            }
            let desc = FILE_ID_DESCRIPTOR {
                dwSize: size_of::<FILE_ID_DESCRIPTOR>() as u32,
                Type: ExtendedFileIdType,
                Anonymous: FILE_ID_DESCRIPTOR_0 {
                    ExtendedFileId: FILE_ID_128 {
                        Identifier: id.file,
                    },
                },
            };
            // SAFETY: a handle on the volume and a valid descriptor; the
            // handle returned is owned by the File below.
            let h = unsafe {
                OpenFileById(
                    r.as_raw_handle(),
                    &desc,
                    FILE_READ_ATTRIBUTES,
                    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                    null(),
                    FILE_FLAG_BACKUP_SEMANTICS,
                )
            };
            if h == INVALID_HANDLE_VALUE {
                let e = io::Error::last_os_error();
                // No such file (NTFS says the ID is not valid).
                return match e.raw_os_error() {
                    Some(2 | 3 | 87) => Ok(Found::Gone),
                    _ => Err(e),
                };
            }
            // SAFETY: a handle this function owns.
            let f = unsafe { std::fs::File::from_raw_handle(h) };
            return final_path(&f).map(Found::At);
        }
        Ok(Found::Away)
    }

    /// `path` with each short (8.3) name in it written out, as the final
    /// path of what it names has them; links and junctions stay as they
    /// are. `path` itself when that fails.
    pub fn long_path(path: &Path) -> PathBuf {
        let p = wide(path.as_os_str());
        let mut buf = vec![0u16; 512];
        loop {
            // SAFETY: a NUL-terminated path and a buffer of the length given.
            let n = unsafe { GetLongPathNameW(p.as_ptr(), buf.as_mut_ptr(), buf.len() as u32) }
                as usize;
            if n == 0 {
                return path.to_path_buf();
            }
            if n < buf.len() {
                buf.truncate(n);
                return PathBuf::from(std::ffi::OsString::from_wide(&buf));
            }
            // Too short: `n` is the length it needs.
            buf.resize(n, 0);
        }
    }

    /// Why what `f` opened at `path` is not an object of its own there, if
    /// it is not: a link or junction on the way leads elsewhere, or it is a
    /// file with other names (hard links), which share its access list.
    fn not_own(f: &std::fs::File, path: &Path) -> io::Result<Option<String>> {
        let now = final_path(f)?;
        if !acl::same_path(&now.to_string_lossy(), &long_path(path).to_string_lossy()) {
            return Ok(Some(format!(
                "it leads to {} (a link or a junction)",
                now.display()
            )));
        }
        let mut info = BY_HANDLE_FILE_INFORMATION::default();
        // SAFETY: an open handle and a buffer for the answer.
        check(unsafe { GetFileInformationByHandle(f.as_raw_handle(), &mut info) })?;
        if !f.metadata()?.is_dir() && info.nNumberOfLinks > 1 {
            return Ok(Some(format!(
                "the file has {} names (hard links), and a grant on it would reach them all",
                info.nNumberOfLinks
            )));
        }
        Ok(None)
    }

    /// A handle, closed when dropped unless it is borrowed.
    struct Obj {
        h: HANDLE,
        owned: bool,
    }

    impl Drop for Obj {
        fn drop(&mut self) {
            if self.owned {
                // SAFETY: a handle this module opened, closed once.
                unsafe { CloseHandle(self.h) };
            }
        }
    }

    /// The error of an NTSTATUS, by Windows' own error code for it.
    fn nt_error(status: NTSTATUS) -> io::Error {
        // SAFETY: a plain conversion.
        io::Error::from_raw_os_error(unsafe { RtlNtStatusToDosError(status) } as i32)
    }

    /// What is called `name` in the folder open as `dir`, opened through
    /// that handle and as itself: a link or junction is not followed, and a
    /// folder on the way that was moved or replaced meanwhile does not count.
    /// An empty name opens `dir` again. `None` when nothing is there, or it
    /// is being deleted.
    fn open_in(dir: HANDLE, name: &[u16], access: u32) -> io::Result<Option<Obj>> {
        let bytes = (name.len() * 2) as u16;
        let us = UNICODE_STRING {
            Length: bytes,
            MaximumLength: bytes,
            Buffer: name.as_ptr() as *mut u16,
        };
        let attrs = OBJECT_ATTRIBUTES {
            Length: size_of::<OBJECT_ATTRIBUTES>() as u32,
            RootDirectory: dir,
            ObjectName: &us,
            Attributes: 0,
            SecurityDescriptor: null(),
            SecurityQualityOfService: null(),
        };
        let mut h: HANDLE = null_mut();
        let mut status_block = IO_STATUS_BLOCK::default();
        // SAFETY: the attributes point to a name that lives through the
        // call; the handle it returns is owned by the Obj below.
        let status = unsafe {
            NtOpenFile(
                &mut h,
                access | SYNCHRONIZE,
                &attrs,
                &mut status_block,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                FILE_OPEN_REPARSE_POINT
                    | FILE_OPEN_FOR_BACKUP_INTENT
                    | FILE_SYNCHRONOUS_IO_NONALERT,
            )
        };
        match status {
            s if s >= 0 => Ok(Some(Obj { h, owned: true })),
            STATUS_OBJECT_NAME_NOT_FOUND | STATUS_DELETE_PENDING => Ok(None),
            s => Err(nt_error(s)),
        }
    }

    const SECURITY_DESCRIPTOR_REVISION: u32 = 1;

    /// The control bits of a list that [`Sd::with`] keeps.
    const DACL_BITS: u16 = SE_DACL_PROTECTED | SE_DACL_AUTO_INHERITED;

    /// A security descriptor in a buffer of its own, self-relative.
    #[derive(Clone)]
    struct Sd(Vec<u64>);

    impl Sd {
        fn ptr(&self) -> PSECURITY_DESCRIPTOR {
            self.0.as_ptr() as PSECURITY_DESCRIPTOR
        }

        /// A copy of the descriptor at `sd`.
        ///
        /// SAFETY: `sd` is a valid self-relative descriptor.
        unsafe fn copy(sd: PSECURITY_DESCRIPTOR) -> Sd {
            // SAFETY: as the caller says.
            let len = unsafe { GetSecurityDescriptorLength(sd) } as usize;
            let mut buf = vec![0u64; len.div_ceil(8)];
            // SAFETY: the descriptor is `len` bytes long, the buffer as long
            // or longer.
            unsafe {
                std::ptr::copy_nonoverlapping(sd as *const u8, buf.as_mut_ptr() as *mut u8, len)
            };
            Sd(buf)
        }

        /// The owner, group and access list of the object open as `h`.
        fn of(h: HANDLE) -> io::Result<Sd> {
            let info =
                OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION;
            let mut buf = vec![0u64; 64];
            loop {
                let mut need = 0u32;
                // SAFETY: an open handle and a buffer of the size given.
                let ok = unsafe {
                    GetKernelObjectSecurity(
                        h,
                        info,
                        buf.as_mut_ptr() as PSECURITY_DESCRIPTOR,
                        (buf.len() * 8) as u32,
                        &mut need,
                    )
                };
                if ok != 0 {
                    return Ok(Sd(buf));
                }
                let e = io::Error::last_os_error();
                if e.raw_os_error() != Some(ERROR_INSUFFICIENT_BUFFER as i32) {
                    return Err(e);
                }
                buf.resize((need as usize).div_ceil(8), 0);
            }
        }

        /// The owner and group of `like`, the access list `dacl`, and of
        /// `control` the bits [`DACL_BITS`].
        fn with(like: &Sd, dacl: *mut ACL, control: u16) -> io::Result<Sd> {
            let mut abs = SECURITY_DESCRIPTOR::default();
            let p = &mut abs as *mut SECURITY_DESCRIPTOR as PSECURITY_DESCRIPTOR;
            let (mut owner, mut group): (PSID, PSID) = (null_mut(), null_mut());
            let mut defaulted = 0;
            // SAFETY: a descriptor on the stack; the owner, group and list
            // it points to live in `like` and `dacl` until the copy below is
            // made.
            unsafe {
                check(GetSecurityDescriptorOwner(
                    like.ptr(),
                    &mut owner,
                    &mut defaulted,
                ))?;
                check(GetSecurityDescriptorGroup(
                    like.ptr(),
                    &mut group,
                    &mut defaulted,
                ))?;
                check(InitializeSecurityDescriptor(
                    p,
                    SECURITY_DESCRIPTOR_REVISION,
                ))?;
                check(SetSecurityDescriptorOwner(p, owner, 0))?;
                check(SetSecurityDescriptorGroup(p, group, 0))?;
                check(SetSecurityDescriptorDacl(p, 1, dacl, 0))?;
                check(SetSecurityDescriptorControl(
                    p,
                    DACL_BITS,
                    control & DACL_BITS,
                ))?;
            }
            let mut len = 0u32;
            // SAFETY: asks for the length only.
            unsafe { MakeSelfRelativeSD(p, null_mut(), &mut len) };
            let mut buf = vec![0u64; (len as usize).div_ceil(8)];
            // SAFETY: a buffer of `len` bytes or more.
            check(unsafe {
                MakeSelfRelativeSD(p, buf.as_mut_ptr() as PSECURITY_DESCRIPTOR, &mut len)
            })?;
            Ok(Sd(buf))
        }

        /// Its owner as text, where it names one.
        fn owner(&self) -> io::Result<Option<String>> {
            let (mut owner, mut defaulted): (PSID, i32) = (null_mut(), 0);
            // SAFETY: a valid descriptor; `owner` points into it.
            check(unsafe { GetSecurityDescriptorOwner(self.ptr(), &mut owner, &mut defaulted) })?;
            if owner.is_null() {
                return Ok(None);
            }
            sid_text(owner).map(Some)
        }

        /// Whether an entry of its access list is marked inherited.
        fn marks_inherited(&self) -> io::Result<bool> {
            let (mut present, mut defaulted) = (0, 0);
            let mut dacl: *mut ACL = null_mut();
            // SAFETY: a valid descriptor; `dacl` points into it.
            check(unsafe {
                GetSecurityDescriptorDacl(self.ptr(), &mut present, &mut dacl, &mut defaulted)
            })?;
            if present == 0 || dacl.is_null() {
                return Ok(false);
            }
            // SAFETY: each ACE lies in `dacl` and starts with its header.
            Ok(aces(dacl)?
                .iter()
                .any(|a| u32::from(unsafe { (**a).AceFlags }) & INHERITED_ACE != 0))
        }

        /// Writes its access list as the list of the object open as `h`,
        /// and nothing below it: unlike SetSecurityInfo, this passes nothing
        /// down. Windows keeps the mark that its inherited entries are
        /// marked (SE_DACL_AUTO_INHERITED) only when the write asks for it.
        fn write(&self, h: HANDLE) -> io::Result<()> {
            let sd = self.clone();
            if sd.control()? & SE_DACL_AUTO_INHERITED != 0 {
                // SAFETY: a valid descriptor of our own.
                check(unsafe {
                    SetSecurityDescriptorControl(
                        sd.ptr(),
                        SE_DACL_AUTO_INHERIT_REQ,
                        SE_DACL_AUTO_INHERIT_REQ,
                    )
                })?;
            }
            // SAFETY: a handle opened for WRITE_DAC, and a valid descriptor.
            check(unsafe { SetKernelObjectSecurity(h, DACL_SECURITY_INFORMATION, sd.ptr()) })
        }

        fn control(&self) -> io::Result<u16> {
            let (mut control, mut revision) = (0u16, 0u32);
            // SAFETY: a valid descriptor.
            check(unsafe {
                GetSecurityDescriptorControl(self.ptr(), &mut control, &mut revision)
            })?;
            Ok(control)
        }

        /// The entries of its access list, byte for byte; `None` without one.
        fn entries(&self) -> io::Result<Option<Vec<u8>>> {
            let (mut present, mut defaulted) = (0, 0);
            let mut dacl: *mut ACL = null_mut();
            // SAFETY: a valid descriptor; `dacl` points into it.
            check(unsafe {
                GetSecurityDescriptorDacl(self.ptr(), &mut present, &mut dacl, &mut defaulted)
            })?;
            if present == 0 || dacl.is_null() {
                return Ok(None);
            }
            ace_bytes(dacl).map(Some)
        }
    }

    /// Whether two lists' entries ([`Sd::entries`]) give the same access
    /// ([`acl::same_entries`]).
    fn same_list(a: &Option<Vec<u8>>, b: &Option<Vec<u8>>) -> bool {
        match (a, b) {
            (Some(a), Some(b)) => acl::same_entries(a, b),
            (a, b) => a == b,
        }
    }

    /// The entries of `dacl`, byte for byte.
    fn ace_bytes(dacl: *mut ACL) -> io::Result<Vec<u8>> {
        let mut out = Vec::new();
        for ace in aces(dacl)? {
            // SAFETY: each ACE lies in `dacl` and is as long as its header
            // says.
            unsafe {
                out.extend_from_slice(std::slice::from_raw_parts(
                    ace as *const u8,
                    usize::from((*ace).AceSize),
                ))
            };
        }
        Ok(out)
    }

    /// The tag bit of a reparse point that names another place (a junction
    /// or a symbolic link); other reparse points, such as those of cloud
    /// files, are the object itself.
    const NAME_SURROGATE: u32 = 0x2000_0000;

    /// The access mapping of files and folders, by which Windows writes out
    /// a generic right of an entry a file or folder inherits.
    const FILE_MAPPING: GENERIC_MAPPING = GENERIC_MAPPING {
        GenericRead: FILE_GENERIC_READ,
        GenericWrite: FILE_GENERIC_WRITE,
        GenericExecute: FILE_GENERIC_EXECUTE,
        GenericAll: FILE_ALL_ACCESS,
    };

    /// What is below a folder, as a change of its list passes down to it
    /// ([`inherit`]): each object opened through its folder's handle, and
    /// the list it gets worked out by Windows, as when the object is made.
    struct Volume {
        /// This process' token, which Windows asks for in that.
        token: Obj,
        /// [`Below::maker`].
        maker: Option<HANDLE>,
    }

    impl Volume {
        fn new() -> io::Result<Volume> {
            Ok(Volume {
                token: process_token()?,
                maker: None,
            })
        }

        /// The account this thread acts as (as a SID), where a cap
        /// (`linked`) is to give it read: it may not look at the file, which
        /// was opened as its maker then ([`Volume::open`], a file a command
        /// linked in from its own store; [`acl::readable_by`]). `None`
        /// otherwise.
        fn reader(&self, obj: &Obj, linked: &Linked) -> io::Result<Option<String>> {
            if self.maker.is_none() || !matches!(linked, Linked::Capped(_)) {
                return Ok(None);
            }
            match open_in(obj.h, &[], READ_CONTROL | FILE_READ_ATTRIBUTES) {
                Err(e) if e.raw_os_error() == Some(ERROR_ACCESS_DENIED as i32) => {
                    acting_sid().map(Some)
                }
                Err(e) => Err(e),
                Ok(_) => Ok(None),
            }
        }
    }

    /// Runs `f` on this thread as the account of the logon `token`, and
    /// then as the thread was again (itself, or whoever it acted as). An
    /// error where it cannot be that again: what follows must not run as
    /// the account.
    fn as_token<T>(token: HANDLE, f: impl FnOnce() -> T) -> io::Result<T> {
        // As the process first: it holds the right to act as another.
        // SAFETY: a logon token.
        as_self(|| check(unsafe { ImpersonateLoggedOnUser(token) }).map(|()| f()))?
    }

    /// Runs `f` on this thread as this process, and then as the thread was
    /// again (whoever it acted as). An error where it cannot be that again:
    /// what follows must not run as the process.
    fn as_self<T>(f: impl FnOnce() -> T) -> io::Result<T> {
        let mut was: HANDLE = null_mut();
        // SAFETY: the thread's own token, opened as the process, owned by
        // the Obj below.
        let had = unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_IMPERSONATE, 1, &mut was) };
        let was = if had != 0 {
            Some(Obj {
                h: was,
                owned: true,
            })
        } else {
            let e = io::Error::last_os_error();
            if e.raw_os_error() != Some(ERROR_NO_TOKEN as i32) {
                return Err(e);
            }
            None
        };
        // SAFETY: plain call.
        check(unsafe { RevertToSelf() })?;
        let r = f();
        // SAFETY: plain calls; the thread's token opened above.
        let back = unsafe {
            RevertToSelf();
            match &was {
                Some(t) => SetThreadToken(null(), t.h),
                None => 1,
            }
        };
        check(back)?;
        Ok(r)
    }

    /// This process' token, which Windows asks for as it works out what an
    /// object inherits. Opened as the process: the account the thread acts
    /// as may not open it (the installed service's owner may not open the
    /// token of the node's account).
    fn process_token() -> io::Result<Obj> {
        let mut token: HANDLE = null_mut();
        // SAFETY: this process' own token, owned by the Obj below.
        as_self(|| {
            check(unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) })
        })??;
        Ok(Obj {
            h: token,
            owned: true,
        })
    }

    /// `sd` with only the entries of its access list that it did not
    /// inherit.
    fn explicit(sd: &Sd) -> io::Result<Sd> {
        let (mut present, mut defaulted) = (0, 0);
        let mut dacl: *mut ACL = null_mut();
        // SAFETY: a valid descriptor; `dacl` points into it.
        check(unsafe {
            GetSecurityDescriptorDacl(sd.ptr(), &mut present, &mut dacl, &mut defaulted)
        })?;
        if present == 0 || dacl.is_null() {
            return Ok(sd.clone());
        }
        let mut info = ACL_SIZE_INFORMATION::default();
        // SAFETY: a valid ACL and a buffer of the size given.
        check(unsafe {
            GetAclInformation(
                dacl,
                &mut info as *mut _ as *mut c_void,
                size_of::<ACL_SIZE_INFORMATION>() as u32,
                AclSizeInformation,
            )
        })?;
        let size = info.AclBytesInUse.max(size_of::<ACL>() as u32);
        let mut buf = vec![0u32; (size as usize).div_ceil(4)];
        let new = buf.as_mut_ptr() as *mut ACL;
        // SAFETY: the buffer holds `size` bytes.
        check(unsafe { InitializeAcl(new, size, ACL_REVISION_DS) })?;
        for ace in aces(dacl)? {
            // SAFETY: the ACE lies in `dacl` and is as long as its header
            // says; the new list has room for all of them.
            unsafe {
                if u32::from((*ace).AceFlags) & INHERITED_ACE == 0 {
                    check(AddAce(
                        new,
                        ACL_REVISION_DS,
                        u32::MAX,
                        ace as *const c_void,
                        u32::from((*ace).AceSize),
                    ))?;
                }
            }
        }
        Sd::with(sd, new, sd.control()?)
    }

    /// `sd` without the entries it inherited that allow anything to a
    /// container whose own entry on it denies everything (a folder closed
    /// to it, [`acl::closed`]). Windows does not hold a container to an
    /// entry that denies it: it checks a container's process by the entries
    /// that allow the container something, and one that inherits the grant
    /// of the folder around it may do all that grant allows (#149's first
    /// run on the service). The denial stays as the mark of the closed
    /// folder; what is below it inherits its list without the grant. Only a
    /// container of the node's kind counts ([`acl::package_sid`]): the
    /// groups all containers are in (`ALL APPLICATION PACKAGES`) keep what
    /// they inherit where another program denied them the folder.
    fn closing(sd: &Sd) -> io::Result<Sd> {
        let (mut present, mut defaulted) = (0, 0);
        let mut dacl: *mut ACL = null_mut();
        // SAFETY: a valid descriptor; `dacl` points into it.
        check(unsafe {
            GetSecurityDescriptorDacl(sd.ptr(), &mut present, &mut dacl, &mut defaulted)
        })?;
        if present == 0 || dacl.is_null() {
            return Ok(sd.clone());
        }
        let all = aces(dacl)?;
        // SAFETY: every ACE lies in `dacl`, valid while `sd` lives; an
        // allowed or denied ACE has its mask after the header and its SID
        // at SidStart.
        let sid_of = |ace: *const ACE_HEADER| unsafe {
            &raw const (*(ace as *const ACCESS_ALLOWED_ACE)).SidStart as PSID
        };
        let mut closed = Vec::new();
        for &ace in &all {
            // SAFETY: as above.
            let h = unsafe { &*ace };
            let mask = unsafe { (*(ace as *const ACCESS_ALLOWED_ACE)).Mask };
            if h.AceType == ACCESS_DENIED_ACE_TYPE
                && u32::from(h.AceFlags) & INHERITED_ACE == 0
                && mask & acl::ALL == acl::ALL
                && acl::package_sid(&sid_text(sid_of(ace))?)
            {
                closed.push(sid_of(ace));
            }
        }
        let opens = |ace: *const ACE_HEADER| {
            // SAFETY: as above.
            let h = unsafe { &*ace };
            h.AceType == ACCESS_ALLOWED_ACE_TYPE
                && u32::from(h.AceFlags) & INHERITED_ACE != 0
                // SAFETY: two valid SIDs.
                && closed.iter().any(|&c| unsafe { EqualSid(sid_of(ace), c) } != 0)
        };
        if !all.iter().any(|&a| opens(a)) {
            return Ok(sd.clone());
        }
        let mut info = ACL_SIZE_INFORMATION::default();
        // SAFETY: a valid ACL and a buffer of the size given.
        check(unsafe {
            GetAclInformation(
                dacl,
                &mut info as *mut _ as *mut c_void,
                size_of::<ACL_SIZE_INFORMATION>() as u32,
                AclSizeInformation,
            )
        })?;
        let size = info.AclBytesInUse.max(size_of::<ACL>() as u32);
        let mut buf = vec![0u32; (size as usize).div_ceil(4)];
        let new = buf.as_mut_ptr() as *mut ACL;
        // SAFETY: the buffer holds `size` bytes.
        check(unsafe { InitializeAcl(new, size, ACL_REVISION_DS) })?;
        for &ace in all.iter().filter(|&&a| !opens(a)) {
            // SAFETY: the ACE lies in `dacl` and is as long as its header
            // says; the new list has room for all of them.
            check(unsafe {
                AddAce(
                    new,
                    ACL_REVISION_DS,
                    u32::MAX,
                    ace as *const c_void,
                    u32::from((*ace).AceSize),
                )
            })?;
        }
        Sd::with(sd, new, sd.control()?)
    }

    /// `sd` with the entries it inherited from a folder whose list is
    /// `parent` marked so. A list written before Windows marked inherited
    /// entries (no SE_DACL_AUTO_INHERITED, as in folders made that way, and
    /// those below them) has them unmarked; Windows tells them by what
    /// `parent` gives, as `SetSecurityInfo` does.
    fn marked(parent: &Sd, sd: &Sd, is_dir: bool) -> io::Result<Sd> {
        if sd.control()? & SE_DACL_AUTO_INHERITED != 0 || sd.marks_inherited()? {
            return Ok(sd.clone());
        }
        let mut made: PSECURITY_DESCRIPTOR = null_mut();
        // SAFETY: two valid descriptors and an out pointer the call sets to
        // a descriptor it allocated, freed with DestroyPrivateObjectSecurity.
        check(unsafe {
            ConvertToAutoInheritPrivateObjectSecurity(
                parent.ptr(),
                sd.ptr(),
                &mut made,
                null(),
                is_dir,
                &FILE_MAPPING,
            )
        })?;
        // SAFETY: the descriptor just made, copied, then freed once.
        Ok(unsafe {
            let copy = Sd::copy(made);
            DestroyPrivateObjectSecurity(&made);
            copy
        })
    }

    /// The list of an object with the descriptor `own` (a folder:
    /// `is_dir`) in a folder whose list is `parent`: its own entries as they
    /// are, and those it inherits from `parent`, as Windows works them out
    /// for an object it makes there. `was` is the list of the folder it
    /// inherited its present entries from, by which those are told.
    fn inherited(parent: &Sd, was: &Sd, own: &Sd, is_dir: bool, token: &Obj) -> io::Result<Sd> {
        // Windows takes every entry of the descriptor it starts from as one
        // of the object's own, so only those go in.
        let own = explicit(&marked(was, own, is_dir)?)?;
        let mut made: PSECURITY_DESCRIPTOR = null_mut();
        // SAFETY: two valid descriptors, a token that may be queried, and an
        // out pointer the call sets to a descriptor it allocated, freed with
        // DestroyPrivateObjectSecurity.
        check(unsafe {
            CreatePrivateObjectSecurityEx(
                parent.ptr(),
                own.ptr(),
                &mut made,
                null(),
                i32::from(is_dir),
                SEF_DACL_AUTO_INHERIT | SEF_AVOID_OWNER_CHECK | SEF_AVOID_PRIVILEGE_CHECK,
                token.h,
                &FILE_MAPPING,
            )
        })?;
        // SAFETY: the descriptor just made, copied, then freed once.
        let made = unsafe {
            let copy = Sd::copy(made);
            DestroyPrivateObjectSecurity(&made);
            copy
        };
        closing(&made)
    }

    /// The list of the folder the object open as `f` is in now, by its
    /// final path; `None` for the root of a volume, or where it cannot be
    /// read.
    fn parent_list(f: &std::fs::File) -> Option<Sd> {
        let now = final_path(f).ok()?;
        let parent = open(now.parent()?, READ_CONTROL).ok()?;
        Sd::of(parent.as_raw_handle()).ok()
    }

    /// A folder's list as the walk passes it down: as it is to be, and as
    /// it was, by which what is below it tells what it inherited.
    #[derive(Clone)]
    struct Lists {
        new: Sd,
        was: Sd,
    }

    impl Objects for Volume {
        type Obj = Obj;
        type List = Lists;

        fn entries(&mut self, dir: &Obj) -> io::Result<Vec<inherit::Entry>> {
            match list_dir(dir, true) {
                // A volume that gives no file IDs in a listing (a share,
                // say): by name alone.
                Err(e)
                    if [
                        ERROR_INVALID_PARAMETER,
                        ERROR_NOT_SUPPORTED,
                        ERROR_INVALID_LEVEL,
                    ]
                    .iter()
                    .any(|c| e.raw_os_error() == Some(*c as i32)) =>
                {
                    list_dir(dir, false)
                }
                r => r,
            }
        }

        fn open(&mut self, dir: &Obj, name: &OsStr) -> io::Result<Option<Obj>> {
            let name: Vec<u16> = name.encode_wide().collect();
            let access = READ_CONTROL | FILE_READ_ATTRIBUTES;
            // A file a command linked in from its own store (pnpm's, uv's,
            // in its profile) keeps the store's list under every name, so
            // the thread may not even look at it: opened as its maker then
            // ([`Below::maker`]), as for a write.
            match open_in(dir.h, &name, access) {
                Err(e) if e.raw_os_error() == Some(ERROR_ACCESS_DENIED as i32) => {
                    match self.maker {
                        Some(t) => as_token(t, || open_in(dir.h, &name, access))?,
                        None => Err(e),
                    }
                }
                r => r,
            }
        }

        fn kind(&mut self, obj: &Obj) -> io::Result<Kind> {
            let mut tag = FILE_ATTRIBUTE_TAG_INFO::default();
            let mut standard = FILE_STANDARD_INFO::default();
            // SAFETY: an open handle and buffers of the sizes given.
            unsafe {
                check(GetFileInformationByHandleEx(
                    obj.h,
                    FileAttributeTagInfo,
                    &mut tag as *mut _ as *mut c_void,
                    size_of::<FILE_ATTRIBUTE_TAG_INFO>() as u32,
                ))?;
                check(GetFileInformationByHandleEx(
                    obj.h,
                    FileStandardInfo,
                    &mut standard as *mut _ as *mut c_void,
                    size_of::<FILE_STANDARD_INFO>() as u32,
                ))?;
            }
            let reparse = tag.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0;
            Ok(Kind {
                folder: tag.FileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0,
                link: reparse && tag.ReparseTag & NAME_SURROGATE != 0,
                names: standard.NumberOfLinks,
            })
        }

        fn derive(&mut self, parent: &Lists, obj: &Obj, kind: &Kind) -> io::Result<Derived<Lists>> {
            let now = Sd::of(obj.h)?;
            if now.control()? & SE_DACL_PROTECTED != 0 {
                return Ok(Derived::Kept);
            }
            let new = inherited(&parent.new, &parent.was, &now, kind.folder, &self.token)?;
            Ok(if same_list(&now.entries()?, &new.entries()?) {
                Derived::Same(Lists {
                    new: now.clone(),
                    was: now,
                })
            } else {
                Derived::Changed(Lists { new, was: now })
            })
        }

        fn write(&mut self, obj: &Obj, list: &Lists) -> io::Result<()> {
            let list = &list.new;
            // Opened for the change only now, on the same object: one the
            // node may read but not change stops a walk only where its list
            // changes. One the thread may not change is opened as its
            // maker where one is given ([`Below::maker`]).
            let w = match open_in(obj.h, &[], WRITE_DAC) {
                Err(e) if e.raw_os_error() == Some(ERROR_ACCESS_DENIED as i32) => {
                    match self.maker {
                        Some(t) => as_token(t, || open_in(obj.h, &[], WRITE_DAC))??,
                        None => return Err(e),
                    }
                }
                r => r?,
            };
            let Some(w) = w else {
                return Err(io::ErrorKind::NotFound.into());
            };
            list.write(w.h)
        }

        fn names_of(&mut self, obj: &Obj) -> io::Result<Vec<PathBuf>> {
            // By 128-bit IDs where the volume gives them (ReFS); NTFS gives
            // 64-bit ones only, which are the low half of its 128-bit IDs.
            let (buf, full) = match link_info(obj.h, FileHardLinkFullIdInformation) {
                Err(s)
                    if [
                        STATUS_INVALID_PARAMETER,
                        STATUS_INVALID_INFO_CLASS,
                        STATUS_NOT_SUPPORTED,
                    ]
                    .contains(&s) =>
                {
                    (
                        link_info(obj.h, FileHardLinkInformation).map_err(nt_error)?,
                        false,
                    )
                }
                r => (r.map_err(nt_error)?, true),
            };
            let mut out = Vec::new();
            // SAFETY: Windows filled the buffer: a header, then entries of
            // the class asked for, each at the offset the one before gives,
            // with its name after its fields.
            unsafe {
                let (count, mut at) = if full {
                    let head = buf.as_ptr() as *const FILE_LINKS_FULL_ID_INFORMATION;
                    (
                        (*head).EntriesReturned,
                        &raw const (*head).Entry as *const u8,
                    )
                } else {
                    let head = buf.as_ptr() as *const FILE_LINKS_INFORMATION;
                    (
                        (*head).EntriesReturned,
                        &raw const (*head).Entry as *const u8,
                    )
                };
                for _ in 0..count {
                    let (next, parent, name) = if full {
                        let e = at as *const FILE_LINK_ENTRY_FULL_ID_INFORMATION;
                        let len = (*e).FileNameLength as usize;
                        let name =
                            std::slice::from_raw_parts(&raw const (*e).FileName as *const u16, len);
                        ((*e).NextEntryOffset, (*e).ParentFileId.Identifier, name)
                    } else {
                        let e = at as *const FILE_LINK_ENTRY_INFORMATION;
                        let len = (*e).FileNameLength as usize;
                        let name =
                            std::slice::from_raw_parts(&raw const (*e).FileName as *const u16, len);
                        let mut id = [0u8; 16];
                        id[..8].copy_from_slice(&(*e).ParentFileId.to_le_bytes());
                        ((*e).NextEntryOffset, id, name)
                    };
                    // A folder the thread may not open may be the command
                    // account's (its profile, where pnpm and uv keep what
                    // they link): opened as its maker then. One neither may
                    // open is left out.
                    let folder = match folder_by_id(obj.h, parent) {
                        Err(e) if e.raw_os_error() == Some(ERROR_ACCESS_DENIED as i32) => {
                            match self.maker {
                                Some(t) => as_token(t, || folder_by_id(obj.h, parent))?,
                                None => Err(e),
                            }
                        }
                        r => r,
                    };
                    match folder {
                        Ok(folder) => out.push(folder.join(std::ffi::OsString::from_wide(name))),
                        Err(e) if e.raw_os_error() == Some(ERROR_ACCESS_DENIED as i32) => {}
                        Err(e) => return Err(e),
                    }
                    if next == 0 {
                        break;
                    }
                    at = at.add(next as usize);
                }
            }
            Ok(out)
        }

        fn owner(&mut self, obj: &Obj) -> io::Result<Option<String>> {
            Sd::of(obj.h)?.owner()
        }

        fn cap(
            &mut self,
            obj: &Obj,
            derived: Derived<Lists>,
            linked: &Linked,
        ) -> io::Result<Derived<Lists>> {
            let lists = match derived {
                Derived::Kept => return Ok(Derived::Kept),
                Derived::Same(l) | Derived::Changed(l) => l,
            };
            let now = Sd::of(obj.h)?;
            // A capped file keeps the list it has: the entries it inherited
            // under its other names' folders (a store's, a cache's, a
            // source repository's) and those of every account but the
            // containers stay as they are. The list worked out under the
            // folder walked would give the file that folder's entries for
            // everyone, under every name. The node's own entries come from
            // the grants alone ([`acl::capped`]). A file that changes as any
            // file gets the folder's list.
            let base = match linked {
                Linked::Capped(_) => &now,
                Linked::Full(_) => &lists.new,
            };
            let reader = self.reader(obj, linked)?;
            let new = capped(base, linked, reader.as_deref())?;
            Ok(if same_list(&new.entries()?, &now.entries()?) {
                Derived::Same(Lists {
                    new: now.clone(),
                    was: now,
                })
            } else {
                Derived::Changed(Lists { new, was: now })
            })
        }
    }

    /// `sd` as `linked` says, the list of a file with more than one name:
    /// with no more than its cap allows the AppContainers
    /// ([`acl::capped`]), and read for `reader` where one is given
    /// ([`acl::readable_by`]), or without the node's own entries of an
    /// earlier cap ([`acl::uncapped`]).
    fn capped(sd: &Sd, linked: &Linked, reader: Option<&str>) -> io::Result<Sd> {
        let (mut present, mut defaulted) = (0, 0);
        let mut dacl: *mut ACL = null_mut();
        // SAFETY: a valid descriptor; `dacl` points into it.
        check(unsafe {
            GetSecurityDescriptorDacl(sd.ptr(), &mut present, &mut dacl, &mut defaulted)
        })?;
        if present == 0 || dacl.is_null() {
            // No list lets everyone in; the node gives it none (`next`).
            return Err(io::Error::other(
                "it has more than one name and no access list, so everyone may open it; the node does not give it one",
            ));
        }
        let old = aces(dacl)?;
        let mut list = Vec::with_capacity(old.len());
        for &ace in &old {
            // SAFETY: every ACE starts with its header and has its mask
            // right after it; the kinds below have their SID after the mask.
            let (kind, flags, mask) = unsafe {
                let a = ace as *const ACCESS_ALLOWED_ACE;
                ((*ace).AceType, (*ace).AceFlags, (*a).Mask)
            };
            let sid = match kind {
                0 | 1 | 9 | 10 => {
                    // SAFETY: as above.
                    let p = unsafe { &raw const (*(ace as *const ACCESS_ALLOWED_ACE)).SidStart };
                    Some(sid_text(p as PSID)?)
                }
                _ => None,
            };
            list.push(acl::Ace {
                kind,
                flags,
                mask,
                sid,
            });
        }
        let names: Vec<&String> = match linked {
            Linked::Full(listed) => listed.iter().collect(),
            Linked::Capped(cap) => cap.containers.iter().map(|(name, _)| name).collect(),
        };
        let sids: Vec<Sid> = names
            .iter()
            .map(|name| Sid::derive(name))
            .collect::<io::Result<_>>()?;
        let texts: Vec<String> = sids
            .iter()
            .map(|sid| sid_text(sid.0))
            .collect::<io::Result<_>>()?;
        let out = match linked {
            Linked::Full(_) => {
                let out = acl::uncapped(&list, &texts);
                // Nothing of the node's: the list as it is.
                if out.len() == list.len() {
                    return Ok(sd.clone());
                }
                out
            }
            Linked::Capped(cap) => {
                let caps: Vec<(String, inherit::Gets)> = texts
                    .into_iter()
                    .zip(&cap.containers)
                    .map(|(sid, (_, g))| (sid, *g))
                    .collect();
                let out = acl::capped(&list, &caps);
                match reader {
                    Some(r) => acl::readable_by(out, &list, r),
                    None => out,
                }
            }
        };
        let reader = reader.map(Sid::derive).transpose()?;
        let mut size = size_of::<ACL>() as u32;
        for e in &out {
            size += match *e {
                // SAFETY: an ACE of the old list, as long as its header says.
                acl::Capped::Entry(i, _) => u32::from(unsafe { (*old[i]).AceSize }),
                // SAFETY: a valid SID.
                acl::Capped::Deny(j, _) | acl::Capped::Allow(j, _) => {
                    size_of::<ACCESS_ALLOWED_ACE>() as u32 - 4 + unsafe { GetLengthSid(sids[j].0) }
                }
                acl::Capped::Reads => {
                    let r = reader
                        .as_ref()
                        .ok_or_else(|| io::Error::other("no reader"))?;
                    // SAFETY: a valid SID.
                    size_of::<ACCESS_ALLOWED_ACE>() as u32 - 4 + unsafe { GetLengthSid(r.0) }
                }
            };
        }
        let mut buf = vec![0u32; (size as usize).div_ceil(4)];
        let new = buf.as_mut_ptr() as *mut ACL;
        // SAFETY: the buffer holds `size` bytes.
        check(unsafe { InitializeAcl(new, size, ACL_REVISION_DS) })?;
        for e in out {
            match e {
                acl::Capped::Entry(i, mask) => {
                    // SAFETY: the ACE lies in `dacl`, as long as its header
                    // says, with its mask right after the header.
                    let mut bytes = unsafe {
                        std::slice::from_raw_parts(
                            old[i] as *const u8,
                            usize::from((*old[i]).AceSize),
                        )
                    }
                    .to_vec();
                    bytes[4..8].copy_from_slice(&mask.to_le_bytes());
                    // SAFETY: a whole ACE, and room for it in the new list.
                    check(unsafe {
                        AddAce(
                            new,
                            ACL_REVISION_DS,
                            u32::MAX,
                            bytes.as_ptr() as *const c_void,
                            bytes.len() as u32,
                        )
                    })?;
                }
                acl::Capped::Deny(j, mask) => {
                    // SAFETY: the list has room for it.
                    check(unsafe {
                        AddAccessDeniedAceEx(new, ACL_REVISION_DS, 0, mask, sids[j].0)
                    })?;
                }
                acl::Capped::Allow(j, mask) => {
                    // SAFETY: the list has room for it.
                    check(unsafe {
                        AddAccessAllowedAceEx(new, ACL_REVISION_DS, 0, mask, sids[j].0)
                    })?;
                }
                acl::Capped::Reads => {
                    let r = reader
                        .as_ref()
                        .ok_or_else(|| io::Error::other("no reader"))?;
                    // SAFETY: the list has room for it.
                    check(unsafe {
                        AddAccessAllowedAceEx(new, ACL_REVISION_DS, 0, acl::READ_AND_EXECUTE, r.0)
                    })?;
                }
            }
        }
        Sd::with(sd, new, sd.control()?)
    }

    /// The names (hard links) of the object open as `h`, as Windows gives
    /// them in `class`; the NTSTATUS where it does not.
    fn link_info(h: HANDLE, class: i32) -> Result<Vec<u64>, NTSTATUS> {
        let mut buf = vec![0u64; 512];
        loop {
            let mut status_block = IO_STATUS_BLOCK::default();
            // SAFETY: an open handle and a buffer of the size given.
            let status = unsafe {
                NtQueryInformationFile(
                    h,
                    &mut status_block,
                    buf.as_mut_ptr() as *mut c_void,
                    (buf.len() * 8) as u32,
                    class,
                )
            };
            if status == STATUS_BUFFER_OVERFLOW || status == STATUS_BUFFER_TOO_SMALL {
                // SAFETY: the buffer starts with a header of either class,
                // which says how much it needs.
                let need =
                    unsafe { (*(buf.as_ptr() as *const FILE_LINKS_INFORMATION)).BytesNeeded };
                let len = (need as usize).div_ceil(8).max(buf.len() * 2);
                buf.resize(len, 0);
                continue;
            }
            if status < 0 {
                return Err(status);
            }
            return Ok(buf);
        }
    }

    /// The entries of the folder open as `dir`, with their file IDs
    /// (`ids`), or by name alone.
    fn list_dir(dir: &Obj, ids: bool) -> io::Result<Vec<inherit::Entry>> {
        let Some(list) = open_in(dir.h, &[], FILE_LIST_DIRECTORY)? else {
            return Err(io::ErrorKind::NotFound.into());
        };
        let class = if ids {
            FileIdExtdDirectoryInfo
        } else {
            FileFullDirectoryInfo
        };
        let mut buf = vec![0u64; 8 * 1024];
        let mut out = Vec::new();
        loop {
            // SAFETY: a handle that may list the folder, and a buffer of the
            // size given.
            let ok = unsafe {
                GetFileInformationByHandleEx(
                    list.h,
                    class,
                    buf.as_mut_ptr() as *mut c_void,
                    (buf.len() * 8) as u32,
                )
            };
            if ok == 0 {
                let e = io::Error::last_os_error();
                if e.raw_os_error() == Some(ERROR_NO_MORE_FILES as i32) {
                    return Ok(out);
                }
                return Err(e);
            }
            let mut at = 0usize;
            loop {
                // SAFETY: Windows filled the buffer with entries of `class`,
                // each at the offset the one before gives and aligned for it,
                // with its name right after its fields.
                let (next, name, id) = unsafe {
                    let base = (buf.as_ptr() as *const u8).add(at);
                    if ids {
                        let e = base as *const FILE_ID_EXTD_DIR_INFO;
                        let len = (*e).FileNameLength as usize / 2;
                        let name =
                            std::slice::from_raw_parts(&raw const (*e).FileName as *const u16, len);
                        let id = Some((*e).FileId.Identifier);
                        ((*e).NextEntryOffset as usize, name, id)
                    } else {
                        let e = base as *const FILE_FULL_DIR_INFO;
                        let len = (*e).FileNameLength as usize / 2;
                        let name =
                            std::slice::from_raw_parts(&raw const (*e).FileName as *const u16, len);
                        ((*e).NextEntryOffset as usize, name, None)
                    }
                };
                let dot = u16::from(b'.');
                if name != [dot] && name != [dot, dot] {
                    out.push((std::ffi::OsString::from_wide(name), id));
                }
                if next == 0 {
                    break;
                }
                at += next;
            }
        }
    }

    /// The path of the folder with the file ID `id`, on the volume of the
    /// object open as `near`, without the `\\?\` prefix.
    fn folder_by_id(near: HANDLE, id: [u8; 16]) -> io::Result<PathBuf> {
        let desc = FILE_ID_DESCRIPTOR {
            dwSize: size_of::<FILE_ID_DESCRIPTOR>() as u32,
            Type: ExtendedFileIdType,
            Anonymous: FILE_ID_DESCRIPTOR_0 {
                ExtendedFileId: FILE_ID_128 { Identifier: id },
            },
        };
        // SAFETY: a handle on the volume and a valid descriptor; the handle
        // returned is owned by the File below.
        let h = unsafe {
            OpenFileById(
                near,
                &desc,
                FILE_READ_ATTRIBUTES,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                null(),
                FILE_FLAG_BACKUP_SEMANTICS,
            )
        };
        if h == INVALID_HANDLE_VALUE {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: a handle this function owns.
        let f = unsafe { std::fs::File::from_raw_handle(h) };
        let p = final_path(&f)?;
        Ok(plain(p.as_os_str().encode_wide().collect()))
    }

    /// The list of the object open as `f` with the grants of `masks` for
    /// `sid` in place of those it had (`None`: without any), as [`set`]
    /// puts it on.
    struct Next {
        sd: Sd,
        /// The list it has now.
        was: Sd,
        is_dir: bool,
        /// Its list does not inherit.
        protected: bool,
        /// Its entries change.
        changed: bool,
    }

    fn next(f: &std::fs::File, sid: &Sid, masks: Option<Masks>) -> io::Result<Next> {
        let is_dir = f.metadata()?.is_dir();
        let now = Sd::of(f.as_raw_handle())?;
        let (mut present, mut defaulted) = (0, 0);
        let mut dacl: *mut ACL = null_mut();
        // SAFETY: a valid descriptor; `dacl` points into it, valid while
        // `now` lives.
        check(unsafe {
            GetSecurityDescriptorDacl(now.ptr(), &mut present, &mut dacl, &mut defaulted)
        })?;
        if present == 0 || dacl.is_null() {
            return Err(io::Error::other(
                "it has no access list, so everyone may open it; the node does not give it one",
            ));
        }
        let control = now.control()?;
        let mut info = ACL_SIZE_INFORMATION::default();
        // SAFETY: a valid ACL and a buffer of the size given.
        check(unsafe {
            GetAclInformation(
                dacl,
                &mut info as *mut _ as *mut c_void,
                size_of::<ACL_SIZE_INFORMATION>() as u32,
                AclSizeInformation,
            )
        })?;
        let add = masks.map(|m| entries(is_dir, m)).unwrap_or_default();
        // SAFETY: a valid SID.
        let sid_len = unsafe { GetLengthSid(sid.0) };
        let ace_len = size_of::<ACCESS_ALLOWED_ACE>() as u32 - 4 + sid_len;
        let size = info.AclBytesInUse + add.len() as u32 * ace_len;
        // u32s, since an ACL is aligned to them.
        let mut buf = vec![0u32; (size as usize).div_ceil(4)];
        let new = buf.as_mut_ptr() as *mut ACL;
        // SAFETY: the buffer holds `size` bytes.
        check(unsafe { InitializeAcl(new, size, ACL_REVISION_DS) })?;
        let old = aces(dacl)?;
        // SAFETY: every ACE starts with its header.
        let inherited_ace =
            |ace: *const ACE_HEADER| u32::from(unsafe { (*ace).AceFlags }) & INHERITED_ACE != 0;
        let copy = |ace: *const ACE_HEADER| {
            // SAFETY: the ACE and its size come from the old list, and the
            // new one has room for all of them.
            check(unsafe {
                AddAce(
                    new,
                    ACL_REVISION_DS,
                    u32::MAX,
                    ace as *const c_void,
                    u32::from((*ace).AceSize),
                )
            })
        };
        // A denial comes before every entry: Windows decides by the first
        // entry that names the asker.
        let deny = masks.is_some_and(|m| m.deny);
        if deny {
            for (flags, mask) in &add {
                // SAFETY: the list has room for each of these ACEs.
                check(unsafe { AddAccessDeniedAceEx(new, ACL_REVISION_DS, *flags, *mask, sid.0) })?;
            }
        }
        // Its own entries but the container's, then the container's new
        // ones, then the inherited entries, as Windows keeps a list's own
        // entries before those it inherited.
        for &ace in old.iter().filter(|a| !inherited_ace(**a)) {
            // SAFETY: the ACE lies in `dacl`, valid while `now` lives.
            let plain = matches!(
                unsafe { (*ace).AceType },
                ACCESS_ALLOWED_ACE_TYPE | ACCESS_DENIED_ACE_TYPE
            );
            // SAFETY: an allowed or denied ACE has its SID at SidStart.
            let ours = plain
                && unsafe {
                    let a = ace as *const ACCESS_ALLOWED_ACE;
                    EqualSid(&raw const (*a).SidStart as PSID, sid.0) != 0
                };
            if !ours {
                copy(ace)?;
            }
        }
        for (flags, mask) in add.into_iter().filter(|_| !deny) {
            // SAFETY: the list has room for each of these ACEs.
            check(unsafe { AddAccessAllowedAceEx(new, ACL_REVISION_DS, flags, mask, sid.0) })?;
        }
        for &ace in old.iter().filter(|a| inherited_ace(**a)) {
            copy(ace)?;
        }
        let mut sd = Sd::with(&now, new, control)?;
        // The inherited entries as Windows works them out from the folder it
        // is in now, as SetSecurityInfo does: a folder moved here from a
        // granted one keeps that one's entries until its list is written
        // so. Where that folder cannot be read, they stay as they are.
        let protected = control & SE_DACL_PROTECTED != 0;
        if !protected && let Some(parent) = parent_list(f) {
            sd = inherited(&parent, &parent, &sd, is_dir, &process_token()?)?;
        }
        // The same entries in another order are the list it has: a grant
        // put on again keeps its place, and the walk below derives from the
        // order the objects there inherited.
        let changed = !same_list(&sd.entries()?, &Some(ace_bytes(dacl)?));
        if !changed {
            sd = now.clone();
        }
        Ok(Next {
            changed,
            sd,
            was: now.clone(),
            is_dir,
            protected,
        })
    }

    /// What a change of a grant asks of what it reaches below its folder.
    pub struct Below<'a> {
        /// What a file with more than one name (hard links) gets
        /// ([`Walk::links`]); `None`: it changes as any file.
        pub links: Option<inherit::Links<'a>>,
        /// Told how far the change is, now and then.
        pub progress: &'a mut dyn FnMut(Walked),
        /// A logon token of the account commands run as, which owns what
        /// they make: a list below the folder the thread may not change is
        /// changed as that account, which as its owner may. Outside your
        /// profile Windows gives you no right to change the list of a file
        /// another account made (#149).
        pub maker: Option<HANDLE>,
    }

    /// Passes the list `next` of the folder open as `f` (at `path`) down
    /// ([`inherit::pass_down`]), into every folder with `every`, and
    /// writes it on the folder last with `write_top`.
    fn pass(
        f: &std::fs::File,
        path: &Path,
        next: &Next,
        write_top: bool,
        every: bool,
        below: Below,
    ) -> io::Result<Walked> {
        let mut volume = Volume::new()?;
        volume.maker = below.maker;
        let top = Obj {
            h: f.as_raw_handle(),
            owned: false,
        };
        let lists = Lists {
            new: next.sd.clone(),
            was: next.was.clone(),
        };
        inherit::pass_down(
            &mut volume,
            top,
            lists,
            path,
            write_top,
            Walk {
                write: true,
                every,
                links: below.links,
                progress: below.progress,
            },
        )
    }

    /// Puts the grants of `masks` for the container `name` on `path`, in
    /// place of any it had (`None` takes them off). Other entries of the
    /// access list stay as they are. [`set_below`] without its checks.
    pub fn set(
        path: &Path,
        name: &str,
        masks: Option<Masks>,
        own: bool,
    ) -> io::Result<Option<FileId>> {
        let below = Below {
            links: None,
            progress: &mut |_| {},
            maker: None,
        };
        set_below(path, name, masks, own, false, None, below).map(|(id, _)| id)
    }

    /// Puts the grants of `masks` for the container `name` on `path`, in
    /// place of any it had (`None` takes them off). They are inherited by
    /// everything below `path`, and the change passes down to what is there
    /// now as far as it changes something ([`inherit`]), before the list of
    /// `path` itself is written. Other entries of the access list stay as
    /// they are.
    ///
    /// With `own`, grants go on only an object of its own at `path`: none
    /// on a link or junction to elsewhere, on a file with other names, or on
    /// one whose list does not inherit. A command may have put what is
    /// there, where it may write; the grant would then reach what it
    /// leads to. A refusal is InvalidInput, and changes nothing. The
    /// [`FileId`] of the object it changed, as its handle names it, when
    /// the volume names one, and how far the change went below it.
    ///
    /// A file with more than one name, `path` itself or one below it, gets
    /// what `below.links` says ([`inherit::pass_down`]).
    ///
    /// With `whole`, the change goes into every folder below, also where
    /// the list of `path` stays as it is: an earlier change there may have
    /// stopped part way, and the folders above what it changed do not show
    /// that. Taking grants off always does.
    ///
    /// With `expect`, the change goes only through that object: one at
    /// `path` that is another, or nothing there (the folder was replaced or
    /// moved since its id was recorded), is refused before anything is
    /// written, so the record and the object a change wrote always agree.
    pub fn set_below(
        path: &Path,
        name: &str,
        masks: Option<Masks>,
        own: bool,
        whole: bool,
        expect: Option<FileId>,
        mut below: Below,
    ) -> io::Result<(Option<FileId>, Walked)> {
        let sid = Sid::derive(name)?;
        let refuse = |why: String| {
            Err(acl::untouched(
                acl::Untouched::Refused,
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("the node puts no grant on it, since {why}"),
                ),
            ))
        };
        // The change goes through this handle, on the object it opened. One
        // the thread may not change is opened as its maker, as below it
        // ([`Below::maker`]): a folder commands made outside your profile.
        // The checks below hold for what that opened as well.
        let access = READ_CONTROL | WRITE_DAC | FILE_READ_ATTRIBUTES;
        let opened = match open(path, access) {
            Err(e) if e.raw_os_error() == Some(ERROR_ACCESS_DENIED as i32) => match below.maker {
                Some(t) => as_token(t, || open(path, access))?,
                None => Err(e),
            },
            r => r,
        };
        let f = match opened {
            Ok(f) => f,
            // The recorded object is not at the path (moved away meanwhile):
            // not "nothing there" for the record, which the next sync finds
            // again where it went.
            Err(e) if expect.is_some() && e.kind() == io::ErrorKind::NotFound => {
                return refuse(
                    "the folder recorded for it is not there now (it was moved meanwhile); the next sync looks again".into(),
                );
            }
            Err(e) => return Err(gone(e)),
        };
        if let Some(want) = expect
            && id_of(&f).ok() != Some(want)
        {
            return refuse(
                "it is another folder than the one recorded (it was replaced meanwhile); the next sync looks again".into(),
            );
        }
        if own
            && masks.is_some()
            && let Some(why) = not_own(&f, path)?
        {
            return refuse(why);
        }
        let mut next = next(&f, &sid, masks)?;
        if own && masks.is_some() && next.protected {
            return refuse("its permissions do not inherit from its folder".into());
        }
        // A granted file with more than one name, as one below a folder.
        // Whether its list inherits does not matter: the cap works on the
        // entries it has, so a file the owner linked from a protected list
        // (an SSH key) gets the cap too, not the grant's own entry.
        if !next.is_dir
            && let Some(links) = below.links.as_mut()
        {
            let top = Obj {
                h: f.as_raw_handle(),
                owned: false,
            };
            let mut volume = Volume::new()?;
            volume.maker = below.maker;
            let names = volume.kind(&top)?.names;
            if names > 1 {
                let owner = next.was.owner()?;
                let linked = links(path, names, &volume.names_of(&top)?, owner.as_deref())?;
                // As below a folder (`Volume::cap`): a cap works from the
                // list the file has, not the one its folder would give it.
                let base = match linked {
                    Linked::Capped(_) => &next.was,
                    Linked::Full(_) => &next.sd,
                };
                let reader = volume.reader(&top, &linked)?;
                next.sd = capped(base, &linked, reader.as_deref())?;
                next.changed = !same_list(&next.sd.entries()?, &next.was.entries()?);
            }
        }
        let every = masks.is_none() || whole;
        let mut walked = Walked::default();
        if next.is_dir && (next.changed || every) {
            // The walk writes the list of `path` itself last.
            walked = pass(&f, path, &next, next.changed, every, below)?;
        } else if next.changed {
            next.sd.write(f.as_raw_handle())?;
        }
        Ok((id_of(&f).ok(), walked))
    }

    /// `e`, marked as nothing at the path where it says so.
    fn gone(e: io::Error) -> io::Error {
        if e.kind() == io::ErrorKind::NotFound {
            acl::untouched(acl::Untouched::Gone, e)
        } else {
            e
        }
    }

    /// HRESULTs of the profile calls.
    const ALREADY_EXISTS: i32 = 0x8007_00B7_u32 as i32;
    const NOT_FOUND: [i32; 2] = [0x8007_0002_u32 as i32, 0x8007_0490_u32 as i32];

    /// Makes the profile of the container `name` for the user this process
    /// runs as, unless it has one: Windows starts no process in a container
    /// without one. It is a registry key and a folder below
    /// `%LOCALAPPDATA%\Packages`, which only the container and the user
    /// reach; [`remove_profile`] takes it away.
    fn ensure_profile(name: &str) -> io::Result<()> {
        let n = wide(OsStr::new(name));
        let mut sid: PSID = null_mut();
        // SAFETY: NUL-terminated strings, no capabilities, and an out
        // pointer the call fills with a SID it allocated.
        let hr = unsafe {
            CreateAppContainerProfile(n.as_ptr(), n.as_ptr(), n.as_ptr(), null(), 0, &mut sid)
        };
        if !sid.is_null() {
            // SAFETY: the SID came from CreateAppContainerProfile.
            unsafe { FreeSid(sid) };
        }
        if hr < 0 && hr != ALREADY_EXISTS {
            return Err(io::Error::other(format!(
                "cannot make the AppContainer profile {name} ({hr:#x})"
            )));
        }
        Ok(())
    }

    #[link(name = "ole32")]
    unsafe extern "system" {
        fn CoTaskMemFree(p: *const c_void);
    }

    /// The container `name` made ready for a command of the user this
    /// process runs as: its profile ([`ensure_profile`]) and the folders of
    /// its home in it ([`acl::container_home`]). Its own folder, `AC`.
    pub fn ready(name: &str) -> io::Result<PathBuf> {
        ensure_profile(name)?;
        let sid = Sid::derive(name)?;
        let text = wide(OsStr::new(&sid_text(sid.0)?));
        let mut at: *mut u16 = null_mut();
        // SAFETY: a NUL-terminated SID string; the call allocates the path,
        // freed below with CoTaskMemFree.
        let hr = unsafe {
            windows_sys::Win32::Security::Isolation::GetAppContainerFolderPath(
                text.as_ptr(),
                &mut at,
            )
        };
        if hr < 0 || at.is_null() {
            return Err(io::Error::other(format!(
                "cannot find the folder of the AppContainer {name} ({hr:#x})"
            )));
        }
        // SAFETY: a NUL-terminated string from the call, freed once.
        let ac = unsafe {
            let len = (0..).take_while(|&i| *at.add(i) != 0).count();
            let p = PathBuf::from(std::ffi::OsString::from_wide(std::slice::from_raw_parts(
                at, len,
            )));
            CoTaskMemFree(at.cast());
            p
        };
        std::fs::create_dir_all(ac.join("home").join("AppData").join("Roaming"))?;
        Ok(ac)
    }

    /// Takes the profile of the container `name` away from the user this
    /// process runs as; one that is not there is fine.
    pub fn remove_profile(name: &str) -> io::Result<()> {
        let n = wide(OsStr::new(name));
        // SAFETY: a NUL-terminated name.
        let hr = unsafe { DeleteAppContainerProfile(n.as_ptr()) };
        if hr < 0 && !NOT_FOUND.contains(&hr) {
            return Err(io::Error::other(format!(
                "cannot remove the AppContainer profile {name} ({hr:#x})"
            )));
        }
        Ok(())
    }

    /// A capability SID in a buffer of its own.
    fn capability(kind: i32) -> io::Result<Vec<u8>> {
        let mut buf = vec![0u8; 68]; // SECURITY_MAX_SID_SIZE
        let mut len = buf.len() as u32;
        // SAFETY: a buffer of `len` bytes for the SID.
        check(unsafe { CreateWellKnownSid(kind, null_mut(), buf.as_mut_ptr() as PSID, &mut len) })?;
        Ok(buf)
    }

    /// `program` as CreateProcessW takes it: a full path. A bare name is
    /// looked for on `PATH`, with `.exe` when it has no extension.
    fn find(program: &Path) -> io::Result<PathBuf> {
        if program.components().count() > 1 {
            return Ok(program.to_path_buf());
        }
        let name = if program.extension().is_some() {
            program.to_path_buf()
        } else {
            program.with_extension("exe")
        };
        std::env::var_os("PATH")
            .iter()
            .flat_map(std::env::split_paths)
            .map(|d| d.join(&name))
            .find(|p| p.is_file())
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("{} is not on PATH", name.display()),
                )
            })
    }

    #[link(name = "user32")]
    unsafe extern "system" {
        fn CreateWindowStationW(
            name: *const u16,
            flags: u32,
            access: u32,
            sa: *const SECURITY_ATTRIBUTES,
        ) -> HANDLE;
        fn GetProcessWindowStation() -> HANDLE;
        fn SetProcessWindowStation(station: HANDLE) -> i32;
        fn CreateDesktopW(
            name: *const u16,
            device: *const u16,
            mode: *const c_void,
            flags: u32,
            access: u32,
            sa: *const SECURITY_ATTRIBUTES,
        ) -> HANDLE;
        fn CloseDesktop(desktop: HANDLE) -> i32;
        fn CloseWindowStation(station: HANDLE) -> i32;
        fn GetUserObjectInformationW(
            obj: HANDLE,
            index: i32,
            info: *mut c_void,
            len: u32,
            need: *mut u32,
        ) -> i32;
    }

    /// The SID as text (`S-1-...`).
    fn sid_text(sid: PSID) -> io::Result<String> {
        let mut text: *mut u16 = null_mut();
        // SAFETY: a valid SID; the call allocates the string, freed below.
        check(unsafe { ConvertSidToStringSidW(sid, &mut text) })?;
        let _text = Local(text as *mut c_void);
        // SAFETY: a NUL-terminated wide string.
        let len = (0..).take_while(|&i| unsafe { *text.add(i) } != 0).count();
        let wide = unsafe { std::slice::from_raw_parts(text, len) };
        Ok(String::from_utf16_lossy(wide))
    }

    /// This process's token, closed when dropped.
    struct Token(HANDLE);

    impl Token {
        fn open() -> io::Result<Token> {
            let mut token: HANDLE = null_mut();
            // SAFETY: this process's pseudo handle and an out pointer.
            check(unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) })?;
            Ok(Token(token))
        }
    }

    impl Drop for Token {
        fn drop(&mut self) {
            // SAFETY: opened in `open`, closed once.
            unsafe { CloseHandle(self.0) };
        }
    }

    /// The SID of the user this process runs as, as text.
    fn user_sid() -> io::Result<String> {
        let token = Token::open()?;
        token_user(&token)
    }

    /// The SID of the account this thread acts as (whom it impersonates,
    /// else this process' user), as text.
    fn acting_sid() -> io::Result<String> {
        let mut h: HANDLE = null_mut();
        // SAFETY: the thread's own token, opened as the process, closed by
        // the Token below.
        if unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1, &mut h) } == 0 {
            let e = io::Error::last_os_error();
            if e.raw_os_error() != Some(ERROR_NO_TOKEN as i32) {
                return Err(e);
            }
            return user_sid();
        }
        token_user(&Token(h))
    }

    /// The user of `token`, as text.
    fn token_user(token: &Token) -> io::Result<String> {
        let mut len = 0u32;
        // SAFETY: the first call asks for the size only.
        unsafe { GetTokenInformation(token.0, TokenUser, null_mut(), 0, &mut len) };
        let mut buf = vec![0usize; (len as usize).div_ceil(size_of::<usize>())];
        // SAFETY: a buffer of at least `len` bytes, aligned for TOKEN_USER.
        check(unsafe {
            GetTokenInformation(
                token.0,
                TokenUser,
                buf.as_mut_ptr() as *mut c_void,
                len,
                &mut len,
            )
        })?;
        // SAFETY: the call filled a TOKEN_USER, whose SID lies in `buf`.
        sid_text(unsafe { (*(buf.as_ptr() as *const TOKEN_USER)).User.Sid })
    }

    /// A window station with one desktop, of the command's own. Windows
    /// keeps an AppContainer out of the window station and desktop it was
    /// started from (a service's, or the user's), and a program that loads
    /// the user interface library (PowerShell does) does not start without
    /// one. Only this user and the container may open these, so the command
    /// does not reach the user's windows or clipboard either. They go when
    /// the shim does.
    struct Desktop {
        /// A station of its own; `None` on the logon's own station.
        station: Option<HANDLE>,
        desktop: HANDLE,
        /// `station\desktop`, for the startup info.
        name: Vec<u16>,
    }

    impl Drop for Desktop {
        fn drop(&mut self) {
            // SAFETY: made in `desktop`, closed once; the logon's own
            // station stays.
            unsafe {
                CloseDesktop(self.desktop);
                if let Some(s) = self.station {
                    CloseWindowStation(s);
                }
            }
        }
    }

    /// The name of the window object `h` (a station).
    fn object_name(h: HANDLE) -> io::Result<String> {
        let mut buf = [0u16; 256];
        let mut need = 0u32;
        // SAFETY: a buffer of its size in bytes; UOI_NAME is 2.
        check(unsafe { GetUserObjectInformationW(h, 2, buf.as_mut_ptr().cast(), 512, &mut need) })?;
        let len = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
        Ok(String::from_utf16_lossy(&buf[..len]))
    }

    /// [`desktop`] where this account may make no window station: a
    /// command account the installed node starts in session 0 of the
    /// services may not. Its process has the station of its own logon
    /// (Windows makes one for each, open to that logon only), and each
    /// command logs on anew (nerve-node's `win_user`), so no two pairings
    /// share one. The container gets an entry on it and a desktop of its
    /// own there.
    ///
    /// The desktop gets the list `sddl` and a low label, so the container's
    /// process, of low integrity, may write to it: the way it was tried on a
    /// Windows 11 machine (#149's probe).
    fn logon_desktop(container: &Sid, sddl: &str) -> io::Result<Desktop> {
        // SAFETY: plain getter; the handle is this process's, not closed.
        let station = unsafe { GetProcessWindowStation() };
        let mut sd: PSECURITY_DESCRIPTOR = null_mut();
        let mut dacl: *mut ACL = null_mut();
        // SAFETY: the station's handle and places for the parts; the
        // descriptor is freed with LocalFree.
        let r = unsafe {
            GetSecurityInfo(
                station,
                SE_WINDOW_OBJECT,
                DACL_SECURITY_INFORMATION,
                null_mut(),
                null_mut(),
                &mut dacl,
                null_mut(),
                &mut sd,
            )
        };
        if r != 0 {
            return Err(io::Error::from_raw_os_error(r as i32));
        }
        let _sd = Local(sd);
        let mut text: *mut u16 = null_mut();
        // SAFETY: a valid descriptor; the string is freed with LocalFree.
        check(unsafe {
            windows_sys::Win32::Security::Authorization::ConvertSecurityDescriptorToStringSecurityDescriptorW(
                sd,
                SDDL_REVISION_1,
                DACL_SECURITY_INFORMATION,
                &mut text,
                null_mut(),
            )
        })?;
        let _text = Local(text.cast());
        // SAFETY: a NUL-terminated string from the call.
        let old = unsafe {
            let len = (0..).take_while(|&i| *text.add(i) != 0).count();
            String::from_utf16_lossy(std::slice::from_raw_parts(text, len))
        };
        // What a process needs of its station, for the container too.
        let entry = format!("(A;;GA;;;{})", sid_text(container.0)?);
        if !old.contains(&entry) {
            let mut new: PSECURITY_DESCRIPTOR = null_mut();
            // SAFETY: a NUL-terminated SDDL string; freed with LocalFree.
            check(unsafe {
                ConvertStringSecurityDescriptorToSecurityDescriptorW(
                    wide(OsStr::new(&format!("{old}{entry}"))).as_ptr(),
                    SDDL_REVISION_1,
                    &mut new,
                    null_mut(),
                )
            })?;
            let _new = Local(new);
            let (mut present, mut defaulted) = (0, 0);
            let mut list: *mut ACL = null_mut();
            // SAFETY: the descriptor made above and places for its parts.
            check(unsafe {
                GetSecurityDescriptorDacl(new, &mut present, &mut list, &mut defaulted)
            })?;
            // SAFETY: the station's handle and a valid list.
            let r = unsafe {
                SetSecurityInfo(
                    station,
                    SE_WINDOW_OBJECT,
                    DACL_SECURITY_INFORMATION,
                    null_mut(),
                    null_mut(),
                    list,
                    null(),
                )
            };
            if r != 0 {
                return Err(io::Error::from_raw_os_error(r as i32));
            }
        }
        let mut labelled: PSECURITY_DESCRIPTOR = null_mut();
        // SAFETY: a NUL-terminated SDDL string; freed with LocalFree.
        check(unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                wide(OsStr::new(&format!("{sddl}S:(ML;;NW;;;LW)"))).as_ptr(),
                SDDL_REVISION_1,
                &mut labelled,
                null_mut(),
            )
        })?;
        let _labelled = Local(labelled);
        let sa = SECURITY_ATTRIBUTES {
            nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: labelled,
            bInheritHandle: 0,
        };
        let name = format!("nerve-{}", std::process::id());
        // SAFETY: a NUL-terminated name and security attributes that live
        // for the call; the desktop goes on this process's station.
        let desktop = unsafe {
            CreateDesktopW(
                wide(OsStr::new(&name)).as_ptr(),
                null(),
                null(),
                0,
                GENERIC_ALL,
                &sa,
            )
        };
        if desktop.is_null() {
            return Err(io::Error::last_os_error());
        }
        Ok(Desktop {
            station: None,
            desktop,
            name: wide(OsStr::new(&format!("{}\\{name}", object_name(station)?))),
        })
    }

    fn desktop(container: &Sid) -> io::Result<Desktop> {
        let sddl = format!(
            "D:P(A;;GA;;;SY)(A;;GA;;;{})(A;;GA;;;{})",
            user_sid()?,
            sid_text(container.0)?
        );
        let mut sd: PSECURITY_DESCRIPTOR = null_mut();
        // SAFETY: a NUL-terminated SDDL string; the descriptor is freed
        // with LocalFree.
        check(unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                wide(OsStr::new(&sddl)).as_ptr(),
                SDDL_REVISION_1,
                &mut sd,
                null_mut(),
            )
        })?;
        let _sd = Local(sd);
        let sa = SECURITY_ATTRIBUTES {
            nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: sd,
            bInheritHandle: 0,
        };
        let name = format!("nerve-{}", std::process::id());
        // SAFETY: NUL-terminated names and security attributes that live
        // for the calls; the handles are closed by `Desktop`.
        unsafe {
            let station =
                CreateWindowStationW(wide(OsStr::new(&name)).as_ptr(), 0, GENERIC_ALL, &sa);
            if station.is_null() {
                let e = io::Error::last_os_error();
                if e.kind() == io::ErrorKind::PermissionDenied {
                    return logon_desktop(container, &sddl);
                }
                return Err(e);
            }
            // CreateDesktopW makes the desktop in this process's window
            // station, so this process stands in the new one meanwhile.
            let old = GetProcessWindowStation();
            if SetProcessWindowStation(station) == 0 {
                let e = io::Error::last_os_error();
                CloseWindowStation(station);
                return Err(e);
            }
            let desktop = CreateDesktopW(
                wide(OsStr::new("Default")).as_ptr(),
                null(),
                null(),
                0,
                GENERIC_ALL,
                &sa,
            );
            let made = io::Error::last_os_error();
            SetProcessWindowStation(old);
            if desktop.is_null() {
                CloseWindowStation(station);
                return Err(made);
            }
            Ok(Desktop {
                station: Some(station),
                desktop,
                name: wide(OsStr::new(&format!("{name}\\Default"))),
            })
        }
    }

    /// Makes `h` inheritable, for the child's standard handles.
    fn inheritable(h: HANDLE) -> io::Result<()> {
        // SAFETY: a handle this process holds.
        check(unsafe { SetHandleInformation(h, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT) })
    }

    /// `vars` as an environment block: each `name=value` ended by a NUL,
    /// sorted by name as Windows keeps them, and a NUL at the end.
    fn env_block(mut vars: Vec<(std::ffi::OsString, std::ffi::OsString)>) -> Vec<u16> {
        vars.sort_by_key(|(k, _)| k.to_string_lossy().to_uppercase());
        let mut block = Vec::new();
        for (k, v) in vars {
            block.extend(k.encode_wide());
            block.push(u16::from(b'='));
            block.extend(v.encode_wide());
            block.push(0);
        }
        block.push(0);
        block
    }

    /// Runs `program` with `args` in the container `spec` names, with this
    /// process's environment as [`acl::container_env`] makes it (Windows
    /// PowerShell's own module path), the container's home where `spec`
    /// says so ([`acl::container_home`]) and `spec`'s variables, this
    /// process's working folder, stdout and stderr, and the null device as
    /// its stdin; no other handle goes to it. Off the network it gets none
    /// of the container's network capabilities. Waits for it and returns
    /// its exit code.
    pub fn run(program: &Path, args: &[String], spec: &super::ContainerSpec) -> io::Result<u32> {
        let name = spec.name.as_str();
        let ac = ready(name)?;
        let sid = Sid::derive(name)?;
        let wanted: &[i32] = if spec.no_network {
            &[]
        } else {
            &[
                WinCapabilityInternetClientSid,
                WinCapabilityInternetClientServerSid,
                WinCapabilityPrivateNetworkClientServerSid,
            ]
        };
        let mut caps_buf: Vec<io::Result<Vec<u8>>> =
            wanted.iter().map(|k| capability(*k)).collect();
        let mut caps = Vec::new();
        for c in caps_buf.iter_mut() {
            let c = c
                .as_mut()
                .map_err(|e| io::Error::new(e.kind(), e.to_string()))?;
            caps.push(SID_AND_ATTRIBUTES {
                Sid: c.as_mut_ptr() as PSID,
                Attributes: SE_GROUP_ENABLED,
            });
        }
        let sc = SECURITY_CAPABILITIES {
            AppContainerSid: sid.0,
            Capabilities: if caps.is_empty() {
                null_mut()
            } else {
                caps.as_mut_ptr()
            },
            CapabilityCount: caps.len() as u32,
            Reserved: 0,
        };
        let null_in = std::fs::File::open("NUL")
            .map_err(|e| io::Error::new(e.kind(), format!("the null device: {e}")))?;
        let stdin = null_in.as_raw_handle() as HANDLE;
        let stdout = std::io::stdout().as_raw_handle() as HANDLE;
        let stderr = std::io::stderr().as_raw_handle() as HANDLE;
        let mut handles = vec![stdin];
        for h in [stdout, stderr] {
            if !h.is_null() && !handles.contains(&h) {
                handles.push(h);
            }
        }
        for h in &handles {
            inheritable(*h)?;
        }

        let mut size = 0usize;
        // SAFETY: the first call only asks for the size and fails with
        // ERROR_INSUFFICIENT_BUFFER.
        unsafe { InitializeProcThreadAttributeList(null_mut(), 2, 0, &mut size) };
        let mut attrs = vec![0usize; size.div_ceil(size_of::<usize>())];
        let list = attrs.as_mut_ptr() as LPPROC_THREAD_ATTRIBUTE_LIST;
        // SAFETY: a buffer of at least `size` bytes.
        check(unsafe { InitializeProcThreadAttributeList(list, 2, 0, &mut size) })?;
        struct List(LPPROC_THREAD_ATTRIBUTE_LIST);
        impl Drop for List {
            fn drop(&mut self) {
                // SAFETY: initialised above, deleted once.
                unsafe { DeleteProcThreadAttributeList(self.0) };
            }
        }
        let _list = List(list);
        // SAFETY: the values outlive the list, which is used only below.
        unsafe {
            check(UpdateProcThreadAttribute(
                list,
                0,
                PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES as usize,
                &sc as *const _ as *const c_void,
                size_of::<SECURITY_CAPABILITIES>(),
                null_mut(),
                null(),
            ))?;
            check(UpdateProcThreadAttribute(
                list,
                0,
                PROC_THREAD_ATTRIBUTE_HANDLE_LIST as usize,
                handles.as_ptr() as *const c_void,
                handles.len() * size_of::<HANDLE>(),
                null_mut(),
                null(),
            ))?;
        }
        let mut desk = desktop(&sid)
            .map_err(|e| io::Error::new(e.kind(), format!("a desktop of its own: {e}")))?;
        let mut si = STARTUPINFOEXW::default();
        si.StartupInfo.lpDesktop = desk.name.as_mut_ptr();
        si.StartupInfo.cb = size_of::<STARTUPINFOEXW>() as u32;
        si.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
        si.StartupInfo.hStdInput = stdin;
        si.StartupInfo.hStdOutput = stdout;
        si.StartupInfo.hStdError = stderr;
        si.lpAttributeList = list;
        let exe = find(program)?;
        let app = wide(exe.as_os_str());
        let mut line = wide(OsStr::new(&command_line(&exe.to_string_lossy(), args)));
        let set = acl::command_set(spec.home.then_some(ac.as_path()), &spec.env);
        let env = env_block(acl::with_vars(
            acl::container_env(std::env::vars_os()),
            &set,
        ));
        let mut pi = PROCESS_INFORMATION::default();
        let started = |e: io::Error| io::Error::new(e.kind(), format!("{}: {e}", exe.display()));
        // SAFETY: NUL-terminated strings, a writable command line, and the
        // startup info with its attribute list, all alive for the call.
        check(unsafe {
            CreateProcessW(
                app.as_ptr(),
                line.as_mut_ptr(),
                null(),
                null(),
                1,
                EXTENDED_STARTUPINFO_PRESENT | CREATE_UNICODE_ENVIRONMENT,
                env.as_ptr().cast(),
                null(),
                &si.StartupInfo,
                &mut pi,
            )
        })
        .map_err(started)?;
        let mut code = 0u32;
        // SAFETY: handles CreateProcessW returned, each closed once.
        unsafe {
            CloseHandle(pi.hThread);
            WaitForSingleObject(pi.hProcess, INFINITE);
            let ok = GetExitCodeProcess(pi.hProcess, &mut code);
            CloseHandle(pi.hProcess);
            check(ok)?;
        }
        Ok(code)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Two lists whose allowing entries of one kind stand in another order
    /// give the same access; a deny moved past an allow, an entry of its
    /// own moved among the inherited ones, or another entry do not (#40,
    /// node-1: a walk compared in order and rewrote every file twice).
    #[test]
    fn allowing_entries_compare_in_any_order() {
        // An ACE: type, flags, its size, the mask and a SID's bytes.
        let ace = |kind: u8, flags: u8, mask: u32, sid: u8| {
            let mut a = vec![kind, flags, 12, 0];
            a.extend(mask.to_le_bytes());
            a.extend([1, 0, 0, sid]);
            a
        };
        let list = |aces: &[&Vec<u8>]| {
            aces.iter()
                .flat_map(|a| a.iter().copied())
                .collect::<Vec<u8>>()
        };
        let (allow, deny, inherited) = (acl::ALLOWED, acl::DENIED, acl::INHERITED);
        let (a, b, c) = (
            ace(allow, 0, 0x1200a9, 1),
            ace(allow, 0, 0x1301bf, 2),
            ace(allow, inherited, 0x1f01ff, 3),
        );
        let d = ace(deny, 0, 0x2, 4);
        let ai = ace(allow, inherited, 0x1200a9, 1);
        let same = |x: &[&Vec<u8>], y: &[&Vec<u8>]| acl::same_entries(&list(x), &list(y));
        assert!(same(&[&a, &b], &[&b, &a]));
        assert!(same(&[&d, &a, &b, &c, &ai], &[&d, &b, &a, &ai, &c]));
        assert!(!same(&[&d, &a], &[&a, &d]));
        assert!(!same(&[&a, &c], &[&c, &a]));
        assert!(!same(&[&a, &b], &[&a, &a]));
        assert!(!same(&[&a, &b], &[&a]));
        // Bytes that are not whole entries compare as they are.
        assert!(acl::same_entries(&[1, 2, 3], &[1, 2, 3]));
        assert!(!acl::same_entries(&a[..5], &b[..5]));
    }

    /// A confined command may not write a terminal: it has none of its own,
    /// and the one it could reach would be the owner's.
    #[test]
    fn no_terminal_is_writable() {
        assert!(!system_writable().iter().any(|p| p.starts_with("/dev/tty")));
        // Windows has no such files; the list is empty there.
        assert_eq!(
            system_writable().contains(&PathBuf::from("/dev/null")),
            cfg!(unix)
        );
    }

    /// The terminals under `/dev` are named for the read sets to leave out.
    #[cfg(target_os = "linux")]
    #[test]
    fn the_terminals_are_named() {
        let t = terminal_devices();
        assert!(t.contains(&PathBuf::from("/dev/pts")), "{t:?}");
        assert!(!t.contains(&PathBuf::from("/dev/null")), "{t:?}");
        assert!(!t.contains(&PathBuf::from("/dev/ptmx")), "{t:?}");
        assert!(t.iter().all(|p| p.starts_with("/dev")), "{t:?}");
    }

    /// A terminal that has no `tty` name, such as a hypervisor console, is
    /// named by the kernel's list of tty devices; `ptmx` is not left out of
    /// the commands' reach by it.
    #[test]
    fn a_terminal_without_a_tty_name_is_left_out_too() {
        let d = tempfile::tempdir().unwrap();
        let (dev, class) = (d.path().join("dev"), d.path().join("class"));
        std::fs::create_dir_all(dev.join("3270")).unwrap();
        std::fs::create_dir_all(&class).unwrap();
        for f in ["hvc0", "ttyS0", "ptmx", "null", "3270/tty1"] {
            std::fs::write(dev.join(f), "").unwrap();
        }
        for f in ["hvc0", "ptmx", "3270!tty1", "gone0"] {
            std::fs::create_dir(class.join(f)).unwrap();
        }
        let t = terminals_in(&dev, &class);
        assert_eq!(
            t,
            [dev.join("3270/tty1"), dev.join("hvc0"), dev.join("ttyS0")],
            "{t:?}"
        );
    }

    /// Landlock below ABI 3 does not guard truncate(2): a node run by hand
    /// takes it as none. From ABI 6 on nothing the node asks for is missing.
    #[test]
    fn landlock_below_the_floor_counts_as_none_by_hand() {
        let at = |abi| Confinement {
            landlock_abi: abi,
            appcontainer: false,
        };
        assert_eq!(at(Some(2)).by_hand().landlock_abi, None);
        assert_eq!(at(Some(3)).by_hand().landlock_abi, Some(3));
        assert_eq!(at(None).by_hand().landlock_abi, None);
        assert!(landlock_gaps(2).contains(&"truncating files"));
        assert!(!landlock_gaps(3).contains(&"truncating files"));
        assert_eq!(
            landlock_gaps(5),
            [
                "signals to other processes of the account",
                "abstract unix sockets"
            ]
        );
        assert!(landlock_gaps(6).is_empty());
    }

    #[test]
    fn spec_round_trips_strictly() {
        let s = ShimSpec {
            program: "/bin/sh".into(),
            args: vec!["-c".into(), "true".into()],
            parent: 1,
            landlock: Some(LandlockSpec::default()),
            container: Some(ContainerSpec {
                no_network: true,
                home: true,
                env: vec![("HTTPS_PROXY".into(), "http://p:3128".into())],
                ..ContainerSpec::new("nerve.x")
            }),
            own_proc: true,
            cwd: Some("C:\\Users\\nerve-run\\x".into()),
        };
        let j = serde_json::to_string(&s).unwrap();
        assert_eq!(serde_json::from_str::<ShimSpec>(&j).unwrap(), s);
        let extra = r#"{"program":"x","args":[],"parent":1,"x":1}"#;
        assert!(serde_json::from_str::<ShimSpec>(extra).is_err());
        let plain = r#"{"program":"x","args":[],"parent":1}"#;
        let plain = serde_json::from_str::<ShimSpec>(plain).unwrap();
        assert_eq!(
            (plain.landlock, plain.container, plain.cwd),
            (None, None, None)
        );
        let mut c = Confinement {
            landlock_abi: None,
            appcontainer: false,
        };
        assert_eq!(c.describe(), "none");
        assert!(!c.available());
        c.appcontainer = true;
        assert_eq!(c.describe(), "appcontainer");
        assert!(c.available());
        assert_eq!(Confinement::detect().appcontainer, cfg!(windows));
    }

    /// Each flag gives its own rights and nothing of another's: `w` reads
    /// and lists nothing, `x` runs and reads files but lists nothing, and
    /// no flag may change the access list or the owner.
    /// A folder without a flag inside a granted one is closed to the
    /// container: one denied entry, every right, for it and all below it,
    /// a file just itself.
    /// A file with more than one name gets no more than its caps: the
    /// entries of the containers the node grants, inherited or its own, go,
    /// and it has its own allowing entry of no more than read and execute
    /// (none for `w` alone) after a denying entry of every other right,
    /// first in the list; a container closed there gets only a denying
    /// entry, one no grant holds none. Other AppContainers
    /// and capabilities are cut down too, without a denying entry; the
    /// owner's entries and other denials stay. Worked out again from the
    /// list it gave, and from that list widened again by Windows, the same
    /// comes out; once the container has nothing, its denial goes too.
    #[test]
    fn a_file_with_more_than_one_name_gets_no_more_than_its_caps() {
        use acl::{
            ALLOWED, Ace, Capped, DENIED, INHERITED, READ_AND_EXECUTE, capped, file_cap, uncapped,
        };
        use inherit::Gets;
        let ace = |kind, flags, mask, sid: &str| Ace {
            kind,
            flags,
            mask,
            sid: Some(sid.into()),
        };
        let rw = acl::masks(true, true, false).file;
        let (c, w, shut, away) = (
            "S-1-15-2-1-2",
            "S-1-15-2-3-4",
            "S-1-15-2-5-6",
            "S-1-15-2-7-8",
        );
        let r = file_cap(true, false, false);
        let caps = vec![
            (c.to_string(), Gets::Rights(file_cap(true, true, false))),
            (w.to_string(), Gets::Rights(file_cap(true, false, false))),
            (shut.to_string(), Gets::Closed),
            (away.to_string(), Gets::Unheld),
        ];
        let list = vec![
            ace(ALLOWED, 0, acl::ALL, "S-1-5-21-1-2-3-1001"),
            ace(DENIED, 0, acl::WRITE_DATA, "S-1-5-21-1-2-3-1002"),
            ace(ALLOWED, INHERITED, rw, c),
            ace(ALLOWED, INHERITED, 0x4000_0000, w),
            ace(ALLOWED, INHERITED, rw, shut),
            ace(ALLOWED, INHERITED, 0x1000_0000, "S-1-15-3-1"),
            ace(ALLOWED, INHERITED, acl::ALL, "S-1-5-18"),
            ace(ALLOWED, INHERITED, rw, away),
        ];
        let out = capped(&list, &caps);
        assert_eq!(
            out,
            [
                Capped::Deny(0, acl::ALL & !r),
                Capped::Deny(1, acl::ALL & !r),
                Capped::Deny(2, acl::ALL),
                Capped::Entry(0, acl::ALL),
                Capped::Entry(1, acl::WRITE_DATA),
                Capped::Allow(0, r),
                Capped::Allow(1, r),
                Capped::Entry(5, READ_AND_EXECUTE),
                Capped::Entry(6, acl::ALL),
            ]
        );
        assert_eq!(r & (acl::WRITE_DATA | acl::DELETE | acl::WRITE_DAC), 0);

        // The list it gave, as Windows writes it.
        let sid_of = |j: usize| caps[j].0.clone();
        let written = |out: &[Capped], from: &[Ace]| -> Vec<Ace> {
            out.iter()
                .map(|e| match *e {
                    Capped::Entry(i, mask) => Ace {
                        mask,
                        ..from[i].clone()
                    },
                    Capped::Deny(j, mask) => ace(DENIED, 0, mask, &sid_of(j)),
                    Capped::Allow(j, mask) => ace(ALLOWED, 0, mask, &sid_of(j)),
                    Capped::Reads => unreachable!(),
                })
                .collect()
        };
        let once = written(&out, &list);
        assert_eq!(written(&capped(&once, &caps), &once), once);
        // Widened again: the folder's whole entries back below the node's
        // own, as Windows passes a list down.
        let mut widened: Vec<Ace> = once[..7].to_vec();
        widened.extend(list[2..].iter().cloned());
        assert_eq!(written(&capped(&widened, &caps), &widened), once);

        // No grant of the container holds a name any more: its entries of
        // the node's go, whatever the list holds.
        let mut gone_caps = caps.clone();
        gone_caps[0].1 = Gets::Unheld;
        let again = written(&capped(&once, &gone_caps), &once);
        assert!(
            !again
                .iter()
                .any(|a| a.sid.as_deref() == Some(c) && a.flags & INHERITED == 0),
            "{again:?}"
        );
        // A change as any file: the node's own entries go, nothing else
        // changes.
        let plain = written(&uncapped(&once, &[c.into(), w.into(), shut.into()]), &once);
        assert!(
            plain.iter().all(|a| a.flags & INHERITED != 0
                || !a.sid.as_deref().is_some_and(|s| [c, w, shut].contains(&s))),
            "{plain:?}"
        );
        assert_eq!(plain.len(), once.len() - 5);
        assert_eq!(uncapped(&list, &[c.into()]).len(), list.len());
    }

    /// The cap of a file with more than one name leaves what the list gives
    /// every other account as it is: a file linked from the owner's store
    /// into a granted folder keeps the store's entries, and gets none of
    /// the folder's (#149). Only the containers' entries are the node's.
    #[test]
    fn a_cap_leaves_the_entries_of_other_accounts_alone() {
        use acl::{ALLOWED, Ace, Capped, INHERITED, capped, file_cap};
        use inherit::Gets;
        let ace = |flags, mask, sid: &str| Ace {
            kind: ALLOWED,
            flags,
            mask,
            sid: Some(sid.into()),
        };
        let (c, owner, everyone) = ("S-1-15-2-1-2", "S-1-5-21-1-2-3-1001", "S-1-1-0");
        let rw = acl::masks(true, true, false).file;
        // As a store's list: the owner's, inherited from the store's folder
        // (the container's stale entry is there too, from a folder it was
        // granted before).
        let list = vec![
            ace(INHERITED, acl::ALL, owner),
            ace(INHERITED, rw, c),
            ace(INHERITED, rw, everyone),
        ];
        let caps = vec![(c.to_string(), Gets::Rights(file_cap(true, true, false)))];
        let out = capped(&list, &caps);
        assert!(out.contains(&Capped::Entry(0, acl::ALL)), "{out:?}");
        assert!(out.contains(&Capped::Entry(2, rw)), "{out:?}");
        assert!(
            !out.iter().any(|e| matches!(e, Capped::Entry(1, _))),
            "{out:?}"
        );
        assert!(out.contains(&Capped::Allow(0, file_cap(true, true, false))));
    }

    /// A capped file the walk could not look at (a command's own store's,
    /// whose list names only the command account, its container and the
    /// system) gets read and execute for the account the walk acts as, the
    /// owner, after the other explicit entries and before the node's
    /// allowing ones, so the owner opens what an agent installed in their
    /// project (#149). The next walk may look at the file and gives no
    /// reader: it leaves the list as it is, and so does one that gives the
    /// reader again.
    #[test]
    fn a_capped_file_the_walk_could_not_look_at_is_read_by_its_account() {
        use acl::{ALLOWED, Ace, Capped, DENIED, INHERITED, capped, file_cap, readable_by};
        use inherit::Gets;
        let ace = |kind, flags, mask, sid: &str| Ace {
            kind,
            flags,
            mask,
            sid: Some(sid.into()),
        };
        let (c, run, owner) = ("S-1-15-2-1-2", "S-1-5-21-1-2-3-1002", "S-1-5-21-1-2-3-1001");
        let list = vec![
            ace(DENIED, 0, acl::WRITE_DATA, owner),
            ace(ALLOWED, INHERITED, acl::ALL, run),
            ace(ALLOWED, INHERITED, acl::ALL, c),
            ace(ALLOWED, INHERITED, acl::ALL, "S-1-5-18"),
        ];
        let caps = vec![(c.to_string(), Gets::Rights(file_cap(true, true, false)))];
        let out = readable_by(capped(&list, &caps), &list, owner);
        let r = file_cap(true, true, false);
        assert_eq!(
            out,
            [
                Capped::Deny(0, acl::ALL & !r),
                Capped::Entry(0, acl::WRITE_DATA),
                Capped::Reads,
                Capped::Allow(0, r),
                Capped::Entry(1, acl::ALL),
                Capped::Entry(3, acl::ALL),
            ]
        );
        // The list as Windows writes it.
        let written = |out: &[Capped], from: &[Ace]| -> Vec<Ace> {
            out.iter()
                .map(|e| match *e {
                    Capped::Entry(i, mask) => Ace {
                        mask,
                        ..from[i].clone()
                    },
                    Capped::Deny(_, m) => ace(DENIED, 0, m, c),
                    Capped::Allow(_, m) => ace(ALLOWED, 0, m, c),
                    Capped::Reads => ace(ALLOWED, 0, acl::READ_AND_EXECUTE, owner),
                })
                .collect()
        };
        let once = written(&out, &list);
        // The next walk, which the owner's entry lets look at the file.
        assert_eq!(written(&capped(&once, &caps), &once), once);
        // One that may not look at it again.
        let again = readable_by(capped(&once, &caps), &once, owner);
        assert_eq!(written(&again, &once), once, "{again:?}");
    }

    /// A granted file with more than one name carries the node's cap in
    /// place of the grant's own entry, and a sync that looks at it counts
    /// that as granted, so it does not put it on again each time: an
    /// allowing entry of no more than the grant's flags give within read
    /// and execute with the denial of the rest, or the denial of every
    /// right alone. A wider allow, the grant's own entry or none does not.
    #[test]
    fn a_capped_file_counts_as_granted() {
        use acl::{ALL, ALLOWED, Capped, DENIED, capped, capped_within, file_cap};
        use inherit::Gets;
        let ours = |g: Gets| -> Vec<(u8, u32, u32)> {
            capped(&[], &[("S-1-15-2-1-2".to_string(), g)])
                .iter()
                .map(|e| match *e {
                    Capped::Deny(_, m) => (DENIED, 0, m),
                    Capped::Allow(_, m) => (ALLOWED, 0, m),
                    Capped::Entry(..) | Capped::Reads => unreachable!(),
                })
                .collect()
        };
        let (rw, rwx, x) = (
            acl::masks(true, true, false),
            acl::masks(true, true, true),
            acl::masks(false, false, true),
        );
        for (m, g) in [
            (rw, Gets::Rights(file_cap(true, true, false))),
            (rwx, Gets::Rights(file_cap(true, true, true))),
            (rwx, Gets::Rights(file_cap(true, false, false))),
            (x, Gets::Rights(file_cap(false, false, true))),
            (rw, Gets::Closed),
        ] {
            assert!(capped_within(&ours(g), m, false), "{m:?} {g:?}");
            // Not while the file inherits an entry for the container again
            // (as when a tool passed its folder's list down).
            assert!(!capped_within(&ours(g), m, true), "{m:?} {g:?}");
        }
        assert!(!capped_within(
            &ours(Gets::Rights(file_cap(true, false, true))),
            rw,
            false
        ));
        assert!(!capped_within(
            &ours(Gets::Rights(file_cap(false, false, true))),
            acl::masks(true, false, false),
            false
        ));
        assert!(!capped_within(
            &[(ALLOWED, 0, rw.file & !acl::DELETE)],
            rw,
            false
        ));
        assert!(!capped_within(&[], rw, false));
        assert!(!capped_within(&[(DENIED, 0, ALL)], acl::closed(), false));
        let r = file_cap(true, false, false);
        assert!(!capped_within(
            &[(ALLOWED, 0, r), (DENIED, 0, ALL)],
            rw,
            false
        ));
    }

    /// Only the SID of a container as the node makes them closes a folder
    /// to what it inherits: not the groups every container is in, nor a
    /// capability, nor a SID of another shape.
    #[test]
    fn only_a_containers_own_package_sid_counts_as_one() {
        let own =
            "S-1-15-2-3624051433-2125758914-1423191267-1740899205-1073925389-3782572162-737981194";
        assert!(acl::package_sid(own));
        assert!(acl::package_sid(&own.to_lowercase()));
        for other in [
            // ALL APPLICATION PACKAGES, ALL RESTRICTED APPLICATION PACKAGES.
            "S-1-15-2-1",
            "S-1-15-2-2",
            // A capability, a user, everyone, a child package (more parts).
            "S-1-15-3-1024-1-2-3-4-5-6-7",
            "S-1-5-21-1-2-3-1001",
            "S-1-1-0",
            "S-1-15-2-1-2-3-4-5-6-7-8-9-10-11",
            "S-1-15-2-1-2-3-4-5-6",
            "S-1-15-2-1-2-3-4-5-6-x",
            "S-1-15-2-1-2-3-4-5-6-",
            "",
        ] {
            assert!(!acl::package_sid(other), "{other}");
        }
    }

    /// Two containers with a grant on one name each of the same file (two
    /// projects linked to one store), walked in turn: the list is worked out
    /// under one name's folder each time, which holds only that one's
    /// inherited entry, yet each keeps its read and its denial of writes,
    /// also when Windows passes either folder's list down again (#149).
    #[test]
    fn a_file_linked_into_two_containers_folders_keeps_both_caps() {
        use acl::{
            ALLOWED, Ace, Capped, DENIED, INHERITED, READ_DATA, WRITE_DATA, capped, file_cap,
        };
        use inherit::Gets;
        let (a, b) = ("S-1-15-2-1-1", "S-1-15-2-2-2");
        let rw = acl::masks(true, true, false).file;
        let owner = Ace {
            kind: ALLOWED,
            flags: INHERITED,
            mask: acl::ALL,
            sid: Some("S-1-5-21-1-2-3-1001".into()),
        };
        // What the folder of each project passes down.
        let folder = |sid: &str| {
            vec![
                owner.clone(),
                Ace {
                    kind: ALLOWED,
                    flags: INHERITED,
                    mask: rw,
                    sid: Some(sid.into()),
                },
            ]
        };
        let caps = vec![
            (a.to_string(), Gets::Rights(file_cap(true, true, false))),
            (b.to_string(), Gets::Rights(file_cap(true, true, false))),
        ];
        let written = |out: &[Capped], from: &[Ace]| -> Vec<Ace> {
            out.iter()
                .map(|e| match *e {
                    Capped::Entry(i, mask) => Ace {
                        mask,
                        ..from[i].clone()
                    },
                    Capped::Deny(j, mask) | Capped::Allow(j, mask) => Ace {
                        kind: if matches!(e, Capped::Deny(..)) {
                            DENIED
                        } else {
                            ALLOWED
                        },
                        flags: 0,
                        mask,
                        sid: Some(caps[j].0.clone()),
                    },
                    Capped::Reads => unreachable!(),
                })
                .collect()
        };
        // Windows' access check: the first entries that name the SID decide
        // each right.
        let may = |list: &[Ace], sid: &str, right: u32| {
            for e in list.iter().filter(|e| e.sid.as_deref() == Some(sid)) {
                if e.mask & right != 0 {
                    return e.kind == ALLOWED;
                }
            }
            false
        };
        // The file's own entries kept, the inherited ones those of `dir`.
        let under = |list: &[Ace], dir: &[Ace]| -> Vec<Ace> {
            let mut l: Vec<Ace> = list
                .iter()
                .filter(|e| e.flags & INHERITED == 0)
                .cloned()
                .collect();
            l.extend(dir.iter().cloned());
            l
        };
        let mut list = folder(a);
        for (walked, other) in [(a, b), (b, a), (a, b)] {
            list = written(
                &capped(&under(&list, &folder(walked)), &caps),
                &under(&list, &folder(walked)),
            );
            for sid in [walked, other] {
                assert!(
                    may(&list, sid, READ_DATA),
                    "{sid} reads after {walked}'s walk: {list:?}"
                );
                assert!(
                    !may(&list, sid, WRITE_DATA),
                    "{sid} writes after {walked}'s walk: {list:?}"
                );
            }
            // Explorer or icacls passes the other one's folder down.
            let passed = under(&list, &folder(other));
            for sid in [walked, other] {
                assert!(
                    !may(&passed, sid, WRITE_DATA),
                    "{sid} writes after {other}'s folder passed down: {passed:?}"
                );
            }
        }
    }

    #[test]
    fn a_closed_folder_denies_every_right_to_it_and_below() {
        use acl::*;
        let c = closed();
        assert!(c.deny && !masks(true, true, true).deny);
        let all = READ_DATA | WRITE_DATA | APPEND_DATA | EXECUTE | DELETE | WRITE_DAC;
        assert_eq!(c.dir & all, all);
        assert_eq!(
            entries(true, c),
            [(OBJECT_INHERIT | CONTAINER_INHERIT, c.dir)]
        );
        assert_eq!(entries(false, c), [(0, c.file)]);
    }

    #[test]
    fn each_flag_gives_its_own_windows_rights() {
        use acl::*;
        let none = masks(false, false, false);
        assert_eq!(none, Masks::default());
        let r = masks(true, false, false);
        assert_eq!(r.dir & READ_DATA, READ_DATA, "r lists a folder");
        assert_eq!(r.file & READ_DATA, READ_DATA, "r reads a file");
        assert_eq!(r.file & EXECUTE, 0, "r runs nothing");
        assert_eq!((r.dir | r.file) & (WRITE_DATA | APPEND_DATA | DELETE), 0);
        let w = masks(false, true, false);
        assert_eq!(w.dir & (WRITE_DATA | APPEND_DATA), WRITE_DATA | APPEND_DATA);
        assert_eq!(w.file & WRITE_DATA, WRITE_DATA);
        assert_eq!(w, masks(true, true, false), "w reads too");
        assert_eq!(w.file & EXECUTE, 0, "w runs nothing");
        let x = masks(false, false, true);
        assert_eq!(x.file & (EXECUTE | READ_DATA), EXECUTE | READ_DATA);
        assert_eq!(x.dir & READ_DATA, 0, "x lists no folder");
        assert_eq!((x.dir | x.file) & (WRITE_DATA | DELETE), 0);
        let all = masks(true, true, true);
        assert_eq!((all.dir | all.file) & (WRITE_DAC | WRITE_OWNER), 0);
        assert_eq!(
            all.dir,
            r.dir | w.dir | x.dir | masks(true, true, false).dir
        );
        assert_eq!(
            all.file,
            r.file | w.file | x.file | masks(true, true, false).file
        );
        // A move is a delete to Windows: only `w` deletes, and it reads, so
        // no move makes what a command may not read readable at its new
        // place.
        for (r, x) in [(true, false), (false, true), (true, true)] {
            let m = masks(r, false, x);
            assert_eq!((m.dir | m.file) & (DELETE | DELETE_CHILD), 0, "{r} {x}");
        }
        assert_eq!(w.dir & (DELETE | DELETE_CHILD), DELETE | DELETE_CHILD);
        assert_eq!(w.file & DELETE, DELETE);
    }

    /// A granted folder or file itself is never deleted, renamed or moved
    /// by a command: its own entry has no `DELETE`, while what is below it
    /// keeps the rights of the flags.
    #[test]
    fn a_granted_folder_itself_has_no_delete() {
        use acl::*;
        let rw = masks(true, true, false);
        let dir = entries(true, rw);
        let on_itself: u32 = dir
            .iter()
            .filter(|(f, _)| f & INHERIT_ONLY == 0)
            .map(|(_, m)| m)
            .fold(0, |a, m| a | m);
        assert_eq!(on_itself, rw.dir & !DELETE, "{dir:?}");
        assert!(
            dir.contains(&(CONTAINER_INHERIT | INHERIT_ONLY, rw.dir)),
            "{dir:?}"
        );
        assert!(
            dir.contains(&(OBJECT_INHERIT | INHERIT_ONLY, rw.file)),
            "{dir:?}"
        );
        assert_eq!(entries(false, rw), [(0, rw.file & !DELETE)]);
        // Without DELETE one entry serves the folder and those below.
        let r = masks(true, false, false);
        assert_eq!(
            entries(true, r),
            [
                (CONTAINER_INHERIT, r.dir),
                (OBJECT_INHERIT | INHERIT_ONLY, r.file)
            ]
        );
        assert!(entries(true, Masks::default()).is_empty());
    }

    /// Paths compare as NTFS names them: in either case, by either
    /// separator, with or without `\\?\`; a share is not a drive path.
    #[test]
    fn windows_paths_compare_by_their_names() {
        use acl::same_path;
        assert!(same_path(r"\\?\C:\Work\Proj", r"c:\work\proj\"));
        assert!(same_path(r"C:/work/proj", r"C:\work\proj"));
        assert!(same_path(r"\\?\UNC\host\share\a", r"\\host\share\a"));
        assert!(!same_path(r"C:\work\proj", r"C:\work\proj2"));
        assert!(!same_path(r"C:\work\proj", r"D:\work\proj"));
        assert!(!same_path(r"\\host\share", r"host\share"));
    }

    /// A file ID reads back as it was written, and nothing else reads as
    /// one.
    #[test]
    fn file_ids_round_trip() {
        use acl::FileId;
        let id = FileId {
            volume: 0x0123_4567_89ab_cdef,
            file: *b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\xff",
        };
        let text = id.to_string();
        assert_eq!(text, "0123456789abcdef:000102030405060708090a0b0c0d0eff");
        assert_eq!(text.parse::<FileId>(), Ok(id));
        for bad in [
            "",
            "0123456789abcdef",
            "0123456789abcdef:00",
            "0123456789abcdeg:000102030405060708090a0b0c0d0eff",
            "0123456789abcdef:000102030405060708090a0b0c0d0eé",
        ] {
            assert!(bad.parse::<FileId>().is_err(), "{bad}");
        }
    }

    /// A container's command gets Windows PowerShell's own module folders
    /// as its module path, whatever the machine's says, and no module
    /// analysis cache; every other variable stays.
    #[test]
    fn the_container_gets_windows_powershells_own_module_path() {
        let vars = |pairs: &[(&str, &str)]| -> Vec<(std::ffi::OsString, std::ffi::OsString)> {
            pairs
                .iter()
                .map(|(k, v)| ((*k).into(), (*v).into()))
                .collect()
        };
        let got = acl::container_env(vars(&[
            ("Path", r"C:\Windows\system32"),
            (
                "PSMODULEPATH",
                r"C:\Program Files\PowerShell\7\Modules;C:\\Modules\az_15.6.1;C:\Users\packer\Documents\WindowsPowerShell\Modules",
            ),
            (
                "PSModuleAnalysisCachePath",
                r"C:\PSModuleAnalysisCachePath\ModuleAnalysisCache",
            ),
            ("ProgramFiles", r"D:\Programs\"),
            ("SystemRoot", r"D:\WIN"),
        ]));
        let as_text: Vec<(String, String)> = got
            .iter()
            .map(|(k, v)| (k.to_string_lossy().into(), v.to_string_lossy().into()))
            .collect();
        let get = |name: &str| {
            as_text
                .iter()
                .filter(|(k, _)| k.eq_ignore_ascii_case(name))
                .map(|(_, v)| v.as_str())
                .collect::<Vec<_>>()
        };
        assert_eq!(
            get("PSModulePath"),
            [
                r"D:\Programs\WindowsPowerShell\Modules;D:\WIN\system32\WindowsPowerShell\v1.0\Modules"
            ]
        );
        assert!(get("PSModuleAnalysisCachePath").is_empty());
        assert_eq!(get("Path"), [r"C:\Windows\system32"]);
        assert_eq!(get("SystemRoot"), [r"D:\WIN"]);
        // Without the two folders' variables, Windows' own places.
        let bare = acl::container_env(Vec::new());
        assert_eq!(
            bare,
            vars(&[(
                "PSModulePath",
                r"C:\Program Files\WindowsPowerShell\Modules;C:\Windows\system32\WindowsPowerShell\v1.0\Modules"
            )])
        );
    }

    /// A pairing's command has its home in its container's own folder: the
    /// variables that name a home and the settings below it name `AC\home`,
    /// in place of the account's, whatever case they came in, and git
    /// trusts the repositories it reaches. `LOCALAPPDATA`, `TEMP` and the
    /// rest stay for Windows to point at the container.
    #[test]
    fn a_containers_home_is_its_own_folder() {
        let ac = std::path::Path::new(r"C:\Users\nerve-run\AppData\Local\Packages\nerve.ab\AC");
        let set = acl::container_home(ac);
        let got = acl::with_vars(
            vec![
                ("userprofile".into(), r"C:\Users\nerve-run".into()),
                (
                    "APPDATA".into(),
                    r"C:\Users\nerve-run\AppData\Roaming".into(),
                ),
                (
                    "LOCALAPPDATA".into(),
                    r"C:\Users\nerve-run\AppData\Local".into(),
                ),
                (
                    "TEMP".into(),
                    r"C:\Users\nerve-run\AppData\Local\Temp".into(),
                ),
            ],
            &set,
        );
        let get = |name: &str| -> Vec<String> {
            got.iter()
                .filter(|(k, _)| k.to_string_lossy().eq_ignore_ascii_case(name))
                .map(|(_, v)| v.to_string_lossy().into_owned())
                .collect()
        };
        let home = r"C:\Users\nerve-run\AppData\Local\Packages\nerve.ab\AC\home";
        assert_eq!(get("USERPROFILE"), [home]);
        assert_eq!(get("HOME"), [home]);
        assert_eq!(get("HOMEDRIVE"), ["C:"]);
        assert_eq!(get("HOMEPATH"), [&home[2..]]);
        assert_eq!(get("APPDATA"), [format!(r"{home}\AppData\Roaming")]);
        assert_eq!(get("LOCALAPPDATA"), [r"C:\Users\nerve-run\AppData\Local"]);
        assert_eq!(get("TEMP"), [r"C:\Users\nerve-run\AppData\Local\Temp"]);
        assert_eq!(get("GIT_CONFIG_KEY_0"), ["safe.directory"]);
        assert_eq!(get("GIT_CONFIG_VALUE_0"), ["*"]);
        // The node's variables the owner passes on (`machine.command_env`)
        // do not move the home, also where they name it: it is in the
        // environment once.
        let passed = [
            (
                "Home".to_string(),
                r"C:\Windows\ServiceProfiles\nerve".to_string(),
            ),
            ("HTTPS_PROXY".to_string(), "http://proxy".to_string()),
        ];
        let more = acl::with_vars(got.clone(), &acl::command_set(Some(ac), &passed));
        let homes: Vec<_> = more
            .iter()
            .filter(|(k, _)| k.to_string_lossy().eq_ignore_ascii_case("HOME"))
            .map(|(_, v)| v.to_string_lossy().into_owned())
            .collect();
        assert_eq!(homes, [home]);
        assert!(
            more.iter()
                .any(|(k, v)| k == "HTTPS_PROXY" && v == "http://proxy")
        );
    }

    /// The command line reads back as the arguments given, by the rules of
    /// `CommandLineToArgvW`.
    #[test]
    fn windows_command_lines_quote_as_rust_does() {
        let line = |args: &[&str]| {
            let args: Vec<String> = args.iter().map(|a| a.to_string()).collect();
            acl::command_line(r"C:\Windows\cmd.exe", &args)
        };
        assert_eq!(line(&["/C", "dir"]), r#""C:\Windows\cmd.exe" /C dir"#);
        assert_eq!(
            line(&["-Command", "echo 'a b'"]),
            r#""C:\Windows\cmd.exe" -Command "echo 'a b'""#
        );
        assert_eq!(line(&[""]), r#""C:\Windows\cmd.exe" """#);
        assert_eq!(
            line(&[r#"say "hi""#]),
            r#""C:\Windows\cmd.exe" "say \"hi\"""#
        );
        assert_eq!(line(&[r"a\b c\"]), r#""C:\Windows\cmd.exe" "a\b c\\""#);
        assert_eq!(line(&[r#"a\"b"#]), r#""C:\Windows\cmd.exe" a\\\"b"#);
    }

    /// Runs `command` in cmd in the container `name`, in `cwd`; its exit
    /// code.
    #[cfg(windows)]
    fn in_container(name: &str, cwd: &std::path::Path, command: &str) -> u32 {
        run_in_container(name, cwd, "cmd.exe", &["/C", command]).0
    }

    /// Runs `program` with `args` in the container `name`, in `cwd`; its
    /// exit code and its output.
    #[cfg(windows)]
    fn run_in_container(
        name: &str,
        cwd: &std::path::Path,
        program: &str,
        args: &[&str],
    ) -> (u32, String) {
        // The shim's process runs in the command's folder; so does this one
        // for the call. Tests run in threads, so a child process takes the
        // place of the shim.
        let exe = std::env::current_exe().unwrap();
        let out = std::process::Command::new(exe)
            .args([
                "--exact",
                "tests::helper_runs_in_a_container",
                "--ignored",
                "--nocapture",
            ])
            .env("NERVE_TEST_CONTAINER", name)
            .env("NERVE_TEST_PROGRAM", program)
            .env("NERVE_TEST_ARGS", args.join("\n"))
            .current_dir(cwd)
            .output()
            .unwrap();
        let text = format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        let code = text
            .lines()
            .find_map(|l| l.strip_prefix("exit code: "))
            .unwrap_or_else(|| panic!("no exit code: {text}"))
            .trim()
            .parse()
            .unwrap();
        (code, text)
    }

    /// Run by [`run_in_container`] in a process of its own.
    #[cfg(windows)]
    #[test]
    #[ignore = "a helper of the AppContainer tests"]
    fn helper_runs_in_a_container() {
        let var = |k: &str| std::env::var(k).unwrap();
        let args: Vec<String> = var("NERVE_TEST_ARGS")
            .split('\n')
            .map(String::from)
            .collect();
        let program = var("NERVE_TEST_PROGRAM");
        // A container that may not enter its working folder does not start.
        match appcontainer::run(
            std::path::Path::new(&program),
            &args,
            &ContainerSpec {
                no_network: std::env::var_os("NERVE_TEST_NO_NETWORK").is_some(),
                home: std::env::var_os("NERVE_TEST_HOME").is_some(),
                ..ContainerSpec::new(var("NERVE_TEST_CONTAINER"))
            },
        ) {
            Ok(code) => println!("exit code: {code}"),
            Err(e) => println!("exit code: {}\n{e}", u32::MAX),
        }
    }

    /// A command in the container reads and writes its granted folder and
    /// reaches nothing outside it; once the grant is off, the folder is
    /// closed too.
    #[cfg(windows)]
    #[test]
    fn an_appcontainer_reaches_its_granted_folder_only() {
        let base = tempfile::tempdir().unwrap();
        let granted = base.path().join("granted");
        let other = base.path().join("other");
        std::fs::create_dir_all(granted.join("sub")).unwrap();
        std::fs::create_dir_all(&other).unwrap();
        std::fs::write(granted.join("sub").join("in.txt"), "inside").unwrap();
        std::fs::write(other.join("secret.txt"), "secret").unwrap();
        let name = format!("nerve.test.{}", std::process::id());
        appcontainer::set(&granted, &name, Some(acl::masks(true, true, true)), false).unwrap();
        let d = |p: &std::path::Path| p.display().to_string();
        let run = |command: String| in_container(&name, &granted, &command);

        assert_eq!(run(r"type sub\in.txt > copy.txt".into()), 0);
        assert_eq!(
            std::fs::read_to_string(granted.join("copy.txt"))
                .unwrap()
                .trim(),
            "inside"
        );
        assert_ne!(
            run(format!(r#"type "{}\secret.txt" > leak.txt"#, d(&other))),
            0
        );
        let leak = std::fs::read_to_string(granted.join("leak.txt")).unwrap_or_default();
        assert!(!leak.contains("secret"), "{leak}");
        assert_ne!(run(format!(r#"echo x> "{}\new.txt""#, d(&other))), 0);
        assert!(!other.join("new.txt").exists());

        appcontainer::set(&granted, &name, None, false).unwrap();
        assert_ne!(run(r"type sub\in.txt > copy2.txt".into()), 0);
        assert!(!granted.join("copy2.txt").exists());
        appcontainer::remove_profile(&name).unwrap();
    }

    /// A folder closed inside a granted one is closed to the container's
    /// commands, and to what is below it, also where the grant around it
    /// comes after the closure: Windows does not hold a container to an
    /// entry that denies it, only to one that allows it nothing (#149's
    /// first run on the service, where the closed folder stayed open).
    /// `look` does not take a closed folder that inherits the grant again
    /// (as when a tool passed the list around it down) as closed.
    #[cfg(windows)]
    #[test]
    fn a_closed_folder_inside_a_granted_one_is_closed_to_its_container() {
        let base = tempfile::tempdir().unwrap();
        let granted = base.path().join("granted");
        let closed = granted.join("closed");
        std::fs::create_dir_all(closed.join("deep")).unwrap();
        std::fs::write(closed.join("deep").join("kept.txt"), "kept").unwrap();
        std::fs::write(granted.join("open.txt"), "open").unwrap();
        let name = format!("nerve.test.closed.{}", std::process::id());
        let rwx = acl::masks(true, true, true);
        let d = |p: &std::path::Path| p.display().to_string();
        // Whether `op` went through, and what PowerShell said.
        let tried = |op: String| {
            let (code, log) = run_in_container(
                &name,
                &granted,
                "powershell.exe",
                &[
                    "-NoProfile",
                    "-Command",
                    &format!("{POWERSHELL_START}try {{ {op}; exit 0 }} catch {{ $_; exit 3 }}"),
                ],
            );
            assert!(code == 0 || code == 3, "{op}: {log}");
            (code == 0, log)
        };
        let reads = || {
            let all = [
                "Get-Content -LiteralPath open.txt -ErrorAction Stop".to_string(),
                format!(
                    "Get-ChildItem -LiteralPath '{}' -ErrorAction Stop",
                    d(&closed)
                ),
                format!(
                    "Get-Content -LiteralPath '{}' -ErrorAction Stop",
                    d(&closed.join("deep").join("kept.txt"))
                ),
            ]
            .map(tried);
            let said: Vec<String> = all.iter().map(|(_, l)| l.clone()).collect();
            ((all[0].0, all[1].0, all[2].0), said)
        };
        // Closed first, granted after; then granted and closed again.
        appcontainer::set(&closed, &name, Some(acl::closed()), false).unwrap();
        appcontainer::set(&granted, &name, Some(rwx), false).unwrap();
        let (r, said) = reads();
        assert_eq!(r, (true, false, false), "{said:?}");
        assert!(appcontainer::look(&closed, &name, acl::closed()).unwrap().1);
        appcontainer::set(&closed, &name, None, false).unwrap();
        let (r, said) = reads();
        assert_eq!(r, (true, true, true), "{said:?}");
        appcontainer::set(&closed, &name, Some(acl::closed()), false).unwrap();
        let (r, said) = reads();
        assert_eq!(r, (true, false, false), "{said:?}");
        let write = format!(
            "Set-Content -LiteralPath '{}' -Value x -ErrorAction Stop",
            d(&closed.join("new.txt"))
        );
        assert!(!tried(write).0);
        assert!(!closed.join("new.txt").exists());

        // Windows passes the list of the granted folder down again, as
        // icacls does: the closed folder inherits the grant, and `look`
        // says it is not closed; the next change closes it again.
        let o = std::process::Command::new("icacls")
            .args([d(&granted).as_str(), "/grant", "*S-1-5-32-545:(OI)(CI)RX"])
            .output()
            .unwrap();
        assert!(o.status.success(), "{o:?}");
        assert!(!appcontainer::look(&closed, &name, acl::closed()).unwrap().1);
        appcontainer::set(&closed, &name, Some(acl::closed()), false).unwrap();
        assert!(appcontainer::look(&closed, &name, acl::closed()).unwrap().1);
        let (r, said) = reads();
        assert_eq!(r, (true, false, false), "{said:?}");

        for p in [&closed, &granted] {
            appcontainer::set(p, &name, None, false).unwrap();
        }
        appcontainer::remove_profile(&name).unwrap();
    }

    /// The access list of `p` as `icacls /save` writes it (SDDL, whose `AC`
    /// is `ALL APPLICATION PACKAGES`): free of the machine's language.
    #[cfg(windows)]
    fn sddl(p: &std::path::Path) -> String {
        let saved = tempfile::NamedTempFile::new().unwrap();
        let o = std::process::Command::new("icacls")
            .arg(p)
            .arg("/save")
            .arg(saved.path())
            .output()
            .unwrap();
        assert!(o.status.success(), "{o:?}");
        // icacls writes UTF-16.
        let text: Vec<u16> = std::fs::read(saved.path())
            .unwrap()
            .chunks(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        String::from_utf16_lossy(&text)
    }

    /// A folder that another program denied `ALL APPLICATION PACKAGES` keeps
    /// what it inherits for that group when the node's walk passes a
    /// grant's list down to it: only the denial of a container's own SID
    /// (as the node derives it) closes a folder ([`acl::package_sid`]). The
    /// entries are read as SDDL, whose `AC` is that group.
    #[cfg(windows)]
    #[test]
    fn a_denial_of_all_application_packages_does_not_take_its_inherited_entry_off() {
        let base = tempfile::tempdir().unwrap();
        let granted = base.path().join("granted");
        let other = granted.join("other");
        std::fs::create_dir_all(&other).unwrap();
        let d = |p: &std::path::Path| p.display().to_string();
        for args in [
            vec![d(&granted), "/grant".into(), "*S-1-15-2-1:(OI)(CI)R".into()],
            vec![d(&other), "/deny".into(), "*S-1-15-2-1:(F)".into()],
        ] {
            let o = std::process::Command::new("icacls")
                .args(&args)
                .output()
                .unwrap();
            assert!(o.status.success(), "{args:?}: {o:?}");
        }
        let inherits = |list: &str| {
            list.split('(')
                .any(|a| a.starts_with("A;") && a.contains("ID;") && a.contains(";;;AC)"))
        };
        assert!(inherits(&sddl(&other)), "{}", sddl(&other));
        let name = format!("nerve.test.group.{}", std::process::id());
        // The walk passes the grant down into `other`.
        appcontainer::set(&granted, &name, Some(acl::masks(true, true, false)), false).unwrap();
        assert!(
            inherits(&sddl(&other)),
            "taken off a folder that is not closed to a container: {}",
            sddl(&other)
        );
        appcontainer::set(&granted, &name, None, false).unwrap();
        appcontainer::remove_profile(&name).unwrap();
    }

    /// A file with more than one name that is granted itself carries the
    /// node's cap, and is not counted as capped once Windows has passed its
    /// folder's list down to it again (Explorer, `icacls`): it inherits the
    /// container's whole entry then, which a denying entry does not hold
    /// back, and the next change caps it again. The container writes it
    /// after the tool and not after the change.
    #[cfg(windows)]
    #[test]
    fn a_capped_file_is_not_in_place_once_its_folders_list_comes_down_again() {
        use std::path::{Path, PathBuf};
        let base = tempfile::tempdir().unwrap();
        let (top, store) = (base.path().join("top"), base.path().join("store"));
        for d in [&top, &store] {
            std::fs::create_dir_all(d).unwrap();
        }
        let (linked, original) = (top.join("l.txt"), store.join("o.txt"));
        std::fs::write(&original, "from the store").unwrap();
        std::fs::hard_link(&original, &linked).unwrap();
        let name = format!("nerve.test.recap.{}", std::process::id());
        let rw = acl::masks(true, true, false);
        let cap = inherit::Cap {
            containers: vec![(
                name.clone(),
                inherit::Gets::Rights(acl::file_cap(true, true, false)),
            )],
        };
        // The grant of `path` as the node puts it on, the cap for a file
        // with more than one name.
        let grant = |path: &Path, whole: bool| {
            let mut capped = |_: &Path, _: u32, _: &[PathBuf], _: Option<&str>| {
                Ok(inherit::Linked::Capped(cap.clone()))
            };
            let below = appcontainer::Below {
                links: Some(&mut capped),
                progress: &mut |_| {},
                maker: None,
            };
            appcontainer::set_below(path, &name, Some(rw), false, whole, None, below).unwrap();
        };
        let writes = || {
            let (code, log) = run_in_container(
                &name,
                &top,
                "powershell.exe",
                &[
                    "-NoProfile",
                    "-Command",
                    &format!(
                        "{POWERSHELL_START}try {{ Add-Content -LiteralPath '{}' -Value x -ErrorAction Stop; exit 0 }} catch {{ $_; exit 3 }}",
                        linked.display()
                    ),
                ],
            );
            assert!(code == 0 || code == 3, "{log}");
            code == 0
        };
        // A list that marks its inherited entries (SE_DACL_AUTO_INHERITED),
        // as one has that a tool wrote; Windows passes a folder's list down
        // to it. (A file Windows just made does not mark them, and the
        // cap's write then gives it a list that does not inherit.)
        let o = std::process::Command::new("icacls")
            .arg(&linked)
            .arg("/reset")
            .output()
            .unwrap();
        assert!(o.status.success(), "{o:?}");
        grant(&top, false);
        // Granted itself too, the cap in place of the grant's own entry.
        grant(&linked, false);
        assert!(appcontainer::look(&linked, &name, rw).unwrap().1);
        assert!(!writes(), "capped to read");

        let o = std::process::Command::new("icacls")
            .args([
                top.display().to_string().as_str(),
                "/grant",
                "*S-1-5-32-545:(OI)(CI)RX",
            ])
            .output()
            .unwrap();
        assert!(o.status.success(), "{o:?}");
        assert!(
            !appcontainer::look(&linked, &name, rw).unwrap().1,
            "{}\n{}",
            sddl(&top),
            sddl(&linked)
        );
        assert!(writes(), "the folder's whole entry comes down again");
        grant(&top, true);
        grant(&linked, false);
        assert!(appcontainer::look(&linked, &name, rw).unwrap().1);
        assert!(!writes(), "capped to read again");

        let below = appcontainer::Below {
            links: None,
            progress: &mut |_| {},
            maker: None,
        };
        appcontainer::set_below(&top, &name, None, false, false, None, below).unwrap();
        appcontainer::remove_profile(&name).unwrap();
    }

    /// Two grants on one folder, as the installed node puts the pairing's
    /// container and nerve-run on every granted folder: putting one of them
    /// on again, with a walk of everything below, changes nothing, and the
    /// lists keep their order (#40, node-1: each walk swapped them and
    /// rewrote every file below).
    #[cfg(windows)]
    #[test]
    fn a_grant_put_on_again_beside_another_changes_nothing_below() {
        let base = tempfile::tempdir().unwrap();
        let top = base.path().join("top");
        std::fs::create_dir_all(top.join("a").join("b")).unwrap();
        std::fs::write(top.join("a").join("f.txt"), "f").unwrap();
        std::fs::write(top.join("a").join("b").join("g.txt"), "g").unwrap();
        let pid = std::process::id();
        let (one, two) = (
            format!("nerve.test.twice1.{pid}"),
            format!("nerve.test.twice2.{pid}"),
        );
        let rw = acl::masks(true, true, false);
        let put = |name: &str, masks: Option<acl::Masks>, whole: bool| {
            let below = appcontainer::Below {
                links: None,
                progress: &mut |_| {},
                maker: None,
            };
            appcontainer::set_below(&top, name, masks, false, whole, None, below)
                .unwrap()
                .1
        };
        put(&one, Some(rw), false);
        put(&two, Some(rw), false);
        let file = top.join("a").join("b").join("g.txt");
        let (top_was, file_was) = (sddl(&top), sddl(&file));
        for name in [&one, &two, &one] {
            let walked = put(name, Some(rw), true);
            assert!(walked.seen >= 4, "{name}: {walked:?}");
            assert_eq!(walked.changed, 0, "{name}: {walked:?}");
        }
        assert_eq!(sddl(&top), top_was);
        assert_eq!(sddl(&file), file_was);
        put(&one, None, false);
        put(&two, None, false);
    }

    /// A grant goes along when its folder is renamed: `look` sees it at the
    /// new name and nothing at the old one, `locate` finds the folder by its
    /// file ID, and finds it gone once it is deleted. A volume that is not
    /// here is away.
    #[cfg(windows)]
    #[test]
    fn a_granted_folder_is_found_again_by_its_file_id() {
        use std::io::ErrorKind::NotFound;
        let base = tempfile::tempdir().unwrap();
        let (a, b) = (base.path().join("a"), base.path().join("b"));
        std::fs::create_dir(&a).unwrap();
        let file = base.path().join("file.txt");
        std::fs::write(&file, "x").unwrap();
        let name = format!("nerve.test.id.{}", std::process::id());
        let m = acl::masks(true, true, false);
        let other = acl::masks(true, false, false);
        for p in [&a, &file] {
            assert!(!appcontainer::look(p, &name, m).unwrap().1);
            appcontainer::set(p, &name, Some(m), false).unwrap();
            assert!(appcontainer::look(p, &name, m).unwrap().1, "{p:?}");
            assert!(!appcontainer::look(p, &name, other).unwrap().1, "{p:?}");
        }
        let id = appcontainer::look(&a, &name, m).unwrap().0.unwrap();
        assert_eq!(appcontainer::file_id(&a).unwrap(), id);
        std::fs::rename(&a, &b).unwrap();
        assert_eq!(
            appcontainer::look(&a, &name, m).unwrap_err().kind(),
            NotFound
        );
        assert!(appcontainer::look(&b, &name, m).unwrap().1, "it went along");
        let acl::Found::At(now) = appcontainer::locate(&id, &a).unwrap() else {
            panic!("not found")
        };
        assert_eq!(appcontainer::file_id(&now).unwrap(), id);
        appcontainer::set(&now, &name, None, false).unwrap();
        assert!(!appcontainer::look(&b, &name, m).unwrap().1);
        std::fs::remove_dir(&b).unwrap();
        assert_eq!(appcontainer::locate(&id, &a).unwrap(), acl::Found::Gone);
        let away = acl::FileId {
            volume: !id.volume,
            ..id
        };
        assert_eq!(appcontainer::locate(&away, &a).unwrap(), acl::Found::Away);
        appcontainer::set(&file, &name, None, false).unwrap();
    }

    /// In the container too `w` reads: a folder with `w` alone is written,
    /// read and listed. One with `x` alone runs its program (and reads it
    /// by name) and is not listed or written.
    #[cfg(windows)]
    #[test]
    fn an_appcontainer_reads_where_it_writes_and_runs_apart_from_read() {
        let base = tempfile::tempdir().unwrap();
        let (work, wo, xo) = (
            base.path().join("work"),
            base.path().join("wo"),
            base.path().join("xo"),
        );
        for d in [&work, &wo, &xo] {
            std::fs::create_dir_all(d).unwrap();
        }
        std::fs::write(wo.join("old.txt"), "old").unwrap();
        std::fs::write(xo.join("tool.cmd"), "@echo tool ran> \"%~1\"\r\n").unwrap();
        let system = std::env::var("SystemRoot").unwrap();
        std::fs::copy(
            std::path::Path::new(&system)
                .join("System32")
                .join("hostname.exe"),
            xo.join("hostname.exe"),
        )
        .unwrap();
        let name = format!("nerve.test.flags.{}", std::process::id());
        let grant = |p: &std::path::Path, r, w, x| {
            appcontainer::set(p, &name, Some(acl::masks(r, w, x)), false).unwrap()
        };
        grant(&work, true, true, true);
        grant(&wo, false, true, false);
        grant(&xo, false, false, true);
        let (w, x) = (wo.display(), xo.display());
        let ps = |c: String| {
            run_in_container(
                &name,
                &work,
                "powershell.exe",
                &["-NoProfile", "-Command", &c],
            )
        };
        // Whether `op` went through; cmd would take a quoted path as a
        // wrong name, which looks like a refusal.
        let tried = |op: String| {
            let (code, log) = ps(format!(
                "{POWERSHELL_START}try {{ {op}; exit 0 }} catch {{ $_; exit 3 }}"
            ));
            assert!(code == 0 || code == 3, "{op}: {log}");
            code == 0
        };

        // cmd opens a file it redirects to for reading as well, so the
        // write goes through .NET, which opens it for writing only.
        let write = format!(r#"[IO.File]::WriteAllText('{w}\new.txt', 'x')"#);
        let (code, log) = run_in_container(
            &name,
            &work,
            "powershell.exe",
            &["-NoProfile", "-Command", &write],
        );
        assert_eq!(code, 0, "{log}");
        assert_eq!(
            std::fs::read_to_string(wo.join("new.txt")).unwrap().trim(),
            "x"
        );
        assert!(tried(format!(
            r"Get-Content -ErrorAction Stop '{w}\old.txt' | Set-Content got.txt"
        )));
        assert!(tried(format!(
            r"Get-ChildItem -ErrorAction Stop '{w}' | Out-Null"
        )));

        let out = work.join("ran.txt");
        let (code, log) = ps(format!(
            "{POWERSHELL_START}& '{x}\\tool.cmd' '{}'; & '{x}\\hostname.exe' > host.txt; \
             exit $LASTEXITCODE",
            out.display()
        ));
        assert_eq!(code, 0, "{log}");
        assert_eq!(
            std::fs::read_to_string(&out)
                .unwrap_or_else(|e| panic!("{e}: {log}"))
                .trim(),
            "tool ran"
        );
        assert!(work.join("host.txt").exists(), "{log}");
        assert!(!tried(format!(
            r"Get-ChildItem -ErrorAction Stop '{x}' | Out-Null"
        )));
        assert!(!tried(format!(
            r"Set-Content -ErrorAction Stop -Path '{x}\no.txt' -Value x"
        )));
        assert!(!xo.join("no.txt").exists());

        for d in [&work, &wo, &xo] {
            appcontainer::set(d, &name, None, false).unwrap();
        }
        appcontainer::remove_profile(&name).unwrap();
    }

    /// A command deletes, renames and moves inside a folder it writes, but
    /// neither moves a granted folder itself nor anything out of a folder it
    /// only reads.
    #[cfg(windows)]
    #[test]
    fn an_appcontainer_moves_only_what_it_reads_and_writes() {
        let base = tempfile::tempdir().unwrap();
        let (work, outbox, empty) = (
            base.path().join("work"),
            base.path().join("outbox"),
            base.path().join("empty"),
        );
        for d in [&work, &outbox.join("sub"), &empty] {
            std::fs::create_dir_all(d).unwrap();
        }
        std::fs::write(outbox.join("secret.txt"), "secret").unwrap();
        let name = format!("nerve.test.move.{}", std::process::id());
        let grant = |p: &std::path::Path, r, w, x| {
            appcontainer::set(p, &name, Some(acl::masks(r, w, x)), false).unwrap()
        };
        grant(&work, true, true, true);
        grant(&empty, true, true, false);
        grant(&outbox, true, false, false);
        std::fs::write(work.join("a.txt"), "a").unwrap();
        let (w, o, e) = (work.display(), outbox.display(), empty.display());
        // .NET moves and deletes by name, where cmd would list the folder
        // first.
        let ps = |op: String| {
            let (code, log) = run_in_container(
                &name,
                &work,
                "powershell.exe",
                &[
                    "-NoProfile",
                    "-Command",
                    &format!("{POWERSHELL_START}try {{ {op}; exit 0 }} catch {{ $_; exit 3 }}"),
                ],
            );
            assert!(code == 0 || code == 3, "{op}: {log}");
            code == 0
        };
        for op in [
            format!(r"mkdir '{w}\d1' | Out-Null; [IO.Directory]::Move('{w}\d1', '{w}\d2')"),
            format!(r"[IO.File]::Move('{w}\a.txt', '{w}\d2\a.txt')"),
            format!(r"[IO.Directory]::Move('{w}\d2', '{e}\d2')"),
            format!(r"[IO.File]::Delete('{e}\d2\a.txt'); [IO.Directory]::Delete('{e}\d2')"),
        ] {
            assert!(ps(op.clone()), "{op}");
        }
        assert!(!empty.join("d2").exists());
        for op in [
            format!(r"[IO.Directory]::Move('{o}', '{w}\o')"),
            format!(r"[IO.Directory]::Move('{o}\sub', '{w}\sub')"),
            format!(r"[IO.File]::Move('{o}\secret.txt', '{w}\s.txt')"),
            format!(r"[IO.File]::Move('{o}\secret.txt', '{o}\s.txt')"),
            format!(r"[IO.File]::Delete('{o}\secret.txt')"),
            // A granted folder itself is not removed either.
            format!(r"[IO.Directory]::Delete('{e}')"),
        ] {
            assert!(!ps(op.clone()), "{op}");
        }
        assert!(outbox.join("secret.txt").exists() && outbox.join("sub").exists());
        assert!(empty.exists() && !work.join("o").exists() && !work.join("s.txt").exists());
        assert!(ps(format!(
            r"[IO.File]::ReadAllText('{o}\secret.txt') | Set-Content got.txt"
        )));

        for d in [&work, &empty, &outbox] {
            appcontainer::set(d, &name, None, false).unwrap();
        }
        appcontainer::remove_profile(&name).unwrap();
    }

    /// Asked for an object of its own, `set` puts no grant on a junction to
    /// another folder, a file with a second name, or a folder whose list
    /// does not inherit; it does on a plain folder. Not asked, it follows a
    /// junction as before.
    #[cfg(windows)]
    #[test]
    fn a_grant_goes_on_an_object_of_its_own_when_asked() {
        let base = tempfile::tempdir().unwrap();
        let (real, link, closed, plain) = (
            base.path().join("real"),
            base.path().join("link"),
            base.path().join("closed"),
            base.path().join("plain"),
        );
        for d in [&real, &closed, &plain] {
            std::fs::create_dir(d).unwrap();
        }
        let mklink = std::process::Command::new("cmd")
            .args(["/C", "mklink", "/J"])
            .arg(&link)
            .arg(&real)
            .output()
            .unwrap();
        assert!(mklink.status.success(), "{mklink:?}");
        let icacls = std::process::Command::new("icacls")
            .arg(&closed)
            .arg("/inheritance:d")
            .output()
            .unwrap();
        assert!(icacls.status.success(), "{icacls:?}");
        let (one, two) = (base.path().join("one.txt"), base.path().join("two.txt"));
        std::fs::write(&one, "x").unwrap();
        std::fs::hard_link(&one, &two).unwrap();
        let name = format!("nerve.test.own.{}", std::process::id());
        let m = acl::masks(true, true, false);
        let granted = |p: &std::path::Path| appcontainer::look(p, &name, m).unwrap().1;

        for p in [&link, &one, &closed] {
            let e = appcontainer::set(p, &name, Some(m), true).unwrap_err();
            assert!(e.to_string().contains("puts no grant"), "{p:?}: {e}");
        }
        assert!(!granted(&real) && !granted(&one) && !granted(&closed));
        let id = appcontainer::set(&plain, &name, Some(m), true).unwrap();
        assert!(granted(&plain));
        assert_eq!(id, Some(appcontainer::file_id(&plain).unwrap()));
        // Taking a grant off is never refused.
        appcontainer::set(&link, &name, None, true).unwrap();
        appcontainer::set(&link, &name, Some(m), false).unwrap();
        assert!(granted(&real), "it went through the junction");
        for p in [&real, &plain] {
            appcontainer::set(p, &name, None, false).unwrap();
        }
        std::fs::remove_dir(&link).unwrap();
    }

    /// A grant passes down to what is below its folder as far as it changes
    /// something: put on again with the same flags, it walks nothing, and
    /// asked to go through every folder (`whole`) it changes nothing. A
    /// folder whose list does not inherit, what is below it, and what a
    /// junction leads to keep out of it; taking it off leaves every list as
    /// it was before. A file below with a second name that `links` refuses,
    /// judged by the names the file itself gives, stops the change before
    /// the folder's own list, and `reaches` finds it and changes nothing. A
    /// folder whose list does not inherit keeps not inheriting when it gets
    /// a grant of its own and loses it again.
    #[cfg(windows)]
    #[test]
    fn a_grant_passes_down_as_far_as_it_changes_something() {
        use std::ffi::OsStr;
        use std::path::{Path, PathBuf};
        let base = tempfile::tempdir().unwrap();
        let (top, outside) = (base.path().join("top"), base.path().join("outside"));
        for d in [top.join("a\\b"), top.join("closed\\in"), outside.clone()] {
            std::fs::create_dir_all(d).unwrap();
        }
        for f in [
            top.join("a\\b\\deep.txt"),
            top.join("a\\f.txt"),
            top.join("closed\\in\\x.txt"),
            outside.join("o.txt"),
        ] {
            std::fs::write(f, "x").unwrap();
        }
        let run = |args: &[&OsStr]| {
            let o = std::process::Command::new("cmd")
                .arg("/C")
                .args(args)
                .output()
                .unwrap();
            assert!(o.status.success(), "{o:?}");
            String::from_utf8_lossy(&o.stdout).into_owned()
        };
        let closed = top.join("closed");
        run(&[
            "icacls".as_ref(),
            closed.as_ref(),
            "/inheritance:d".as_ref(),
        ]);
        let j = top.join("j");
        run(&[
            "mklink".as_ref(),
            "/J".as_ref(),
            j.as_ref(),
            outside.as_ref(),
        ]);
        let icacls = |p: &Path| run(&["icacls".as_ref(), p.as_ref()]);
        let has = |p: &Path| icacls(p).contains("S-1-15-2-");
        let protected = |p: &Path| {
            let o = std::process::Command::new("powershell.exe")
                .args(["-NoProfile", "-Command"])
                .arg(format!(
                    "(Get-Acl -LiteralPath '{}').AreAccessRulesProtected",
                    p.display()
                ))
                .output()
                .unwrap();
            String::from_utf8_lossy(&o.stdout).trim() == "True"
        };
        let all = ["", "a", "a\\b", "a\\b\\deep.txt", "a\\f.txt", "closed"];
        let lists = || all.map(|p| icacls(&top.join(p)));
        let at_first = lists();
        let name = format!("nerve.test.pass.{}", std::process::id());
        let m = acl::masks(true, true, false);
        let set = |masks: Option<acl::Masks>, whole: bool| {
            let below = appcontainer::Below {
                links: None,
                progress: &mut |_| {},
                maker: None,
            };
            appcontainer::set_below(&top, &name, masks, false, whole, None, below)
                .unwrap()
                .1
        };

        let first = set(Some(m), false);
        for p in ["a\\b\\deep.txt", "a\\f.txt", "a\\b"] {
            assert!(has(&top.join(p)), "{p}");
        }
        for p in [
            top.join("closed"),
            top.join("closed\\in\\x.txt"),
            outside.join("o.txt"),
        ] {
            assert!(!has(&p), "{p:?}");
        }
        // a, a\b, deep.txt, f.txt and the junction itself.
        assert_eq!(first.changed, 5, "{first:?}");
        assert_eq!(set(Some(m), false), inherit::Walked::default());
        let whole = set(Some(m), true);
        assert_eq!(whole.changed, 0, "{whole:?}");
        assert_eq!(
            whole.seen, 6,
            "a, a\\b, deep.txt, f.txt, closed, j: {whole:?}"
        );
        // Through another object than the one at the path: refused, and
        // nothing written.
        let elsewhere = appcontainer::file_id(&outside).unwrap();
        let below = appcontainer::Below {
            links: None,
            progress: &mut |_| {},
            maker: None,
        };
        let e = appcontainer::set_below(&top, &name, None, false, false, Some(elsewhere), below)
            .unwrap_err();
        assert_eq!(acl::untouched_by(&e), Some(acl::Untouched::Refused), "{e}");
        assert!(has(&top.join("a\\f.txt")), "nothing taken off");
        // The recorded folder moved away, nothing at the path: refused too,
        // not taken for nothing there.
        let below = appcontainer::Below {
            links: None,
            progress: &mut |_| {},
            maker: None,
        };
        let missing = top.join("moved-away");
        let e =
            appcontainer::set_below(&missing, &name, None, false, false, Some(elsewhere), below)
                .unwrap_err();
        assert_eq!(acl::untouched_by(&e), Some(acl::Untouched::Refused), "{e}");
        let other = set(Some(acl::masks(true, false, false)), false);
        assert_eq!(other.changed, 5, "{other:?}");
        set(None, false);
        assert_eq!(lists(), at_first, "every list as it was");

        // A folder that does not inherit, granted itself.
        assert!(protected(&closed));
        appcontainer::set(&closed, &name, Some(m), false).unwrap();
        assert!(has(&closed) && protected(&closed), "{}", icacls(&closed));
        appcontainer::set(&closed, &name, None, false).unwrap();
        assert!(!has(&closed) && protected(&closed), "{}", icacls(&closed));

        // A file with a second name outside, capped: it reads and runs,
        // and has a denying entry of every other right, under either name.
        let linked = top.join("a\\b\\l.txt");
        let o = outside.join("o.txt");
        std::fs::hard_link(&o, &linked).unwrap();
        let asked: std::cell::RefCell<Vec<Vec<PathBuf>>> = Default::default();
        let cap = inherit::Cap {
            containers: vec![(
                name.clone(),
                inherit::Gets::Rights(acl::file_cap(true, true, false)),
            )],
        };
        let mut capped = |_: &Path, _: u32, names: &[PathBuf], _: Option<&str>| {
            asked.borrow_mut().push(names.to_vec());
            Ok(inherit::Linked::Capped(cap.clone()))
        };
        let mut quiet = |_: inherit::Walked| {};
        let below = appcontainer::Below {
            links: Some(&mut capped),
            progress: &mut quiet,
            maker: None,
        };
        appcontainer::set_below(&top, &name, Some(m), false, false, None, below).unwrap();
        let names = asked.borrow()[0].clone();
        for n in ["outside\\o.txt", "top\\a\\b\\l.txt"] {
            assert!(names.iter().any(|p| p.ends_with(n)), "{n}: {names:?}");
        }
        assert!(appcontainer::look(&top, &name, m).unwrap().1);
        // The container's lines of a list, and whether one allows a write.
        let ours = |p: &Path| -> Vec<String> {
            icacls(p)
                .lines()
                .filter(|l| l.contains("S-1-15-2-"))
                .map(str::to_string)
                .collect()
        };
        let writes = |l: &String| ["(W", ",W", "(M)", "(F)"].iter().any(|w| l.contains(w));
        for p in [&o, &linked] {
            let lines = ours(p);
            assert!(lines.iter().any(|l| l.contains("(DENY)")), "{lines:?}");
            let allows: Vec<&String> = lines.iter().filter(|l| !l.contains("(DENY)")).collect();
            assert!(!allows.is_empty(), "{lines:?}");
            assert!(
                allows.iter().all(|l| l.contains("(R") && !writes(l)),
                "{lines:?}"
            );
        }
        assert!(ours(&top.join("a\\f.txt")).iter().any(writes));
        // Granted itself, it carries the cap in place of the grant's
        // entry, which counts as granted.
        let below = appcontainer::Below {
            links: Some(&mut capped),
            progress: &mut quiet,
            maker: None,
        };
        appcontainer::set_below(&linked, &name, Some(m), false, false, None, below).unwrap();
        assert!(
            appcontainer::look(&linked, &name, m).unwrap().1,
            "{}",
            icacls(&linked)
        );
        // Taken off, where no grant of it holds a name: neither the entry
        // nor the denial stays.
        let mut unheld = |_: &Path, _: u32, _: &[PathBuf], _: Option<&str>| {
            Ok(inherit::Linked::Capped(inherit::Cap {
                containers: vec![(name.clone(), inherit::Gets::Unheld)],
            }))
        };
        let below = appcontainer::Below {
            links: Some(&mut unheld),
            progress: &mut quiet,
            maker: None,
        };
        appcontainer::set_below(&top, &name, None, false, false, None, below).unwrap();
        assert!(ours(&o).is_empty(), "{}", icacls(&o));
        std::fs::remove_file(&linked).unwrap();
        set(None, false);
        assert_eq!(lists(), at_first, "every list as it was");
        std::fs::remove_dir(&j).unwrap();
    }

    /// A file a command linked into a granted folder from a store of its
    /// own (pnpm's, uv's, in its profile) keeps the store's list under
    /// every name, so the owner, as whom the node's service walks (a
    /// standard user, or an administrator without its group), may not even
    /// look at it. The walk opens it, and its name in the store, as the
    /// command account ([`appcontainer::Below::maker`]) and caps it, where
    /// it would stop at it with "access denied" (#149), and gives the owner
    /// read and execute on it, so the owner opens what the agent installed.
    /// The next walk, which may look at it then, changes nothing.
    /// Here the walk acts as this process' user, with the signed-in users,
    /// the administrators and privileges made unusable (so it stands for
    /// the owner), and this process is the maker.
    #[cfg(windows)]
    #[test]
    fn a_linked_file_the_walk_may_not_look_at_is_opened_as_its_maker() {
        use std::path::{Path, PathBuf};
        use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, LocalFree};
        use windows_sys::Win32::Security::Authorization::ConvertStringSidToSidW;
        use windows_sys::Win32::Security::{
            CreateRestrictedToken, DISABLE_MAX_PRIVILEGE, ImpersonateLoggedOnUser, PSID,
            RevertToSelf, SID_AND_ATTRIBUTES, TOKEN_DUPLICATE, TOKEN_IMPERSONATE, TOKEN_QUERY,
        };
        use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
        let base = tempfile::tempdir().unwrap();
        let (top, store) = (base.path().join("top"), base.path().join("store"));
        for d in [top.join("a"), store.clone()] {
            std::fs::create_dir_all(d).unwrap();
        }
        std::fs::write(top.join("a\\own.txt"), "x").unwrap();
        let run = |args: &[&str]| {
            let o = std::process::Command::new(args[0])
                .args(&args[1..])
                .output()
                .unwrap();
            assert!(o.status.success(), "{o:?}");
            String::from_utf8_lossy(&o.stdout).into_owned()
        };
        let me = run(&["whoami", "/user", "/fo", "csv", "/nh"]);
        let me = me
            .trim()
            .rsplit(',')
            .next()
            .unwrap()
            .trim_matches('"')
            .to_string();
        assert!(me.starts_with("S-1-5-"), "{me}");
        // The project: everyone, so the walk reaches it without this user.
        let (t, s) = (top.display().to_string(), store.display().to_string());
        run(&["icacls", &t, "/grant", "*S-1-1-0:(OI)(CI)F"]);
        // The store: the signed-in users alone, which the walker below is
        // not (as only the command account is on a command's own store);
        // whoever owns what is in it may only read its attributes.
        run(&[
            "icacls",
            &s,
            "/inheritance:r",
            "/grant:r",
            "*S-1-5-11:(OI)(CI)F",
            "*S-1-3-4:(OI)(CI)(RA)",
        ]);
        let (in_store, linked) = (store.join("x.js"), top.join("a\\x.js"));
        std::fs::write(&in_store, "x").unwrap();
        std::fs::hard_link(&in_store, &linked).unwrap();
        // The store's list but for the container's lines: the walk below
        // must not give the file the project's entries (everyone's, here).
        let others = |p: &Path| -> Vec<String> {
            let path = p.display().to_string();
            icacls(&[&path])
                .lines()
                .filter(|l| l.contains(":(") && !l.contains("S-1-15-2-"))
                .map(|l| l.replace(&path, "").trim().to_string())
                .collect()
        };
        let store_list = others(&in_store);
        assert!(!store_list.is_empty());

        let sid = |text: &str| {
            let mut p: PSID = std::ptr::null_mut();
            let w: Vec<u16> = text.encode_utf16().chain([0]).collect();
            // SAFETY: a NUL-terminated string; the SID is freed below.
            assert!(unsafe { ConvertStringSidToSidW(w.as_ptr(), &mut p) } != 0);
            p
        };
        // The walker is this user, as the owner the walk acts as, without
        // the groups the store lets in.
        let off = [sid("S-1-5-11"), sid("S-1-5-32-544")];
        let disable: Vec<SID_AND_ATTRIBUTES> = off
            .iter()
            .map(|&p| SID_AND_ATTRIBUTES {
                Sid: p,
                Attributes: 0,
            })
            .collect();
        let (mut process, mut walker): (HANDLE, HANDLE) =
            (std::ptr::null_mut(), std::ptr::null_mut());
        // SAFETY: this process' own token, and a restricted copy of it,
        // both closed below; the SIDs live through the call.
        unsafe {
            assert!(
                OpenProcessToken(
                    GetCurrentProcess(),
                    TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_IMPERSONATE,
                    &mut process,
                ) != 0
            );
            assert!(
                CreateRestrictedToken(
                    process,
                    DISABLE_MAX_PRIVILEGE,
                    disable.len() as u32,
                    disable.as_ptr(),
                    0,
                    std::ptr::null(),
                    0,
                    std::ptr::null(),
                    &mut walker,
                ) != 0,
                "{}",
                std::io::Error::last_os_error()
            );
            for p in off {
                LocalFree(p);
            }
        }
        // This thread acts as the walker until the end, however the test
        // ends.
        struct Back(HANDLE, HANDLE);
        impl Drop for Back {
            fn drop(&mut self) {
                // SAFETY: plain calls; the tokens opened above.
                unsafe {
                    RevertToSelf();
                    CloseHandle(self.0);
                    CloseHandle(self.1);
                }
            }
        }
        let _back = Back(process, walker);
        // SAFETY: a token of this process' own user.
        assert!(unsafe { ImpersonateLoggedOnUser(walker) } != 0);

        let name = format!("nerve.test.maker.{}", std::process::id());
        let m = acl::masks(true, true, false);
        let e = appcontainer::look(&linked, &name, m).unwrap_err();
        assert_eq!(e.kind(), std::io::ErrorKind::PermissionDenied, "{e}");
        let asked: std::cell::RefCell<Vec<(Vec<PathBuf>, Option<String>)>> = Default::default();
        let mut capped = |_: &Path, _: u32, names: &[PathBuf], owner: Option<&str>| {
            asked
                .borrow_mut()
                .push((names.to_vec(), owner.map(String::from)));
            Ok(inherit::Linked::Capped(inherit::Cap {
                containers: vec![(
                    name.clone(),
                    inherit::Gets::Rights(acl::file_cap(true, true, false)),
                )],
            }))
        };
        let below = appcontainer::Below {
            links: Some(&mut capped),
            progress: &mut |_| {},
            maker: Some(process),
        };
        appcontainer::set_below(&top, &name, Some(m), false, false, None, below).unwrap();
        // The walker, the owner, now opens what the command installed.
        assert_eq!(std::fs::read(&linked).unwrap(), b"x");
        // SAFETY: a plain call.
        unsafe { RevertToSelf() };
        let (names, owner) = asked.borrow()[0].clone();
        for n in ["store\\x.js", "top\\a\\x.js"] {
            assert!(names.iter().any(|p| p.ends_with(n)), "{n}: {names:?}");
        }
        // Who made the file (this process: its user, or the administrators
        // where it runs elevated), as the node tells a store's file by.
        assert!(
            owner.as_deref().is_some_and(|o| o.starts_with("S-1-5-")),
            "{owner:?}"
        );
        let lines = icacls(&[&in_store.display().to_string()]);
        let ours: Vec<&str> = lines.lines().filter(|l| l.contains("S-1-15-2-")).collect();
        assert!(ours.iter().any(|l| l.contains("(DENY)")), "{lines}");
        assert!(ours.iter().any(|l| !l.contains("(DENY)")), "{lines}");
        // The store's own entries, and the owner's read.
        let now = others(&in_store);
        let added: Vec<&String> = now.iter().filter(|l| !store_list.contains(l)).collect();
        assert!(store_list.iter().all(|l| now.contains(l)), "{now:?}");
        assert!(added.len() == 1 && added[0].ends_with(":(RX)"), "{now:?}");
        // The next walk, which the owner's read lets look at the file,
        // leaves its list as it is.
        // SAFETY: a token of this process' own user.
        assert!(unsafe { ImpersonateLoggedOnUser(walker) } != 0);
        let below = appcontainer::Below {
            links: Some(&mut capped),
            progress: &mut |_| {},
            maker: Some(process),
        };
        let again = appcontainer::set_below(&top, &name, Some(m), false, true, None, below);
        // SAFETY: a plain call.
        unsafe { RevertToSelf() };
        let (_, walked) = again.unwrap();
        assert!(walked.seen >= 2, "{walked:?}");
        assert_eq!(walked.changed, 0, "{walked:?}");
        let below = appcontainer::Below {
            links: None,
            progress: &mut |_| {},
            maker: None,
        };
        std::fs::remove_file(&linked).unwrap();
        appcontainer::set_below(&top, &name, None, false, false, None, below).unwrap();
    }

    /// The installed service changes the entries of the owner's folders
    /// as the owner, who may not open the token of the node's own account,
    /// which the walk asks Windows to work out what each object below
    /// inherits: the walk opens it as the node (#149's first run on the
    /// service, where every grant failed with "access denied"). Here the
    /// walk acts as this process' user, restricted to everyone's and the
    /// users' rights: the folders give everyone every right, this process'
    /// token gives neither any.
    #[cfg(windows)]
    #[test]
    fn a_walk_as_an_account_that_may_not_open_the_nodes_token_puts_its_grant_on() {
        use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, LocalFree};
        use windows_sys::Win32::Security::Authorization::ConvertStringSidToSidW;
        use windows_sys::Win32::Security::{
            CreateRestrictedToken, DISABLE_MAX_PRIVILEGE, ImpersonateLoggedOnUser, PSID,
            RevertToSelf, SID_AND_ATTRIBUTES, TOKEN_DUPLICATE, TOKEN_IMPERSONATE, TOKEN_QUERY,
        };
        use windows_sys::Win32::System::Threading::{
            GetCurrentProcess, GetCurrentThread, OpenProcessToken, OpenThreadToken,
        };
        let base = tempfile::tempdir().unwrap();
        let top = base.path().join("top");
        std::fs::create_dir(&top).unwrap();
        let t = top.display().to_string();
        let o = std::process::Command::new("icacls")
            .args([t.as_str(), "/grant", "*S-1-1-0:(OI)(CI)F"])
            .output()
            .unwrap();
        assert!(o.status.success(), "{o:?}");
        std::fs::create_dir(top.join("a")).unwrap();
        std::fs::write(top.join("a").join("f.txt"), "x").unwrap();
        // Everyone's and the users' rights: the users' let it load the
        // system's programs, which give everyone nothing.
        let only: Vec<SID_AND_ATTRIBUTES> = ["S-1-1-0", "S-1-5-32-545"]
            .iter()
            .map(|text| {
                let mut p: PSID = std::ptr::null_mut();
                let w: Vec<u16> = text.encode_utf16().chain([0]).collect();
                // SAFETY: a NUL-terminated string; the SID is freed below.
                assert!(unsafe { ConvertStringSidToSidW(w.as_ptr(), &mut p) } != 0);
                SID_AND_ATTRIBUTES {
                    Sid: p,
                    Attributes: 0,
                }
            })
            .collect();
        let (mut process, mut walker): (HANDLE, HANDLE) =
            (std::ptr::null_mut(), std::ptr::null_mut());
        // SAFETY: this process' own token, and a restricted copy of it,
        // both closed below; the SID lives through the call.
        unsafe {
            assert!(
                OpenProcessToken(
                    GetCurrentProcess(),
                    TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_IMPERSONATE,
                    &mut process,
                ) != 0
            );
            assert!(
                CreateRestrictedToken(
                    process,
                    DISABLE_MAX_PRIVILEGE,
                    0,
                    std::ptr::null(),
                    0,
                    std::ptr::null(),
                    only.len() as u32,
                    only.as_ptr(),
                    &mut walker,
                ) != 0,
                "{}",
                std::io::Error::last_os_error()
            );
            for s in &only {
                LocalFree(s.Sid);
            }
        }
        struct Back(HANDLE, HANDLE);
        impl Drop for Back {
            fn drop(&mut self) {
                // SAFETY: plain calls; the tokens opened above.
                unsafe {
                    RevertToSelf();
                    CloseHandle(self.0);
                    CloseHandle(self.1);
                }
            }
        }
        let _back = Back(process, walker);
        // SAFETY: a token of this process' own user.
        assert!(unsafe { ImpersonateLoggedOnUser(walker) } != 0);
        let mut token: HANDLE = std::ptr::null_mut();
        // SAFETY: an out pointer; a handle opened is closed at once.
        let opened = unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) };
        if opened != 0 {
            // SAFETY: the handle just opened.
            unsafe { CloseHandle(token) };
        }
        assert_eq!(opened, 0, "the walker opens this process' token");

        let name = format!("nerve.test.astoken.{}", std::process::id());
        let m = acl::masks(true, true, false);
        let below = appcontainer::Below {
            links: None,
            progress: &mut |_| {},
            maker: None,
        };
        let put = appcontainer::set_below(&top, &name, Some(m), false, false, None, below);
        // It still acts as the walker afterwards.
        let mut now: HANDLE = std::ptr::null_mut();
        // SAFETY: the thread's token, opened as the process, closed at once.
        assert!(unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1, &mut now) } != 0);
        // SAFETY: the handle just opened.
        unsafe {
            CloseHandle(now);
            RevertToSelf();
        }
        put.unwrap();
        let icacls = |p: &std::path::Path| {
            let o = std::process::Command::new("icacls")
                .arg(p)
                .output()
                .unwrap();
            String::from_utf8_lossy(&o.stdout).into_owned()
        };
        for p in ["", "a", "a\\f.txt"] {
            assert!(icacls(&top.join(p)).contains("S-1-15-2-"), "{p}");
        }
        let below = appcontainer::Below {
            links: None,
            progress: &mut |_| {},
            maker: None,
        };
        appcontainer::set_below(&top, &name, None, false, false, None, below).unwrap();
    }

    /// A granted file with more than one name whose list does not inherit
    /// (the owner made it a link of an SSH key, say) is capped as one that
    /// does, not given the grant's own entry (#149): a name in a folder
    /// closed to the container leaves it with a denial and no entry.
    #[cfg(windows)]
    #[test]
    fn a_protected_linked_file_that_is_granted_gets_the_cap() {
        use std::path::{Path, PathBuf};
        let base = tempfile::tempdir().unwrap();
        let (top, other) = (base.path().join("top"), base.path().join("other"));
        for d in [&top, &other] {
            std::fs::create_dir(d).unwrap();
        }
        let key = top.join("key");
        std::fs::write(&key, "x").unwrap();
        std::fs::hard_link(&key, other.join("key")).unwrap();
        let o = std::process::Command::new("icacls")
            .arg(&key)
            .arg("/inheritance:d")
            .output()
            .unwrap();
        assert!(o.status.success(), "{o:?}");
        let name = format!("nerve.test.protected.{}", std::process::id());
        let m = acl::masks(true, true, false);
        let mut closed = |_: &Path, _: u32, _: &[PathBuf], _: Option<&str>| {
            Ok(inherit::Linked::Capped(inherit::Cap {
                containers: vec![(name.clone(), inherit::Gets::Closed)],
            }))
        };
        let below = appcontainer::Below {
            links: Some(&mut closed),
            progress: &mut |_| {},
            maker: None,
        };
        // Not `own`: the owner put the grant on a file it chose.
        appcontainer::set_below(&key, &name, Some(m), false, false, None, below).unwrap();
        let lines = icacls(&[&key.display().to_string()]);
        let ours: Vec<&str> = lines.lines().filter(|l| l.contains("S-1-15-2-")).collect();
        assert!(!ours.is_empty(), "{lines}");
        // A denial of every right is listed as "no access".
        assert!(
            ours.iter()
                .all(|l| l.trim_end().ends_with(":(N)") || l.contains("(DENY)")),
            "{lines}"
        );
    }

    /// A folder on a volume mounted in a folder (no drive letter) is found
    /// again by its file ID after a rename, and so it is once the volume
    /// has no path at all but its own name. Makes a virtual disk, so it
    /// needs an administrator.
    #[cfg(windows)]
    #[test]
    #[ignore = "needs an administrator: mounts a virtual disk in a folder"]
    fn a_folder_on_a_volume_mounted_in_a_folder_is_found_again() {
        let base = tempfile::tempdir().unwrap();
        let (vhd, mnt) = (base.path().join("v.vhdx"), base.path().join("mnt"));
        std::fs::create_dir(&mnt).unwrap();
        let diskpart = |script: String| {
            let file = base.path().join("diskpart.txt");
            std::fs::write(&file, script).unwrap();
            let o = std::process::Command::new("diskpart")
                .arg("/s")
                .arg(&file)
                .output()
                .unwrap();
            assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stdout));
        };
        let v = vhd.display();
        diskpart(format!(
            "create vdisk file=\"{v}\" maximum=16 type=expandable\nselect vdisk file=\"{v}\"\n\
             attach vdisk\ncreate partition primary\nformat fs=ntfs quick\n\
             assign mount=\"{}\"\n",
            mnt.display()
        ));
        // Detaches the disk however the test ends, before its folder goes.
        struct Detach(std::path::PathBuf);
        impl Drop for Detach {
            fn drop(&mut self) {
                let file = self.0.with_extension("detach.txt");
                let script = format!("select vdisk file=\"{}\"\ndetach vdisk\n", self.0.display());
                if std::fs::write(&file, script).is_ok() {
                    let _ = std::process::Command::new("diskpart")
                        .arg("/s")
                        .arg(&file)
                        .output();
                }
            }
        }
        let _detach = Detach(vhd.clone());
        let (proj, old) = (mnt.join("proj"), mnt.join("proj-old"));
        std::fs::create_dir(&proj).unwrap();
        let id = appcontainer::file_id(&proj).unwrap();
        assert_ne!(
            id.volume,
            appcontainer::file_id(base.path()).unwrap().volume
        );
        std::fs::rename(&proj, &old).unwrap();
        let found = appcontainer::locate(&id, &proj).unwrap();
        let acl::Found::At(now) = &found else {
            panic!("{found:?}")
        };
        assert!(
            acl::same_path(&now.to_string_lossy(), &old.to_string_lossy()),
            "{now:?}"
        );
        // Without its mount point the volume is reached by its own name.
        let o = std::process::Command::new("mountvol")
            .arg(format!("{}\\", mnt.display()))
            .arg("/D")
            .output()
            .unwrap();
        assert!(o.status.success(), "{o:?}");
        let found = appcontainer::locate(&id, &proj).unwrap();
        let acl::Found::At(now) = &found else {
            panic!("{found:?}")
        };
        assert!(
            now.to_string_lossy().starts_with(r"\\?\Volume{")
                && now.to_string_lossy().ends_with("proj-old"),
            "{now:?}"
        );
        assert_eq!(appcontainer::file_id(now).unwrap(), id);
    }

    /// Windows PowerShell, the default shell, works in the container: it
    /// reads and writes its folder and is refused outside it.
    #[cfg(windows)]
    #[test]
    fn powershell_runs_in_an_appcontainer() {
        let base = tempfile::tempdir().unwrap();
        let granted = base.path().join("granted");
        std::fs::create_dir_all(&granted).unwrap();
        std::fs::write(granted.join("in.txt"), "inside").unwrap();
        std::fs::write(base.path().join("secret.txt"), "secret").unwrap();
        let name = format!("nerve.test.ps.{}", std::process::id());
        appcontainer::set(&granted, &name, Some(acl::masks(true, true, true)), false).unwrap();
        let script = format!(
            "{POWERSHELL_START}Get-Content in.txt | Set-Content out.txt; \
             mkdir sub | Out-Null; cd sub; Set-Content here.txt (cmd /c cd); cd ..; \
             try {{ Get-Content '{}' -ErrorAction Stop | Set-Content leak.txt }} \
             catch {{ Set-Content refused.txt $_.Exception.GetType().Name }}",
            base.path().join("secret.txt").display()
        );
        let (code, log) = run_in_container(
            &name,
            &granted,
            "powershell.exe",
            &["-NoProfile", "-Command", &script],
        );
        assert_eq!(code, 0, "{log}");
        assert_eq!(
            std::fs::read_to_string(granted.join("out.txt"))
                .unwrap_or_else(|e| panic!("{e}: {log}"))
                .trim(),
            "inside",
            "{log}"
        );
        // Native programs start where PowerShell stands.
        assert_eq!(
            std::fs::read_to_string(granted.join("sub").join("here.txt"))
                .unwrap_or_else(|e| panic!("{e}: {log}"))
                .trim(),
            granted.join("sub").display().to_string(),
            "{log}"
        );
        assert!(!granted.join("leak.txt").exists(), "{log}");
        let refused = std::fs::read_to_string(granted.join("refused.txt")).unwrap();
        assert!(refused.contains("UnauthorizedAccess"), "{refused} {log}");
        appcontainer::set(&granted, &name, None, false).unwrap();
        appcontainer::remove_profile(&name).unwrap();
    }

    /// What [`diagnose_powershell_in_the_container`] runs in the container:
    /// Windows PowerShell's own state (its providers, FileSystem drives and
    /// location, its module folders as it resolves them), whether the
    /// command reads each key, folder and file Windows PowerShell 5.1 reads
    /// at its start (`yes`, or `NO` with the error), what the failing tests
    /// run, the cmdlets it finds before and after an import by name, and
    /// every error record. Only .NET and the language until the import, as
    /// the container's PowerShell may have no cmdlet but its core ones. No
    /// line break, at which the helper splits its arguments, and no `"`,
    /// which the command line would escape.
    #[cfg(windows)]
    const DIAGNOSE_INSIDE: &str = concat!(
        r"$start = @($Error); $Error.Clear(); ",
        r"function global:Line([string]$t) { [Console]::Out.WriteLine($t); [Console]::Out.Flush() }; ",
        r"function global:Inner($e) { while ($e.InnerException) { $e = $e.InnerException }; $e }; ",
        r"function global:Probe([string]$what, [scriptblock]$probe) { try { $r = & $probe; ",
        r"Line ('yes ' + $what + ': ' + $r) } catch { $e = Inner $_.Exception; ",
        r"Line ('NO  ' + $what + ': ' + $e.GetType().FullName + ': ' + $e.Message) } }; ",
        r"function global:List([string]$p) { '' + ([IO.Directory]::GetFileSystemEntries($p)).Count + ' entries' }; ",
        r"function global:ReadAll([string]$p) { '' + ([IO.File]::ReadAllBytes($p)).Length + ' bytes' }; ",
        r"function global:Key([string]$k, [string[]]$values) { ",
        r"$o = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($k); if (-not $o) { throw 'no such key' }; ",
        r"$s = @(); foreach ($v in $values) { $s += ($v + '=' + $o.GetValue($v)) }; ",
        r"$s += ('subkeys ' + ($o.GetSubKeyNames() -join ',')); $s -join ' ' }; ",
        r"function global:Dump($records) { foreach ($r in $records) { ",
        r"$e = if ($r -is [Exception]) { $r } else { $r.Exception }; ",
        r"Line ('-- ' + $r.FullyQualifiedErrorId + ' | ' + $r.CategoryInfo + ' | target: ' + $r.TargetObject); ",
        r"if ($r.InvocationInfo) { Line ('   at: ' + $r.InvocationInfo.PositionMessage) }; ",
        r"while ($e) { Line ('   ' + $e.GetType().FullName + ': ' + $e.Message); ",
        r"if ($e.FileName) { Line ('   file: ' + $e.FileName) }; if ($e.FusionLog) { Line ('   fusion log: ' + $e.FusionLog) }; ",
        r"if ($e.ItemName) { Line ('   item: ' + $e.ItemName) }; $e = $e.InnerException }; ",
        r"try { Line (($r | Format-List * -Force | Out-String -Width 160).Trim()) } ",
        r"catch { Line ('   (Format-List: ' + (Inner $_.Exception).Message + ')') } } }; ",
        r"$win = [Environment]::GetEnvironmentVariable('SystemRoot'); $ps = $win + '\System32\WindowsPowerShell\v1.0'; ",
        r"$net = $win + '\Microsoft.NET'; $gac = $net + '\assembly\GAC_MSIL\'; ",
        r"$native = $win + '\assembly\NativeImages_v4.0.30319_64'; ",
        r"Line '==== in the container: Windows PowerShell at its start'; ",
        r"Line ('PSVersion ' + $PSVersionTable.PSVersion + ', CLR ' + $PSVersionTable.CLRVersion + ', PSHOME ' + $PSHOME); ",
        r"foreach ($n in 'TEMP', 'TMP', 'LOCALAPPDATA', 'USERPROFILE', 'PSModulePath', 'PSModuleAnalysisCachePath') { ",
        r"Line ($n + '=' + [Environment]::GetEnvironmentVariable($n)) }; ",
        r"Line ('the LocalApplicationData folder: ' + [Environment]::GetFolderPath('LocalApplicationData')); ",
        r"Probe 'the providers' { $n = @(); foreach ($p in $ExecutionContext.SessionState.Provider.GetAll()) { $n += $p.Name }; $n -join ', ' }; ",
        r"Probe 'the FileSystem drives' { $n = @(); ",
        r"foreach ($d in $ExecutionContext.SessionState.Drive.GetAllForProvider('FileSystem')) { $n += ($d.Name + '=' + $d.Root) }; ",
        r"if (-not $n) { throw 'none' }; $n -join ', ' }; ",
        r"Probe 'the current FileSystem location' { $ExecutionContext.SessionState.Path.CurrentFileSystemLocation.ProviderPath }; ",
        r"Probe 'the current location' { $ExecutionContext.SessionState.Path.CurrentLocation.Path }; ",
        r"foreach ($m in [Environment]::GetEnvironmentVariable('PSModulePath').Split(';')) { if ($m) { ",
        r"Probe ('the module folder ' + $m + ' as PowerShell resolves it') { $x = $null; ",
        r"$ExecutionContext.SessionState.Path.GetResolvedProviderPathFromPSPath($m, [ref]$x) -join ', ' } } }; ",
        r"Line ('---- the drives, as the FileSystem provider looks at them at its start'); ",
        r"try { $drives = [IO.DriveInfo]::GetDrives() } catch { $drives = @(); Line ('NO  the drives: ' + (Inner $_.Exception).Message) }; ",
        r"foreach ($v in $drives) { Probe ('drive ' + $v.Name) { '' + $v.DriveType + ', RootDirectory.Exists ' + $v.RootDirectory.Exists }; ",
        r"Probe ('list ' + $v.Name) { List $v.Name } }; ",
        r"$w = [Environment]::CurrentDirectory; while ($w) { Line ('Directory.Exists ' + $w + ': ' + [IO.Directory]::Exists($w)); ",
        r"$w = [IO.Path]::GetDirectoryName($w) }; ",
        r"Line '---- the keys, folders and files it reads'; ",
        r"foreach ($k in 'SOFTWARE\Microsoft\PowerShell\1\PowerShellEngine', 'SOFTWARE\Microsoft\PowerShell\3\PowerShellEngine') { ",
        r"Probe ('HKLM\' + $k) { Key $k 'ApplicationBase', 'RuntimeVersion', 'PowerShellVersion' } }; ",
        r"foreach ($k in 'SOFTWARE\Microsoft\PowerShell\1\PowerShellSnapIns', 'SOFTWARE\Microsoft\PowerShell\3\PowerShellSnapIns', ",
        r"'SOFTWARE\Microsoft\.NETFramework', 'SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full') { ",
        r"Probe ('HKLM\' + $k) { Key $k 'InstallRoot', 'Release' } }; ",
        r"foreach ($p in $ps, ($ps + '\Modules'), ($ps + '\Modules\Microsoft.PowerShell.Management'), ",
        r"($ps + '\Modules\Microsoft.PowerShell.Utility'), ([Environment]::GetEnvironmentVariable('ProgramFiles') + '\WindowsPowerShell\Modules'), ",
        r"($gac + 'System.Management.Automation'), ($gac + 'Microsoft.PowerShell.Commands.Management'), ",
        r"($gac + 'Microsoft.PowerShell.Commands.Utility'), ($gac + 'Microsoft.PowerShell.ConsoleHost'), ",
        r"($win + '\assembly'), $native) { Probe ('list ' + $p) { List $p } }; ",
        r"foreach ($p in ($ps + '\powershell.exe'), ($ps + '\types.ps1xml'), ($ps + '\DotNetTypes.format.ps1xml'), ",
        r"($ps + '\Modules\Microsoft.PowerShell.Management\Microsoft.PowerShell.Management.psd1'), ",
        r"($ps + '\Modules\Microsoft.PowerShell.Utility\Microsoft.PowerShell.Utility.psd1'), ",
        r"($net + '\Framework64\v4.0.30319\Config\machine.config')) { Probe ('read ' + $p) { ReadAll $p } }; ",
        r"foreach ($a in 'System.Management.Automation', 'Microsoft.PowerShell.Commands.Management', 'Microsoft.PowerShell.Commands.Utility') { ",
        r"Probe ('read ' + $a + '.dll in GAC_MSIL') { $d = [IO.Directory]::GetDirectories($gac + $a)[0]; ReadAll ($d + '\' + $a + '.dll') }; ",
        r"Probe ('read the native image of ' + $a) { $f = @(); ",
        r"foreach ($d in [IO.Directory]::GetDirectories($native, $a.Substring(0, 8) + '*')) { ",
        r"$f += [IO.Directory]::GetFiles($d, $a + '.ni.dll', 'AllDirectories') }; ",
        r"if (-not $f) { throw 'none found' }; $f[0] + ', ' + (ReadAll $f[0]) } }; ",
        r"Line '---- what the failing tests run, and the errors it leaves'; $Error.Clear(); ",
        r"$null = New-PSDrive -Name Work -PSProvider FileSystem -Root ([Environment]::CurrentDirectory) -Scope Global; ",
        r"& ($win + '\System32\cmd.exe') /c echo a native program started by its whole path; ",
        r"cmd.exe /c echo a native program started by its name; ",
        r"Get-Content -LiteralPath ([Environment]::CurrentDirectory + '\in.txt'); 'x' > out.txt; ",
        r"$tried = @($Error); ",
        r"Line '---- the cmdlets'; ",
        r"Probe 'the snap-ins' { $n = @(); foreach ($s in Get-PSSnapin) { $n += $s.Name }; $n -join ', ' }; ",
        r"Probe 'the modules found (Get-Module -ListAvailable)' { $n = @(); ",
        r"foreach ($s in Get-Module -ListAvailable -ErrorAction Stop) { $n += $s.Name }; [string]$n.Count + ': ' + ($n -join ', ') }; ",
        r"Probe 'New-PSDrive found by its name alone' { (Get-Command New-PSDrive -ErrorAction Stop).Source }; ",
        r"Probe 'Import-Module Microsoft.PowerShell.Management, Microsoft.PowerShell.Utility' { $n = @(); ",
        r"foreach ($m in Import-Module Microsoft.PowerShell.Management, Microsoft.PowerShell.Utility -PassThru -ErrorAction Stop) { ",
        r"$n += $m.Path }; $n -join ', ' }; ",
        r"Probe 'New-PSDrive found after the import' { (Get-Command New-PSDrive -ErrorAction Stop).Source }; ",
        r"Probe 'New-PSDrive Work and Set-Location Work:\ after the import' { ",
        r"$null = New-PSDrive -Name Work -PSProvider FileSystem -Root ([Environment]::CurrentDirectory) -Scope Global -ErrorAction Stop; ",
        r"Set-Location Work:\ -ErrorAction Stop; Get-Content in.txt -ErrorAction Stop }; ",
        r"Line ('---- the errors at the start (' + $start.Count + ')'); Dump $start; ",
        r"Line ('---- the errors of what the failing tests run (' + $tried.Count + ')'); Dump $tried; ",
        r"exit 0",
    );

    /// What [`diagnose_powershell_in_the_container`] runs in the container
    /// with cmd: the same keys, folders and files without .NET.
    #[cfg(windows)]
    const DIAGNOSE_CMD: &str = concat!(
        r"echo ==== in the container: cmd & ",
        r"reg query HKLM\SOFTWARE\Microsoft\PowerShell\1\PowerShellEngine & ",
        r"reg query HKLM\SOFTWARE\Microsoft\PowerShell\3\PowerShellEngine & ",
        r"reg query HKLM\SOFTWARE\Microsoft\PowerShell\1\PowerShellSnapIns & ",
        r"echo ---- dir C:\ & dir /b C:\ & echo ---- dir D:\ & dir /b D:\ & ",
        r"echo ---- dir WindowsPowerShell & dir /b %SystemRoot%\System32\WindowsPowerShell\v1.0\Modules & ",
        r"echo ---- dir GAC_MSIL & dir /b %SystemRoot%\Microsoft.NET\assembly\GAC_MSIL\System.Management.Automation & ",
        r"echo ---- dir assembly & dir /b %SystemRoot%\assembly & ",
        r"echo ---- read machine.config & copy /y %SystemRoot%\Microsoft.NET\Framework64\v4.0.30319\Config\machine.config NUL & ",
        r"echo ---- read types.ps1xml & copy /y %SystemRoot%\System32\WindowsPowerShell\v1.0\types.ps1xml NUL",
    );

    /// What [`diagnose_powershell_in_the_container`] runs outside the
    /// container: the permissions of the drives' roots, of the folders above
    /// the granted one (`NERVE_DIAG_FOLDER`) and of what Windows PowerShell
    /// reads at its start, each with its entry for ALL APPLICATION PACKAGES
    /// (S-1-15-2-1), to compare with a stock Windows.
    #[cfg(windows)]
    const DIAGNOSE_OUTSIDE: &str = concat!(
        r"function Line([string]$t) { [Console]::Out.WriteLine($t) }; ",
        r"function Packages($a, [string]$rights) { $n = @(); foreach ($r in $a.Access) { ",
        r"if ($r.IdentityReference.Value -match 'ALL APPLICATION PACKAGES' -or $r.IdentityReference.Value -eq 'S-1-15-2-1') { ",
        r"$n += ('' + $r.AccessControlType + ' ' + $r.$rights + ', inherited ' + $r.IsInherited) } }; ",
        r"Line ('  ALL APPLICATION PACKAGES: ' + $(if ($n) { $n -join '; ' } else { 'no entry' })) }; ",
        r"$win = $env:SystemRoot; $ps = $win + '\System32\WindowsPowerShell\v1.0'; ",
        r"$net = $win + '\Microsoft.NET'; $gac = $net + '\assembly\GAC_MSIL\'; ",
        r"Line ('==== outside the container: ' + [Environment]::OSVersion.VersionString + ', ' + ",
        r"(Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').ProductName); ",
        r"$paths = @(); foreach ($v in [IO.DriveInfo]::GetDrives()) { if ($v.DriveType -eq 'Fixed') { $paths += $v.Name } }; ",
        r"$w = $env:NERVE_DIAG_FOLDER; ",
        r"while ($w -and $paths -notcontains $w) { $paths += $w; $w = [IO.Path]::GetDirectoryName($w) }; ",
        r"$paths += $win, ($win + '\System32'), $ps, ($ps + '\Modules'), ($ps + '\Modules\Microsoft.PowerShell.Management'), ",
        r"($ps + '\Modules\Microsoft.PowerShell.Management\Microsoft.PowerShell.Management.psd1'), ($ps + '\types.ps1xml'), ",
        r"($env:ProgramFiles + '\WindowsPowerShell\Modules'), $net, ($net + '\assembly'), ($gac + 'System.Management.Automation'), ",
        r"([IO.Directory]::GetDirectories($gac + 'System.Management.Automation')[0]), ",
        r"($gac + 'Microsoft.PowerShell.Commands.Management'), ($win + '\assembly'), ",
        r"($win + '\assembly\NativeImages_v4.0.30319_64'), ($net + '\Framework64\v4.0.30319\Config\machine.config'); ",
        r"foreach ($p in $paths) { Line ('---- ' + $p); foreach ($l in (icacls $p 2>&1)) { Line ('  ' + $l) }; ",
        r"try { $a = Get-Acl -LiteralPath $p -ErrorAction Stop; Packages $a 'FileSystemRights'; Line ('  SDDL ' + $a.Sddl) } ",
        r"catch { Line ('  Get-Acl: ' + $_.Exception.Message) } }; ",
        r"foreach ($k in 'SOFTWARE\Microsoft\PowerShell', 'SOFTWARE\Microsoft\PowerShell\1', ",
        r"'SOFTWARE\Microsoft\PowerShell\1\PowerShellEngine', 'SOFTWARE\Microsoft\PowerShell\1\PowerShellSnapIns', ",
        r"'SOFTWARE\Microsoft\PowerShell\3\PowerShellEngine', 'SOFTWARE\Microsoft\.NETFramework') { ",
        r"Line ('---- HKLM\' + $k); try { $a = Get-Acl -Path ('HKLM:\' + $k) -ErrorAction Stop; Packages $a 'RegistryRights'; ",
        r"foreach ($l in $a.AccessToString.Split([Environment]::NewLine)) { if ($l) { Line ('  ' + $l) } }; ",
        r"Line ('  SDDL ' + $a.Sddl) } catch { Line ('  Get-Acl: ' + $_.Exception.Message) } }",
    );

    /// What [`powershell_runs_in_an_appcontainer`] starts with, run in the
    /// container `name` in `granted` (which holds `in.txt`), said under
    /// `title` with the time it took and whether it read and wrote.
    #[cfg(windows)]
    fn diagnose_the_tests_start(title: &str, name: &str, granted: &std::path::Path) {
        let _ = std::fs::remove_file(granted.join("out.txt"));
        let script = format!(
            "{POWERSHELL_START}Get-Content in.txt | Set-Content out.txt; (Get-Command New-PSDrive).Source"
        );
        let started = std::time::Instant::now();
        let (code, log) = run_in_container(
            name,
            granted,
            "powershell.exe",
            &["-NoProfile", "-Command", &script],
        );
        let out = std::fs::read_to_string(granted.join("out.txt"));
        println!(
            "==== {title}: the failing tests' start ended with {code} after {:.1} s; out.txt: {out:?}\n{log}",
            started.elapsed().as_secs_f64()
        );
    }

    /// The roots of the fixed drives of this machine, as `C:\`.
    #[cfg(windows)]
    fn drive_roots() -> Vec<String> {
        use windows_sys::Win32::Storage::FileSystem::{GetDriveTypeW, GetLogicalDrives};
        const DRIVE_FIXED: u32 = 3;
        // SAFETY: no arguments.
        let mask = unsafe { GetLogicalDrives() };
        (0..26u8)
            .filter(|i| mask & (1 << i) != 0)
            .map(|i| format!("{}:\\", char::from(b'A' + i)))
            .filter(|root| {
                let wide: Vec<u16> = root.encode_utf16().chain([0]).collect();
                // SAFETY: a NUL-terminated string.
                unsafe { GetDriveTypeW(wide.as_ptr()) == DRIVE_FIXED }
            })
            .collect()
    }

    /// `icacls` with `args`, its output.
    #[cfg(windows)]
    fn icacls(args: &[&str]) -> String {
        match std::process::Command::new("icacls").args(args).output() {
            Ok(o) => format!(
                "{}{}",
                String::from_utf8_lossy(&o.stdout),
                String::from_utf8_lossy(&o.stderr)
            ),
            Err(e) => format!("cannot start icacls: {e}"),
        }
    }

    /// A diagnostic for #105 and #106, run by hand on a runner where Windows
    /// PowerShell in the container finds none of its own cmdlets (repeat.yml,
    /// filter `--ignored --exact tests::diagnose_powershell_in_the_container
    /// --nocapture`). In the container the product makes, started as the
    /// failing tests start it, Windows PowerShell and then cmd say what they
    /// can read of what PowerShell reads at its start, and PowerShell its
    /// state and errors; outside it, the permissions of the same places, to
    /// compare with a stock Windows. It passes whatever it finds.
    ///
    /// PowerShell's FileSystem provider makes a drive only of a root whose
    /// attributes it reads, and without a drive it resolves no module folder.
    /// So on a GitHub runner (`GITHUB_ACTIONS`), which goes with its job, a
    /// fixed drive's root without an entry for ALL APPLICATION PACKAGES gets
    /// one that reads its attributes, on the root alone, the tests' start
    /// runs again, and the entries go. Nothing is changed elsewhere.
    #[cfg(windows)]
    #[test]
    #[ignore = "a diagnostic, run by hand with --nocapture"]
    fn diagnose_powershell_in_the_container() {
        let base = tempfile::tempdir().unwrap();
        let granted = base.path().join("granted");
        std::fs::create_dir_all(&granted).unwrap();
        std::fs::write(granted.join("in.txt"), "inside").unwrap();
        let name = format!("nerve.test.diag.{}", std::process::id());
        appcontainer::set(&granted, &name, Some(acl::masks(true, true, true)), false).unwrap();
        diagnose_the_tests_start("as it is", &name, &granted);
        let (code, log) = run_in_container(
            &name,
            &granted,
            "powershell.exe",
            &["-NoProfile", "-Command", DIAGNOSE_INSIDE],
        );
        println!("{log}\n==== Windows PowerShell in the container ended with {code}\n");
        let (code, log) = run_in_container(&name, &granted, "cmd.exe", &["/C", DIAGNOSE_CMD]);
        println!("{log}\n==== cmd in the container ended with {code}\n");
        // Windows PowerShell's own module path, as in the container: the
        // runner's would load PowerShell 7's modules.
        match std::process::Command::new("powershell.exe")
            .args(["-NoProfile", "-Command", DIAGNOSE_OUTSIDE])
            .env_clear()
            .envs(acl::container_env(std::env::vars_os()))
            .env("NERVE_DIAG_FOLDER", &granted)
            .output()
        {
            Ok(out) => println!(
                "{}{}\n==== outside the container: {}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr),
                out.status
            ),
            Err(e) => println!("==== outside the container: cannot start powershell.exe: {e}"),
        }
        if std::env::var_os("GITHUB_ACTIONS").is_some_and(|v| v == "true") {
            let mut given = Vec::new();
            for root in drive_roots() {
                if icacls(&[&root]).contains("ALL APPLICATION PACKAGES") {
                    continue;
                }
                println!(
                    "==== {root} gets ALL APPLICATION PACKAGES:(RA)\n{}",
                    icacls(&[&root, "/grant", "*S-1-15-2-1:(RA)"])
                );
                given.push(root);
            }
            diagnose_the_tests_start("with the roots' attributes readable", &name, &granted);
            for root in given {
                println!(
                    "==== {root} loses the entry again\n{}",
                    icacls(&[&root, "/remove:g", "*S-1-15-2-1"])
                );
            }
        }
        appcontainer::set(&granted, &name, None, false).unwrap();
        appcontainer::remove_profile(&name).unwrap();
    }

    /// In the container, `cd` and `pushd` go to whole paths of the folders
    /// the command may see, and with `..` up out of its working folder into
    /// one of them, and native programs start there. A folder it may not
    /// see stays refused, with `$?` false and the location kept, also when
    /// `..` names it or the error action keeps the error quiet. An escaped
    /// `-Path`, one with `..` before a wildcard and one with a wildcard
    /// right after `\` go where the cmdlet would take them, `cd $null`
    /// fails as the cmdlet does, a new drive leaves `$Error` empty, and a
    /// folder piped to `cd` or `pushd` is bound as the cmdlet binds it.
    #[cfg(windows)]
    #[test]
    fn powershell_changes_to_whole_paths_in_an_appcontainer() {
        let base = tempfile::tempdir().unwrap();
        let (granted, other, hidden) = (
            base.path().join("granted"),
            base.path().join("other"),
            base.path().join("hidden"),
        );
        for d in [
            &granted.join("app").join("b[1]"),
            &granted.join("app").join("lib"),
            &granted.join("app").join("sub").join("lib"),
            &granted.join("lib"),
            &granted.join("sub"),
            &other,
            &hidden,
        ] {
            std::fs::create_dir_all(d).unwrap();
        }
        let name = format!("nerve.test.cd.{}", std::process::id());
        for d in [&granted, &other] {
            appcontainer::set(d, &name, Some(acl::masks(true, true, true)), false).unwrap();
        }
        let (g, o, h) = (granted.display(), other.display(), hidden.display());
        let ps = |cwd: &std::path::Path, script: String| {
            run_in_container(
                &name,
                cwd,
                "powershell.exe",
                &["-NoProfile", "-Command", &script],
            )
        };
        let (code, log) = ps(
            &granted.join("app"),
            format!(
                "{POWERSHELL_START}Get-ChildItem '{g}' -Directory -Filter lib | cd; \
                 Set-Content pipe.txt (cmd /c cd); cd '{g}\\app'; \
                 Get-Item -LiteralPath 'b[1]' | pushd; Set-Content -LiteralPath pb.txt (cmd /c cd); popd; \
                 cd 'b`[1`]'; Set-Content -LiteralPath br.txt (cmd /c cd); \
                 cd ..; $Error.Clear(); cd ..\\l*; $errors = $Error.Count; \
                 Set-Content lib.txt (cmd /c cd); Set-Content '{g}\\errors.txt' $errors; \
                 cd '{g}\\app'; cd sub; cd \\l*; Set-Content root.txt (cmd /c cd); cd '{g}\\app'; \
                 cd ..\\app\\..\\sub; Set-Content climb.txt (cmd /c cd); \
                 cd ..\\app; Set-Content app.txt (cmd /c cd); \
                 cd ..; Set-Content up.txt (cmd /c cd); \
                 cd '{g}\\sub'; Set-Content here.txt (cmd /c cd); \
                 cd '{o}'; Set-Content there.txt (cmd /c cd); \
                 pushd '{g}\\app'; Set-Content back.txt (cmd /c cd); popd; \
                 Set-Content popped.txt (cmd /c cd); \
                 cd '{h}'; $ok = $?; Set-Content '{g}\\hidden.txt' $ok; \
                 Set-Content '{g}\\stayed.txt' (cmd /c cd); \
                 try {{ cd '{h}' -ErrorAction Stop; Set-Content wrong.txt x }} \
                 catch {{ Set-Content '{g}\\refused.txt' $_.Exception.GetType().Name }}"
            ),
        );
        assert_eq!(code, 0, "{log}");
        let read = |p: std::path::PathBuf, log: &str| {
            std::fs::read_to_string(&p)
                .unwrap_or_else(|e| panic!("{}: {e}: {log}", p.display()))
                .trim()
                .to_string()
        };
        let (sub, app) = (granted.join("sub"), granted.join("app"));
        let bracket = app.join("b[1]");
        assert_eq!(
            read(bracket.join("br.txt"), &log),
            bracket.display().to_string()
        );
        assert_eq!(
            read(bracket.join("pb.txt"), &log),
            bracket.display().to_string()
        );
        let lib = granted.join("lib");
        assert_eq!(read(lib.join("lib.txt"), &log), lib.display().to_string());
        // A folder piped from `Get-ChildItem` is its whole path, not its name.
        assert_eq!(read(lib.join("pipe.txt"), &log), lib.display().to_string());
        // A `cd` that made a drive leaves nothing in `$Error`.
        assert_eq!(read(granted.join("errors.txt"), &log), "0");
        // `\l*` is `lib` at the root of `Work:`, not below `sub`.
        let root = app.join("lib");
        assert_eq!(
            read(root.join("root.txt"), &log),
            root.display().to_string()
        );
        assert_eq!(read(sub.join("climb.txt"), &log), sub.display().to_string());
        assert_eq!(read(app.join("app.txt"), &log), app.display().to_string());
        assert_eq!(read(granted.join("up.txt"), &log), g.to_string());
        assert_eq!(read(sub.join("here.txt"), &log), sub.display().to_string());
        assert_eq!(read(other.join("there.txt"), &log), o.to_string());
        assert_eq!(read(app.join("back.txt"), &log), app.display().to_string());
        assert_eq!(read(other.join("popped.txt"), &log), o.to_string());
        assert_eq!(read(granted.join("hidden.txt"), &log), "False");
        assert_eq!(read(granted.join("stayed.txt"), &log), o.to_string());
        assert!(granted.join("refused.txt").exists(), "{log}");
        assert!(!other.join("wrong.txt").exists() && !hidden.join("wrong.txt").exists());

        // The folder above `other` is not granted: `cd ..` fails and stays,
        // and a command that ends with it fails, also with its errors kept
        // quiet. `cd $null` fails as Windows PowerShell's own `cd` does.
        let (code, log) = ps(
            &other,
            format!(
                "{POWERSHELL_START}cd $null; $ok = $?; Set-Content null.txt $ok; \
                 cd ..; $ok = $?; Set-Content up.txt $ok; \
                 Set-Content where.txt (cmd /c cd); \
                 $ErrorActionPreference = 'SilentlyContinue'; cd ..; $ok = $?; \
                 Set-Content quiet.txt $ok; cd '{h}' -ErrorAction Ignore"
            ),
        );
        assert_eq!(code, 1, "{log}");
        assert_eq!(read(other.join("null.txt"), &log), "False");
        assert_eq!(read(other.join("up.txt"), &log), "False");
        assert_eq!(read(other.join("where.txt"), &log), o.to_string());
        assert_eq!(read(other.join("quiet.txt"), &log), "False");
        for d in [&granted, &other] {
            appcontainer::set(d, &name, None, false).unwrap();
        }
        appcontainer::remove_profile(&name).unwrap();
    }

    /// The start of a PowerShell command in a container stands in for `cd`
    /// and `pushd`, and is whole: no `"`, which the Windows command line
    /// would escape, and its brackets close outside its quoted strings.
    #[test]
    fn the_powershell_start_takes_over_cd_and_pushd() {
        for f in [
            "function global:Set-Location",
            "function global:Push-Location",
        ] {
            assert!(POWERSHELL_START.contains(f), "{f}");
        }
        for cmd in [
            r"& $cmd @a",
            r"$PSCmdlet.WriteError($_)",
            r"{ return $full }",
            r"[Management.Automation.WildcardPattern]::Unescape($v)",
            r"$s = $v -split '[\\/]'",
            r"$a['ErrorAction'] = 'Continue'; & $cmd @a",
            r"-ErrorAction Ignore) { $n++ }",
            r"$PSCmdlet.MyInvocation.ExpectingInput 2>&1",
            r"$a['LiteralPath'] = [string]$q[$n].Value",
            r"($i -eq 1 -and $s[0] -eq '')",
            r"ValueFromPipelineByPropertyName = $true)] $Path, ",
            r"'Microsoft.PowerShell.Management\Set-Location'",
            r"'Microsoft.PowerShell.Management\Push-Location'",
        ] {
            assert!(POWERSHELL_START.contains(cmd), "{cmd}");
        }
        assert!(!POWERSHELL_START.contains('"'));
        assert!(POWERSHELL_START.ends_with("; "));
        // The core modules first: a container may not load them on its own.
        assert!(POWERSHELL_START.starts_with(
            "Import-Module Microsoft.PowerShell.Management, Microsoft.PowerShell.Utility -ErrorAction Stop; "
        ));
        let (mut quoted, mut open) = (false, Vec::new());
        for c in POWERSHELL_START.chars() {
            match c {
                '\'' => quoted = !quoted,
                '(' | '{' | '[' if !quoted => open.push(c),
                ')' | '}' | ']' if !quoted => {
                    let want = match c {
                        ')' => '(',
                        '}' => '{',
                        _ => '[',
                    };
                    assert_eq!(open.pop(), Some(want), "{POWERSHELL_START}");
                }
                _ => {}
            }
        }
        assert!(!quoted && open.is_empty(), "{POWERSHELL_START}");
    }

    /// Runs `script` in `/bin/sh` under `spec`; whether it succeeded.
    #[cfg(target_os = "linux")]
    fn confined_sh(spec: &LandlockSpec, script: &str) -> bool {
        use std::os::unix::process::CommandExt;
        let mut rs = Some(landlock_rules::prepare(spec).unwrap());
        let mut cmd = std::process::Command::new("/bin/sh");
        cmd.arg("-c").arg(script);
        // SAFETY: the closure only makes the Landlock syscalls on a ruleset
        // built before the fork.
        unsafe {
            cmd.pre_exec(move || match rs.take() {
                Some(r) => landlock_rules::enforce(r),
                None => Ok(()),
            });
        }
        cmd.status().unwrap().success()
    }

    /// The rules hold in a real child: writes inside the read-write folder
    /// work, writes elsewhere fail. Skipped where the kernel has no Landlock.
    #[cfg(target_os = "linux")]
    #[test]
    fn landlock_confines_writes() {
        if landlock_rules::abi_version().is_none() {
            eprintln!("skipped: no Landlock here");
            return;
        }
        let tmp = std::env::temp_dir();
        let rw = tempfile::tempdir_in(&tmp).unwrap();
        let other = tempfile::tempdir_in(&tmp).unwrap();
        let spec = LandlockSpec {
            read: [system_dirs(), vec![rw.path().into()]].concat(),
            write: [system_writable(), vec![rw.path().into()]].concat(),
            exec: system_dirs(),
            no_network: false,
            unix: Vec::new(),
        };
        let run = |target: &std::path::Path| {
            confined_sh(&spec, &format!("echo x > {}", target.display()))
        };
        assert!(run(&rw.path().join("ok")));
        assert!(rw.path().join("ok").exists());
        assert!(!run(&other.path().join("no")));
        assert!(!other.path().join("no").exists());
    }

    /// The system's own paths are given at their real place (`/bin`, `/dev/log`
    /// are links on many systems), since the shim leaves out a rule whose path
    /// is a link ([`landlock_rules`]).
    #[cfg(target_os = "linux")]
    #[test]
    fn the_systems_paths_are_not_links() {
        for p in [system_dirs(), system_writable(), kept_sockets()].concat() {
            assert_eq!(std::fs::canonicalize(&p).unwrap(), p);
        }
        let dirs = system_dirs();
        assert!(
            dirs.iter()
                .all(|p| dirs.iter().filter(|q| *q == p).count() == 1)
        );
    }

    /// A rule's path is opened without following a link: a folder the node
    /// judged as a plain one, and that is a link now, or lies behind one,
    /// gives its flags nowhere. Skipped where the kernel has no Landlock.
    #[cfg(target_os = "linux")]
    #[test]
    fn landlock_rules_do_not_follow_a_link() {
        if landlock_rules::abi_version().is_none() {
            eprintln!("no Landlock here; skipped");
            return;
        }
        let tmp = std::fs::canonicalize(std::env::temp_dir()).unwrap();
        let d = tempfile::tempdir_in(&tmp).unwrap();
        let base = std::fs::canonicalize(d.path()).unwrap();
        let (plain, other) = (base.join("plain"), base.join("other"));
        std::fs::create_dir_all(plain.join("inner")).unwrap();
        std::fs::create_dir_all(other.join("inner")).unwrap();
        // The folder itself, and a folder behind another, each a link.
        std::os::unix::fs::symlink(&other, base.join("is_link")).unwrap();
        std::os::unix::fs::symlink(&other, base.join("behind")).unwrap();
        let spec = |w: &Path| LandlockSpec {
            read: system_dirs(),
            write: [system_writable(), vec![w.to_path_buf()]].concat(),
            exec: system_dirs(),
            no_network: false,
            unix: Vec::new(),
        };
        let put = |w: &Path, target: &Path| {
            confined_sh(&spec(w), &format!("echo x > {}", target.display()))
        };
        // The same rules at a plain place do give the write.
        assert!(put(&plain.join("inner"), &plain.join("inner/ok")));
        assert!(!put(&base.join("is_link"), &other.join("no")));
        assert!(!put(&base.join("behind/inner"), &other.join("inner/no")));
        assert!(!other.join("no").exists() && !other.join("inner/no").exists());
    }

    /// A folder in `write` alone can be written, read and listed (`w` reads
    /// too), and one in `exec` alone can run its program and not be read.
    #[cfg(target_os = "linux")]
    #[test]
    fn landlock_write_reads_too_and_execute_without_read() {
        if landlock_rules::abi_version().is_none() {
            eprintln!("skipped: no Landlock here");
            return;
        }
        let tmp = std::env::temp_dir();
        let wo = tempfile::tempdir_in(&tmp).unwrap();
        let xo = tempfile::tempdir_in(&tmp).unwrap();
        std::fs::write(wo.path().join("old"), "old").unwrap();
        std::fs::copy("/bin/true", xo.path().join("tool")).unwrap();
        let spec = LandlockSpec {
            read: system_dirs(),
            write: [system_writable(), vec![wo.path().into()]].concat(),
            exec: [system_dirs(), vec![xo.path().into()]].concat(),
            no_network: false,
            unix: Vec::new(),
        };
        let d = |p: &std::path::Path| p.display().to_string();
        assert!(confined_sh(
            &spec,
            &format!("echo x > {}/new", d(wo.path()))
        ));
        assert_eq!(
            std::fs::read_to_string(wo.path().join("new")).unwrap(),
            "x\n"
        );
        assert!(confined_sh(&spec, &format!("cat {}/old", d(wo.path()))));
        assert!(confined_sh(&spec, &format!("ls {}", d(wo.path()))));
        assert!(confined_sh(&spec, &format!("{}/tool", d(xo.path()))));
        // Not listed, not written; a file can be read by name only because
        // Landlock cannot run what it may not read.
        assert!(!confined_sh(&spec, &format!("ls {}", d(xo.path()))));
        assert!(confined_sh(
            &spec,
            &format!("cat {}/tool > /dev/null", d(xo.path()))
        ));
        assert!(!confined_sh(
            &spec,
            &format!("echo x > {}/no", d(xo.path()))
        ));
        // Without the exec right the same program does not start.
        let none = LandlockSpec {
            exec: system_dirs(),
            ..spec.clone()
        };
        assert!(!confined_sh(&none, &format!("{}/tool", d(xo.path()))));
    }

    /// The network switch holds in a real child: with it a command cannot
    /// connect to a TCP port that it reaches without it. Skipped where the
    /// kernel's Landlock has no network rules, or there is no bash to
    /// connect with (`/dev/tcp`).
    #[cfg(target_os = "linux")]
    #[test]
    fn landlock_keeps_a_command_off_tcp() {
        if landlock_rules::abi_version().is_none_or(|v| v < LANDLOCK_NETWORK)
            || !std::path::Path::new("/bin/bash").exists()
        {
            eprintln!("no Landlock network rules or no bash here; skipped");
            return;
        }
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let open = LandlockSpec {
            read: system_dirs(),
            write: system_writable(),
            exec: system_dirs(),
            no_network: false,
            unix: Vec::new(),
        };
        let connect = |spec: &LandlockSpec| {
            confined_sh(
                spec,
                &format!("/bin/bash -c 'exec 3<>/dev/tcp/127.0.0.1/{port}'"),
            )
        };
        assert!(connect(&open));
        let off = LandlockSpec {
            no_network: true,
            ..open.clone()
        };
        assert!(!connect(&off));
        // The files stay as the folders say.
        assert!(confined_sh(&off, "cat /etc/passwd > /dev/null"));
    }

    /// The switch's Landlock layer works on the first kernels with
    /// Landlock's network rules (ABI 4, Linux 6.7 to 6.9), whose file rights
    /// are fewer than the node asks for, and a kernel without them (ABI 3)
    /// takes the ruleset all the same: the node's filter ([`net_filter`])
    /// holds the command off the network there. The kernel here is told to
    /// say it is of that ABI ([`at_abi`]). Skipped where it has no network
    /// rules itself, or no bash to connect with.
    #[cfg(target_os = "linux")]
    #[test]
    fn the_network_switch_holds_from_the_first_abi_with_network_rules() {
        if landlock_rules::abi_version().is_none_or(|v| v < LANDLOCK_NETWORK)
            || !std::path::Path::new("/bin/bash").exists()
        {
            eprintln!("no Landlock network rules or no bash here; skipped");
            return;
        }
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let off = LandlockSpec {
            read: system_dirs(),
            write: system_writable(),
            exec: system_dirs(),
            no_network: true,
            unix: Vec::new(),
        };
        let connect = format!("/bin/bash -c 'exec 3<>/dev/tcp/127.0.0.1/{port}'");
        let Some((reached, read)) = at_abi(LANDLOCK_NETWORK, || {
            (
                confined_sh(&off, &connect),
                confined_sh(&off, "cat /etc/passwd > /dev/null"),
            )
        }) else {
            eprintln!("no seccomp listener here; skipped");
            return;
        };
        assert!(!reached);
        assert!(read);
        let older = at_abi(LANDLOCK_NETWORK - 1, || {
            landlock_rules::prepare(&off).map(|_| ())
        })
        .unwrap();
        assert!(older.is_ok(), "{older:?}");
    }

    /// The system bus is kept where its address puts it, escapes undone,
    /// and at its usual place without one; a bus on another transport has
    /// no path to keep.
    #[test]
    fn the_system_bus_is_kept_where_its_address_puts_it() {
        let default = vec![PathBuf::from("/run/dbus/system_bus_socket")];
        assert_eq!(bus_sockets(None), default);
        assert_eq!(bus_sockets(Some(" ")), default);
        assert_eq!(
            bus_sockets(Some(
                "unix:guid=1,path=/run/my%20bus;tcp:host=h,port=1;unix:path=/b"
            )),
            vec![PathBuf::from("/run/my bus"), PathBuf::from("/b")]
        );
        assert!(bus_sockets(Some("unix:abstract=x;tcp:host=h")).is_empty());
    }

    /// Whether a child under `spec` connects to the unix socket at `path`.
    /// It connects in the child itself, after the rules hold and before it
    /// runs `/bin/true`, so no program with sockets of its own is needed.
    #[cfg(target_os = "linux")]
    fn confined_connect(spec: &LandlockSpec, path: &std::path::Path) -> bool {
        use std::os::unix::ffi::OsStrExt;
        use std::os::unix::process::CommandExt;
        let mut rs = Some(landlock_rules::prepare(spec).unwrap());
        // SAFETY: a zeroed sockaddr_un is a valid, empty one.
        let mut addr: libc::sockaddr_un = unsafe { std::mem::zeroed() };
        addr.sun_family = libc::AF_UNIX as libc::sa_family_t;
        let bytes = path.as_os_str().as_bytes();
        assert!(bytes.len() < addr.sun_path.len());
        for (d, b) in addr.sun_path.iter_mut().zip(bytes) {
            *d = *b as libc::c_char;
        }
        let mut cmd = std::process::Command::new("/bin/true");
        // SAFETY: the closure makes the Landlock syscalls on a ruleset built
        // before the fork, then socket, connect and close on an address
        // built before it.
        unsafe {
            cmd.pre_exec(move || {
                if let Some(r) = rs.take() {
                    landlock_rules::enforce(r)?;
                }
                let fd = libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0);
                if fd < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                let r = libc::connect(
                    fd,
                    (&raw const addr).cast(),
                    std::mem::size_of::<libc::sockaddr_un>() as libc::socklen_t,
                );
                let e = std::io::Error::last_os_error();
                libc::close(fd);
                if r < 0 { Err(e) } else { Ok(()) }
            });
        }
        cmd.status().is_ok_and(|s| s.success())
    }

    /// With its network off and Landlock from ABI 9, a command reaches a
    /// unix socket by path only below `unix`, a folder or the socket itself,
    /// and without the switch every socket it may see. A kernel told it is
    /// of ABI 8 ([`at_abi`]) takes the ruleset and leaves the sockets open,
    /// as the docs say. Skipped below ABI 9.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_command_off_the_network_reaches_the_unix_sockets_below_its_rules_only() {
        if landlock_rules::abi_version().is_none_or(|v| v < LANDLOCK_RESOLVE_UNIX) {
            eprintln!("no Landlock rules for unix sockets here; skipped");
            return;
        }
        let tmp = std::env::temp_dir();
        let given = tempfile::tempdir_in(&tmp).unwrap();
        let other = tempfile::tempdir_in(&tmp).unwrap();
        let bind = |p: std::path::PathBuf| (std::os::unix::net::UnixListener::bind(&p).unwrap(), p);
        let (_a, in_given) = bind(given.path().join("s"));
        let (_b, kept) = bind(other.path().join("kept"));
        let (_c, elsewhere) = bind(other.path().join("s"));
        let open = LandlockSpec {
            read: [system_dirs(), vec![tmp.clone()]].concat(),
            write: system_writable(),
            exec: system_dirs(),
            no_network: false,
            unix: vec![given.path().into(), kept.clone()],
        };
        for p in [&in_given, &kept, &elsewhere] {
            assert!(confined_connect(&open, p), "{p:?}");
        }
        let off = LandlockSpec {
            no_network: true,
            ..open.clone()
        };
        assert!(confined_connect(&off, &in_given));
        assert!(confined_connect(&off, &kept));
        assert!(!confined_connect(&off, &elsewhere));
        let older = at_abi(LANDLOCK_RESOLVE_UNIX - 1, || {
            confined_connect(&off, &elsewhere)
        });
        assert_ne!(older, Some(false), "{older:?}");
    }

    /// Runs `f` on a thread of its own where the kernel says its Landlock
    /// ABI is `abi`: a seccomp filter hands the version query to this
    /// thread, which answers it. Every other call reaches the kernel as it
    /// is, so the rules made there are those a kernel of that ABI gets.
    /// `None` where the kernel has no seccomp listener.
    #[cfg(target_os = "linux")]
    fn at_abi<T: Send>(abi: i32, f: impl FnOnce() -> T + Send) -> Option<T> {
        use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
        let stmt = |code: u32, k: u32| libc::sock_filter {
            code: code as u16,
            jt: 0,
            jf: 0,
            k,
        };
        let jeq = |k: u32, jf: u8| libc::sock_filter {
            code: (libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K) as u16,
            jt: 0,
            jf,
            k,
        };
        let nr = std::mem::offset_of!(libc::seccomp_data, nr) as u32;
        // The low half of the third argument (the flags) on these
        // little-endian machines.
        let flags = (std::mem::offset_of!(libc::seccomp_data, args) + 2 * 8) as u32;
        let load = libc::BPF_LD | libc::BPF_W | libc::BPF_ABS;
        let mut filter = [
            stmt(load, nr),
            jeq(libc::SYS_landlock_create_ruleset as u32, 3),
            stmt(load, flags),
            // LANDLOCK_CREATE_RULESET_VERSION
            jeq(1, 1),
            stmt(libc::BPF_RET | libc::BPF_K, libc::SECCOMP_RET_USER_NOTIF),
            stmt(libc::BPF_RET | libc::BPF_K, libc::SECCOMP_RET_ALLOW),
        ];
        let prog = libc::sock_fprog {
            len: filter.len() as u16,
            filter: filter.as_mut_ptr(),
        };
        let prog = &prog as *const libc::sock_fprog as usize;
        let (tx, rx) = std::sync::mpsc::channel::<Option<OwnedFd>>();
        std::thread::scope(|s| {
            let worker = s.spawn(move || {
                // SAFETY: the filter outlives the call, and binds this thread
                // alone (and what it starts), which ends with the test.
                let fd = unsafe {
                    libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
                    libc::syscall(
                        libc::SYS_seccomp,
                        libc::SECCOMP_SET_MODE_FILTER,
                        libc::SECCOMP_FILTER_FLAG_NEW_LISTENER,
                        prog as *const libc::sock_fprog,
                    )
                };
                if fd < 0 {
                    let _ = tx.send(None);
                    return None;
                }
                // SAFETY: the kernel gave this descriptor to this thread.
                let _ = tx.send(Some(unsafe { OwnedFd::from_raw_fd(fd as i32) }));
                Some(f())
            });
            let listener = rx.recv().ok().flatten()?;
            while !worker.is_finished() {
                let mut p = libc::pollfd {
                    fd: listener.as_raw_fd(),
                    events: libc::POLLIN,
                    revents: 0,
                };
                // SAFETY: plain calls on our descriptor with structs of ours;
                // the kernel wants the notification zeroed.
                unsafe {
                    if libc::poll(&mut p, 1, 20) <= 0 || p.revents & libc::POLLIN == 0 {
                        continue;
                    }
                    let mut n: libc::seccomp_notif = std::mem::zeroed();
                    if libc::ioctl(listener.as_raw_fd(), libc::SECCOMP_IOCTL_NOTIF_RECV, &mut n)
                        != 0
                    {
                        continue;
                    }
                    let mut r = libc::seccomp_notif_resp {
                        id: n.id,
                        val: abi.into(),
                        error: 0,
                        flags: 0,
                    };
                    libc::ioctl(listener.as_raw_fd(), libc::SECCOMP_IOCTL_NOTIF_SEND, &mut r);
                }
            }
            worker.join().unwrap()
        })
    }
}
