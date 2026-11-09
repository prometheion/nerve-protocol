# Windows (until 0.1.0)

The releases before 0.1.0 publish the Linux programs only; Windows comes with 0.1.0.
The user guide is Linux only until then. This page keeps everything it said
about Windows, for the work toward 0.1.0. It comes back to the user guide,
short, with that release.

## Linux and Windows

The center and the node run on Linux (x86_64, aarch64) and Windows (x86_64),
the [desktop app](desktop.md) (`nerve-node-desktop`, the node with an app) on
Linux x86_64 and Windows x86_64. The node behaves the same except where this
page says so. The Linux programs are static and run on any distribution;
installing them as a service needs systemd ([distributions](service.md#linux-distributions)).
The desktop app is not static, and needs glibc 2.35 or newer (Ubuntu 22.04,
Debian 12, Fedora 36 and later) and fontconfig.

| | Linux | Windows |
|---|---|---|
| The node's program | `nerve-node`, or the [desktop app](desktop.md) | The desktop app only |
| Shell for commands | `/bin/sh -c` | Windows PowerShell 5.1 (`powershell.exe -NoProfile -Command`) |
| `folder` mode runs commands | Yes, confined by Landlock; on the installed node as `nerve-run`, also where Landlock is missing | Yes, as `nerve-run` in the pairing's AppContainer ([the account](#the-account-commands-run-as-on-windows)) |
| `allowlist` and `user` mode run commands | Yes | Yes: `allowlist` as `nerve-run` in the pairing's AppContainer, or as you with `--as-owner`; `user` as you. Each in a Job Object |
| Sudo switch | Yes | On the [installed service](#the-node-as-a-service-on-windows), with your administrator token ([sudo on Windows](#sudo-on-windows)) |
| [Network switch](sandbox-linux.md#no-network-for-a-centers-commands) | The node's seccomp filter | The AppContainer without its network capabilities, while the Windows Firewall service runs |
| Control socket | Yes | A [control pipe](#the-control-pipe): every change at once, no providers |
| [Limits per command](#limits-per-command) | A cgroup | The command's job object |
| [Providers](capabilities.md#capability-providers-in-use) | Yes | Not yet |
| [Capabilities of `node.toml`](capabilities.md#capabilities-of-your-own-in-nodetoml) | Yes: the installed node, as `nerve-run`; a node you run yourself offers none | Yes: as `nerve-run`, in the pairing's AppContainer |
| Install as a service | Yes, with systemd, the node and the [center](service.md#the-center-as-a-service) | The node and the [center](#the-center-as-a-windows-service) |
| A second center on one state folder | Attaches over a socket | Attaches over a [pipe](#a-second-center-attaches) |
| The center's [action checker](action-checker.md#the-checker-as-the-owner-sets-it-up) | Yes. Its local model on x86_64 and aarch64, on the CPU or a Vulkan GPU; the installed center service runs it on the CPU only | Yes. Its local model on x86_64, on the CPU or a Vulkan GPU; the installed center service runs it on the CPU only |
| Config folder | `~/.config/nerve` | `C:\ProgramData\Nerve\config` (the installed service) |

## How Windows differs

- The [desktop app](desktop.md) is the only way to the node: there is no
  `nerve-node` for a terminal, and the app does each of its commands.
- Commands run in Windows PowerShell 5.1. `;` chains commands. `&` does not.
- Each command runs in a Job Object. The shell starts suspended, joins the job
  and only then runs, so every process it starts is in the job. Ending the job
  ends all of them. The job closes with the node, so a node that dies leaves no
  command running.
- Windows has no signals. A timeout, `term` and `int` send Ctrl+C to the
  command's console (each command has one of its own, without a window) and
  ask its windows to close, then end the job 3 seconds later. `kill` ends the
  job at once. See [what ends a command](sandbox-linux.md#what-ends-a-command). A node
  started with Ctrl+C ignored, as cmd's `start /b` starts it, stops ignoring
  it at its first command, so that its commands hear it: Ctrl+C in that
  console then stops the node too.
- A process that another program starts for the command, such as WMI, a
  service or the task scheduler, belongs to that program and is not in the job.
- A Job Object does not limit file access. It is not a sandbox. In `folder`
  mode the command also runs in an AppContainer, which is. See
  [modes](#what-a-command-can-reach-in-folder-mode-windows), and for
  what the container does not stop,
  [the list there](#what-the-appcontainer-does-not-stop).
- Output that is not UTF-8 is read in the OEM code page, the one a new
  console starts with.
- A [sudo](#sudo-on-windows) command runs with your elevated token (the
  owner's), and you must be an administrator. Your other commands (`user`
  mode, `allowlist` mode with `--as-owner`) run with the token UAC
  filtered. UAC is no security boundary, so those commands can get the
  administrator rights back as well.
- Paths in rules and over the wire look like `/c/Users/x`.
- The node runs only as the installed service, which the
  [desktop app](desktop.md) installs and starts, as its own account `nerve`:
  never elevated, and never by hand ([root and administrator](#root-and-administrator)).
- A [capability of your own](capabilities.md#capabilities-of-your-own-in-nodetoml)
  runs as `nerve-run` in the pairing's AppContainer, as the pairing's
  commands do.

### Limits per command

Each command's job holds it to the limits under **Settings › Limits ›
Each command**, as a cgroup does on Linux
([node-local spec](spec/node-local.md)): its memory, its CPU and its
processes at once. Past its memory the node ends the job, and the result
says `killed: "memory"`. The CPU limit is in percent of one CPU, as on
Linux; Windows holds it as a share of every CPU of the machine. Windows
counts processes, not their threads, and the console host and the helper
that asks a command to end run in the job beside the command, so the job
allows two more than the limit (three in `folder` mode, with its shim).

### Root and administrator

A node with full rights hands those rights to every command a center runs:
root on Linux. The installed node runs the commands as `nerve-run` or its
owner instead. On Linux, a node you run by hand as root is refused at start
unless you allow it:

```
nerve-node config set machine.allow_root true
```

The refusal says: `refusing to run as root; set machine.allow_root = true
to allow it`.

On Windows the node runs only as the installed service, as `nerve`, and
starts commands as the account chosen for them
([Windows](#the-node-as-a-service-on-windows)): it is never run by hand, elevated or not,
and `machine.allow_root` has no use there.

When the node runs with full rights because you allowed it, it says so with a
warning at start: in the stderr output and in the node's log file. The
center's Log page shows the center's own log and does not carry it. Commands
from a center then run with full rights on the machine (on Linux unless the
node is the installed one, which runs them as `nerve-run` or its owner), and
you are responsible for
what they do.

### The node's web UI

The installed node on Linux can serve a [web UI](web-uis.md#the-nodes-web-ui). On Windows
there is none: the desktop app is the node's UI there.

### The control pipe

A running node on Windows takes every change at once over a named pipe, as
the Linux node does over its control socket: the app's status and relay
pages, a pairing, a pause, rules, modes, the proxy, the relay, a new key for
a center, the sudo switch, panic and unlock, and the folder changes of
**Permissions › Folders**, for which it brings the folders' permission
entries in line before it answers. The app restarts no service for a
change, so running commands go on. Only the administrators, SYSTEM and the
node's own account can open the pipe; the owner's changes in the app reach
it through the service, which runs them as its own account. The node
refuses every request from a process of a command it runs. A panic the node
does not take over the pipe makes the app stop the service, which ends
every link and command, and then save the lock for its next start; the app
says that the links ended only once the service has stopped. With the node
stopped, a change goes to the signed `node.toml`, which the node takes when
it starts; a node that runs without its pipe, or does not answer within 90
seconds, is an error, so nothing is written behind it. A node that does not
answer is also a panic the node did not take. A running node never saves
over a `node.toml` it signed that is newer than what it runs: it refuses the
change instead, a panic excepted
([troubleshooting](#restart-the-node-then-make-the-change-again-windows)).
The commands the node runs for a center run as another account than the
node's, which cannot open the node's folders unless it is an administrator:
UAC is no security boundary ([Windows](#the-node-as-a-service-on-windows)).

### Windows protected paths

See [protected paths](policy-engine.md#protected-paths-as-the-owner-sees-them) for the Windows list. A folder that
is spelled so that it matches nothing is refused: a `..` part, an 8.3 short
name such as `NODE-S~1`, or a name that ends in a dot or a space. Use the full
name.

## Install on Windows

In PowerShell, compare each hash with its line in `SHA256SUMS`:

```powershell
(Get-FileHash .\nerve-node-desktop-x86_64-windows.exe).Hash
```

Then double-click `nerve-node-desktop-x86_64-windows.exe`. Its installer
installs the node as a service that starts with the machine, and the app with
**Nerve** in the Start menu ([desktop app](desktop.md#install)). The app does
everything for the node from then on: pairing, settings, folders, rules,
sudo, backups, update and uninstall. No terminal command is needed or
offered.

For the center, rename `nerve-center-x86_64-windows.exe` to `nerve-center.exe`
and put it in a folder on your `PATH`. A harness starts it from there, or it
runs as a [service](#the-center-as-a-windows-service).

### Let the file run (Windows)

Double-click the file. It is not signed, so Windows may show "Windows
protected your PC": **More info**, then **Run anyway**.

## The node as a service on Windows

On Windows the node is the [desktop app](desktop.md). Open the downloaded
`nerve-node-desktop-x86_64-windows.exe`: its installer installs the node as a
service, and the app does everything else for it
([install](desktop.md#install)). There is no `nerve-node` for a terminal on
Windows, and the node runs only as the service: started any other way, it
says so and does not run.

The install does this, and the installer shows each step:

1. Makes the local user `nerve`, with a long random password that nobody
   types; the service manager keeps it. `nerve` may log on as a service and
   in no other way, and does not show on the sign-in screen. A `nerve` user
   that the install did not make is refused.
2. Makes the folders and gives them an access list of their own: `nerve`,
   SYSTEM and the administrators, nothing inherited from the folders above.
3. Makes the local user `nerve-run`, which commands from centers run as
   ([the account](#the-account-commands-run-as-on-windows)), with a long
   random password stored with DPAPI in the config folder, and its profile.
   It is no administrator, may log on as a batch job (its commands) and as
   a service (step 6) only, and does not show on the sign-in screen. A
   `nerve-run` that the install did not make is refused, and so is one that
   can open the node's folders or your registry.
4. Stores your password (**Your Windows password**) with DPAPI in the config
   folder, for the commands that run as you: `user` mode, `allowlist` mode
   with `--as-owner`, and sudo; and for the permission entries of `folder`
   and `allowlist` mode, which the node changes on your folders as you. A
   stored password that still works is not asked for again.
5. Copies the program to `C:\Program Files\Nerve\nerve-node-desktop.exe`.
6. Registers and starts the service `nerve-run-profile`, which runs as
   `nerve-run` and does nothing but keep its profile loaded: Windows starts a
   process in an AppContainer only for an account whose registry is loaded,
   and only the service manager loads it for an account that is not signed
   in.
7. Registers the service `nerve-node`, which runs as `nerve`, starts with the
   machine (after `nerve-run-profile`) and starts again after a failure.
8. Registers the source `nerve-node` in the Windows Event Log, then starts
   the service. It waits until the node runs.

| What | Where |
|---|---|
| `node.toml`, one key per center, `nerve-run`'s password and yours, the sudo password while sudo is on | `C:\ProgramData\Nerve\config` |
| Audit log, [log](logging.md#the-log-as-the-owner-reads-it), config key, the last version of `node.toml`, the record of the folder grants (`grants.json`) | `C:\ProgramData\Nerve\state` |
| The program | `C:\Program Files\Nerve\nerve-node-desktop.exe` |
| Start, stop, a start that fails, a crash | The Windows Event Log, Application, source `nerve-node` ([logs](#the-windows-event-log)) |

The service writes its log to `C:\ProgramData\Nerve\state\log.jsonl`, which
the app's **Log** page shows. When it does not start, the Event Viewer says
why, and the log has the rest.

The install also makes the user who ran it the owner of the node: its SID
goes into the service's registry key
(`HKLM\SYSTEM\CurrentControlSet\Services\nerve-node\Parameters`, value
`Owner`), and the service lets it start, stop and restart the service. A node
has one owner: another user who installs over it takes that place. The
owner changes the node in the app without administrator rights; the service
runs the app's commands as `nerve` over a pipe open to the owners only, and
audits them with the owner's name
([who may change the node](desktop.md#administrator-rights)). For update,
uninstall, turning sudo on and the `machine.*` settings that pick the
account (also a restore that would change them), the app asks Windows for an
administrator's rights, with the UAC prompt. Uninstalling removes the
service, and the owners and their rights with it.

The service takes every change at once over its
[control pipe](#the-control-pipe).

The installed node on Windows keeps its keys in files. The service runs as
`nerve`, and the Credential Manager is one per account: keys put in the
keyring would be in the Credential Manager of the account that put them
there, where the service does not find them. The app's first-run steps
leave the keys alone, and the keyring under **Settings**, **Keys** is
refused and changes nothing. A `node.toml` that keeps the keys in the keyring is refused by the
install, before it changes anything, and the service does not start with
one: those keys are out of the service's reach. If the keys are still in
files in `config\keys` (the line in `node.toml` was changed), set the line
back to `"file"` and nothing is lost. Otherwise delete the node's folders
(with **Settings**, **App**, **Uninstall** and **Delete the data**, where
Nerve is installed; that deletes the audit log too, so copy
`state\audit.jsonl` aside first) and pair the centers again.

The same account problem keeps the proxy's values out of reach: the installed
node on Windows takes a proxy only if it needs no header and no password.
A proxy with either is refused and changes nothing
([proxy](#a-proxy-for-the-service-on-windows)).

### The account commands run as on Windows

`folder` mode, and `allowlist` mode unless the pairing runs as you
(`--as-owner`), run commands as `nerve-run`, each pairing's in an
AppContainer of its own ([folder mode](#what-a-command-can-reach-in-folder-mode-windows)),
as Landlock holds them on Linux. The node logs `nerve-run` on as a batch
job for each command, with the password the install stored, and starts its
shim as it; the shim makes the container's profile in `nerve-run`'s profile
and starts the command in the container. A command of `nerve-run` never
runs outside its container. `user` mode and `allowlist` mode with
`--as-owner` run as you, logged on with your stored password, outside a
container; a sudo command with your administrator token.

`nerve-run`'s permission entries on your folders are those of every
pairing at once, so `nerve-run` alone reaches each pairing's folders. Only
the containers keep the pairings apart: a process in a container opens
only what both its container and `nerve-run` may. The node's file calls for
a pairing (`fs`, the paths of a call) act in that pairing's container too,
so a read outside its folders is what the container may read: the Windows
folder, Program Files and what is open to every AppContainer, and nothing
that only `nerve-run` may open.

`nerve-run` cannot open the node's config and state folders, your registry
(`HKEY_USERS\<your SID>`, with your environment variables) or the node's
pipes: the install checks the first two, and the CI job all of them
([tests](#tests-on-an-installed-node)).

A command gets `nerve-run`'s own environment, not the service's or yours,
with its home moved into its container's own folder (`AC`, below
`C:\Users\nerve-run\AppData\Local\Packages\<container>`): `USERPROFILE`,
`HOME`, `HOMEDRIVE`, `HOMEPATH` name `AC\home`, `APPDATA` the
`AppData\Roaming` there, and Windows points `LOCALAPPDATA`, `TEMP` and `TMP`
at `AC`. Each pairing has its own, and no pairing reaches another's. git
trusts the repositories the command reaches (`safe.directory`), as on
Linux. Programs that ask Windows for the profile folder instead of reading
these variables (the known-folder API, OpenSSH's `known_hosts`) get
`C:\Users\nerve-run`, which the container cannot write. The names in
`machine.command_env` are passed on with the service's values, but for
the home variables above, which stay the container's, as on Linux.

The commands of one pairing cannot see or open another pairing's
processes, nor yours: a container sees only its own processes (checked:
the process list shows its own, and opening another container's process
for any right is refused), the Windows counterpart of Linux's own `/proc`
([Linux](sandbox-linux.md#a-proc-of-its-own)). Processes of `nerve-run`
outside a container (its shim, `nerve-run-profile`) are open to other
processes of `nerve-run` outside one; no command runs so.

UAC is no security boundary: a command that runs as you, where you are an
administrator, can get the group's rights back and read the keys. The
install warns about an owner in Administrators or Backup Operators, and so
do the Overview (`status`'s `owner_is_admin`) and giving a center the
settings grant, as a center with the grant can set its own mode to `user`:
the twin of root as the owner on Linux.
[Sudo on Windows](#sudo-on-windows) needs you to be an administrator.

If your password changes, commands that run as you fail until you save the
new one under **Settings**, **General**, **Account for commands**. So do
the changes of your folders' entries for `folder` and `allowlist` mode: a
folder you add gives the commands no access, and one you remove or close
stops the pairing's commands, until the node can log on as you again (the
log says so). The node tries a stored password that failed once only, until
you save a new one (or the service restarts), so its calls cannot run up the
wrong-password count that locks your account. [Sudo](#sudo-on-windows) keeps
a copy of your password of its own, which saving the new one does not renew:
the node tries it once too, and sudo commands fail until you turn sudo off
and on again. A Microsoft account works with its Microsoft password, which
can change outside the machine.

To start a process as another account, the service keeps two privileges,
`SeAssignPrimaryTokenPrivilege` and `SeIncreaseQuotaPrivilege`. Windows
takes every other privilege from it, `SeImpersonatePrivilege` included. No
command gets them.

### Update and uninstall on Windows

**Settings**, **App**, **Update** downloads
`nerve-node-desktop-x86_64-windows.exe` and checks it as above, or takes a
file you downloaded. It stops the service, moves the old program aside, puts
the new one in its place and starts the service; if the new one does not
start, the old one goes back. The old program goes once nothing holds it, or
at the next restart of Windows when Windows still holds it: when the update
ran from it, or when the Event Log read the text of the node's entries from
it. An install over an installed node moves the old program aside the same
way.

**Settings**, **App**, **Uninstall** (or **Nerve** in Apps & features) stops
and removes the service, the service `nerve-run-profile`, the source
`nerve-node` of the Event Log (its entries stay), the users `nerve` and
`nerve-run` and their profiles (the commands' AppContainers have theirs in
`nerve-run`'s), the program, the app's Start menu entry, its link handler and
its entry in Apps & features. It also takes off the folder grants left on
your folders, the containers' and `nerve-run`'s
([modes](#what-a-command-can-reach-in-folder-mode-windows)). With
**Keep the data** the folders and the stored password stay, open to the
administrators only; the [sudo](#sudo-on-windows) password goes, so
sudo is off after a later install. A later install takes them up again.
**Delete the data** deletes them. The installed program cannot delete its
own file at once: it moves it aside, and Windows deletes it at its next
start. Where Windows still holds the profile of `nerve` or `nerve-run`
(Windows Search can, and a loaded registry of `nerve-run` stays loaded after
its service stopped until Windows restarts), the uninstall says where to
remove it after a restart.

## The center as a Windows service

As on Linux, the center runs as a service of its own, so an agent's shell
command, which runs as you or as the node's account, cannot read its owner
token or its TLS key. In a terminal opened with **Run as administrator**:

```powershell
nerve-center install --name lab --public-url https://lab.example:7443
```

The install does this, and says each step:

1. Makes `C:\ProgramData\nerve-center`, open to SYSTEM and the
   administrators only, with `state` and `settings` in it. The `state`
   folder is open to the service's account too, the `settings` folder only
   for reading. The administrators own all three. A folder that is there
   already is taken only from SYSTEM or the administrators: one another
   account made, one a program of yours made without **Run as
   administrator** (an agent's shell command could), and a link in its
   place are refused; delete it and run the install again. The service
   checks the `state` and `settings` folders again at each start.
2. Makes the owner token in the state folder (one made before is kept) and
   writes `settings\center.env` with a new harness token; `--name`,
   `--public-url` and `--listen` go into it.
3. Copies the program to `C:\Program Files\Nerve\nerve-center.exe`.
4. Registers the service `nerve-center`. It runs as its virtual account
   `NT SERVICE\nerve-center`, which Windows makes and removes with the
   service: no password, no user to keep. It starts with the machine and
   again after a failure: 5 seconds after the first two, then a minute after
   each, as long as it takes (the manager repeats the last action). A
   center that finds a lock poisoned ends and starts again, and so does one
   that stops with an error at its start (an address that is not there yet
   at boot). What stopped a start is in `log.jsonl` in the state folder,
   also a value mistyped in `center.env`.
   It keeps no privilege but passing through folders.
5. Adds the Windows Firewall rule `Nerve center`: other machines may reach
   the node port (`--listen`, 7443 by default) of that program, and nothing
   else. The web UI and MCP stay on loopback.
6. Starts the service and waits until the center runs, then says the web
   UI's address, the owner token and where harnesses connect.

The service reads its settings only from `center.env`, the same
`NERVE_CENTER_*` lines as on Linux; MCP is over HTTP unless the file says
otherwise, and a file that is missing means the defaults. A center that
cannot start because the file cannot be read says why in its log. Change them as an administrator, then
`Restart-Service nerve-center`. After a change of `--listen` run
`nerve-center install --listen …` again, so the firewall rule follows.

`nerve-center status` in an administrator's terminal says whether the
center runs, the service's state, where it is reached, where its owner
token is (`nerve-center owner-token` shows it there) and its log,
`C:\ProgramData\nerve-center\state\log.jsonl`. A restore into the
installed center stops the service and starts it again after; its state
folder must be there as the install left it.

These commands take `C:\ProgramData`, `C:\Program Files` and the system
folder from Windows, not from the variables `ProgramData`, `ProgramFiles`
and `SystemRoot`: an administrator's terminal takes those from your
account's own variables, which any program of yours may set. The same
goes for the proxy and the trusted certificates (`HTTPS_PROXY`,
`SSL_CERT_FILE` and the like): `update` takes them from the machine's
environment, which only the administrators change, so a program of yours
cannot steer its download. In an administrator's terminal `status`,
`owner-token`, `backup` and `restore` refuse a state folder given by
`NERVE_CENTER_STATE_DIR` (give `--state-dir`), `install` refuses
`NERVE_CENTER_NAME`, `_PUBLIC_URL` and `_LISTEN` from a variable (give the
flags), and `backup` and `restore` say which folder they used.

`nerve-center update` stops the service, moves the old program aside, puts
the new one in place and starts the service; a new program that does not
start is replaced by the old one again. It asks the new program its version
without the administrators' rights, with an environment of `SystemRoot`
alone, in the system folder, and in a job object that ends what it starts;
it still runs as the administrator's own account, so it comes from the
administrator's own hand (`--from`) or a release asset. `nerve-center
uninstall` removes the service, its account, the firewall rule and the program; the folders stay,
open to the administrators only, and `--purge` deletes them. Run from the
installed program, it moves that aside, and Windows deletes it at its next
start.

None of `install`, `update` and `uninstall` runs as a command of the
installed node: the node's control pipe says whether the caller is one. A
caller's environment cannot hide the node: where the service manager says
the node's service runs and its pipe cannot be found, the command is
refused.

### A second center attaches

A second `nerve-center` a harness starts on the same state folder attaches
to the first, as on Linux, over a named pipe named by a hash of the folder.
Only the center's account, SYSTEM and the administrators may open it, and
no other machine. The center checks the account of the process at the other
end, and the second center checks that the pipe belongs to its own account
before it sends anything: another account could make a pipe of that name
first. A center that finds its pipe taken runs without it and says so in
its log; a second center then says whose the pipe is.

The state folder of a center a harness starts gets an access list of its
own on Windows: your account, SYSTEM and the administrators, which the owner
token, the TLS key and the state take. A backup file gets the same from its
first moment: it is written in a private folder beside it, which is held
open (nobody can rename it) until the file is moved into place, and given
its private list through that hold. A backup to a network share
(`\\nas\backups\center.backup`, a mapped drive) is written there as it
is, since the share's server knows none of this machine's accounts and its
own permissions govern, as on Linux over CIFS; the file is encrypted. A
state folder on a drive without access lists (FAT32, exFAT) is refused: the
owner token and the TLS key would be open to every account there. Where the
installed center's path has no service registered (before the first install,
after `uninstall` without `--purge`) it is open to the administrators only,
so run a center or a restore there as an administrator (one that is
not elevated says so, and names `install`). On loopback the center counts the process Windows names for the
connection: by its account where the center may open the process (a center
a harness starts runs as your account and opens yours), else by its session.
The installed service is no administrator, so it cannot open another
account's process, and the system's list of processes (which any caller may
read) names its session only: a program of another sign-in cannot take the
places of your browser or your harness, but two accounts in one session
(a program started as another account) share their places. Programs of one
account share theirs, as on Linux.

The action checker's local model runs in a job object of the center's, so
it ends with the center also when the center is killed. The installed
service runs it on the CPU only.

## What a command can reach in `folder` mode (Windows)

Each pairing's commands run in an AppContainer of their own. A new pairing
gets a new one, also when you pair the same center again under the same
name. Windows lets a
process there open only what is granted to that container, and what it opens
to every AppContainer, and only where `nerve-run` may open it too
([the account](#the-account-commands-run-as-on-windows)). `allowlist` mode
runs in the container as well, unless the pairing runs as you.

| A command can | Where |
|---|---|
| Read and run programs | the Windows folder and Program Files |
| Read, write, run programs | each folder by its rights |

- Windows PowerShell in the container loads modules from its own folders
  only, `%ProgramFiles%\WindowsPowerShell\Modules` and
  `%SystemRoot%\system32\WindowsPowerShell\v1.0\Modules`, whatever the
  machine's `PSModulePath` holds, and uses no module analysis cache of the
  machine's (`PSModuleAnalysisCachePath`). Other entries there, PowerShell
  7's folders, those of SQL Server or Azure tools and of other accounts,
  kept it from finding its own cmdlets and made it take half a minute to
  start. A module installed for all users (`Install-Module -Scope
  AllUsers`) is in the first folder.
- Each PowerShell command in the container imports
  `Microsoft.PowerShell.Management` and `Microsoft.PowerShell.Utility`
  first. On some machines (GitHub's Windows Server 2025 image) PowerShell
  in a container reads every module but does not load one on its own when
  a command names a cmdlet; other modules still load on their own where
  that works.

- The node gives each folder a permission entry for the pairing's container,
  with the folder's rights, and on the installed service one for
  `nerve-run` with the rights of every pairing that has the folder. Everything below the folder inherits it. Windows
  keeps the permissions of each file and folder, so the node writes the
  entry into each one below the folder: the first grant of a large folder,
  changing its rights and taking it off take a while. A change goes only as
  far as it changes something: putting the same entry on again changes
  nothing, a later change skips the parts of the folder it leaves as they
  are, and a folder whose permissions do not inherit keeps the change out
  of itself and of what is below it. A change that stopped part way (the
  node stopped, or it failed) goes through the whole folder
  again at the next sync; until it is done, the node treats the folder as
  having the flags it was heading for as well, and where the change is
  refused, the pairing's commands do not run. A change that takes more than a few seconds says
  how far it is: the node writes it to its log, and a command waits for
  it.
- A file or folder moved into a granted folder keeps the access list it
  had, without the entry. **Sync folders** under **Permissions ›
  Folders** walks every grant again into every folder below it, which gives
  it the entry (`folder sync`; the running node does it, or the app's
  command when none runs).
- A network folder (`\\server\share`) or a folder on a network drive is
  refused when it is added, in the app's folder picker too: the service
  runs in a session of its own, where a drive mapped at your sign-in does
  not exist, and the container reaches no network folder by its grants.
- A folder without a flag inside a granted folder (a folder a pairing has
  with `w`, and one inside it it has with none) is closed to that pairing's
  container: the node gives it a denying entry, which counts before what it
  inherits from the folder around it. Without it, it would inherit the
  entry of the folder around. Where the node cannot close it, that
  pairing's commands do not run. A file in it with another name elsewhere
  (a hard link) is closed under every name (see hard links below).
  A command may rename a closed folder through the rights of the folder
  around it: it stays closed where it went. Where it went to a place the
  same pairing is granted, or above one, that place gets no entry, and the
  pairing's commands do not run until the folder is moved back or you open
  it. A link a command puts at a closed folder's path, or above it inside
  a folder commands may write, is not followed, whatever it points at
  (another machine too): the folder stays closed where it is, the link gets
  no entry, and the pairing's commands do not run until the link is gone.
  A granted folder that holds a protected entry (your home holds `.ssh`) is
  given as its other entries, each with its flags; a closed folder among
  them gets none, nor does anything in it. The service lists such a folder
  as you, since its own account may not open your home; a folder it cannot
  list gives nothing, and the node's log says so. A folder both granted (by
  another spelling, through a link of yours) and closed is closed.
- A link to another machine (a symbolic link to `\\server\share`) is never
  followed by the node: its walks, the paths of a call and the changes of
  the folders' entries stop there, refused, and a folder closed there gets
  no entry. A link whose target is not on a drive of this machine (a device
  path too, and a path from a root without a drive) counts as such a link. Following it would connect to that machine as the account the
  node acts as, and send that account's NTLM answer there. A command in a
  container that opens such a link gets "network access denied", and no
  connection leaves the machine (checked).
- Removing a folder or changing its rights under **Permissions ›
  Folders** changes the entry, and removing the pairing takes it off. That
  is the node's entry on the folder: permissions a command gave what it made
  there stay (see "What the AppContainer does not stop" below). The running
  node makes these changes itself, over its
  [control pipe](#the-control-pipe), and has changed the entries when the
  app says so.
- Uninstalling takes off the node's entries. The record of the entries
  is in the node's state folder: uninstall with the app, never by deleting
  the folders.
- Each pairing's container has a profile in the account its commands run
  as, `nerve-run` on the installed service: a folder
  `%LOCALAPPDATA%\Packages\nerve.…` and a registry key. The node makes and
  removes it through a helper it starts as `nerve-run`, which alone may write
  that profile. The
  profile holds the pairing's home, so it goes with the pairing, not with
  its folders: the running node removes it when the pairing is removed
  (also one that never had a folder), and uninstall does. The name comes
  from the path of the state folder and the pairing in `node.toml`, so the
  node finds the profile as long as the config folder is there.
- If the config folder is gone, the node cannot tell which profiles
  were its own. `Get-ChildItem $env:LOCALAPPDATA\Packages -Filter nerve.*`
  lists the profiles of all nodes this account ran; while no node runs
  there, each of them is left over. Remove each, as that account, with
  `[Nerve.Profile]::DeleteAppContainerProfile('nerve.…')` after
  `Add-Type -Namespace Nerve -Name Profile -MemberDefinition '[DllImport("userenv.dll", CharSet = CharSet.Unicode)] public static extern int DeleteAppContainerProfile(string name);'`.
  It returns 0 also for a name that has no profile, so check that the
  folder is gone. A folder that stays may be held by a registry hive that is
  still loaded; it goes after a restart of Windows
  ([#94](https://github.com/prometheion/nerve-protocol/issues/94)). A node that still runs makes the profile of its
  container again at its next command, without what its commands kept
  there.
- A granted folder you move or rename on the same drive takes its entry
  along, as Windows keeps its permissions. At its next sync (at start, on a
  change, before a command, and on **Sync folders**) the node
  finds it by its file ID and takes the entry off where it is now, also on a
  drive mounted in a folder. A granted folder you delete and make again gets
  its entry back at the next sync. One on a drive that is not connected keeps
  its entry until the drive is back; uninstalling names those it leaves on.
- A file or folder you move out of a granted folder on the same drive keeps
  the entry it inherited. `icacls <path> /reset` gives it the permissions of
  its new place.
- The flags stay independent: `w` without `r` writes but neither reads nor
  lists, `x` runs programs and reads files by name but does not list. The
  permissions a command gives what it makes are the exception, see the
  bullet on permission entries below.
- Deleting and renaming need `r` and `w`, since Windows allows a move with
  the same right as a delete: a command must not move what it cannot read
  to a folder where it can. So in a folder with `w` but not `r`, a command
  adds and changes files, but does not delete, rename or move any. A
  granted folder or file itself is deleted, renamed or moved only through
  the folder above it, with `r` and `w` there; on Linux too that needs a
  right on the folder above.
- A folder you grant inside another granted folder with `w` gets its entry
  only while it is a folder of its own there: not a junction or link to
  another place, not a file with a second name (a hard link), and with
  permissions that inherit. A command may write there, so it could put a
  junction in its place, and the entry would land on the folder it leads
  to. This holds for a folder inside a `w` folder of any pairing. The node
  names such a folder in its log (`left out of the command's sandbox: it
  passes through the link …`) and grants it once it is a plain folder again.
  A junction of yours that leads into the `w` folder is followed to its end
  and judged on the way. A folder you added under **Permissions › Folders**
  stays out when
  a junction has replaced it since, also after you took the `w` off the
  folder above or removed the pairing that had it
  ([above](sandbox-linux.md#a-folder-keeps-the-place-you-added)). A folder without that
  record (see there) is followed again once nothing shows commands could
  write there: check it for junctions and links (`dir /AL /S <folder>`)
  before you take `w` off the folder above or remove a pairing.
- The node's own folders and the [protected paths](policy-engine.md#protected-paths-as-the-owner-sees-them) get no
  entry, also inside a folder you grant. That folder is granted as its other
  entries instead, as on Linux.
- PowerShell starts on a drive `Work:` that is the working folder, because the
  container may not look at the folders above it. Whole paths, relative paths
  below the working folder and native programs work as usual.
- `cd` and `pushd` to the whole path of a folder the command may see, or with
  `..` up out of the working folder into one, put PowerShell on a drive of
  that folder (`Work2:`, `Work3:`, …), and native programs start in the folder
  itself. These drives open nothing; the container decides what the command
  reaches. `cd` to a folder the command may not see fails as any other access
  does, also with `..`: PowerShell stays where it was, `$?` is false, and a
  command that ends with that `cd` fails.
- Other commands keep `..` on the drive they stand on: on `Work:\`,
  `Get-Content ..\README.md` reads the working folder's own `README.md` or
  fails, but does not read the one above it. Give them a whole path for a
  folder above the one PowerShell stands in, or `cd` there first.
- The command has the network, but not `localhost`, unless the owner turned
  the pairing's network off (below). It has its own desktop, so it cannot
  reach your windows or clipboard, and Windows gives its container a folder
  of its own for temporary files, where its home is too
  ([the account](#the-account-commands-run-as-on-windows)).
- What the AppContainer does not stop (the network, what Windows opens to
  every AppContainer, the environment the command starts with, and more) has
  [its own list](#what-the-appcontainer-does-not-stop) below.
- A command sets the permissions of a folder or file it makes, as every
  Windows program may, so it can give them an entry of its own, of three
  kinds: for its pairing's container (`S-1-15-2-…`), for all AppContainers
  (`ALL APPLICATION PACKAGES`, `S-1-15-2-1`), or for a capability that
  every pairing's container has (`S-1-15-3-1`, `-2` and `-3`, which
  `icacls` shows as `APPLICATION PACKAGE AUTHORITY\Your …`). The node
  neither sees nor removes these. They stay when you remove the folder,
  change its flags, remove the pairing or uninstall Nerve. An entry for the
  container belongs to that pairing: no later pairing runs in that
  container, also not one of the same center or under the same name. The
  other two kinds count at once, for every pairing of the
  node and for every app on the machine that runs in an AppContainer (for
  a capability: every such app that has it). In a
  folder with `w` but not `r`, a command can make a folder that lets it
  read what you or another pairing save into it later. So do not save
  files a pairing must not read into a folder where it may write. After you
  take `w` off a pairing's folder or remove the pairing, clean the folder.
  Only `icacls <folder> /reset /T` removes all of them with certainty; it
  also resets permissions of your own below the folder. To keep those,
  find the entries with
  `icacls <folder> /T | findstr /C:"S-1-15-" /C:"APPLICATION PACKAGE"` and
  remove each with `icacls <folder> /remove *<SID> /T`: every `S-1-15-2-…`
  and `S-1-15-3-…` entry, and `ALL APPLICATION PACKAGES` as `*S-1-15-2-1`.
- A hard link is one file under two names, and both share one access list.
  pnpm links `node_modules` to its store, uv links a `.venv` to its cache,
  and a local `git clone` links its objects. Such files are readable but not
  writable for commands: a pairing whose folder holds one of the names gets
  read and run, and no more than each of its names' folders gives (none
  under a `w`-only name), by entries of the node's own, with a denying
  entry of every other right. So two pairings whose projects link to one
  store both read it, and the denial stays when Explorer or `icacls` passes
  a folder's permissions down to the file. A file whose names all lie in
  the granted folder under the same grants (cargo's `target`, links within
  a project) gets the grant as any file. A name in a closed folder (also
  one a command moved, or one inside a split folder), in a protected entry
  or in the node's own folders closes the file under every name. A name in
  a folder the node cannot open (another account's) does not count. The
  node adds its own entries only: what the file's list gives other accounts
  (the owner's store, cache or repository) stays under both names, and the
  granted folder's entries for them do not reach it. The node changes the
  file's entries only as a change reaches it: **Sync
  folders** cuts one you widened back down. So after you or an agent
  install dependencies or clone into a folder that is granted already
  (`pnpm install`, `uv sync`, `git clone --local`), press **Sync folders**:
  until then the new files keep the store's permissions, so commands may
  not read what you installed, and you may not open what the agent
  installed. After it you may read and run what the agent installed from
  its own store. On the installed service its commands keep reading their
  store also once the folder is no longer granted: a file its commands made
  there belongs to `nerve-run`. A file of yours that a command linked into
  its own folder does not: once the folder's grant goes, the pairing reads
  it no more. A command can make a hard link
  only to a file it may write (Windows asks that of a sandboxed process
  since 2015; checked), so it cannot read a file of yours through one. From
  a folder it may write but not read, it can link a file it knows the name
  of into a folder it may read; the walk keeps that file closed to it, and to
  every pairing that has no grant on the write-only folder, while the grant
  is on and after it is taken off (Linux refuses such a link), for as long
  as the folder is there; the node keeps a
  mark of the grant for that in `grants.json`. The walk cannot tell which
  way such a link was made, so it closes a file of a shared project that a
  command linked *into* its write-only folder the same way, to every other
  pairing without a grant on that folder (Linux lets that link be made, and
  the other pairing keeps its rights there). Delete the name in the
  write-only folder to open it. Hard links only work within one drive. A grant on a single file with a second
  name is refused where commands may write around it, and capped as above
  elsewhere. Limits:
  - `icacls /reset` and Explorer's "Replace all child object permission
    entries" take the node's own entries off too: the file is widened until
    **Sync folders**.
  - A file that lost its other names keeps the node's entries; a pairing
    whose folder goes keeps read on it until `icacls <file> /reset`.
  - On a node you run yourself, commands run as you, so the node cannot
    tell the store's files from yours: once no granted folder holds a store
    file's other name, the pairing's commands may not read it in their
    store either. pnpm or uv then fails on that package until you delete
    the store or cache (in the container's `AC` folder).
  - A file another pairing's command made in a folder both pairings share
    also belongs to `nerve-run`: a pairing that linked it into its own
    folder keeps reading it once the folder's grant goes, as on Linux.
  - A file linked out of a write-only folder is closed to every pairing
    that has no grant on that folder, not only the one that linked it, and
    stays closed through every later walk (**Sync folders** too) until its
    mark goes: when the folder is gone, when the folder is granted to the
    pairing again (the new grant decides), or at uninstall. Moving the
    folder takes the mark along, so a new folder made at its old path and
    granted does not end it, and neither does a sync that cannot look at the
    folder. A pairing that has no folder left, is removed, or is the last
    one and is paired again, leaves its marks, so a pairing made later is
    held back too. Delete the file, or grant the folder again, to open it
    sooner.
  - The closing holds while one of the file's names lies in the write-only
    folder. If you move your file out of that folder (a rename on the same
    drive) while a command's link to it is in a granted folder, the next walk
    that reaches the link (**Sync folders**, or a change of a grant there)
    gives the pairing read on it. Before you file away something from a
    folder you gave write only, look for links to it
    (`fsutil hardlink list <file>`) and delete the ones in a granted folder.
  - A folder whose permission inheritance you turned off by hand is not
    looked at: a file linked from it into a granted folder gets that
    folder's grant. Close such a folder in Nerve (a folder without flags)
    instead.
  - A closed folder that a command renames while the node changes the
    folders' entries may leave a file linked across its edge (by you)
    readable through the other name until the next **Sync folders**.

The app's **Overview** shows a running node's confinement, which it asks the
node over its [control pipe](#the-control-pipe). The node also names it when it
starts, in its output and its [log](logging.md#the-log-as-the-owner-reads-it):
`node daemon running (…, confinement appcontainer, …)`. The center sees it in
the node's `exec` state, `confinement appcontainer`, or `none` on the
installed service.

### What the AppContainer does not stop

The container keeps a command out of the files you did not grant. It is not
a box around everything else. This is what a `folder` mode command can still
do on Windows, as far as the owner might expect otherwise. Each point says
how it is known. "Checked" means a command was started in an AppContainer
the way the node starts one, on Windows 11 Pro (26H2, build 10.0.26300) from an
elevated administrator session over SSH; that is one machine, and Windows
and other software may open more or less to AppContainers elsewhere. "Code"
means it follows from the node's code. What is marked "not checked" is not
known.

In short: `folder` mode keeps the command's own files and the owners' pipe
closed, but it is not shown to hold against every program of yours that
runs things on request. One that opens itself to all AppContainers runs
what the command asks as you, outside the container, and then a command
can do all you can, Nerve's settings too. The command itself runs as
`nerve-run`, so what it reaches by its own rights is what both its
container and `nerve-run` may open.

- **The network.** The container has the capabilities `internetClient`,
  `internetClientServer` and `privateNetworkClientServer` (code). Checked: a
  command connects to the internet, resolves names and connects to other
  machines of the local network. Nothing in the node filters by address or
  port. So whatever a command may read it can send out, and it can download
  into a folder where it may write and run what it fetched. It cannot reach
  the machine itself: `127.0.0.1`, the machine's own network address and its
  computer name all timed out (checked), so a service that listens only on
  this machine is out of reach, and one on another machine is not. A command
  can listen on a port (checked). Whether another machine gets through to it
  is the Windows Firewall's say: with the firewall on and no rule for the
  port it did not, with a rule for the port it did (checked). The node adds
  no firewall rule (code). With a pairing's
  [network switch](sandbox-linux.md#no-network-for-a-centers-commands) off,
  its container has none of the three capabilities (code), and Windows keeps
  it off every network. Checked: a TCP connection is refused (10013), UDP gets
  no answer, a name lookup fails, the machine's own addresses stay closed;
  the same with every profile of the Windows Firewall off. Unlike Linux, which
  leaves the resolver open, no name resolves then. That isolation is the
  Windows Firewall service's (MpsSvc), which an administrator could not stop
  (checked); while it does not run, the node runs none of the pairing's
  commands. Commands that run as you (`user` mode, `--as-owner`) and sudo
  commands do not run while the switch is off.
- **The environment.** On the installed service a command starts with
  `nerve-run`'s own environment, its home moved into its container, and the
  names of `machine.command_env` (code,
  [the account](#the-account-commands-run-as-on-windows)); none of the
  service's other variables. Windows replaces `TEMP`, `TMP` and
  `LOCALAPPDATA` with the container's own folder (checked).
- **Files outside the folders.** Windows opens its own folder and Program
  Files to every AppContainer, and a command reads and runs programs there:
  what Windows's permissions on a file below them leave to all AppContainers
  is readable, also software settings you keep in Program Files. Checked:
  `C:\Windows`, `C:\Program Files` and `C:\Program Files (x86)` list, and
  a file below `C:\Windows` (the hosts file) reads. Refused: the listing of `C:\`, `C:\Users`, your profile and its
  `Desktop` and `AppData`, `C:\ProgramData`, `C:\Windows\Temp` and
  `C:\Windows\System32\config`, and writing to `C:\`, `C:\Users\Public`,
  `C:\ProgramData` and `C:\Windows\Temp`. A command also writes the
  container's own folder, `%LOCALAPPDATA%\Packages\<container>\AC` (it
  holds `Temp`), without any grant. It stays between the commands of the
  pairing, also when its last folder is removed, and Windows deletes it
  with the container's profile, which goes with the pairing (see above)
  (checked, code).
- **The registry.** Checked: a command reads the machine part (`HKLM`, for
  example the Windows version), lists the keys of your `HKCU` and reads
  `HKCU\Environment`, which holds the environment variables you set for
  yourself. It was refused the `Run` key and every write it tried, to `HKCU`
  and `HKLM`. This is not a map of the registry: Windows decides per key.
- **Other processes of your user.** Checked: the container sees its own
  processes only (two, in the test), could not look up a process of yours by
  its number, and so could not stop it. Everything the command starts itself
  stays in the container and in its job. Not checked: other ways to reach a
  process, such as a window of the same desktop (it has its own).
- **Work another program does for it.** Checked with the usual tools, none
  of these got through: WMI (`Invoke-CimMethod Win32_Process Create`,
  `tasklist`), the task scheduler (`schtasks /create`), the service manager
  (`sc.exe`, `Start-Service`), `Start-Process -Verb RunAs`, `Start-Process`
  on a document or a web address, and `Shell.Application` and
  `WScript.Shell`. The node does not block these itself: a service, COM
  server or pipe that Windows or a program on the machine opens to all
  AppContainers can be used. What such a program starts is its own process,
  outside the container and outside the job ([Windows](#how-windows-differs)).
  Not checked: other interfaces, such as direct calls to a service or the
  task scheduler without these tools.
- **Named pipes.** Checked: the pipes of system services (`lsass`, `svcctl`,
  `atsvc`, `srvsvc`, `wkssvc`, `ntsvcs`, `eventlog`, `InitShutdown`) and a
  pipe a program of yours made with the default security were refused. The
  RPC endpoint mapper (`epmapper`) and a pipe made open to all AppContainers
  were opened. So a program of yours that makes a pipe open to all
  AppContainers can be talked to. Not checked: other local endpoints (COM
  servers, ALPC ports).
- **The clipboard and your windows.** The command has a window station and
  desktop of its own (code). Checked: reading the clipboard fails. Not
  checked against a signed-in desktop with something on its clipboard: the
  test session had no desktop.
- **Credentials.** Not checked: the Credential Manager, since the test
  session could not use it. The container has none of the capabilities for
  your sign-in credentials or certificates (code), so it should not reach
  network shares as you; not checked. With the node's keys in the
  Credential Manager (`machine.secret_storage = keyring`) `folder` mode runs
  no command on Windows (code, [keys](settings-and-config.md#where-the-node-keeps-its-keys)).
  Checked: a blob protected with DPAPI for the machine can be opened by the
  command. A blob for your user could not be made in the test session, so
  that is not checked. The node's own keys are files in folders that get no
  grant (code).
- **The token.** Checked: low integrity level, no privileges but
  `SeChangeNotifyPrivilege` and `SeIncreaseWorkingSetPrivilege`, and
  `Start-Process -Verb RunAs` was refused. That held in a session with the
  administrator's elevated token, so a node you allowed to run elevated
  ([root and administrator](#root-and-administrator)) does not
  hand that token to the command. The container limits nothing; the
  command's job holds it to its limits, as for every command ([Limits per
  command](#limits-per-command)).
- **What a granted folder allows.** The flags are the rights, and a command
  in the folder is in the container too. A command with `w` can leave files
  there that you, a build or an editor run later, outside the container: a
  script, a build file, a Git hook, an install script of a package. The
  container holds the command, not the files it writes. Links: a command
  made a hard link to a file in its own folder and was refused one to a file
  it may only read (checked). It made a junction to a folder inside its own folder and
  was refused one to `C:\Windows`, `C:\Program Files` and `C:\Users`
  (checked), and a symbolic link needs a privilege it does not have
  (checked). What that means for a folder inside another granted folder, for
  hard links and for the permission entries a command gives what it makes is
  in the bullets of the section above.
- **The sudo path.** A command on the [sudo list](#sudo-on-windows)
  runs as you, with your administrator token, in a job but not in an
  AppContainer, and in every mode (code). The folders do not apply to it:
  only the switch, the sudo list, the
  [deny rules](policy-engine.md#deny-a-command) and the
  [protected paths](policy-engine.md#protected-paths-as-the-owner-sees-them)
  decide, and none runs while the pairing's network is off.

## Sudo on Windows

Windows has no `sudo` program. A sudo command runs as you, the node's
owner, with your administrator rights: the elevated token that "Run as
administrator" gives, not the token UAC gives your other commands. Commands
of `nerve-run`, which is no administrator, never get them. So:

- It works on the node installed as a service, which on Windows is always
  the node ([Windows](#the-node-as-a-service-on-windows)).
- You must be an administrator. Otherwise the switch refuses to turn on.
  Your other commands (`user` mode, `--as-owner`) run with the token UAC
  filtered, but UAC is no security boundary: any of them can get the
  administrator rights back and read the node's keys.
- Turning it on asks for your password. A wrong password is refused and
  the switch stays as it was.
- The node keeps the password with DPAPI in the config folder (`sudo.dpapi`).
  Unlike on Linux, sudo stays on when the service restarts. Turning it off
  removes the file, and uninstalling removes it too. Neither takes you out
  of Administrators. Turning it off reminds you.
- If your password changes, turn sudo off and on again: the node tries the
  password it kept once, not at every command, and a sudo command fails
  until then.
- No sudo command runs while the pairing's network is off.

In the [desktop app](desktop.md), the **Sudo** section of **Permissions**
turns it on and off, and the center's sudo list there takes the commands
(`net session`). Turning it on needs an administrator: the app asks Windows
for the rights, with the UAC prompt. Both take effect at once, over the
[control pipe](#the-control-pipe): the running service checks the password
and keeps it, or drops it. Turning it on needs the node running.

A center with the settings grant switches the running service at once, as on
Linux.

The node starts the command line after `sudo` with the shell
(`machine.shell`, Windows PowerShell 5.1 by default), logged on as a batch
job: the logon Windows uses for a scheduled task that runs with highest
privileges. You need the right "Log on as a batch job", which
administrators have unless a policy takes it. The command runs in a Job
Object like every other command, so a timeout ends it.

A sudo command can change anything on the machine and read the node's keys.
Put only the commands you mean on the sudo list. On Windows the sudo list is
not the only way to those rights: see the administrator above.

## A proxy for the service on Windows

The installed node on Windows runs as the account `nerve`, and the Credential
Manager is one per account. A header value or a password would go to the
Credential Manager of the account that sets the proxy, where the service does
not find it. The node keeps them nowhere else (not in a file), so the
installed node on Windows takes a proxy that needs neither: set it in the
[desktop app](desktop.md) under **Settings**, **Network**, **Proxy**, as
`http://proxy.example:3128`.

A proxy with a header, or with a user name and password in the URL, is
refused there and changes nothing. If the proxy needs a login, the installed
node on Windows cannot use it.

A header in `node.toml` is not read by the service: the link stays down. The
app's **Overview** shows it as `bad proxy:` with the reason, which it asks the
running node over its [control pipe](#the-control-pipe). The
service's [log](logging.md#the-log-as-the-owner-reads-it) has the reason as an `error` line with `bad proxy:`, in
`C:\ProgramData\Nerve\state\log.jsonl`. Set the proxy again without the header,
or remove it; either deletes the old entry from the Credential Manager of the
account that does it.

## A relay on Windows

On Windows the [desktop app](desktop.md)'s **Relay** page does the relay's
commands. The running node takes a relay change at once over its
[control pipe](#the-control-pipe), as on Linux: a token taken away or
replaced stops working now, and its tunnels end. The **Relay** page asks
the running node who is connected. Windows Firewall must let other machines
reach the relay's port.

## The Windows Event Log

The node installed as a service on Windows also writes four events to the
Windows Event Log, so they show in the Event Viewer under **Windows Logs >
Application**, source `nerve-node`:

| ID | Kind | When |
|---|---|---|
| 1 | Information | The node started. The entry names the log file |
| 2 | Information | The node stopped, because the service was stopped or Windows shut down |
| 3 | Error | The node did not start: it refused to (for example `refusing to run as root`, or a `node.toml` whose MAC does not match) or could not. The entry says why |
| 4 | Error | The node crashed: a panic in its main thread ended it. The service's recovery settings start it again, three times a day at most; after that it stays stopped. Or a part of the node panicked and the node runs on; the entry says which. Or the node stopped with an error after it ran |

The log file has the details, and the app's **Log** page shows it. In the
Event Viewer, **Filter Current Log…** with the event source `nerve-node`
lists the node's entries alone.

After an uninstall the entries stay, but Windows no longer shows their text
in the description. Their text is still in them, under **Details**.

Every user of the machine can read the Application log, so these entries are
redacted like the log ([below](logging.md#what-is-never-in-it)). On Linux the journal has the
service's output (`journalctl -u nerve-node`, `journalctl -u nerve-center`).

## Tests on an installed node

The tests that need a Windows machine of their own carry
`#[ignore = "<reason>"]`. CI's `windows-installed` job
(`.github/workflows/installed-windows.yml`) runs them on a fresh
`windows-2025` runner, with the programs and test programs the `windows`
job built:

- it checks the runner is Windows Server 2025 (`.github/scripts/windows-runner.ps1`);
- it makes an administrator account and a standard account with random
  passwords, and their profiles by a logon that loads them, as nobody signs
  in on a runner;
- the app installs, starts, stops, restarts, updates and uninstalls Nerve
  (`nerve-node-desktop/tests/real.rs`);
- the node is installed again by that account, its owner; the install makes
  `nerve-run`, its profile (by a logon that loads it) and
  `nerve-run-profile`, which the job checks. Then the sudo switch
  (`nerve-node/tests/win_sudo.rs`), the limits per command
  (`nerve-node/tests/win_limits.rs`), the command account
  (`nerve-node/tests/win_account.rs`: a command in its folder works and one
  outside is refused and audited; one pairing reaches neither another's
  folders, nor its home, nor its processes; a folder without flags inside a
  `w` folder is closed; `nerve-run` opens neither the node's config and state
  folders, nor the owner's registry, nor the node's pipes; with the network
  off a connection and a sudo command are refused), the account's batch
  logon, a folder on a virtual disk mounted in a folder, a backup's folder
  on a FAT32 virtual disk and a folder reached over the machine's own share
  run on it;
- the center is installed as a service, its `status`, its restart actions
  (and a restart after its process is killed), its web UI in Chrome
  (`.github/scripts/web-ui-smoke.mjs`), what the standard account cannot
  read or take (the state, the owner's places on a port), what the
  administrator's other account and a pipe the standard account made get
  from a second center, a second center that attaches to a first, a backup
  and a restore into the service (also with the folder spelled another
  way), `update` (a program that is not the center, another build) and
  `uninstall --purge` run (`nerve-center/tests/win_service.rs`);
- the node's uninstall removes `nerve-run` and `nerve-run-profile` too.

A test that skips fails the job. The `windows` job also keeps the debug
`nerve-node-desktop.exe` and `nerve-center.exe` as the artifact
`windows-programs` for three days, to try a change on a Windows test
machine as a person would.

## Restart the node, then make the change again (Windows)

A change on **Permissions** or another page says `node.toml holds changes
the running node takes at its next start`: a change went into the file while
the app found no node running (in the moment the node started, say), and
waits there for its next start. The node saves its whole config with a change
and would undo that one, so it refuses. Restart the node (**Restart** on the
app's **Overview**) and make the change again. A panic is never refused: it
locks the node over such a file.

## The control pipe is not the node's (Windows)

A folder change says `the control pipe is not the node's`: another process
made a pipe of the node's name before the node started, and the node runs
without its pipe (its log says `the control pipe … is taken`); once that
process has let the name go, a change says `the node runs without its
control pipe`. The node's commands send that pipe nothing. Find the
process with Sysinternals Process Explorer (**Find**, **Find Handle or
DLL**, `nerve-node-`), end it, and
restart the node (**Restart** on the app's **Overview**). With the node
stopped, folder changes go to `node.toml` as every other change does. A
panic in that state makes the app stop the service, as for any node that does
not take it.
