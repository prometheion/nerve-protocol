# Nerve on Windows

On Windows the node is the desktop app: it installs the node as a service,
and you do everything in its window. There is no `nerve-node` to type. The
rest of this guide holds on Windows too; this page says where each task is
in the app, and what differs. [Windows in depth](../dev/windows.md).

## Download and check

From [Releases](https://github.com/prometheion/nerve-protocol/releases/latest)
take `nerve-node-desktop-x86_64-windows.exe`, the node with its app, and for a
center `nerve-center-x86_64-windows.exe`. Both are for x64. In PowerShell,
compare the hash with its line in `SHA256SUMS`:

```powershell
(Get-FileHash .\nerve-node-desktop-x86_64-windows.exe).Hash
```

The programs are not signed yet. SmartScreen says "Windows protected your
PC": press **More info**, then **Run anyway**. Smart App Control, where it is
on, can block them, with no way past.

## Install

Double-click the file. The installer asks for your Windows password, then
Windows asks once for an administrator (UAC). You become the node's owner.
It installs:

- the services `nerve-node` and `nerve-run-profile`, which start with Windows;
- the users `nerve`, which runs the node, and `nerve-run`, which runs a
  center's commands;
- **Nerve** in the Start menu, `nerve://` links, and an entry in Apps & features.

Then the first-run steps pair your first center, choose its mode and its
network, and in folder mode give it a first folder.

`nerve-node-desktop-x86_64-windows.exe --silent` installs without a window
or a question, for scripts and winget. The app asks for your password later,
where it needs it.

### What it needs

| | |
|---|---|
| The owner | A local account of this machine with a password; a domain or Microsoft Entra ID account is refused |
| Tested | Windows 11 Pro (build 26300), Windows Server 2025; not tested: Windows 10, Home editions, ARM |
| The network switch | The Windows Firewall service |
| The state folder | An NTFS drive |
| Commands | Windows PowerShell 5.1 |
| The center's local model | `tar.exe`, part of Windows |

When your Windows password changes, save the new one under **Settings ›
General › Account for commands**. Until then, commands that run as you fail,
and a folder you add gives no access.

## Where each task is

| Task | In the app | What differs |
|---|---|---|
| Pair a center | **Centers › Pair a center**, or open the `nerve://` link | |
| Choose what it may do | **Permissions › Mode** | `user` mode and allowlist as you use your Windows password |
| Give it a folder | **Permissions › Folders** | Commands run as `nerve-run` in an AppContainer of the pairing's own; network folders and mapped drives are refused |
| Run commands with sudo | **Permissions › Sudo** | Only an administrator owner; only here, never from a center; off after a restart |
| Keep commands off the network | **Permissions › Mode › No network for its commands** | Name lookups fail too |
| Limits per command | **Settings › Limits** | Held by the command's job object |
| Capabilities, programs | **Capabilities** | A program attaches over a pipe |
| Where the keys live | **Settings › Keys** | Files, or the service's own Credential Manager |
| A proxy, a relay | **Settings › Network**, **Relay** | The proxy's login goes into that Credential Manager |
| Rotate a center's key | **Centers › New key…** | |
| Back up, restore | **Settings › Backup** | |
| See what happened | **Audit**, **Log** | The log is `C:\ProgramData\Nerve\state\log.jsonl`; the Event Viewer has the starts and stops (Application, `nerve-node`) |
| Stop everything | **Overview › Panic** | |
| Update, uninstall | **Settings › App** | Also Apps & features |

## Folders

The node watches each granted folder: what you or an agent move, install or
clone into it gets its access by itself, seconds later. **Sync folders**
under **Permissions › Folders** is only for a folder it does not watch.
The watch costs:

- The folders above a granted folder cannot be renamed, moved or deleted to
  the Recycle Bin. Remove the grant first.
- An external disk that holds a granted folder cannot be removed safely.
  A stick or card is not watched.

## A capability's argument

A word `{field}` of a [capability of your own](capabilities.md) is one whole
argument for the program. `cmd`, a `.bat` or `.cmd` file, and PowerShell
without `-File` read their line again as commands, so a template with
`{field}` for them is refused. Put the command in a script:
`powershell -NoProfile -File script.ps1 {field}`.

## The center as a service

Double-click `nerve-center-x86_64-windows.exe`. After the UAC prompt it
installs itself, and its window shows the web UI's address and the owner
token until you press Enter. A newer one double-clicked later installs over
it, and the settings stay. To give
it a name or other settings, run it in a terminal opened with **Run as
administrator**, in the download folder:

```powershell
.\nerve-center-x86_64-windows.exe install --name lab
```

It puts itself in `C:\Program Files\Nerve` as `nerve-center.exe`, on the
machine's `Path`, so a harness and every terminal opened after it find
`nerve-center`. It runs as the service `nerve-center`, keeps its state in
`C:\ProgramData\nerve-center`, and adds the firewall rule `Nerve center` for
the node port. `nerve-center set` shows its settings, in
`settings\center.env` there; `nerve-center set ui 0.0.0.0:7480` changes one
and restarts the service. A new `listen` port takes the firewall rule along.
The rule lets in the node port only: for the web UI or MCP beyond loopback,
`set` prints the `New-NetFirewallRule` line for their port. These and the
center's other commands work in an administrator's terminal: `status`,
`service start|stop|restart`, `pair`, `nodes`, `token`, `log` and
`owner-token` ([in the terminal](center.md#in-the-terminal)).
[Run the center](center.md) says what comes next.

A relay on Windows needs a firewall rule for its port, which you add yourself.

## Update and uninstall

Update the center first, then the nodes. **Settings › App › Update…** checks
the download against `SHA256SUMS`; if the new program does not start, the
old one comes back. **Pre-releases** beside it makes Update take test
builds too. The center: `nerve-center update` as an administrator, with
`--pre` or `--tag <tag>` for a pre-release.

**Settings › App › Uninstall…** (or Apps & features) asks whether to **Keep
the data** or **Delete the data**. The quiet uninstall of Apps & features
keeps it. The data holds your stored Windows password too, open to the
administrators: **Delete the data** deletes it. The Event Log's entries stay. A profile folder of `nerve` or
`nerve-run` that Windows still holds goes after a restart; the uninstall
says where.

**From 0.0.6:** uninstall it with **Delete the data** (Apps & features),
install this version, and pair the node again. The installer refuses to
install or update over 0.0.6, whose settings it cannot read, and the app's
**Update** of 0.0.6 puts the old program back.

## What Windows does not have

- No `nerve-node` for a terminal: the app runs its commands for you.
- No node web UI: the app is the node's window.
- No node run by hand: it runs only as the installed service.

## Limits

These are in [safety](safety.md#windows) too.

- UAC is no boundary: a command that runs as you, where you are an
  administrator, can take the full rights back and read the node's keys.
- Your Windows password is stored on disk, sealed for this machine (DPAPI);
  only the folder's access list guards it.
- The administrators and the Backup Operators can read the node's keys and
  your stored password.
- A folder mode command reads the Windows folder and Program Files, and has
  the network until you turn it off.
- Pipes, RPC and COM servers open to every AppContainer are open to the
  commands: a program that offers itself so can act for them, as you.
- Work started through WMI, the task scheduler or a service runs outside the
  command's job: a stop and the limits do not reach it.
- Sudo commands run as you with your administrator rights, outside the
  container and the folders.
- With the Firewall service stopped, a pairing whose network is off runs no
  command.
- The guard does not catch a service or task made by writing the registry or
  the Tasks folder directly, the Startup folder, or WMI.
- The programs are not signed.

[What the container does not stop](../dev/windows.md#what-the-appcontainer-does-not-stop).

## When something fails

| Message | Fix |
|---|---|
| `Windows lets no program log on to an account without a password …` | Give your account a password, then save it under **Settings › General › Account for commands** |
| `… the Windows Firewall service … does not run …` | Start that service, or turn the pairing's network on |
| `… is a network folder` (or `network drive`) | Grant a folder on a drive of this machine |
| `node.toml holds changes the running node takes at its next start` | **Restart** on the Overview, then make the change again |
| `the control pipe is not the node's` | Another program holds the node's pipe: end it, then **Restart** ([why](../dev/windows.md#the-control-pipe-is-not-the-nodes-windows)) |
| `… may not open <path> …` | The rest of the message says why ([the list](../dev/windows.md#a-path-a-pairings-container-may-not-open-windows)) |
