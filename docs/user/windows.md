# Nerve on Windows

On Windows the app `nerve` is the node or the center: it installs one of
them as a service, and you do everything in its window and the web UIs.
There is no `nerve-node` or `nerve-center` to type. The rest of this guide
holds on Windows too; this page says where each task is in the app, and
what differs. [Windows in depth](../dev/windows.md).

## Download and check

From [Releases](https://github.com/prometheion/nerve-protocol/releases/latest)
take `nerve-x86_64-windows.exe`, the app, for x64. In PowerShell, compare
the hash with its line in `SHA256SUMS`:

```powershell
(Get-FileHash .\nerve-x86_64-windows.exe).Hash
```

The programs are not signed yet. SmartScreen says "Windows protected your
PC": press **More info**, then **Run anyway**. Smart App Control, where it is
on, can block them, with no way past.

## Install

Double-click the file. The installer asks what this machine is: **A node**
or **A center** (for a center, see [below](#the-center-as-a-service)). For a
node it asks for your Windows password, then Windows asks once for an
administrator (UAC). You become the node's owner. It installs:

- the services `nerve-node` and `nerve-run-profile`, which start with Windows;
- the users `nerve`, which runs the node, and `nerve-run`, which runs a
  center's commands;
- **Nerve** in the Start menu, `nerve://` links, and an entry in Apps & features.

Then the first-run steps pair your first center, choose its mode and its
network, and in folder mode give it a first folder. After a reinstall,
**Restore a backup…** there brings your pairings back instead.

An empty password is not stored: Windows logs no program on to an account
without one. Commands that run as you wait until you set it under
**Settings › General › Account for commands**. Over a node of another
program (a pre-release) the install takes over and removes the old one.

`nerve-x86_64-windows.exe --silent` installs the node without a window or a
question, for scripts; the app asks for your password later.

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
General › Account for commands**; until then commands that run as you fail.

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

A file another account owns keeps its own permissions, so commands do not
reach it; the rest of the folder gets its access. **Permissions › Folders**
names it: take it over or move it out, then **Sync folders**.

## A capability's argument

A word `{field}` of a [capability of your own](capabilities.md) is one whole
argument for the program. `cmd`, a `.bat` or `.cmd` file, and PowerShell
without `-File` read their line again as commands, so a template with
`{field}` for them is refused. Put the command in a script:
`powershell -NoProfile -ExecutionPolicy Bypass -File script.ps1 {field}`.
Windows' default policy runs no script without the flag.

## The center as a service

Double-click the file and pick **A center**. After the UAC prompt it
installs the center as the service `nerve-center`, which runs the app's
program, `C:\Program Files\Nerve\nerve.exe`. It keeps its state in
`C:\ProgramData\nerve-center` and adds the firewall rule `Nerve center` for
the node port (7443) of the center's service. Its last step shows what it
did, and the owner token with a **Copy** button. Keep the token in your
password manager. **Nerve** in the Start menu then opens the center's pages,
which ask for the token ([the center in the app](center.md#in-the-app)).

Harnesses connect over HTTP MCP (**Harnesses › Connect a harness**), on this
machine only. The center's web UI is off: **Settings › This machine › Web
UI** turns it on.

**Change the role…** (Settings › This machine, on a node Settings › App)
backs up, removes the role with its data, and installs the other.

A relay needs a firewall rule for its port, which you add yourself in
Windows Security; the **Relay** page says so.

## Update and uninstall

Update the center first, then the nodes. **Settings › App › Update…** (on a
center **Settings › This machine › Update**) checks the download against
`SHA256SUMS`; if the new program does not start, the old one comes back.
**Pre-releases** beside it makes Update take test builds too. When no newer
version is there, it says so and changes nothing.

**Settings › App › Uninstall…** (or Apps & features) asks whether to **Keep
the data** or **Delete the data**. On a center, Apps & features or
**Settings › This machine › Uninstall…** removes the center and the app. The
quiet uninstall of Apps & features keeps it. The data holds your stored
Windows password too, open to the administrators: **Delete the data** deletes
it. The Event Log's entries stay. A profile folder of `nerve` or `nerve-run`
that Windows still holds goes at Nerve's next install or uninstall after a
restart; the uninstall says where.

**From 0.0.6:** uninstall it with **Delete the data**, install this version,
and pair the node again. The installer and the 0.0.6 app's **Update** change
nothing over it.

## The node's web UI

The node's own web UI is off until you turn it on in **Settings › Network ›
Web UI**, where you also make its tokens (each is shown once) and revoke
them. From this machine it lets in programs of your own session only;
everyone needs a token
([web UIs](web-uis.md#the-nodes-web-ui)).

## What Windows does not have

- No `nerve-node` for a terminal: the app runs its commands for you.
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
- A command can write Event Viewer entries as `nerve-node`; the audit log is
  the record.
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
| `node.toml holds changes the running node takes at its next start` | **Restart** on the Overview, then make the change again |
| `the control pipe is not the node's` | Another program holds the node's pipe: end it, then **Restart** ([why](../dev/windows.md#the-control-pipe-is-not-the-nodes-windows)) |
| `… may not open <path> …` | The rest of the message says why ([the list](../dev/windows.md#a-path-a-pairings-container-may-not-open-windows)) |
