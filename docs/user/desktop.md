# The desktop app

`nerve-node-desktop` is the node with a window, for a machine with a desktop:
Linux x86_64 with GNOME or KDE Plasma (Wayland or X11), and Windows x86_64.
It is one program: it holds the node, its CLI and the app. It installs
itself like any other program, runs the node as a service, and does what
`nerve-node` does in a terminal (pairing, modes, folders, rules, sudo, the
proxy, the relay, the audit log, backups, the account commands run as)
without one; two things stay with the terminal ([settings](#settings)). The
window runs the CLI for every action, so it has the CLI's checks and audit
records.

## Download

From [Releases](https://github.com/prometheion/nerve-protocol/releases):

| System | File |
|---|---|
| Linux, x86_64 | `nerve-node-desktop-x86_64-linux` (needs glibc 2.35 or newer: Ubuntu 22.04, Debian 12, Fedora 36 and later) |
| Windows, x86_64 | `nerve-node-desktop-x86_64-windows.exe` |

Check it against `SHA256SUMS` ([install](install.md#download)).

## Install

### Let the file run (Linux)

A downloaded file may not run as a program yet.

- **GNOME Files**: right-click the file, **Properties**, switch on
  **Executable as Program**, close the window, then double-click the file.
- **KDE Dolphin**: right-click the file, **Properties**, **Permissions**, tick
  **Is executable**, **OK**, then click the file.

### Windows

Double-click the file. It is not signed, so Windows may show "Windows
protected your PC": **More info**, then **Run anyway**.

### The installer

The first start shows the app's installer. It says what it installs, and
**Install** does it:

- the node, as a service under a user of its own, `nerve`, that starts with
  the machine (what `nerve-node install` does, [service](service.md));
- the app, with **Nerve** in the application menu (the Start menu on
  Windows);
- `nerve://` links, so a pairing link from a center's web UI opens in Nerve.

Installing changes the system, so the system asks for an administrator's
password next: polkit's dialog on Linux, the UAC prompt on Windows. You
become the node's owner: from then on the app needs it only for update,
uninstall and a few more ([administrator rights](#administrator-rights)). On
Windows the installer first asks for your own Windows password: commands
from your centers run as you, and the service needs your password to start
them ([Windows](service.md#the-account-commands-run-as-on-windows)). That
holds when you are a standard user and an administrator types their name and
password into the UAC prompt: the commands still run as you, not as the
administrator. If your password was mistyped, enter it again under
**Settings**, **General**, **Account for commands**. On Linux `folder` and
`allowlist` mode run them as `nerve-run`, an account of their own that
install makes, and `user` mode as you ([modes](modes.md#the-account-nerve-run-linux)).

When it is done, **Open Nerve** opens the app. Its first-run steps name the
machine, choose where the keys live, pair the first center and choose its
mode; **Back** goes to the step before, **Skip** past one. The downloaded
file is no longer needed.

| What | Linux | Windows |
|---|---|---|
| The program, which the service runs too | `/usr/local/bin/nerve-node-desktop` | `C:\Program Files\Nerve\nerve-node-desktop.exe` |
| The menu entry | `/usr/local/share/applications/nerve-node-desktop.desktop`, its icon in `/usr/local/share/icons/hicolor` | `Nerve` in the Start menu of all users |
| `nerve://` links | the entry's `x-scheme-handler/nerve`, the default in `/etc/xdg/mimeapps.list` | `HKEY_LOCAL_MACHINE\Software\Classes\nerve` |
| Apps & features | | `Nerve`, in `HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Uninstall\Nerve` |
| The node's files, the service | as `nerve-node install` puts them ([service](service.md#install)) | as on Windows ([service](service.md#windows)) |

A node installed before with `nerve-node install` keeps its settings, pairings
and keys: the installer adds the app, and the service runs the app's program
from then on, so there is one program to update. On Linux the old program,
`/usr/local/bin/nerve-node`, becomes a link to the app's, so the command
`nerve-node` keeps working. On Windows the old
`C:\Program Files\Nerve\nerve-node.exe` is removed: the app replaces it, and
for a terminal you download the CLI edition on its own
([in a terminal](#in-a-terminal)). A plain `nerve-node uninstall` later hands
over to the app's uninstall, so it removes the app too
([uninstall](service.md#uninstall)).

## Administrator rights

Like any installed program, Nerve asks for an administrator's password at
install, and later only for what changes the system or gives root. The user
who installs it becomes its **owner**. An owner opens the app, reads the node,
changes its settings, pairs centers, edits rules, and starts, stops and
restarts the service without a question, right after the install, without
logging in again.

The system's dialog (polkit on Linux, the UAC prompt on Windows) comes for
these only, each time, for that one action, and the app says why first:
update, uninstall, turning sudo on, and the settings `machine.allow_root`,
`machine.sudo_path` and `machine.shell` (on Windows also `machine.user`, the
account commands run as), which decide which account and program commands
run as (also restoring a backup that would change them). The rights end with
the action.

Who changes the node's settings without a password:

- **Linux:** root, and the owner, the account that ran `install` (`sudo`, or
  the app's polkit dialog). The unit names it; there is one, and another
  install by another account makes that one the owner. The owner starts,
  stops and restarts the service from their own session at the machine (the
  desktop, a console), through a helper that does only that for this
  service, and polkit lets the owner run it (by a rule, or on polkit 0.105,
  as on Ubuntu 22.04, by a `.pkla` file); over SSH, or from a program
  outside a session, polkit asks for an administrator's password as before.
- **Windows:** the administrators, and the user who installed (by SID, in the
  service's registry key `Parameters\Owners`). The service lets that user
  start, stop and restart it.

How: the running node takes the owner's command over a socket of its own
(`/run/nerve-node/owner.sock`; on Windows a named pipe open to the owners
only), checks who asks by the account the system names for the caller, and
runs the command as its own user, exactly as `sudo nerve-node …` does. Every
change keeps the CLI's checks and is in the [audit log](audit.md) with the
owner's name. While the node is stopped, only an administrator changes it:
start it first.

**Who a center's commands run as** (Linux):

- **`folder` mode, and `allowlist` mode:** as `nerve-run`. It is not you:
  the owner socket refuses it, your session's programs (the service manager,
  the session bus, tmux) take no requests from it, and it reaches your files
  only where you gave it a folder. In `allowlist` mode **Run them as you**
  under the mode runs the allowed commands as you instead; a click on the
  mode's own tile leaves that as it is. Under **Folders** a center shows the
  folders of its own that `nerve-run` did not get, and why.
- **`user` mode:** as you, with your rights and without a sandbox. It can
  change the node's settings as you can, also through a program of yours
  outside the node (your systemd user manager, a tmux server). That is your
  choice when you give a center this mode, and yours to answer for. By
  default the center's [blocklist and action checker](action-checker.md) and
  the node's [guard](rules.md#the-guard-against-changing-the-node) catch a
  command that tries it by mistake; they are no boundary.

On Windows every command runs as you, `folder` mode in an AppContainer
([modes](modes.md#what-a-command-can-reach-in-folder-mode-windows)); an
account of their own there is planned.

The node also refuses the owner socket to a process it sees below a command
it runs, and on Linux to one with `no_new_privs`, which every confined
command keeps. That catches mistakes, not a command that gets around it.

The app's link to an administrator's rights, while an action has them, is its
own: on Linux the app closes itself to the other processes of your user once
it asks (they can neither open that link nor trace the app), and its file
dialogs then run in a process of their own, which the desktop portal
answers; on Windows the link is open to the app's process alone. On Windows
the app also loads the system's DLLs from System32 only, never from the
folder it was downloaded to.

What this does not cover, while an action has the rights:

- On Windows, any program that runs as you may reach into the app's
  process and act through it: Windows does not keep a user's programs
  apart.
- On X11 every program in your desktop session can send key presses and
  clicks to any window, this one too. Wayland does not let it.
- A program that runs as you can change how the app starts, for example
  through your session's environment or a menu entry of its own in your
  home folder, and run in its place.
- A file you pick in the app, such as a backup to restore or a program to
  update from, lies in your folders, which any program that runs as you
  may change before the node reads it.

A user who is not the owner is asked for the rights once each time the app
opens, and the app keeps them until it closes.

## Start and stop

The **Overview** shows the service: whether it runs and starts with the
machine. **Stop** ends the node's links and runs nothing until **Start**;
**Restart** stops and starts it. A stopped service starts again with the
machine. In a terminal this is `nerve-node service stop|start|restart`
([service](service.md#start-and-stop)).

On Windows the running service takes folder changes at once and every other
change only when it starts again, a pairing too. So after such a change the
app restarts the service itself, two seconds after the last one, and says
so; closed before then, the app restarts it as it closes. The first-run
steps restart it once, at their end, also when you close them early. The node's links come
back at once, but a command a center runs at that moment ends. If the
restart fails, the Overview says that changes wait and offers **Restart**.

## Settings

Settings has tabs. Each control runs the `config` command a terminal would,
so the node checks a value as it checks the command line's.

- **General**: the machine's **Name**; the **Account for commands** (on
  Linux it says who runs them: `nerve-run`, or you in `user` mode; on
  Windows, enter its new password there when it changed, or your own when no
  account is chosen yet: the service needs it to start commands);
  the **Shell** that runs each command (`machine.shell`); and how much the
  **Log** says (`log.level`).
- **Keys**: in files, or in the system keyring where one can hold them. Where
  it cannot (the installed node on Windows, no keyring
  answering for the account the node runs as), the app says why and keeps
  them in files.
- **Network**: the **Proxy**. The relay has a page of its own
  ([Relay](#relay)).
- **Limits**: what one command may use and the most a call may ask for
  (`limits.command`, [limits](limits.md)), how long a command runs
  (`limits.default_timeout_secs`, `max_timeout_secs`, in minutes), and the
  node's commands at once and output kept of a command (`limits.max_running`,
  `output_cap_bytes`, in MiB). An empty field is the default again.
- **Backup**: **Back up…** and **Restore…** write and read the file as you,
  in your own folders, and hand it to the node. A restore never goes under a
  running node: the node stops for it and starts again after (for an
  administrator's restore the app stops and starts the service). **Keep its
  keys in files** restores the backup of a machine that kept them in a
  keyring onto one without.
- **App**: **Update…** and **Uninstall…**. Light, dark or the system's
  look is chosen at the foot of the sidebar, on every page.
- **Advanced**: **Any setting** shows and sets any setting of `node.toml`
  by its name, and **Add** and **Remove** change a list, such as
  `policy.protected.allow`; and taking a `node.toml` changed by hand. On
  **Permissions**, a pattern for files (`fs.read:~/notes/*`) goes on the
  allow or deny list as it is.

The settings without a control of their own are under **Advanced**:
`machine.allow_root` and `machine.sudo_path` (for a node run by hand, not
the installed one), `providers.allowed` ([providers](providers.md)), and
`policy.protected` of a center ([protected paths](protected-paths.md)).
A center's other settings are on **Centers** and **Permissions**.

On **Permissions**, the commands that count in the center's mode come first:
in allowlist mode its allowed commands, with the deny rules below them as
**Exceptions** (closed until you open them); in folder and user mode its
forbidden commands, and a line that the allow rules count only in allowlist
mode. The sudo list is in **Sudo**, beside its switch. The pencil beside a
rule edits it in place, as one change (`rule edit`), the rules of the guard
too. A list longer than some eight rows (rules, folders, capabilities, a
relay's nodes, the centers on the Overview) scrolls in a box of its own, with
its scroll bar beside it, so the page stays short.

On **Permissions**, the **Mode** names who runs the commands: in folder
mode `nerve-run`, in user mode you; in allowlist mode **Run them as you**
switches between `nerve-run` and you (`mode set allowlist --as-owner`).
Where root is the node's owner ([service](service.md#root-as-the-owner)),
the Overview says so, user mode and the chip say **as root**, and the mode
shows **Its commands run as root** while they do. On **Centers**, a center's
settings grant says **Up to user mode, which runs as root on this node**, and
giving it says that the center can now make itself root.
Under **Folders**, the line **Always** names what `nerve-run` has besides
the folders you give it: `/tmp`, `/var/tmp` and its home. A folder that
`nerve-run` could not be given (a file system without ACLs, a folder of
another account's on its way) shows above the list with the reason. Access
`nerve-run` keeps although it should have lost it (a folder you removed
whose entries the node could not take off) shows on every center whose
commands run as `nerve-run`, as **nerve-run keeps access it should have
lost**: none of its commands runs until that is fixed.

Where the kernel has no Landlock, a center whose commands run as `nerve-run`
shows **Without Landlock** under the mode, and **nerve-run can read more of
your home** when your home is open to other accounts or a folder you gave
lies in it ([modes](modes.md#your-home-and-other-accounts)). With Landlock
neither shows.

On **Permissions**, a center that lacks the guard against changing the node
(you took a rule of it off) shows **Add the guard**, and one that still holds
the guard's older text patterns, which keep working, shows **Update the
guard**. Both run `rule guard`
([rules](rules.md#the-guard-against-changing-the-node)).

What stays with the terminal: restoring the keys straight into the keyring
(`restore --secret-storage keyring`; restore, then switch **Keys** to the
keyring), and the keyring `setup` installs for the node's account on a
Linux without a desktop session for it.

## Relay

The **Relay** page has both sides of a [relay](relay.md). **This node
through a relay**: for a machine that reaches no center itself, **Connect…**
takes the link a relay showed (or its parts: the relay's address, this
node's name there, its token and the relay's pin), and the page says through
which relay the node goes and how many of its centers are linked.
**Disconnect** reaches the centers directly again. **This machine as a
relay**: its switch and address, its pin, the nodes that use it, each with
**Centers and limits…**, **New link…** and remove, the tunnels it carries
now, and its limits (`relay.max_links`, `max_links_per_node`,
`max_opens_per_minute`). **Add a node…** asks for its name and where it
reaches this machine, and shows its link once, with **Copy**. A
`nerve://relay` link you click opens the Relay page with it.

## Audit and Log

**Audit** and **Log** follow the node as it writes. **Audit** reads the
newest 1000 entries and filters them: **All**, **Allowed**, **Refused** or
**Changes** (settings), a center, an action (`exec.run`, `fs.read`, …) and
words to find in the target and the reason (in a change, its settings). The
filters combine, each choice shows how many entries it has, and the line below
says how many match. **Newest first** or **Oldest first** turns the list.
**Clear** on either asks
first, then runs `nerve-node audit clear` or `log clear`. A cleared audit log
is not gone: its entries stay in `audit.jsonl.1` ([audit](audit.md#clear-it)),
and the page starts with "Audit log cleared" and who did it.

## Pairing links

A `nerve://` link opens in Nerve and goes straight to what the pairing would
be. Before it offers **Pair**, the app checks the link: the center answers,
its certificate is the pinned one, and the code is still valid. When one of
these fails it says which, and what to do, and offers no **Pair**. Nothing
is paired until you confirm. Nerve has one window: opening it
again, or a link while it is open, goes to the window that is open. A link
carries the pairing's code and pin, so it goes only to a window of your
own: where the app cannot make sure of that (on Windows, when a program
that is not your Nerve holds the name the window listens by; on Linux,
when `$XDG_RUNTIME_DIR` is not a folder only you may open), each start
opens a window of its own and says so.

## Update

**Settings**, **App**, **Update…**: from the latest release
on GitHub (checked against its `SHA256SUMS`), or from a file you downloaded.
The update replaces the program, puts the menu entry back and restarts the
service; the node's settings, keys and audit log stay. **Restart Nerve**
opens the new version. Opening a newer downloaded file offers **Update** too,
also while the app is open: the open window comes to the front and says
which version the file is (on Wayland, where no program may raise itself,
the desktop says that Nerve wants your attention).

## Uninstall

**Settings**, **App**, **Uninstall…**. Choose whether the
node's data (settings, pairings, keys, audit log) stays or goes. The service,
its user, the program, the menu entry, the link handler and, on Linux, the
`nerve-node` link go, and the window says "Nerve is removed" until you close
it. Opening
the downloaded file again offers **Uninstall…** too, and on Windows so does
**Uninstall** at Nerve in **Settings**, **Apps** (Apps & features): it opens
the same in the app. Kept data comes back with the next install
([uninstall](service.md#uninstall)).

## What the app needs

On Linux the window uses parts of the desktop. GNOME and KDE Plasma bring all
of them; on another desktop, install what is missing.

| Part | What it is for | GNOME | KDE Plasma | Other desktops |
|---|---|---|---|---|
| A display, Wayland or X11 | The window | yes | yes | yes |
| OpenGL (Mesa's libEGL, libGL) | Drawing with the GPU; without it the app draws in software | yes | yes | usually |
| `pkexec` and a polkit authentication agent | Asking for administrator rights | built into GNOME Shell | `polkit-kde-agent-1`, part of Plasma | `polkit` and an agent, for example `polkit-gnome`, `lxpolkit`, `mate-polkit` |
| `xdg-desktop-portal` with a file chooser | The file and folder dialogs | `xdg-desktop-portal-gnome` | `xdg-desktop-portal-kde` | `xdg-desktop-portal` and `-gtk` or `-wlr` |
| `update-desktop-database` (desktop-file-utils) | Telling the desktop at once that Nerve opens `nerve://` links | yes | yes | install it, or log out and in after installing |

When a part is missing, the app says so:

| Missing | What happens |
|---|---|
| A display | The app does not start. It prints `no display: …` and shows it as a desktop notification where it can |
| OpenGL | The app starts once more drawing in software, and prints that it does. If that fails too, it prints `the window did not open …` |
| `pkexec` | Instead of the system's question: "There is no pkexec on this machine …", with the package to install |
| The polkit agent | pkexec says that no authentication agent answered, and the app shows instead: "No polkit authentication agent is running …", with agents to install |
| The portal | The button that opens a file or folder dialog says "No file dialog: …" and names the portal packages |
| `update-desktop-database` | Installing goes on, and its last step warns that the desktop may not know about the `nerve://` handler yet |

Windows needs nothing besides the app.

## In a terminal

On Linux, `nerve-node-desktop <command>` is `nerve-node <command>`, with
`sudo` on the installed node; where the app took over a node installed with
`nerve-node`, the command `nerve-node` runs the app's program, which says
`nerve-node-desktop` for `--version`.

On Windows the app is the node's program, and it has no console, so a
terminal does not wait for it. For a terminal, download the CLI edition
`nerve-node-x86_64-windows.exe` from the release: it is a console program,
and run from an administrator's terminal it works on the node the app
installed ([commands](commands.md)). The app's program in a terminal needs a
pipe to be waited for: `"C:\Program Files\Nerve\nerve-node-desktop.exe" status | more`
in cmd, `& "C:\Program Files\Nerve\nerve-node-desktop.exe" status | Out-Default`
in PowerShell. A batch file waits for it as it is.

## Keyboard

| Keys | Do |
|---|---|
| Ctrl+1 … Ctrl+8 | Open Overview, Centers, Relay, Permissions, Audit, Log, Settings, Help |
| Ctrl+R, F5 | Read the page again |
| Esc | Close a dialog |
| Enter | The dialog's main button |
| Tab, Shift+Tab | The next or the last control |
| Space | Press a button, tick a box |
| ← → | Choose in a row of choices or tabs |

A click on the page that is open reads nothing again; **Refresh** does.

## Help

**Help** lists these keys and has the command reference: every `nerve-node`
command by topic or from A to Z, with a filter. A command opens on its
arguments, an example, and a button to the place in the app that does the
same. The keys, the reference, each topic and each command open and close on
their own.

## The app's own settings

With **System**, the app is light or dark as the desktop is. On Linux it asks
the desktop portal's `color-scheme`, then GNOME's `color-scheme` and the
name of its GTK theme (a theme named `…-dark`, as on Zorin OS), and on KDE
its colour scheme; it follows a change within a few seconds. **Light** and
**Dark** win over the desktop. A change of the look comes in one step, with no
light frame between two dark ones.

Pages, dialogs, notes in the corner, sections that open, buttons and switches
move briefly (up to 200 ms). When the desktop asks for less motion they do not,
and the loading dots and spinners stand still: on GNOME **Reduce Animation**
in the accessibility settings (`enable-animations`), on KDE an animation
speed of **Instant** (`AnimationDurationFactor=0` in `kdeglobals`), on Windows
**Animation effects** off (Accessibility, Visual effects). On Linux the app
asks the desktop portal's `reduced-motion` first, and GTK's
`gtk-enable-animations` on other desktops. It follows a change within a few
seconds.

The appearance (system, light or dark), and the card on commands that run as
you when you hid it, are kept in
`~/.config/nerve-node-desktop/settings.json` on Linux and
`%APPDATA%\nerve-node-desktop\settings.json` on Windows, apart from the
node's settings.
