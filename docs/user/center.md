# Run the center and connect a harness

The center is what your harness talks to. Run it as the service
([install](install.md#the-center-as-a-service)):

```sh
sudo ./nerve-center-x86_64-linux install --name lab
nerve-center status
```

`status` says whether it runs, its addresses and its machines, and what to
do next. `sudo nerve-center service start|stop|restart` starts and stops
it. The app `nerve` installs the center too, as its role
([the desktop app](install.md#the-desktop-app)); then `nerve-center` is a
link to it, and the app manages it ([in the app](#in-the-app)). On Windows
the app installs it ([Windows](windows.md#the-center-as-a-service)).

## In the app

On a machine where the app `nerve` installed the center (on Windows always),
**Nerve** in the menu opens the center's pages: Overview, Nodes, Harnesses,
Action checker, Capabilities, Statistics, Audit, Log, Settings and Help.
They ask for the owner token first: paste it, or **Read it from this
machine…**, which asks for an administrator's password once. The app keeps
it in memory until it closes; **Settings › Owner token › Remember the log-in
in my keyring** keeps it for the next start, where other programs of yours,
an agent among them, could read it.

The pages ask the center as its terminal commands do, with the web UI on or
off. Before the token goes out, the app checks that the center's service
answers; another program gets nothing. What only an administrator may do
(start and stop, an address in **Settings › Center**, update, uninstall, the
owner token, backup and restore) asks for the password each time.

A copied harness token, harness line or pairing link leaves the clipboard
after a minute, or when the app closes.

**Settings › Backup › Restore…** takes a backup of this center. To move a
center to a new machine, install the center there, then restore its backup
with **It is another center's backup** ticked: the new center takes the old
one's key, pairings and settings.

**Settings › This machine › Change the role…** makes the machine a node:
it offers a backup first, names the machines paired with this center (they
keep it until it is removed there), removes the center with its data, and
opens the installer for the node.

## In the terminal

What the web UI and the app do, the terminal does too, also with the web UI
off:

```sh
sudo nerve-center pair                  # a link that pairs a new machine
sudo nerve-center nodes                 # the paired machines
sudo nerve-center nodes disable lab     # off: the agent cannot use it
sudo nerve-center nodes rm lab          # unpaired
sudo nerve-center token new laptop      # a harness token, shown once
sudo nerve-center token list
sudo nerve-center token rm laptop
sudo nerve-center checker               # its switches and rules, numbered
sudo nerve-center checker block add 'exec.run:shutdown *'
sudo nerve-center audit skip 3a9f01c2d4e5b678   # such calls skip the model
sudo nerve-center log --problems
```

The rest is in [commands](commands.md#nerve-center). They ask the running
center through its own socket, which root, an administrator, the center's
account and the account that installed it may use. All but root and an
administrator give the owner token: a program of yours gets nothing without
it.

## Log in to the web UI

The web UI is on by default on Linux, at `http://127.0.0.1:7480`. On Windows
it is off: **Settings › This machine › Web UI** in the app turns it on, as
`set ui 127.0.0.1:7480` does. Log in with the **owner token**. `install`
prints it, and this shows it again:

```sh
sudo nerve-center owner-token
sudo nerve-center owner-token --new   # a new one; the old one stops
```

The owner token is the one secret of the web UI. A harness token never logs
in there ([web UIs](web-uis.md#the-centers-web-ui)).

## Connect a harness

The web UI's **Harnesses** page does it, under **Connect a harness**:

1. Press **Make a token**. The token is shown only now.
2. Copy the JSON into your harness's MCP settings. Or copy the URL and the
   header, or the `claude mcp add` line for Claude Code.

```json
{"mcpServers": {"nerve": {"type": "http", "url": "http://127.0.0.1:7481/mcp",
  "headers": {"Authorization": "Bearer <harness token>"}}}}
```

The `claude mcp add` line puts the token in your shell's history; the JSON
does not. An agent can read its harness token. That token opens `/mcp`
only ([tokens](../dev/mcp-surface.md#tokens)).

Remove a token on the **Harnesses** page to stop it: its sessions
end at once, with their jobs. A session also ends after 30 minutes without
a request; the harness then opens a new one
([sessions](../dev/mcp-surface.md#sessions)).

The harness gets two tools: `list` shows the machines and what they offer,
and `execute` runs one action. Your harness may ask before each tool call.
Allowing `execute` allows all a machine lets this center do, so decide that
on the machine: its [mode](folders-and-modes.md) and [rules](rules.md)
([the tools](../dev/mcp-surface.md#the-tools-the-model-gets)).

A call still running after 20 seconds becomes a job: `execute` answers its
id at once, and `job.status` gives the result later. `--call-wait` changes
the 20 seconds; keep it below your harness's own timeout for a tool call
([jobs](../dev/mcp-surface.md#long-calls-become-jobs)).

## Ports

| Port | For | Setting |
|---|---|---|
| 7443 | nodes, over TLS | `--listen`, `NERVE_CENTER_LISTEN` |
| 7480 | the web UI, this machine only (off on Windows until you turn it on) | `--ui`, `NERVE_CENTER_UI` |
| 7481 | harnesses over HTTP, this machine only | `--mcp`, `NERVE_CENTER_MCP` |

Set `--public-url` when nodes reach the center under another name than its
host name, such as a DNS name, an address or a forwarded port. `status` shows
it, and warns of a bare host name.
`NERVE_CENTER_HARNESS_TOKEN` adds a fixed harness token, for a harness a
script sets up; `--harness-token` does too, but shows it in the process
list. `nerve-center --help`
lists every setting.

The service keeps its settings in `/etc/nerve-center/center.env` (on
Windows `C:\ProgramData\nerve-center\settings\center.env`). `set` changes
`name`, `public-url`, `listen`, `ui` or `mcp` there and restarts the
service; `install` takes them as flags (`--ui 0.0.0.0:7480`):

```sh
sudo nerve-center set                   # shows them
sudo nerve-center set ui 0.0.0.0:7480   # the web UI for other machines
```

Change the others in that file, then `sudo systemctl restart nerve-center`.
On Windows, run `set` in an administrator's terminal.

### Which setting wins

- A flag wins over its variable.
- `--name` replaces the name set in the web UI each time the center starts.
- `--log` holds for one run. Without it, the level set in the web UI holds.

## A center on another machine

The center on a server, the harness on your laptop:

- **SSH tunnel** (simplest): keep the center on loopback, and forward its
  ports.

  ```sh
  ssh -L 7480:127.0.0.1:7480 -L 7481:127.0.0.1:7481 you@center-host
  ```

- **Beyond loopback**: `sudo nerve-center set mcp 0.0.0.0:7481` (and
  `set ui 0.0.0.0:7480` for the web UI). They then use TLS with the center's
  self-signed certificate. **Connect a harness** shows its fingerprint:
  let the harness and the browser trust that certificate, and compare the
  fingerprint before you log in
  ([TLS](../dev/settings-and-config.md#tls)).

Nodes always connect over TLS. The pairing link carries the certificate's
pin, so a node trusts exactly that center.

## Rotate the key

**Settings › Center key › Rotate key** (or `sudo nerve-center key rotate`)
makes a new key and shows its pin. The center tells every machine that links
in the next 7 days. Then it switches; **Serve the new key now**
(`key finish`) switches at once.

- A machine that does not link within the 7 days must be paired again.
- Update the nodes before you rotate the key.
- A browser asks again to trust the web UI's new certificate beyond
  loopback.

[Rotation](../dev/identity-and-pairing.md#rotate-the-centers-key).

## A center your harness starts

A harness may start `nerve-center` itself, over stdio:

```json
{"mcpServers": {"nerve": {"command": "nerve-center"}}}
```

Then the center runs as you, with its state in
`~/.local/state/nerve-center`. `nerve-center owner-token` shows its owner
token, without `sudo`. Started by hand at a terminal, the center waits for a
harness there and takes what you type as MCP: run commands in another
terminal. An agent with file or shell tools can read that
token and log in to the web UI. Run the center as the service to keep the
agent out.

The commands of [In the terminal](#in-the-terminal) work on it without
`sudo`.

Several harnesses on one machine share one such center: a second
`nerve-center` attaches to the first. A harness cannot start its own center
while the service runs, as the port is taken. To move a center you ran
yourself into the service, with its pairings, see [backup](backup.md#move).

## Its log

```sh
sudo nerve-center log                   # its log file, the older one first
sudo nerve-center log --problems --last 50
journalctl -u nerve-center              # what the service printed
```

The web UI's **Log** page shows the same log, with links, pairings,
refusals and errors ([watch and stop](watch-and-stop.md)).
