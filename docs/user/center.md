# Run the center and connect a harness

The center is what your harness talks to. Run it as the service
([install](install.md#the-center-as-a-service)):

```sh
sudo ./nerve-center-x86_64-linux install --name lab
nerve-center status
```

`status` says whether it runs, its addresses and its machines, and ends
with its log command, `journalctl -u nerve-center`. On Windows, run these in
an administrator's terminal ([Windows](windows.md#the-center-as-a-service)).

## Log in to the web UI

Open `http://127.0.0.1:7480` and log in with the **owner token**. `install`
prints it, and this shows it again:

```sh
sudo nerve-center owner-token
sudo nerve-center owner-token --new   # a new one; the old one stops
```

The owner token is the one secret of the web UI. A harness token never logs
in there ([web UIs](web-uis.md#the-centers-web-ui)).

## Connect a harness

The web UI's **Connect a harness** card (on the Overview, and under
**Settings › Harness tokens**) does it:

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

Delete a token under **Settings › Harness tokens** to stop it: its sessions
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
| 7480 | the web UI, this machine only | `--ui`, `NERVE_CENTER_UI` |
| 7481 | harnesses over HTTP, this machine only | `--mcp`, `NERVE_CENTER_MCP` |

Set `--public-url` when nodes reach the center under another name than its
host name, such as a DNS name or a forwarded port.
`NERVE_CENTER_HARNESS_TOKEN` adds a fixed harness token, for a harness a
script sets up; `--harness-token` does too, but shows it in the process
list. `nerve-center --help`
lists every setting. For the service they live in
`/etc/nerve-center/center.env`; change them there, then
`sudo systemctl restart nerve-center`. On Windows the file is
`C:\ProgramData\nerve-center\settings\center.env`, and
`Restart-Service nerve-center` restarts it.

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

- **Beyond loopback**: set `NERVE_CENTER_MCP=0.0.0.0:7481` (and
  `NERVE_CENTER_UI` for the web UI). They then use TLS with the center's
  self-signed certificate. The Connect a harness card shows its fingerprint:
  let the harness and the browser trust that certificate, and compare the
  fingerprint before you log in
  ([TLS](../dev/settings-and-config.md#tls)).

Nodes always connect over TLS. The pairing link carries the certificate's
pin, so a node trusts exactly that center.

## Rotate the key

**Settings › Center key › Rotate key** makes a new key and shows its pin.
The center tells every machine that links in the next 7 days. Then it
switches; **Serve the new key now** switches at once.

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

Several harnesses on one machine share one such center: a second
`nerve-center` attaches to the first. A harness cannot start its own center
while the service runs, as the port is taken. To move a center you ran
yourself into the service, with its pairings, see [backup](backup.md#move).

## Its log

```sh
journalctl -u nerve-center
```

The web UI's **Log** page shows the same log, with links, pairings,
refusals and errors ([watch and stop](watch-and-stop.md)).
