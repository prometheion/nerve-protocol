# Troubleshooting

Start with these on the machine:

```sh
nerve-node status
nerve-node audit --refused --last 20
nerve-node log --problems --last 20
```

The refusal in the audit log is the text the agent saw. One that starts with
`the center's action checker` comes from the center: look at the center's
Audit and Log pages. Every message, with its cause and fix, is in
[messages](../dev/messages.md).

<details>
<summary>The agent sees <code>forbidden</code></summary>

| Message | Fix |
|---|---|
| `no allow rule matches …` | `allowlist` mode: [add a rule](rules.md), or choose another [mode](folders-and-modes.md) |
| `outside the folders that allow reading` (or `writing`) | `nerve-node folder add <path> rw` |
| `the working directory is not in a folder that allows running` | `nerve-node folder add <path> rwx` |
| `… chains commands or holds an expression …` | A wildcard covers plain commands only: add a rule for the whole line |
| `… is turned off on node … by its owner` | `nerve-node cap set <capability> on` |
| `the owner turned the network off for this center's commands …` | That mode runs nothing with the network off: `nerve-node network on`, or `folder` mode ([network](network.md)) |
| `the center's action checker refused this call …` | See the action checker below |

</details>

<details>
<summary>A file in a granted folder gives <code>Permission denied</code></summary>

The file was moved there (`mv`) and kept its own access list. The node
fixes that by itself within seconds. If it stays (the log says the folder is
too large to watch), press **Sync folders** under **Permissions › Folders**,
or run `nerve-node folder sync`.

</details>

<details>
<summary>The action checker refuses a call</summary>

| Message | Fix |
|---|---|
| `… it is on the center's blocklist …` | Switch the entry off, for every machine or for this one, on the Action checker page |
| `… decision model judged this call dangerous …` | **Trust this** on the Audit page adds a Skip the model rule |
| `… could not reach its decision model … (fail closed)` | Install or start the local model, or switch it to allow-and-log |
| `… no answer within the timeout …` | Raise the timeout under **Advanced**, or use an endpoint |

</details>

<details>
<summary>Pairing fails</summary>

| Message | Fix |
|---|---|
| `the pairing code is unknown, used, expired or out of tries` | Make a new link in the web UI |
| `another node already has this name` | `nerve-node config set node.name <other>`, then pair again |
| `this center is paired already as …` | Use that pairing, or `nerve-node center rm` it first |
| A link or TLS error | Check the center's `--public-url` and port, then make a new link |

</details>

<details>
<summary>The machine shows offline</summary>

`nerve-node center` shows a flag:

| Flag | Fix |
|---|---|
| `[paused]` | `nerve-node center resume <name>` |
| `[revoked]` or `[unknown]` | `nerve-node center rm <name>`, then pair again |
| none | The node is dialling, with a wait of up to 60 seconds |

- `status` says `LOCKED (panic)`: `nerve-node unlock`.
- `status` says the center is older than this node: update the center first.
- `node: not running`: `nerve-node service start`.

</details>

<details>
<summary>The node does not start</summary>

`journalctl -u nerve-node` says why.

| Message | Fix |
|---|---|
| `node.toml is refused: its MAC does not match …` | Read the file, then `nerve-node config accept` ([settings](settings.md#a-file-changed-by-hand)) |
| `… format 2: a newer version of Nerve wrote this file …` | Run that version again, or restore a backup |
| `machine.secret_storage is "keyring", but the system keyring cannot be reached …` | Start the keyring, or keep the keys in files |
| `rename NERVE_… to NERVE_NODE_… where you set it …` | Rename it in your shell, script or unit |

</details>

<details>
<summary>The center does not start, or harnesses get 401</summary>

`journalctl -u nerve-center` says why.

| Message | Fix |
|---|---|
| `another nerve-center already runs the center in …` | Stop the other center, or use another `--state-dir` |
| `rename NERVE_… to NERVE_CENTER_… in /etc/nerve-center/center.env` | Rename it there, then `sudo systemctl restart nerve-center` |
| `401` for a harness | Make a harness token on the Connect a harness card |

</details>

<details>
<summary>I cannot log in to the center's web UI</summary>

| Message | Fix |
|---|---|
| `Wrong owner token.` | `sudo nerve-center owner-token` shows it; without `sudo` for a center your harness starts. A harness token never logs in |
| `… holds no owner token` | `nerve-center owner-token --new` |
| `403` behind a reverse proxy | Let the proxy send a loopback `Host`, or serve the UI beyond loopback with TLS |

</details>

<details>
<summary>The node's web UI does not answer</summary>

| What you see | Fix |
|---|---|
| `cannot listen on …` | Free the port, or `nerve-node ui on --listen 127.0.0.1:<port>` |
| `the web UI is part of the installed node …` | `sudo nerve-node install`; a node run by hand serves none |
| `Wrong token.` | `nerve-node ui token add <label>` makes a new one |
| The browser warns about the certificate | Compare its fingerprint with the one `nerve-node ui` prints |

</details>

<details>
<summary>A command does not see a variable, or a password prompt hangs</summary>

- Commands of `nerve-run` get only `PATH`, `LANG`, `TERM` of the service's
  environment: `nerve-node config add machine.command_env <NAME>`.
- A `folder` mode command has no terminal. Give `ssh`, `gpg` or git a key or
  a credential file in the pairing's home, `/var/lib/nerve-run/<center>/home`.

</details>

<details>
<summary>A command is killed or its output is cut</summary>

- `killed: … memory limit` raise `limits.command.memory_mb`, or the call asks
  for more ([settings](settings.md#limits-per-command)).
- A command returns at most 1 MiB of stdout and of stderr (`truncated:
  true`). A file read returns at most 2 MiB.

</details>

<details>
<summary>A change did not apply</summary>

A command that changes the node goes through the running node. Without one,
it says `the change is in node.toml; it takes effect at the next start of
the node`: `nerve-node service start`. A command a center runs as
`nerve-run` cannot change the node: `refused: this request comes from a
command the node runs for a center`. One that runs as you (`user` mode,
`--as-owner`) is refused only when it runs `nerve-node` itself, and can go
another way ([user mode](../dev/policy-engine.md#user-mode)).

</details>
