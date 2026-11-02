# The node's web UI

The installed node on Linux can serve a web UI like the desktop app: the same
pages, the same look. It is off unless you turn it on, and the CLI keeps
working beside it. It is part of the service: no other program runs for it.

This holds for both programs on Linux: the plain `nerve-node` and the desktop
app `nerve-node-desktop` (its node and its CLI work the same). On Windows there
is no node web UI: the desktop app is the node's UI there, and `ui` says so.

## Turn it on

```sh
nerve-node ui on
```

- The UI listens on `http://127.0.0.1:7470`. `--listen ADDRESS` picks another.
- With no token yet, `ui on` makes one named `first` and shows it once. Keep
  it in a password manager: node.toml keeps only its SHA-256.
- The running node takes the change at once. `ui on` waits up to 3 seconds and
  says what the node did: `listening on 127.0.0.1:7470`, or why it cannot
  (`cannot listen on 127.0.0.1:7470: …`).
- Open the UI after `nerve-node ui status` says `listening`. Until then
  another program could hold the port.

From another machine, keep the UI on loopback and use an SSH tunnel:

```sh
ssh -L 7470:127.0.0.1:7470 you@node-host
```

Then open `http://127.0.0.1:7470` on your machine.

```sh
nerve-node ui off
```

turns it off: the node stops listening, and every session ends. The tokens
and the certificate stay. Off, the node listens on nothing and does nothing
for the UI.

`nerve-node ui` (or `ui status`) shows whether it is on, where it listens, the
node's state of it, and the labels of the tokens.

A node you run by hand (`nerve-node run`) serves no web UI.

## Tokens

| Command | Does |
|---|---|
| `nerve-node ui token add <label>` | Makes a token and shows it once. A label is 1 to 32 of `a-z`, `0-9` and `-` |
| `nerve-node ui token ls` | Lists the labels and when each was made, never a token |
| `nerve-node ui token rm <label>` | Revokes a token. The sessions it opened end at once |

Tokens are made only at the CLI. In the UI you can revoke one
(**Settings › Web UI**), but not make one: a browser session must not be able
to give itself a login that outlives it.

Lost a token? Make a new one with `ui token add`, and `ui token rm` the old
one.

## Log in

- The login is always on, on loopback too.
- A wrong token costs 300 ms. It never locks the login: any program on this
  machine could otherwise keep you out. The log says how many were refused,
  once a minute.
- The session lasts 12 hours and belongs to the browser tab. A new tab, or the
  browser opened again, logs in again. No cookie is kept.
- A session ends with **Sign out**, when its token is revoked, with `ui off`,
  when the node restarts, and with **panic**.
- **Sign out** also clears what the page kept in this browser for the UI's
  address, so its other tabs of the UI sign in again too.

## Panic

**Panic** (on the Overview, or `nerve-node panic`) ends every web UI session
too. Maybe a browser or a session leaked; a leaked session must not undo the
panic. To unlock in the UI, log in again with a token, or run
`nerve-node unlock`.

## Who can reach it

| Who | Can | Cannot |
|---|---|---|
| A command of a center as `nerve-run` (`folder`, `allowlist` mode) | Open a connection, which is closed at once | Read a byte of the UI or try a token |
| A command of a center as you (`user` mode, `--as-owner`) | Reach the login page and try tokens, 300 ms each | Read a token or a session: the hashes are in the node's own folder, sessions only in the node's memory |
| Another account of this machine | The same as `nerve-run` | |
| Another machine | Only beyond loopback (below), and then only with a token | |

From this machine, only your account and root may connect. The token is what
keeps the commands of `user` mode out. A command of `user` mode can already
change the node's settings as you can (see [modes](modes.md)); the web UI adds
no way for it.

## What the web UI does

Every change in the UI is one `nerve-node` command, run for you by the node,
with every check the CLI makes. So the UI may do what you may do as the owner,
and nothing more.

| Page | Does |
|---|---|
| **Overview** | Status, the centers and their links, the root-as-owner warning, **Panic** and **Unlock** |
| **Centers** | Pair from a pasted link (it goes to the node as the command's input, never in a command line), pause and resume, the settings grant, a new key, remove |
| **Permissions** | Mode (also for some hours, and as the owner), folders (a whole path), allow, deny and sudo rules, the guard, sudo off |
| **Audit** | What the node allowed and refused, refused only, Live; **Allow**, **Allow as wildcard** and **Deny** show the rule as it will be stored first, with hidden characters written out |
| **Log** | Problems only, Live, clear |
| **Capabilities** | A center's switches (on, off, hidden), your own capabilities, the programs that may add capabilities |
| **Relay** | Connect through a relay, or let other nodes reach this node's centers through it; a new node's link is shown once |
| **Settings** | The name, the log level, any setting by its name (**Advanced**), and **Web UI**: where it listens and its tokens, with **Revoke** |
| **Help** | The command reference |

Done only at the CLI: `install`, `update`, `uninstall`, `service …`, `setup`,
`sudo on`, `backup` and `restore`, `config accept`, every `ui …` change but
revoking a token, the settings that decide which account commands run as
(`machine.user`, `machine.allow_root`, `machine.sudo_path`, `machine.shell`;
shown in the UI), and any setting under `ui`. The Overview shows the command
to start, stop or restart the service; a page served by the service cannot
restart it.

## Beyond loopback

```sh
nerve-node ui on --listen 0.0.0.0:7470
```

- Any address but loopback makes the UI reachable from the network. `ui on`
  says so, and how to keep it on loopback with the SSH tunnel instead.
- The UI is then served over HTTPS with a certificate of its own, made the
  first time. It names the address (when it is a specific one), this
  machine's name, `localhost`, and each `--name HOST`. Giving `--name` makes a
  new one.
- `ui on` and `ui status` print its SHA-256 fingerprint. Your browser warns
  about the certificate the first time: compare the fingerprint it shows with
  the printed one before you sign in.
- `--new-cert` makes a new certificate: every session ends, and the browser
  asks again.
- Without its certificate the UI does not listen beyond loopback at all;
  `ui status` says why.
- One address has at most 16 connections at once (an IPv6 /64 counts as one
  address, and on this machine each account counts as one). A browser opens
  six to load a page. A wrong token's 300 ms hold none of them.

The UI's certificate is its own, not the relay's. Its key is kept with the
node's other keys (`machine.secret_storage`). It is not in a backup: a restore
says when the restored config turns the UI on, and when it needs a new
certificate, which `ui on --new-cert` makes.

## node.toml

```toml
[ui]
listen = "127.0.0.1:7470"   # absent: off
pin = "…"                   # the certificate's pin, beyond loopback

[[ui.token]]
label = "laptop"
token_sha256 = "…"
made = "2026-11-02T10:00:00Z"
```

Change it with `nerve-node ui`, not by hand: a node.toml the node did not sign
is refused. A center never sees or changes `[ui]`.
