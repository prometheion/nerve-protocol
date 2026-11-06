# The web UIs and the app

Three windows on Nerve: the center's web UI, the node's web UI and the
desktop app. Each change you make there runs the same check as the CLI.

## The center's web UI

Open `http://127.0.0.1:7480` and log in with the **owner token**:

```sh
sudo nerve-center owner-token          # the service
nerve-center owner-token               # a center your harness starts
```

- The login is always on, on loopback too. A harness token never logs in.
- The session lasts 12 hours and belongs to the browser tab. **Sign out**
  ends it. `owner-token --new` makes a new token and ends every session.
- A wrong token costs a short wait. It never locks the login.
- On loopback the UI answers only to a loopback host name. A reverse proxy
  must send that `Host`, or the UI refuses it
  ([log in](../dev/web-uis.md#log-in)).
- A center you run as yourself keeps its owner token where your agent may
  read it. Run the center as the service
  ([center](center.md#a-center-your-harness-starts)).

From another machine, use an SSH tunnel:
`ssh -L 7480:127.0.0.1:7480 you@center-host`.

| Page | Does |
|---|---|
| **Overview** | Get started, the machines, **Pair a machine**, **Connect a harness**, the sessions |
| **Statistics** | Calls per day, per machine and per action |
| **Audit** | Each call the center sent, with **Trust this** buttons that add a rule |
| **Action checker** | Blocklist, decision model, Skip the model ([action checker](action-checker.md)) |
| **Capabilities** | What each machine offers, and capabilities this center adds |
| **Log** | The center's log, problems only, Live |
| **Help** | Connect a harness, the `nerve-center` and `nerve-node` commands |
| **Settings** | Name, log level, center key, harness tokens, machines with the settings grant |

The Audit buttons and a machine's settings need that machine's
[settings grant](rules.md#the-settings-grant)
([the pages](../dev/web-uis.md#pages)).

## The node's web UI

The installed node can serve a web UI with the app's pages. It is off until
you turn it on:

```sh
nerve-node ui on                       # shows a first token once
nerve-node ui                          # on or off, where, the tokens
nerve-node ui off                      # stops it; every session ends
```

It listens on `http://127.0.0.1:7470`. Keep the token in a password manager:
the node keeps only its hash. From another machine, use an SSH tunnel:
`ssh -L 7470:127.0.0.1:7470 you@node-host`.

| Command | Does |
|---|---|
| `nerve-node ui token add laptop` | Makes a token and shows it once |
| `nerve-node ui token` | Lists the tokens by label, never a token |
| `nerve-node ui token rm laptop` | Revokes it; its sessions end at once |

Tokens are made only at the CLI. A command of a center as `nerve-run` cannot
reach the UI. One as you (`user` mode) reaches only the login. A session
ends with **Sign out**, `ui off`, a revoked token, a restart and **Panic**.
A node run by hand serves no web UI.

`ui on --listen 0.0.0.0:7470` opens it to the network, over HTTPS with a
certificate of its own. `ui on` prints its fingerprint.

- Beyond loopback, both web UIs need TLS on a self-signed certificate.
  Compare its fingerprint before you log in, or keep them on loopback
  behind an SSH tunnel ([beyond loopback](../dev/web-uis.md#beyond-loopback)).

Done only at the CLI: `install`, `update`, `uninstall`, `service`, `setup`,
`sudo on`, `backup`, `restore`, the `ui` settings and the settings that
decide the account commands run as.

## The desktop app

The app is the node with a window ([install](install.md#the-desktop-app)).
Open **Nerve** from the application menu. It does what `nerve-node` does,
and runs the CLI for each action. Its node has the node's web UI too, off
until `nerve-node-desktop ui on`.

| Page | Does |
|---|---|
| **Overview** | Status, the service (Start, Stop, Restart), **Panic** and **Unlock** |
| **Centers** | Pair from a link, pause, the settings grant, a new key, remove |
| **Relay** | Connect through a relay, or be one |
| **Permissions** | Mode, the network, folders, allow, deny and sudo rules, sudo off |
| **Capabilities** | Switches, your own capabilities, the programs that may add some |
| **Audit** | What the node allowed and refused, with **Allow** and **Deny** buttons |
| **Log** | The node's log, problems only |
| **Settings** | Name, keys, log level, backup, update and uninstall |
| **Help** | The keys, and the command reference |

Ctrl+1 to Ctrl+9 open the pages. The app asks for an administrator's
password only for what changes the system: update, uninstall, turning sudo
on, and the settings that decide the account commands run as
([rights](../dev/desktop.md#administrator-rights)).

On a desktop other than GNOME or KDE Plasma, the app needs a polkit agent
and `xdg-desktop-portal`; it says when one is missing
([what the app needs](../dev/desktop.md#what-the-app-needs)).
