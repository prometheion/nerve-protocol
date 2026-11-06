# What Nerve guards and what it does not

Nerve keeps a center to what you give it on each machine. These are its
limits, one line each. Each comes back on the page of its task, and the link
leads to the detail.

## Modes and accounts

- `user` mode, and `allowlist` mode with `--as-owner`, run commands as you,
  outside the sandbox. Where root is the owner, they run as root
  ([accounts](../dev/sandbox-linux.md#the-accounts-commands-run-as)).
- A command that runs as you can change the node's settings as you can:
  the node refuses only the simple ways, as a guard against mistakes
  ([user mode](../dev/policy-engine.md#user-mode)).
- With root as the owner, a center with the settings grant can switch
  itself to `user` mode and so run commands as root
  ([root as the owner](../dev/service.md#root-as-the-owner)).
- Commands on the sudo list run as root, outside the folders. With the
  network off they do not run
  ([sudo](../dev/policy-engine.md#sudo-as-the-owner-uses-it)).
- Taking the grant back leaves what the center changed, still on.
  `center settings off` names it
  ([the grant](../dev/settings-and-config.md#without-the-grant)).
- Turning sudo on in the center's web UI puts your password into a page the
  center serves. If you do not trust it, run `sudo nerve-node sudo on` on the
  machine ([from the web UI](../dev/policy-engine.md#from-the-web-ui)).

## Folders

- On the installed node, a file call in `folder` mode may also read what
  every account may read, such as `/etc` and most of `/usr`
  ([reading](../dev/sandbox-linux.md#reading-in-folder-mode)).
- A command in an `x` folder can also read its files by name, not list them
  ([reading](../dev/sandbox-linux.md#what-a-command-can-reach-in-folder-mode)).
- A folder with `none` is closed to file calls. A command started in the
  folder around it still reaches it
  ([folders](../dev/policy-engine.md#folders-and-rights)).
- A file you move into a granted folder keeps its own access list. Run
  `nerve-node folder sync`
  ([why](../dev/sandbox-linux.md#a-folder-keeps-the-place-you-added)).
- Without Landlock, `nerve-run` can read every file in your home that other
  accounts may read, once you give it a folder there. `status` warns
  ([your home](../dev/sandbox-linux.md#your-home-and-other-accounts)).

## Pairings on one machine

- All pairings share `/tmp` and `/var/tmp`. Keep no secret there, and run no
  key agent or credential cache in a pairing's home
  ([the account](../dev/sandbox-linux.md#the-account-nerve-run)).
- Without Landlock, each pairing's commands reach the homes, the folders and the
  running commands of the others, with their network, as all run as
  `nerve-run`. `status` warns; give a center you trust less a
  machine of its own ([the account](../dev/sandbox-linux.md#the-account-nerve-run)).
- Below Linux 6.12 (stock Ubuntu 22.04, 24.04 and Debian 12), one center's
  commands can signal another's and reach its abstract sockets. `status`
  warns ([Landlock versions](../dev/sandbox-linux.md#landlock-versions)).
- Below Linux 6.2 (stock Ubuntu 22.04 and Debian 12), a command can empty a
  file `nerve-run` may write outside its folders. A node run by hand there
  runs no `folder` mode command
  ([Landlock versions](../dev/sandbox-linux.md#landlock-versions)).

## Network

- `folder` mode leaves the network open. `nerve-node network off` closes it
  for one center's commands ([network](network.md)).
- With the network off, none of that center's commands runs in `user` mode,
  in `allowlist --as-owner`, on most nodes run by hand, or where the machine
  cannot hold the switch
  ([no network](../dev/sandbox-linux.md#no-network-for-a-centers-commands)).
- A command reaches every unix socket its account may write to. On a node
  run by hand, that includes your session's (tmux, X)
  ([what it does not stop](../dev/sandbox-linux.md#what-it-does-not-stop-linux)).
- The network switch does not stop a name lookup through the system's
  resolver, a program a command left running, or a program's action
  ([network](network.md)).

## Commands

- Commands of `nerve-run` see only the variables you name in
  `machine.command_env`. Put no secret into the service unit
  ([environment](../dev/sandbox-linux.md#the-accounts-commands-run-as)).
- The action checker's blocklist and the node's guard catch mistakes by
  name, not someone who hides the name. The mode, the rules and the account
  are the protection ([guard](../dev/policy-engine.md#the-guard)).
- A mode change, `cap set ... off` or the end of a `--for` does not stop a
  running command. A program handed to a service manager, or detached on a
  node without a cgroup, outlives a stop
  ([what ends a command](../dev/sandbox-linux.md#what-ends-a-command)).
- While a command runs, its line, with the call's values, is readable by
  every account, the other centers' commands too. Put no secret in a command
  or a capability's line
  ([secrets](../dev/capabilities.md#keep-secrets-out-of-the-command)).
- The check of a program's provider tells programs apart, not users: allow
  only programs you trust
  ([capabilities](capabilities.md)).
- On a node run by hand the keyring is yours: an allow rule for `secret-tool`
  hands a center the node's keys
  ([keys](../dev/settings-and-config.md#where-the-node-keeps-its-keys)).
- A command that asks another program for something, such as the keyring
  over D-Bus, names no protected path
  ([protection](../dev/policy-engine.md#what-protection-covers)).

## The center

- The decision model fails closed by default: while it is on and not
  running, every call it checks is refused
  ([decision model](../dev/action-checker.md#the-decision-model)).
- The installed center sees no GPU. Its local model runs on the CPU
  ([the service](../dev/service.md#settings-of-the-service)).
- An agent can read its harness token. That token opens `/mcp` only, never
  the web UI ([tokens](../dev/mcp-surface.md#tokens)).
- A center you run as yourself keeps its owner token where your agent may
  read it. Run the center as the service
  ([center](center.md#a-center-your-harness-starts)).
- A machine that does not link within 7 days of a center key rotation must
  be paired again ([rotation](../dev/identity-and-pairing.md#rotate-the-centers-key)).
- A backup holds neither the owner token nor the checker's endpoint token
  ([backup](../dev/backup.md#what-is-not-in-a-backup)).
- A restored backup brings its own pairings, modes and rules: restore only
  one you made yourself ([restore](../dev/backup.md#restore)).
- While `center add` asks, the link is in the process list: use
  `center add -` ([pair](pair.md)).
- The relay link holds the relay token, and the `claude mcp add` line holds
  the harness token. Delete them from your shell's history
  ([pair](pair.md), [center](center.md)).
- A relay token reaches the relay's centers' host and port, and the other
  sites a reverse proxy serves there
  ([relay](../dev/node-link.md#a-relay-as-the-owner-sets-it-up)).

## Web UIs, updates and logs

- Beyond loopback, both web UIs need TLS on a self-signed certificate.
  Compare its fingerprint before you log in, or keep them on loopback
  behind an SSH tunnel ([beyond loopback](../dev/web-uis.md#beyond-loopback)).
- A panic ends web UI sessions, not tokens: `ui token rm` a leaked one first
  ([panic](../dev/web-uis.md#panic)).
- Releases are not signed yet. `update` trusts the `SHA256SUMS` of the same
  release ([update](../dev/service.md#update-the-node)).
- The audit log (about 20 MiB) and the log (about 10 MiB) drop their oldest
  entries ([logs](../dev/logging.md#the-file)).
