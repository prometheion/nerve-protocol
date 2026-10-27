# Back up, restore and move

`nerve-node backup` and `nerve-center backup` write what a machine would lose
to one file, protected with a passphrase. `restore` puts it back: on the same
machine after a mishap, or on another one when you move the node or the
center.

The file holds private keys. It is encrypted, so it can lie on a stick or in a
cloud folder, but only as safely as its passphrase. A passphrase has at least
12 characters. Nobody, you included, can open the file without it.

## The node

```sh
nerve-node backup ~/nerve-node.bak
```

It asks for the passphrase twice. The file is private to you (mode 0600; on
Windows it gets the permissions of its folder). It refuses to replace a file
that exists; `--overwrite` does.

| In the backup | Not in it |
|---|---|
| `node.toml` as the node reads it: pairings with their `url`, `pin`, `center_id` and `node_id`, modes, folders, rules, relay and proxy settings | The key of the config's MAC: a node that restores makes its own |
| The node key of every center, the relay's TLS key, the password of an `https://` proxy (the keys in `keys/`) | The sudo password. It is not stored anywhere, so a node restores with `sudo` off. On Windows the restore also deletes `sudo.dpapi`, which holds that password only while the switch is on |
| The proxy's header values | The audit log, the [log](logs.md), the control socket |
| | On Windows, `sudo.dpapi` and `command-account.dpapi`: DPAPI ties them to the machine |

The node can run while you back it up.

| Option | Does |
|---|---|
| `--include-keyring` | Also take the keys that are in the system keyring ([below](#keys-in-the-keyring)) |
| `--overwrite` | Replace the file when it exists |
| `--passphrase-file <file>` | Read the passphrase from the first line of a file instead of asking. On Linux the file must not be readable by others; Windows does not check, so keep the file in a folder only you can read. Without a terminal, one line of stdin is the passphrase |

### Keys in the keyring

With `machine.secret_storage = "keyring"` the node keeps its keys in the system
keyring ([keys](config.md#where-the-node-keeps-its-keys)), and so does it keep
the header values of a proxy whatever that setting says. These leave the
keyring only if you agree:

```sh
nerve-node backup ~/nerve-node.bak --include-keyring
```

Without `--include-keyring` the backup holds the config and the keys that are
in files, and says which it left out. A node restored from such a backup has
pairings without keys (below).

### Restore

Stop the node first. A restore never goes under a running node: it refuses
when a node holds the folders (`keys.lock`), and holds the lock itself while
it works. On the [installed service](service.md) stop the service
(`sudo systemctl stop nerve-node`, on Windows `Stop-Service nerve-node`).

```sh
nerve-node restore ~/nerve-node.bak
nerve-node run
```

On a node that has config here already:

- **The same node** (it shares a pairing with the backup, or has none): the
  restore replaces `node.toml` and the keys. Keys of pairings the backup does
  not have are deleted, and the config goes back in time to the backup's: its
  version is set above everything this node had saved, so the node does not
  take it for an older file put back
  ([an older file put back](config.md#an-older-file-put-back)).
- **Another node**, or a `node.toml` here that the node cannot read: the
  restore refuses. `--replace` says you mean it.

| Option | Does |
|---|---|
| `--replace` | Restore over a node that is not the one the backup is of |
| `--secret-storage file\|keyring` | Keep the keys here in files or in the keyring, whatever the backup's config says. Needed when the backup was made on a machine with a keyring and this one has none |
| `--without-proxy` | Leave the proxy out of the restored config, with its pin, password and header values, and set it again on this machine with `proxy set`: the address, the `--pin=<pin>` of an `https://` proxy and its login (for a relay, `relay token <name>` on the relay prints the whole command, with a new token and the pin). Nothing of it is kept or needed, so no keyring is asked and nothing can go to the wrong proxy |
| `--passphrase-file <file>` | Read the passphrase from the first line of a file instead of asking. On Linux the file must not be readable by others; Windows does not check |

If the backup has no key for a pairing, `restore` says so and names the
pairing. When this machine still holds a key that fits the pairing, in the
files or in the keyring (a restore on the same machine), it stays, and it
goes where the restored node keeps its keys: a restore with `--secret-storage`
takes it over from the other place before that place is emptied. Otherwise
that center cannot connect: run `nerve-node center rm --center <name>`, then
`nerve-node center add` with a new link. The relay's TLS key, which must fit
`relay.pin`, is treated the same way.

The proxy's password and header values are credentials, and nothing in them
says which proxy they are for, so a backup that lacks them (they are left out
unless you give `--include-keyring`) does not keep whatever is on this machine:

- The password stays only when the config it belonged to, the one being
  replaced, names the same proxy, pin and user as the restored one.
- The header values (an `http://` proxy's login is one) stay only when that
  config names the same proxy, pin and header names.
- Anything else is deleted, wherever it is (in the files and in the keyring),
  so that it is never sent to a proxy it does not belong to, and `restore`
  says so: run `nerve-node proxy set` again. It says the same when a password
  or values are missing.
- When this machine's keyring does not answer (locked, or no desktop session
  to ask), `restore` cannot tell whose the header values are and stops with
  nothing written, unless the config being replaced names the same proxy, pin
  and header names. Restore with `--without-proxy` and set the proxy again
  here; or start or unlock the keyring (on a Linux without a desktop,
  `nerve-node setup` can install one if you answer `keyring` where it asks
  where the keys go); or take the header values off the node you back up
  (`nerve-node proxy rm` there) and make a new backup. A backup made with
  `--include-keyring` does not get round this: it writes the values into the
  same keyring, and fails the same way.
- Header values for the same proxy and names that lack one of the names are
  kept, and `restore` says so. They are for the right proxy, and the link
  fails with a message naming the missing header until `proxy set` gives all
  of them.

A restore that fails half way puts the keys back as they were and writes
nothing. If the machine dies in the middle of it, run it again.

Restore only a backup you made yourself. It is the whole `node.toml`, with
everything the file can set: the programs allowed to attach as providers, the
[capabilities of your own](config-capabilities.md) with their commands (run
as `nerve-run` or as you), the `sudo` program, the account commands run as,
the folders and rules of every center. The passphrase proves that whoever made the file knew it, not that the
file is yours.

## The center

```sh
nerve-center backup ~/nerve-center.bak
nerve-center restore ~/nerve-center.bak
```

The backup holds `tls.pem` (the center's certificate and private key) and
`state.json` (its id and name, the paired nodes with their public keys, the
hashes of the harness tokens, the statistics, the settings of the
[action checker](action-checker.md)). During the 7 days after a
[key rotation](center.md#rotate-the-key) it also holds the new key,
`tls.next.pem`, which the machines already trust. Not the [log](logs.md).

Not the action checker's endpoint token (`checker-model.token`), which is a
secret, and not its local model (the `checker/` folder), which is downloaded
again. After a restore on another machine, enter the token again, or install
the local model again (**Install on CPU** on the Action checker page): until
then a model that is on refuses every call it sees (fail closed).

Back up while it runs; the statistics may be a few seconds behind. Restore
only when no center runs on the state folder (`--state-dir`): stop the harness
that started it. Both take `--state-dir`, `--overwrite` (backup) or
`--replace` (restore), and `--passphrase-file` like the node's.

A center that has another id than the backup is refused without `--replace`:
replacing it means every node paired with it must pair again.

## What a restore does to the pins

A pin is the hash of a certificate's public key. Nodes hold the pin of their
center, a relayed node holds the pin of its relay, and a node behind an
`https://` proxy holds the proxy's.

- **A restored node keeps every pin in its `node.toml`** exactly as saved. It
  does not learn them again. There are three exceptions: `--without-proxy`
  drops the `https://` proxy's pin along with the proxy; a center's pin that
  the node here was told after the backup was made (a rotation of the
  center's key), or that was set here by hand since, stays over the backup's
  older one (below); and a center's old pin whose time ended here after the
  backup was made (the center ended its grace) does not come back. The
  relay's pin always stays. The node also keeps the node key of each center, so the
  center knows it by the same node id and needs no pairing: the pairing is
  what the node had at the time of the backup.
- **A restored center brings back its certificate**, so the pin that its nodes
  hold fits again. This is what saves the pairing when `tls.pem` was lost and
  the center made a new certificate (all its nodes refuse a center with a new
  pin).
- **A restored relay keeps its TLS key**, so the nodes that use it still fit
  its pin. If the relay's key is not in the backup (it was in the keyring and
  you left it there), the relay does not listen until `nerve-node relay set
  <address>` makes a new key and pin, and every node behind it needs the new
  pin (`proxy set --pin`).
- **A pairing that ended after the backup does not come back.** If you ran
  `center rm` on the node, or removed the node in the center, the other side
  forgot the key. The restored node dials with it and is told the center does
  not know it; pair it again.
- **A key rotated after the backup.** A backup made before a
  [key rotation](pairing.md#rotate-the-machines-key) holds the old key. On the
  same machine, the restore keeps what was rotated since and is still there:
  the node's key, the center's pin the node was told (or that was set by
  hand), on a center its new key and the new key of each node that rotated
  its own. It says so. A copy that is older than the backup (fewer
  rotations) gives way to the backup. On another machine the restored
  node has the old key, which the center takes only for the 7 days after the
  rotation, and the center's old pin: after the center's 7 days set the new
  one with `nerve-node config set center.<name>.pin <pin>` (the web UI shows
  it). A restored center serves its old key, which the machines it told stop
  taking after those 7 days, and knows a machine that rotated its own key
  since only by its old key, which that machine no longer has: pair it
  again. Back up the machine, and the center, after each rotation.
- **A center backup made during the 7 days of a rotation** brings back that
  rotation. If you ended it early (**Serve the new key now**) after the
  backup was made, press it again after a restore on another machine; on the
  same machine the restore keeps the new key served.
- **Do not run the old node and the restored one together.** They have the
  same key, and a center keeps one live link per node: the second one is
  refused with an alert.

## Moving

**A node to another machine.**

1. On the old machine: `nerve-node backup file` (with `--include-keyring` if
   the keys are in the keyring), then stop the node.
2. Copy the file, install `nerve-node` on the new machine
   ([install](install.md)), and `nerve-node restore file`.
3. Check what belongs to the machine and not to the node: the folders in
   `center.<name>.policy.folders`, the account commands run as on Windows
   (`machine.user`), the paths of providers, the programs of your own
   capabilities (`nerve-node cap ls`), and the address of the relay.
   On Linux the installed node's owner is whoever installed it there, not
   part of the backup.
   `nerve-node config get` shows each.
4. `nerve-node sudo on` if you used the sudo switch, then `nerve-node run`.

A node whose proxy has header values (an `http://` proxy with a login is one)
needs a keyring that answers on the new machine, since the node reads those
values from it ([keys](config.md#where-the-node-keeps-its-keys) says how a
Linux without a desktop gets one). Without a keyring the restore stops, and the node could not use
that proxy anyway. Restore with `--without-proxy` and set the proxy again on the
new machine, or take the header values off the old node with `nerve-node proxy
rm` and back it up again.

The centers see the same node id from a new address. Their link rule keeps one
live link per node, so stop the old node before the new one connects.

**A center to another machine.**

1. `nerve-center backup file` on the old machine, stop it.
2. `nerve-center restore file` on the new machine, with `--state-dir` if you
   use one.
3. Start it with the `--public-url` the nodes can reach. If the nodes reach
   the center under another address than before, change it on each node:
   `nerve-node config set center.<name>.url 'https://new.example:7443'`. The
   pin stays, so no node pairs again.

## On a node installed as a service

The command runs as the user `nerve` after `sudo` (see [service](service.md)),
but it opens the backup file as you, the user who ran `sudo`: name one in your
own folders, such as `~/nerve.bak`. A backup written there is yours, readable
by you only. Where you may not open the file, the owner of its folder opens it:
in a root shell (`sudo -i`, which still knows who ran `sudo`) a file in `/root`
is root's, and one in `/var/lib/nerve/state` is written as `nerve`. Run as root
without `sudo`, it opens the file as root. The file `--passphrase-file` names
is read as `nerve`; typing the passphrase needs no file.

An owner of the installed node (see [service](service.md#use-the-commands))
needs no `sudo` for either:

```sh
nerve-node backup ~/nerve.bak
nerve-node restore ~/nerve.bak
```

Your own `nerve-node` opens the file, as you, and hands the open file to the
running node with the command (on Windows it sends the file's bytes): the
node never opens a path in your folders itself. It asks the passphrase here
too, or reads `--passphrase-file` as you. A backup is put in place once it is
complete. For a restore the node stops, restores and starts again by itself,
so it must run when you start it. A backup that would change
`machine.user`, `machine.allow_root`, `machine.sudo_path` or `machine.shell`
is refused to the owner: restore it with `sudo` (on Windows from an
administrator's terminal).

The desktop app does this for the owner without a question; it asks for the
administrator only for such a backup. For someone who is not the owner it works
as `sudo` above, without the second try: a file you may not open is refused
there.

## On a center installed as a service

Name its state folder with `--state-dir /var/lib/nerve-center`. Run with
`sudo`, the commands work there as the user `nerve-center`, as the node's do
as `nerve` ([center](center.md#run-it-as-a-service)): root follows no link
that user put in the folder, and what a restore writes stays the center's.

- `backup` writes the backup, and reads the file `--passphrase-file` names,
  as `nerve-center`. Name a backup in a folder that user can use, such as
  `/var/lib/nerve-center/center.bak`, and copy it from there as root.
  Typing the passphrase needs no file.
- `restore` reads the backup and the passphrase as root, so they may be
  anywhere, and then restores as `nerve-center`. It needs the service
  stopped: `sudo systemctl stop nerve-center` before, `sudo systemctl start
  nerve-center` after.

## Messages

| Message | Cause |
|---|---|
| `cannot open the backup: the passphrase is wrong, or the file was changed` | The two cannot be told apart |
| `a nerve-node runs on these folders` | Stop the node, then restore |
| `a nerve-center runs on …` | Stop the center, then restore |
| `… are not the same node` or `… not the same center` | The backup is of another one. `--replace` if you mean it |
| `… is the backup of a center, not of a node` | Use the other program's `restore` |
| `… made by a newer program` | Update this program first |
| `cannot read the proxy's header values in the system keyring … to check whose they are` | The keyring does not answer and the backup cannot say whose the values are. `--without-proxy`, or a keyring that answers, or `proxy rm` on the old node and a new backup |
| `cannot read the keyring entry …` (in a restore) | The backup holds the proxy's header values and they go into a keyring that does not answer. `--without-proxy`, or a keyring that answers |
