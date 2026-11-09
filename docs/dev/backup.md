# Backup and restore

How `nerve-node backup|restore` and `nerve-center backup|restore` work, and
why. The owner's view is in [docs/user/backup.md](../user/backup.md). The
container is `crates/nerve-transport/src/backup.rs`; what goes in and what a
restore does is `crates/nerve-node/src/backup.rs` and
`crates/nerve-center/src/backup.rs`.

## Decisions

- **One encrypted file, passphrase only.** The file holds private keys, and a
  backup is meant to lie in places a key file should not (a stick, a cloud
  folder, a mail). There is no plain mode. The passphrase comes from the
  terminal, a file (`--passphrase-file`, which must not be readable by others
  on Unix) or one line of stdin; never from an argument or a variable, which
  other processes of the user can see. A new backup takes at least 12
  characters.
- **Only `ring`.** `ring` has PBKDF2 and the AEADs but no memory-hard KDF
  (Argon2, scrypt). The file uses PBKDF2-HMAC-SHA256 with 600 000 rounds (the
  OWASP 2023 figure) and ChaCha20-Poly1305. A memory-hard KDF would resist a
  graphics card better and needs a new crate, so it is a later change:
  `kdf` in the header says which one a file used.
- **The keyring is the owner's call.** A key in the system keyring is read
  out only with `--include-keyring`. The backup says what it left out.
- **A restore asks before it replaces.** A backup that is of another node or
  center than the one here is refused without `--replace`.
- **A restore never goes under a running node or center.** It holds the
  node's `keys.lock` (a node holds it for its life) or the center's lock
  (`center.lock`, on Linux and Windows alike).

## The file

All numbers are big-endian. The header is the associated data of the
encryption, so a changed header opens nothing.

| Offset | Size | Field |
|---|---|---|
| 0 | 8 | `NERVEBAK` |
| 8 | 1 | format, `1` |
| 9 | 1 | kind: `1` node, `2` center |
| 10 | 1 | kdf: `1` PBKDF2-HMAC-SHA256 |
| 11 | 1 | cipher: `1` ChaCha20-Poly1305 |
| 12 | 4 | PBKDF2 rounds (1 to 10 000 000; a file asking for more is refused before any work) |
| 16 | 16 | salt, random per file |
| 32 | 12 | nonce, random per file |
| 44 | n + 16 | ciphertext and tag |

The key is `PBKDF2(passphrase, salt, rounds)`, 32 bytes. Salt and nonce are new
for every file, so one passphrase never gives two files the same key. A file
larger than 32 MiB is refused before it is read.

The plaintext is JSON: `kind`, `created_ms`, `program`, and `files`, texts by
a **logical name**, never by a path, so a file cannot name where a restore
writes.

| Kind | Names |
|---|---|
| node | `node.toml`, `key/<center>` (one per pairing), `relay-tls`, `proxy-login`, `proxy-headers` |
| center | `tls.pem`, `state.json`, and `tls.next.pem` during the grace of a key rotation |

`node.toml` is the config as the node reads it, verified (a refused config is
not backed up) and without its MAC line. The MAC key
(`config.key`) is not in the file: it only says that this node wrote the file,
so the node that restores makes its own and signs the restored config with it.

A backup is trusted as far as its passphrase: it carries every setting of
`node.toml`, `providers.allowed`, `machine.sudo_path` and (Windows)
`machine.user` among them. The Linux node's owner is the unit's, not in the
file. The user page tells the owner to restore only a file they made;
the program cannot tell it from one that someone else made with a passphrase
they know.

## Backup of a node

1. The config comes from the running node over the control socket, else from
   the file with its MAC checked ([`read_config`](../../crates/nerve-node/src/cli.rs)).
   `owner.check` comes first, so a command of a center cannot take the keys
   out under a passphrase of its own.
2. Each key is read from where `machine.secret_storage` says. With `keyring`
   and no `--include-keyring` the keyring is not asked for it. A node key is
   checked against the `node_id` of its pairing, the relay key against
   `relay.pin`; one that does not fit is left out and said.
3. The proxy's header values are read from their keyring entry, again only
   with consent.

## Restore of a node

In this order:

1. The file is read (size and kind are checked before the passphrase is
   asked), opened, and every key in it is checked against the config: a key of
   a pairing the config lacks, a text that is no key, a node key whose id is
   not the pairing's, or a name this program does not know refuses the whole
   file.
2. `keys.lock` is taken, or the restore refuses.
3. The folders here are inspected. A node here is **the same** when it has no
   pairing, or shares a `(center_id, node_id)` pair with the backup. Any other
   node, or a `node.toml` that cannot be read, needs `--replace`.
4. The keys' place is `--secret-storage`, else what the backup's config says.
   A place the node cannot use (`no_keyring`) is refused here, before any
   write. The sudo switch is set off: its password is in no backup.
5. The config's version is set above the version of the backup, the record
   (`config.version`) and the file it replaces. The record only goes up, so an
   older config is not accepted by lowering it.
6. The MAC key is taken from `to` itself, or made there. It is not read the
   way the node reads it, which falls back to `config.key` while a move of the
   keys is unfinished: that file is about to be deleted with the old place,
   and the restored config would be signed with a key that is gone.
7. Every key is written with a read-back. Before a key is overwritten its old
   text is noted; when one write fails, the earlier ones are put back, and
   nothing else has been written.
8. The config is written signed, the record is raised, an audit entry
   (`config`, `restored`) is made. On Windows `sudo.dpapi`, which holds the
   administrator's password only while the switch is on, is deleted.
9. Keys the replaced config kept and the new one does not name are deleted,
   and every key left in the place the keys moved away from.

A key the backup lacks (a node key, the relay's TLS key) is looked for in
`to` and in the other place. One that fits the config (the pairing's
`node_id`, `relay.pin`) stays, and is copied into `to` when it is in the other
place, before step 9 empties that place. Otherwise it is listed or noted, and
the owner pairs again or runs `relay set`.

The proxy's password and the proxy's header values are credentials that
nothing in them ties to a proxy, and the node sends them to whichever proxy the
config names. A backup that lacks them (no `--include-keyring`) therefore does
not keep what is here unless the replaced config (`Target::Node`) vouches for
it:

- The password is taken from the replaced config's own place, and only when
  that config names the same `connection.proxy`, `connection.pin` and
  `connection.login` as the restored one. Every other copy, in `to` and in the
  other place, is deleted, with an undo entry that remembers the place: the
  node reads the file when the keyring holds none, and a move of the keys
  copies what it finds in the other place, so a copy left there would still be
  sent.
- The header values (the keyring entry `Entry::proxy`, whatever
  `machine.secret_storage` says) stay when the replaced config names the same
  proxy, pin and header names (as a set) and the entry holds a value for each
  name. Another entry is deleted (`Undo::Headers`). One that lacks a value is
  left and noted.

A replaced config that could not be read, or none, vouches for nothing. Each
case adds a note that says to run `proxy set` again.

A keyring that does not answer is not an empty one: its entry would be sent to
the restored proxy as soon as it answers again. So when the replaced config
does not vouch for the header values, a keyring that cannot be asked stops the
restore ("cannot read the proxy's header values ... to check whose they are"),
with nothing written. The remedies are `--without-proxy`, a keyring that
answers (`nerve-node config set machine.secret_storage keyring` at a terminal
offers to install one) or a backup of a node whose
proxy has no header values. A backup made with `--include-keyring` is no
remedy: writing the values into the keyring asks the same keyring.

`--without-proxy` (`Parsed::without_proxy`) makes the backup a backup without
a proxy before anything else looks at it: `connection` is the default, and the
password and header values are dropped. So no credential is kept, written or
needed, no keyring is asked for them, and the old node's header entry is
deleted like any entry the restored config does not name. It is also the way
to restore a config with header values on the installed node on Windows, which
takes none.

When the replaced config does vouch for the header values (the same proxy, pin
and names), they are that proxy's whatever the keyring says, and the restore
goes on with the note.

## Center

`tls.pem` and `state.json` are read as they are on disk. Both are written
whole by the center (a temporary file and a rename), so a backup of a running
center is a state it had; only the statistics may lag by up to 5 seconds.

The action checker's settings are a field of `state.json` and go with it. Its
endpoint token, `checker-model.token`, is a secret and is not taken, like a
node's keyring secrets without `--include-keyring`; the local model's files in
`checker/` are not taken either, since they are pinned downloads. A restore
leaves both as they are in the state folder. A restored state with the local
model on, where `checker/` is missing, refuses the calls the model sees until
the owner installs it again ([action-checker](action-checker.md)).

During the grace of a rotation of the center's key (protocol §4.10) the new
key is in `tls.next.pem`, and the nodes the center told pin it already. The
backup takes it then: read first, kept only when the `state.json` read last
still holds the rotation unfinished, and a restore checks that it is the key
`key_rotation.new_spki` names. Without it, the restored center would drop the
rotation and serve the old key for good, and every told node would be locked
out once its old pin's time is over. A restore without `tls.next.pem`
deletes one left in the state folder, unless it is the new key of a rotation
made after the backup (below).

A restore takes the center lock, checks `center_id` (the same center is
restored, another needs `--replace`), writes `tls.pem`, then `tls.next.pem`
(or deletes one there), then `state.json`. When a write fails it puts back
the `tls.pem` and the `tls.next.pem` that were there (or deletes the one that
was not), so the old state meets its own keys.

A restore over the same center keeps what was rotated after the backup, by
counts in `state.json`. Where the state here counts more rotations of the
center's key (`key_rotations`), its keys stay, as long as they are the ones
it names: in a grace, the old key in `tls.pem`, the new one in
`tls.next.pem` and the record; after it, the newest key in `tls.pem`. Its
nodes were told the new keys. A backup made in the grace of the same
rotation gives way to one that ended here (also early). Where a node's
record here counts more rotations of the node's key (`key_rotations` of the
record), its `public_key` and `old_key` stay: the node holds only its new
key.

A node restore keeps likewise what was rotated after the backup, for the same
pairing (name, `center_id`, `node_id`), by the counts `key_rotations` and
`pin_rotations` of each entry: where the config being replaced counts more,
its `public_key` stays when that key is on the machine, over the older key in
the backup, and its `pin` and `old_pin` stay. Where it counts fewer (an older
copy of the node), the backup's stay. The same count with another key or pin
keeps the backup's, with a note. A pin the owner sets by hand counts as a
rotation the node took (the settings store raises `pin_rotations`). With the same count and the same
pin, an `old_pin` here that is gone, or whose time is over, means the center
ended its grace after the backup, maybe because the old key leaked: the
backup's old pin does not come back, with a note. One here that still runs
and ends a little sooner (each later notice of the same grace is taken from
the center's time left, so it can end some milliseconds sooner) stays, without
a note.

## Pins

A pin is the hash of a public key. Where each one is kept decides what a
restore does to it:

| Pin | Kept in | Restore |
|---|---|---|
| A center's, held by its nodes | `center.<name>.pin` in `node.toml` | Kept as saved, unless the config being replaced counts more `pin_rotations` (it was told a newer pin, or one was set by hand): then its `pin` and `old_pin` stay. With the same count and pin, a backup's `old_pin` whose time ended here does not come back. The center keeps it by restoring `tls.pem` |
| The relay's | `relay.pin` in `node.toml`; its key in `relay-tls` | Kept; the key is checked against it. A relay whose key is missing does not listen until `relay set` makes a new key and pin |
| An `https://` proxy's | `connection.pin` in `node.toml` | Kept, unless `--without-proxy` leaves the whole `connection` section out: the pin goes with the proxy, and `proxy set --pin` gives it again |

A restore never learns a pin. It keeps the backup's, with three exceptions: a
center's pin here that is further along (above) stays, a center's old pin
whose time ended here does not come back, and `--without-proxy` drops the
proxy's pin. A pairing that was ended
on one side after the backup is not revived: the other side no longer knows
the node's key.

## What is not in a backup

The MAC key (made again), the sudo password (never at rest on Linux; DPAPI on
Windows is tied to the machine), the audit log, the log, the control socket
and token, the Windows record of folder grants (`grants.json`, rebuilt by the
running node before a command), and the center's log.

## Back up, restore and move, step by step

`nerve-node backup` and `nerve-center backup` write what a machine would lose
to one file, protected with a passphrase. `restore` puts it back: on the same
machine after a mishap, or on another one when you move the node or the
center.

The file holds private keys. It is encrypted, so it can lie on a stick or in a
cloud folder, but only as safely as its passphrase. A passphrase has at least
12 characters. Nobody, you included, can open the file without it.

### The node

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
| The proxy's header values | The audit log, the [log](logging.md#the-log-as-the-owner-reads-it), the control socket |
| | On Windows, `sudo.dpapi` and `command-account.dpapi`: DPAPI ties them to the machine |

The node can run while you back it up.

| Option | Does |
|---|---|
| `--include-keyring` | Also take the keys that are in the system keyring ([below](#keys-in-the-keyring)) |
| `--overwrite` | Replace the file when it exists |
| `--passphrase-file <file>` | Read the passphrase from the first line of a file instead of asking. On Linux the file must not be readable by others; Windows does not check, so keep the file in a folder only you can read. Without a terminal, one line of stdin is the passphrase |

#### Keys in the keyring

With `machine.secret_storage = "keyring"` the node keeps its keys in the system
keyring ([keys](settings-and-config.md#where-the-node-keeps-its-keys)), and so does it keep
the header values of a proxy whatever that setting says. These leave the
keyring only if you agree:

```sh
nerve-node backup ~/nerve-node.bak --include-keyring
```

Without `--include-keyring` the backup holds the config and the keys that are
in files, and says which it left out. A node restored from such a backup has
pairings without keys (below).

#### Restore

Stop the node first. A restore never goes under a running node: it refuses
when a node holds the folders (`keys.lock`), and holds the lock itself while
it works. On the [installed service](service.md#the-node-as-a-service) stop the service
(`sudo systemctl stop nerve-node`). On Windows the
[desktop app](desktop.md#settings)'s restore under **Settings**, **Backup**
stops the node and starts it again itself.

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
  ([an older file put back](settings-and-config.md#an-older-file-put-back)).
- **Another node**, or a `node.toml` here that the node cannot read: the
  restore refuses. `--replace` says you mean it.

| Option | Does |
|---|---|
| `--replace` | Restore over a node that is not the one the backup is of |
| `--secret-storage file\|keyring` | Keep the keys here in files or in the keyring, whatever the backup's config says. Needed when the backup was made on a machine with a keyring and this one has none |
| `--without-proxy` | Leave the proxy out of the restored config, with its pin, password and header values, and set it again on this machine with `proxy set`: the address, the `--pin=<pin>` of an `https://` proxy and its login (for a relay, `relay token <name>` on the relay prints the whole command, with a new token and the pin). Nothing of it is kept or needed, so no keyring is asked and nothing can go to the wrong proxy |
| `--passphrase-file <file>` | Read the passphrase from the first line of a file instead of asking. On Linux the file must not be readable by others; Windows does not check. On Windows the center's backup file gets an access list of its own: your account, SYSTEM and the administrators |

If the backup has no key for a pairing, `restore` says so and names the
pairing. When this machine still holds a key that fits the pairing, in the
files or in the keyring (a restore on the same machine), it stays, and it
goes where the restored node keeps its keys: a restore with `--secret-storage`
takes it over from the other place before that place is emptied. Otherwise
that center cannot connect: run `nerve-node center rm <name>`, then
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
  `nerve-node config set machine.secret_storage keyring` at a terminal offers
  to install one); or take the header values off the node you back up
  (`nerve-node proxy off` there) and make a new backup. A backup made with
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
[capabilities of your own](capabilities.md#capabilities-of-your-own-in-nodetoml) with their commands (run
as `nerve-run`), the `sudo` program, the account commands run as,
the folders and rules of every center. The passphrase proves that whoever made the file knew it, not that the
file is yours.

### The center

```sh
nerve-center backup ~/nerve-center.bak
nerve-center restore ~/nerve-center.bak
```

The backup holds `tls.pem` (the center's certificate and private key) and
`state.json` (its id and name, the paired nodes with their public keys, the
hashes of the harness tokens, the statistics, the settings of the
[action checker](action-checker.md#the-checker-as-the-owner-sets-it-up)). During the 7 days after a
[key rotation](identity-and-pairing.md#rotate-the-centers-key) it also holds the new key,
`tls.next.pem`, which the machines already trust. Not the [log](logging.md#the-log-as-the-owner-reads-it).

Not the [owner token](web-uis.md#log-in) (`owner-token`). The center makes one only where none exists: a center restored into a
state folder with no token makes one at its next start, and one that has its token keeps it.
`nerve-center owner-token` says it, and `--new` replaces it.

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

### What a restore does to the pins

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
  [key rotation](identity-and-pairing.md#rotate-the-machines-key) holds the old key. On the
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

### Moving

**A node to another machine.**

1. On the old machine: `nerve-node backup file` (with `--include-keyring` if
   the keys are in the keyring), then stop the node.
2. Copy the file, install `nerve-node` on the new machine
   ([install](service.md#download-and-install)), and `nerve-node restore file`.
3. Check what belongs to the machine and not to the node: the folders in
   `center.<name>.policy.folders`, the account commands run as on Windows
   (`machine.user`), the paths of providers, the programs of your own
   capabilities (`nerve-node cap`), and the address of the relay.
   On Linux the installed node's owner is whoever installed it there, not
   part of the backup.
   `nerve-node config get` shows each.
4. `nerve-node sudo on` if you used the sudo switch, then `nerve-node run`.

A node whose proxy has header values (an `http://` proxy with a login is one)
needs a keyring that answers on the new machine, since the node reads those
values from it ([keys](settings-and-config.md#where-the-node-keeps-its-keys) says how a
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

### On a node installed as a service

The command runs as the user `nerve` after `sudo` (see [service](service.md#the-node-as-a-service)),
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
is refused to the owner: restore it with `sudo` (on Windows the app asks
Windows for an administrator's rights for it).

The desktop app does this for the owner without a question; it asks for the
administrator only for such a backup. For someone who is not the owner it works
as `sudo` above, without the second try: a file you may not open is refused
there.

### On a center installed as a service

Where the center is installed, `backup` and `restore` work on its state
folder, `/var/lib/nerve-center`, without `--state-dir`. Run with
`sudo`, the commands work there as the user `nerve-center`, as the node's do
as `nerve` ([center](service.md#the-center-as-a-service)): root follows no link
that user put in the folder, and what a restore writes stays the center's.

- `backup` writes the backup, and reads the file `--passphrase-file` names,
  as `nerve-center`. Name a backup in a folder that user can use, such as
  `/var/lib/nerve-center/center.bak`, and copy it from there as root.
  Typing the passphrase needs no file.
- `restore` reads the backup and the passphrase as root, so they may be
  anywhere, and then restores as `nerve-center`. Where the service runs, it
  stops it first and starts it again after, whether the restore worked or
  not (`service::with_service_stopped`).

### Messages

| Message | Cause |
|---|---|
| `cannot open the backup: the passphrase is wrong, or the file was changed` | The two cannot be told apart |
| `a nerve-node runs on these folders` | Stop the node, then restore |
| `a nerve-center runs on …` | Stop the center, then restore |
| `… are not the same node` or `… not the same center` | The backup is of another one. `--replace` if you mean it |
| `… is the backup of a center, not of a node` | Use the other program's `restore` |
| `… made by a newer program` | Update this program first |
| `cannot read the proxy's header values in the system keyring … to check whose they are` | The keyring does not answer and the backup cannot say whose the values are. `--without-proxy`, or a keyring that answers, or `proxy off` on the old node and a new backup |
| `cannot read the keyring entry …` (in a restore) | The backup holds the proxy's header values and they go into a keyring that does not answer. `--without-proxy`, or a keyring that answers |
