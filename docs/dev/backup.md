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
  (`center.lock`; on Windows, where the center takes none, a share-less open
  of the same file).

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
