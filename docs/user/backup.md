# Back up, restore and move

`backup` writes what a machine would lose to one file, protected with a
passphrase of at least 12 characters. `restore` puts it back, here or on
another machine. The file holds private keys: keep it as safe as its
passphrase.

## The node

```sh
nerve-node backup ~/nerve-node.bak
nerve-node restore ~/nerve-node.bak
```

The owner of the installed node needs no `sudo`. There a restore stops the
node, restores and starts it again; stop a node you run by hand first. The backup holds `node.toml` with its
pairings, modes, folders and rules, and the keys in files. Not the audit
log, the log or the sudo password: a restored node has sudo off.

Restore only a backup you made yourself: it brings its pairings, modes, rules
and allowed programs ([restore](../dev/backup.md#restore)).

| Option | Does |
|---|---|
| `--include-keyring` | Also takes the keys that are in the system keyring |
| `--overwrite` | Replaces a backup file that exists |
| `--passphrase-file F` | Reads the passphrase from a file, or stdin with `-` |
| `--replace` (restore) | Replaces a node here that is not the one the backup is of |

- The keys stay in the keyring unless you add `--include-keyring`. A node
  restored without them has pairings without their keys
  ([keyring](../dev/backup.md#keys-in-the-keyring)).

## The center

```sh
sudo nerve-center backup /var/lib/nerve-center/center.bak
sudo nerve-center restore ~/nerve-center.bak     # stops the service and starts it again
```

The backup holds the center's key and certificate, its paired machines, its
harness token hashes and the action checker's settings. The machines find it
again by the same pin and need not pair again.

- A backup holds neither the owner token nor the checker's endpoint token.
  A center restored where it had none makes one at its next start; one that
  has its token keeps it. `sudo nerve-center owner-token` shows it, and
  `--new` replaces it. Enter the endpoint token again,
  or install the local model again
  ([what is not in a backup](../dev/backup.md#what-is-not-in-a-backup)).

A center whose id is not the backup's is refused without `--replace`, since
every machine paired with it would have to pair again.

## Move

**A node to another machine.**

1. On the old machine, `nerve-node backup file`, then stop the node.
2. Install the node on the new one, and `nerve-node restore file`.
3. Check what belongs to the machine: the folders, the paths of providers
   and of your own capabilities, the relay's address. `nerve-node status`
   shows them.
4. `sudo nerve-node sudo on`, if you used sudo.

Stop the old node before the new one links: a center keeps one link per
machine. A proxy with a password needs a keyring on the new machine;
otherwise restore with `--without-proxy` and set it again.

**A center to another machine, or into the service.**

```sh
nerve-center --state-dir ~/.local/state/nerve-center backup ~/nerve-center.bak
sudo nerve-center restore ~/nerve-center.bak --replace
```

Start it with a `--public-url` the machines reach. If that address changed,
set it on each node; the pin stays:

```sh
nerve-node config set center.lab.url 'https://new.example:7443'
```

Stop the old center for good: the new one has its key now
([moving](../dev/backup.md#moving)).
