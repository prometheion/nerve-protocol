# Identity and pairing

Exact formats are in [spec/protocol.md](spec/protocol.md) §2 and §3.

## Identities

| Who | Identity |
|---|---|
| Center | A random id (UUID-shaped) and a name, both made on its first start. A TLS key and a self-signed certificate. Its **pin** is the base64url SHA-256 of the certificate's public key info (43 characters) |
| Node | One Ed25519 key pair **per center**, made at pairing and kept in `keys/<name>.key` (mode 0600), or in the system keyring with `machine.secret_storage = "keyring"`. The **node id** is the base32 of the first 16 bytes of the SHA-256 of the public key (26 characters). The node name is 1 to 32 characters of `a-z`, `0-9` and `-`, starting and ending with a letter or digit, from the host name by default |
| Harness | A token, from `--harness-token` or made in the web UI. It is local to the center host, and opens the HTTP MCP endpoint only |
| Owner (center web UI) | The owner token in `owner-token` in the center's state folder, made at its first start. It logs in to the web UI and opens nothing else; no harness token logs in there. A backup does not carry it |

Because the key is per center, two centers see two unrelated ids for the same
machine. They cannot link the machine across trust domains.

A node has no bearer token. A config copied without its private key cannot
connect. A copied key is caught by the [one-link rule](node-link.md#one-live-link).

The center may give a node a display name. That name never goes back to the
node.

## Pairing

1. In the center's web UI, **Pair a machine** makes a one-time code and shows
   the link. The code lasts 10 minutes by default (up to 24 hours), allows 10
   tries and works once.
   `nerve://pair?center=<percent-encoded URL>&code=<code>&pin=<pin>`
2. On the node: `nerve-node center add '<link>'`. The node parses the link
   strictly and shows the center's address, plus the policy the new pairing
   starts with (mode `folder`, no folder, the guard's deny rules
   `nerve_policy::rules::GUARD`, settings grant `off`). Before it asks, it
   checks the link (`nerve_node::pair::check`): it opens the way the pairing
   will (proxy or relay, pin) and sends `POST <center>/nerve/v0/pair/check`
   `{code}`, which answers `open`, `used`, `gone` or `busy` without using the
   code or counting a try (`nerve_center::pairing::Codes::probe`: a check
   with a code that is not open costs one of 10 checks per 10 minutes, after
   which every check gets `busy`, so it is no cheaper a way to guess). It
   asks only when the pairing can work, and stores nothing before the owner
   confirms.
3. The node makes a key pair for this center and sends
   `POST <center>/nerve/v0/pair` with `{code, name, platform, arch,
   public_key}` over TLS, checked against the pin.
4. The center answers `{center_id, center_name, node_id}` and stores the public
   key. The node stores the pairing.

The center computes the `node_id` from the public key itself.

### The link

- `center` is an `https://` URL, or `http://` to a loopback address. It has no
  user info, query or fragment and no `.` or `..` path segments.
- `pin` is optional. Without it the node checks the certificate against the
  system roots.
- The parser refuses unknown keys, a key given twice, bad percent escapes, a
  fragment and a link over 4096 bytes.
- Over plain `http`, the node on Linux checks that the listening socket belongs
  to its own user.

### Answers to a pair request

| Status | Meaning |
|---|---|
| 200 | Paired |
| 400 | Malformed request or name |
| 403 | Code unknown, used, expired or out of tries |
| 409 | Another node has this name, or this key is paired |

## Key rotation

Both keys of a pairing can be replaced without pairing again
([spec/protocol.md](spec/protocol.md) §4.10). The side whose
key changes starts it on its owner's command; the new key goes over the
live link, signed by the old one, and the old key stays valid for a grace of
7 days.

| Key | Started by | Code |
|---|---|---|
| The node's key for a center | `nerve-node center rotate-key` | `crates/nerve-node/src/rotate.rs`, `Center::rotate_node_key` |
| The center's TLS key | the web UI (Settings, Center key) | `Center::rotate_key`, `crate::rotate::center_rotated` on the node |

- The node id stays the one of the first key. The center keeps the node's
  old key beside the new one (`old_key` in `state.json`) until the grace
  ends or the node ends it (`key.retire`).
- The node keeps its new key aside (`keys/<name>.next.key`, or its keyring
  entry) until the center answered; no answer sends it again on the next
  link, so a rotation the center took is never lost.
- The center keeps its new key in `tls.next.pem`, serves the old one during
  the grace so that nodes away for a while can still be told, then moves the
  new one to `tls.pem`. A start that finds a half-made rotation keeps the
  old key. The node keeps the old pin as `old_pin` until the grace ends.
- Each rotation is in the node's audit log and the center's log.

## Unpairing

Both sides can end a pairing.

- **From the node.** `nerve-node center rm` sends `bye {reason: "unpaired"}` if
  a link is up, and deletes the key. The center forgets the node when it sees
  that.
- **From the center.** Removing the node in the web UI sends
  `bye {reason: "revoked"}` and closes the link. The node stops dialling that
  center and keeps the key until `center rm`, so the owner can see what
  happened.

## Pairing, as the owner does it

Pairing links a machine to a center. Do it once per machine and center.

### Steps

1. Open the center's web UI (`http://127.0.0.1:7480`). On Overview, press
   **Pair a machine**. It shows a command and the pairing link, each with a
   Copy button. With the [desktop app](desktop.md), paste the link there
   (Centers, **Pair a center**) and skip the command.
2. On the machine, as a normal user, run the command it shows:

   ```sh
   nerve-node center add 'nerve://pair?center=https%3A%2F%2Flab.example%3A7443&code=k3v7x9q2m1ab&pin=...'
   ```

   Keep the quotes. The link has `&` in it.

   The node shows the center's address and what the center may do at first,
   then asks you to confirm. Nothing is stored before you say yes.

3. Start the node. It stays in the foreground, so run later commands in
   another shell:

   ```sh
   nerve-node run
   ```

4. Check the link:

   ```sh
   nerve-node status
   ```

   The machine shows as online in the web UI, and the pairing card there
   closes: the code is used up.

The new pairing starts in mode `folder`, with no folder of yours, and the
center may not change settings. On the node installed as a service its
commands run as `nerve-run`, with `/tmp`, `/var/tmp` and its own home and
nothing of yours until you give it a folder. There its file calls may still
read what every account on the machine may read
([reading in folder mode](sandbox-linux.md#reading-in-folder-mode)); writes and
commands wait for a folder:
`nerve-node folder add ~/project rwx` ([modes](policy-engine.md#modes-and-folders-as-the-owner-sets-them),
[rules](policy-engine.md#rules-as-the-owner-writes-them)). Its deny list holds the
guard, which keeps commands off this node itself
([rules](policy-engine.md#the-guard-against-changing-the-node)).

### The code

- It is valid for 10 minutes and for one machine. Change the time in Settings,
  Center (1 to 1440 minutes).
- It allows 10 tries in all. After that make a new one.
- A wrong code counts against every open code.

Before it asks you, `center add` checks the link: the center answers (through
your proxy or relay, if you use one), its certificate is the one the link
pins, and the code is still valid. If one of these fails, it says why and asks
nothing: make a new link, or fix the way to the center. The check uses
nothing up and counts no try. A center that gets many checks with wrong codes
stops saying whether a code is valid for a while; `center add` then asks all
the same.

### Options of `center add`

| Option | Does |
|---|---|
| `--name <name>` | The name you use for this center on the machine. Default: the center's own name. Letters, digits, `-` and `_`, starting and ending with a letter or digit |
| `--yes` | Skip the question |

### Machine names

A machine's name comes from its host name. It has 1 to 32 characters of `a-z`,
`0-9` and `-`, starting and ending with a letter or digit. To choose it, run `nerve-node config set node.name <name>`
before `center add`. Later, the web UI can rename a machine (Rename). That name
stays in the center.

### Several centers

A node can pair with any number of centers. Each one is separate: its own key,
rules, folders and audit entries. A center cannot tell whether other centers
exist.

Every command that works on one center takes `--center <name>`. With more than
one center the command refuses to guess:

```sh
nerve-node mode folder --center lab
nerve-node center
```

### Unpair

| From | How | Effect |
|---|---|---|
| The machine | `nerve-node center rm lab` | Tells the center if the link is up, forgets the center and deletes its key |
| The center | Overview, **Remove** on the machine | Ends the link. The node stops dialling that center and shows it as `revoked` until you run `center rm` |

To pair again, remove the old pairing on both sides, then make a new link.

### Rotate the machine's key

Each pairing has its own key. To replace the key for a center without pairing
again, run on the machine, while the node runs and is linked to that center:

```sh
nerve-node center rotate-key lab
```

The node makes a new key and sends it to the center over the link, signed with
the old one. It prints the new public key once. The center takes the old key
for 7 more days, so nothing breaks while the switch is under way. To end that
now:

```sh
nerve-node center rotate-key --end-grace lab
```

- The machine keeps its id at the center; what it offers and its statistics stay.
- If the center refuses the new key, the old one stays. If no answer comes,
  the old key stays in use and the node sends the new key again on its next
  link.
- Each rotation is in the [audit log](logging.md#the-audit-log-as-the-owner-reads-it).

The center's own key is rotated in its web UI ([center](#rotate-the-centers-key)).
A running node follows it by itself.

### Drops

The node dials the center. When a link drops without a goodbye (an address
change, a short outage), both sides keep it for 30 seconds: running commands
go on, and their output reaches the agent once the node is back. The node
dials again: it waits 1 second, then doubles the wait up to 60 seconds. If
the link is not back within 30 seconds, or the node or the center restarted,
the commands on it end and their calls fail with `connection_lost`.

A machine whose key was copied to another machine is caught: a center keeps
one live link per machine. If a second link arrives while the first still
answers, the center refuses it and shows an alert.

### Back up or move

`nerve-node backup <file>` keeps the config and the keys, and
`nerve-node restore <file>` puts them back on this machine or another one, so
a moved node needs no new pairing ([backup](backup.md#back-up-restore-and-move-step-by-step)).

### Keep it running

`nerve-node run` runs in the foreground. On Linux with systemd,
`sudo nerve-node install` makes it a service that starts with the machine,
under a user of its own ([service](service.md#the-node-as-a-service)). Elsewhere, run
`nerve-node run` under your own service manager. On Windows the node is
always the service, which the [desktop app](desktop.md)'s installer installs;
the app pairs it under **Centers**, **Pair a center**.

### Rotate the center's key

In the web UI, Settings, **Center key**, press **Rotate key**. The center makes
a new key and shows its pin once. It tells every machine that is linked, and
every machine that links in the next 7 days, signed with the old key; each
machine then trusts the new key too. The center keeps serving the old key for
those 7 days, then switches to the new one. **Serve the new key now** switches
at once.

- A machine that does not link during the 7 days does not learn the new key.
  After the switch it cannot connect and has to be [paired again](#pairing-as-the-owner-does-it).
- A node of 0.0.6 links to this center but does not take the notice (it asks
  for rotation by a feature that every link has now, and the center no longer
  names it), and the count of machines told includes it. Update the nodes
  before you rotate the center's key.
- New pairing links carry the pin of the key the center serves.
- The switch also changes the certificate of the web UI and the HTTP MCP
  endpoint when they use TLS. A browser asks to trust it again.
- The center's [log](logging.md#the-log-as-the-owner-reads-it) says when the key was rotated and when the new
  one is served. The keys are `tls.pem` and, during the 7 days, `tls.next.pem`
  in the state folder.
