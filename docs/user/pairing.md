# Pair a machine

Pairing links a machine to a center. Do it once per machine and center.

## Steps

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
nothing of yours until you give it a folder:
`nerve-node folder add ~/project +r +w +x` ([modes](modes.md),
[rules](rules.md)). Its deny list holds the
guard, which keeps commands off this node itself
([rules](rules.md#the-guard-against-changing-the-node)).

## The code

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

## Options of `center add`

| Option | Does |
|---|---|
| `--name <name>` | The name you use for this center on the machine. Default: the center's own name. Letters, digits, `-` and `_`, starting and ending with a letter or digit |
| `--yes` | Skip the question |

## Machine names

A machine's name comes from its host name. It has 1 to 32 characters of `a-z`,
`0-9` and `-`, starting and ending with a letter or digit. To choose it, run `nerve-node config set node.name <name>`
before `center add`. Later, the web UI can rename a machine (Rename). That name
stays in the center.

## Several centers

A node can pair with any number of centers. Each one is separate: its own key,
rules, folders and audit entries. A center cannot tell whether other centers
exist.

Every command that works on one center takes `--center <name>`. With more than
one center the command refuses to guess:

```sh
nerve-node mode set folder --center lab
nerve-node center ls
```

## Unpair

| From | How | Effect |
|---|---|---|
| The machine | `nerve-node center rm --center lab` | Tells the center if the link is up, forgets the center and deletes its key |
| The center | Overview, **Remove** on the machine | Ends the link. The node stops dialling that center and shows it as `revoked` until you run `center rm` |

To pair again, remove the old pairing on both sides, then make a new link.

## Rotate the machine's key

Each pairing has its own key. To replace the key for a center without pairing
again, run on the machine, while the node runs and is linked to that center:

```sh
nerve-node center rotate-key --center lab
```

The node makes a new key and sends it to the center over the link, signed with
the old one. It prints the new public key once. The center takes the old key
for 7 more days, so nothing breaks while the switch is under way. To end that
now:

```sh
nerve-node center rotate-key --end-grace --center lab
```

- The machine keeps its id at the center; what it offers and its statistics stay.
- If the center refuses the new key, the old one stays. If no answer comes,
  the old key stays in use and the node sends the new key again on its next
  link.
- Each rotation is in the [audit log](audit.md).

The center's own key is rotated in its web UI ([center](center.md#rotate-the-key)).
A running node follows it by itself.

## Drops

The node dials the center. When a link drops without a goodbye (an address
change, a short outage), both sides keep it for 30 seconds: running commands
go on, and their output reaches the agent once the node is back. The node
dials again: it waits 1 second, then doubles the wait up to 60 seconds. If
the link is not back within 30 seconds, or the node or the center restarted,
the commands on it end and their calls fail with `connection_lost`.

A machine whose key was copied to another machine is caught: a center keeps
one live link per machine. If a second link arrives while the first still
answers, the center refuses it and shows an alert.

## Back up or move

`nerve-node backup <file>` keeps the config and the keys, and
`nerve-node restore <file>` puts them back on this machine or another one, so
a moved node needs no new pairing ([backup](backup.md)).

## Keep it running

`nerve-node run` runs in the foreground. On Linux with systemd,
`sudo nerve-node install` makes it a service that starts with the machine,
under a user of its own ([service](service.md)); on Windows `install` does
the same from a terminal opened with "Run as administrator". Elsewhere, run
`nerve-node run` under your own service manager.
