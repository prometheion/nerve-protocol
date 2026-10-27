# Audit

The node writes down every decision about a call, and every change to its
settings. Read it on the machine, or in the center's web UI.

## On the machine

```sh
nerve-node audit               # everything, oldest first
nerve-node audit --denied      # only refused calls
nerve-node audit --follow      # keep running and print new entries
nerve-node audit --last 50     # only the newest 50
```

A call looks like this: a time in milliseconds since the epoch, the center, the
action, the target and the decision. A refusal adds its reason.

```
1791834106607  lab  fs.read  /etc/hostname  forbidden: no allow rule matches /etc/hostname
1791834531401  lab  fs.read  /home/u/proj/a.txt  allowed
```

The reason says what is missing. Use it to write the rule you want
([rules](rules.md)). The target of a call that names paths is its path (an
`fs` call's, or the paths a program's capability takes, joined by `, `; a
path that does not resolve is refused as given, with `bad_path`). The
refusal the center gets names each path as it gave it; only the audit names
where it led, which can be another place when the path goes through a link.
A call to a capability you switched `off` is a refusal too, with the path or
command line an `fs` or `exec.run` call names as its target. An `fs` path the node did
not resolve is the target only where it is written as a resolved one
(absolute, no `.` or `..` part), since a rule made of it would match nothing
otherwise; else the target is empty and the reason names the path:

```
1791834531650  lab  notes.open  notes.open  forbidden: notes.open is off
```

A call whose folders the node was still checking for links when it ended
(its deadline passed, or the center cancelled it) is a refusal with the
code `cancelled`: it never reached the program
([providers](providers.md#paths-it-takes)).

A command killed for its memory limit gets a second line, `killed`, with the
reason ([limits](limits.md)):

```
1791834531877  lab  exec.run  make -j8  killed: the command went past its memory limit of 4096 MiB and was killed
```

Settings changes are lines like `1791834068828  settings v1 by local (alice)`.
They show the new version and who changed it: `local` for `nerve-node`, with
the account that ran it (the user behind `sudo`, or the owner of the installed
node, [administrator rights](desktop.md#administrator-rights)), or the name of
a center. The log holds the old and the new value of each setting.

`install`, `setup`, `update` and `uninstall` are lines like
`1791834068828  update: replaced nerve-node <old> with <new>; restarted the service nerve-node.service`,
with the steps that were done and the error that stopped the rest, if any
([service](service.md)).

A tunnel of the [relay](relay.md) is one line when it ends: who, from where,
to which center, why it ended, how long it lasted and how much it carried.
It never holds a token.

```
1791834106607  relay  lab-pc from 10.0.0.7:51544 to center home: cut off by the owner after 2 h 5 min (81234 bytes up, 90211 down)
```

A key rotation is one line, with the public keys or pins and never a private
key ([pairing](pairing.md#rotate-the-machines-key)):

```
1791834106607  lab  key node-key: the center took the new key <hex> in place of <hex>, which it takes for 7 d more
```

The events are `node-key`, `node-key-refused`, `node-key-unanswered` and
`node-key-grace-ended` for the machine's key, and `center-key`,
`center-key-refused` and `center-key-grace-ended` for the center's.

## What the log holds

- Targets: paths and command lines, cut at 512 characters.
- Never file contents or command output.
- Never the sudo password.
- Refusals of a changed `node.toml`, and the owner taking it with
  `config accept`.

## Where it is and how big it gets

The log is `audit.jsonl` in the node's state folder
([where](install.md#where-files-live)). One line is one JSON object.

At 10 MiB the node moves it to `audit.jsonl.1` and replaces the older copy, so
the log stays below about 20 MiB. A center that makes many refused calls cannot
push out what the node allowed or changed: refusals take at most half of a full
file, and the oldest refusals go first.

## Clear it

```sh
nerve-node audit clear
```

starts the audit log afresh. Nothing goes silently: the entries so far become
`audit.jsonl.1`, as at 10 MiB (the older copy gives way), and the new log
begins with `audit cleared by <account>`. `nerve-node audit` and the app show
the entries from there on; the cleared ones stay in `audit.jsonl.1` until the
log moves aside again. Only the owner or root may clear it: never a center,
and never a command a center runs (the node refuses it there).

## The audit log and the log

The audit log is the node's record of its decisions. The [log](logs.md) is
what the program did: links, pairing, changes, errors. They are separate files
with their own sizes. A call that worked is only in the audit log; a call that
was refused or failed is in both, in the log with its reason.

## In the web UI

The Audit page lists the latest decisions of all machines, newest first, and
those of the center's [action checker](action-checker.md), which refuses some
calls before a machine sees them; those are not in the machine's audit log.
It keeps at most 500 decisions or 1 MiB, in memory. See
[the web UI](web-ui.md#audit).
