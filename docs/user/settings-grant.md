# Let a center change settings

A center cannot change anything on a machine at first (`settings off`). The
settings grant lets it. Only you can give it, on the machine.

```sh
nerve-node center grant settings write
nerve-node center grant settings off      # take it back
nerve-node center ls                      # shows "settings write" or "settings off"
```

With several centers, add `--center <name>`.

Every center, with the grant or without, is told its own pairing's mode,
until when it holds, the account its commands run as and, in `folder` mode,
its folders (a folder you closed inside one is not named, only that some
folder below is closed): the agent needs them to know where it may work
([modes](modes.md#folders)). It is never told another center's.

## What a center with the grant can do

- Change its own pairing's policy, and read the rest of it: mode (up to
  `user`), folders, rules, capability switches.
- Add rules with the web UI's Audit buttons.
- Edit the machine's settings as JSON in the web UI, Settings.
- Pause the node's link.
- Turn the [sudo switch](sudo.md) on and off.

Each change is checked, then saved. A change is audited on the machine with the
old and the new value and the name of the center.

A center with the grant can widen its own rights up to `user` mode. A center
that is taken over is then as strong as `user` mode on that machine. Give the
grant only to a center you would also give a shell.

Where root is the node's owner ([service](service.md#root-as-the-owner)),
`user` mode runs commands as root. A center with the grant can switch itself
to it, and so run commands as root, with no password asked. On such a node
the grant gives the center root: `center grant settings write` warns of it,
and so does the desktop app when you give the grant.

## What stays with you

No grant lets a center change:

- pairing and unpairing, the node's keys, the list of centers
- the grant itself
- `panic` and `unlock`, or an unpause (you resume with `center resume`)
- machine settings: the shell, `allow_root`, the sudo path, the account commands run as, where the keys are, the log level
- the proxy and its secrets
- another center's pairing
- the sudo password. A center only passes it on, sealed
- the release of a [protected path](protected-paths.md). A center may add paths
  to protect, never remove one, and its folders cannot open a protected place
  that yours do not
- the audit log
- the programs that may add capabilities ([providers](providers.md))
- turning on what senses (a camera, a microphone): an allow rule or an `on`
  switch for it, and taking away an `off` or `hidden` switch or a deny rule
  that keeps it off. The same holds for a capability no program offers now,
  or an action an offered one lacks, as the machine cannot tell yet whether it
  senses

A change that touches one of these is refused as a whole, and the refusal names
the field.

One more field is yours, and a change to it is not refused but dropped: the
node's record of the folders it recorded at their real place (`places` in the
policy, see [modes](modes.md#a-folder-keeps-the-place-you-added)). The
settings document shows it, and a center that saves the document with another
value there changes nothing; an entry goes only with its folder.

## Without the grant

Everything is still possible on the machine, with [`nerve-node`](commands.md).
The web UI shows such a machine as keeping its settings to itself, and its
Audit buttons stay off.
