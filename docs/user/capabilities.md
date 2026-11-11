# Capabilities

A capability is what a center may ask a machine for. The node has its own,
`fs` (files) and `exec` (commands). You can add more: a fixed command in
`node.toml`, or a program that attaches to the node as a **provider**. A
center then sees them next to `fs` and `exec`, and the node decides each call
by that center's mode and rules.

```sh
nerve-node cap                         # every capability, and each center's access
```

## Add a command of your own

```sh
nerve-node cap add sensors.read --effect sense --summary "Temperatures of this machine." \
  --result '{"type": "object"}' -- sensors -j
```

What follows `--` is the command: the program, then its arguments. The name
is `cap.action`. The options:

| Option | Sets |
|---|---|
| `--effect` | `read`, `write`, `execute`, `sense` or `actuate`: when a center may use it |
| `--summary` | one line for the agent |
| `--params` | the JSON Schema of its arguments, or `none`; `-` reads it from stdin |
| `--result` | `text` (the default), or a JSON Schema the output must fit |
| `--timeout` | seconds it may run |

A word written `{field}` is the call's argument `field`, as one whole
argument. No shell reads the command, so `;` and `$(...)` in a value are
just characters. Put `--` before arguments that name files or text: a value
that starts with `-` is taken only after it.

On Windows, `cmd`, a `.bat` or `.cmd` file and PowerShell without `-File`
would read a value again as commands, so a command of theirs with a
`{field}` is refused. Put the command in a script and run it with
`powershell -NoProfile -File script.ps1 {field}`.

```sh
nerve-node cap add logs.tail --effect read \
  --params '{"type": "object", "required": ["path", "lines"],
             "properties": {"path": {"type": "string", "x-nerve-path": "read"},
                            "lines": {"type": "integer"}}}' \
  -- tail -n {lines} -- {path}
```

Mark an argument that is a path with `"x-nerve-path": "read"` or `"write"`,
and the folders judge it as they judge a file call. `cap edit NAME` changes
one, `cap rm NAME` removes it. In the desktop app, **Capabilities › Add a
capability…** does the same in a form.

It runs as `nerve-run`, from the calling pairing's home, held like that
pairing's commands. A node run by hand offers none
([the account](../dev/capabilities.md#the-account-it-runs-as)).

- While a command runs, its line, with the call's values, is there for every
  account on the machine to read. Put no secret in it: give it a file the
  program reads, or write a provider
  ([secrets](../dev/capabilities.md#keep-secrets-out-of-the-command)).

## Allow a program

A program of yours (a desktop app, a home service) can add capabilities:
a lamp it switches, a window it shows. Name it first, with the full path of
its executable:

```sh
nerve-node provider add desk /usr/lib/nerve-desktop/nerve-desktop
nerve-node provider                    # the programs you allow, and which are attached
nerve-node provider rm desk            # its capabilities leave at once
```

The node checks that the program that attaches under that name runs that
very file. On the installed node only your own programs and root's attach.
A provider runs as you, with your rights; the node sees only the paths its
actions mark ([providers](../dev/capabilities.md#capability-providers-in-use)).

- The check tells programs apart, not users: another program of yours can
  make the allowed one attach for it. Allow only programs you trust.

## When a center may use one

| Mode | A capability's action runs when |
|---|---|
| `allowlist` | an allow rule names it, such as `lamp.on`, or `lamp` for all its actions |
| `folder` | the folders allow the paths it marks; one that marks none needs `on` |
| `user` | always, but one that senses or acts on the world needs `on` |

```sh
nerve-node cap set lamp on
nerve-node config add center.lab.policy.allow 'lamp.on'
```

Only you turn on an action that senses (a camera, a microphone) or acts on
the world (a lamp, a lock). A center with the settings grant can allow
others. [Rules](rules.md#rules-for-files-and-other-actions) holds a rule to
an action's arguments.

## See what is there

`nerve-node cap` lists one action a line: its effect, where it comes from
(`built-in`, `config`, `program desk`), and for each center whether it may
use it now. An action the node left out says why.

```text
fs.read       read     built-in      lab: on
lamp.on       actuate  program desk  lab: on (set on)
lamp.dim      -        program desk  left out: params: …
```

`nerve-node status` lists the attached programs. [Switch a
capability off](rules.md#switch-a-capability-off) with `cap set … off`.
