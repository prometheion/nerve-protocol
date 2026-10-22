# Rules

Rules say which calls are allowed and which are refused. Each pairing has
three lists.

| List | Counts in | Does |
|---|---|---|
| `allow` | `allowlist` mode only | A matching call may run |
| `deny` | every mode | A matching call is refused. A deny rule beats every other rule and mode |
| `sudo` | every mode, while [sudo](sudo.md) is on | A matching `sudo` command may run |

In `folder` and `user` mode, allow rules do nothing. The mode decides.

## Allow a command

```sh
nerve-node rule add allow 'git status'
nerve-node rule add allow 'git status' --wildcard
```

The first allows that exact command line. The second allows `git` with
anything after it. A rule applies to one command line, so `git status` does not
allow `git status --short`. Use `--wildcard` for that.

## Deny a command

```sh
nerve-node rule add deny 'rm' --wildcard
nerve-node rule add deny 'git push origin main'
```

A deny rule matches the whole command line. It does not see `rm` inside
`x; rm …`, in `/bin/rm`, in a script, or in another program that deletes
files. In `folder` and `user` mode it guards against mistakes. It is not a
sandbox. (The guard's own rules read each command of a line; see below.)

## The guard against changing the node

Every new pairing starts with deny rules that keep its commands off this
node itself. `rule ls deny` shows them; remove any you do not want.

| Rule | Refuses |
|---|---|
| `guard:node-programs` | A command that runs `nerve-node` or `nerve-node-desktop`, by its name or a path, `.exe` too |
| `guard:node-paths` | A command that names the node's socket or pipes or its config and state folders (`/run/nerve-node`, `/etc/nerve`, `/var/lib/nerve`, `~/.config/nerve`, `~/.local/state/nerve`, `%ProgramData%\Nerve`) |
| `guard:node-service` | A command that stops, restarts, disables or kills the node's service or process, as the node's own `service stop` would |
| `fs.write:…` (five rules) | A write into those folders |

The three `guard:` rules read the command line as the node's shell does
(`/bin/sh` or `machine.shell` on Linux, PowerShell or cmd on Windows) and
look at each command in it. The whole line is refused when any one of them
is a guarded command:

- in a list or a pipe: after `;`, `&&`, `||`, `&`, `|` or a line break, with
  any indent;
- in a group or block: `{ … }`, `( … )`, `if`, `for`, `while`, `case`, a
  function, PowerShell's `{ … }` and `( … )`;
- in a substitution: `$( … )` and backticks, also inside double quotes;
- in the text a shell runs: `sh -c`, `bash -c`, `su -c`, `eval`,
  `powershell -Command`, `cmd /c`, `Invoke-Expression`, and a here-document
  fed to a shell;
- behind a program that runs another: `sudo` (with its options), `env`,
  `timeout`, `nohup`, `nice`, `ionice`, `time`, `stdbuf`, `xargs`, `exec`, a
  path to the program, and on Windows `&`, `Start-Process` and cmd's `start`.

So `env X=1 sudo systemctl stop nerve-node`, `timeout 30 sudo systemctl
restart nerve-node`, `bash -c 'pkill nerve-node'` and
`powershell -Command "Stop-Service nerve-node"` are refused. A word of
another program is data, so a line that only mentions the node runs:
`git commit -m "refuse systemctl stop nerve-node"`, `echo`, `grep`, a
here-document written to a file. The name alone is not refused either:
`cargo build -p nerve-node`, `journalctl -u nerve-node`,
`ls -l /usr/local/bin/nerve-node`. A path in a sentence (a blank before it in
the same word) is data too.

| | Refused | Still runs |
|---|---|---|
| Linux | `systemctl stop`, `restart`, `try-restart`, `reload-or-restart`, `disable`, `kill` or `mask` on `nerve-node` (or `nerve-node.service`); `service nerve-node stop`, `restart`, `try-restart`, `force-reload` or `condrestart`; `pkill` or `killall` on `nerve-node` or `nerve-node-desktop`, with flags such as `-9`, `-f` or `-x`; `kill` with what `pidof`, `pgrep` or a pipe from them finds (`kill $(pidof nerve-node)`, `pgrep nerve-node \| xargs kill`) | `systemctl status`, `is-active`, `show`, `cat` on it, `service nerve-node status`, `journalctl -u nerve-node`, `pgrep`, `ps`, `pkill -f "cargo run -p nerve-node"` (another program) |
| Windows | `sc stop`, `config` or `delete`; `net stop`; `Stop-Service`, `Restart-Service`, `Set-Service` or `Remove-Service`; `Stop-Process` and `taskkill` with `nerve-node.exe` or `nerve-node-desktop.exe`, or with what `Get-Process` finds (`Stop-Process -Id (Get-Process nerve-node).Id`); `Get-Service` or `Get-Process` on the node piped into one of the cmdlets | `sc query`, `sc qc`, `Get-Service nerve-node`, `Get-Process nerve-node` |

The Windows commands and program names match in any case (`STOP-SERVICE`,
`NET STOP`, `sc stop Nerve-Node`, `taskkill /IM NERVE-NODE.EXE`), as Windows
reads them, and `\` separates a path there.

A line the guard cannot read with confidence (a quote or bracket left open,
a line nested deeper than 16 levels, a shell that reads its script from a
pipe such as `curl … | sh`, PowerShell's `-EncodedCommand`) is checked with
the guard's text patterns from before it read commands. Those look for the
commands where a command starts in the text, so such a line is refused
wherever they refused it.

What the guard does not see: a name built at run time
(`n=nerve-node; systemctl stop $n`), a program that another program runs
(`cargo run -p nerve-node`, `find … -exec`, `ssh`, a script file), and
`pkill` or `killall` with a part of the name (`pkill nerve`, which matches
the node too).

A rule of the guard is written `guard:<name>`, and only these three exist.
They belong on the deny list; the allow list refuses them.

```sh
nerve-node rule guard --center lab   # puts back the ones a pairing lacks
```

A pairing that lacks some of them (you removed them) gets them back with
`rule guard`, and the desktop app offers it on **Permissions**. A pairing
made before the guard read commands holds its rules as text patterns. They
work on as they did until `rule guard` (or **Add the guard**) takes them off
and puts the three rules in their place. Those older patterns hold tabs and
line breaks: `rule ls` and the app's rule lists write them as `\t`, `\r` and
`\n`, so a rule stays one line, and `rule rm` and `rule edit` take the entry
as it is listed there (the new entry of `rule edit` too). `config add` and
the app's add field take the character itself: the listed text of such a
rule, or of a rule already on that list, is refused there, since pasted so
its `\n` would be the letter, not the line break. Any other text is a rule as
it stands, a Windows path such as `C:\tools\x.exe` too.

The guard catches an agent's mistakes, such as an agent that tries to give
itself more rights. It does not stop a command written to get around it (a
name built at run time, a copy of the program). The real protection is that
commands run as an account of their own, which may not change the node
([service](service.md)), and the node's own folders, which no rule or mode
opens ([protected paths](protected-paths.md)).

## List, change and remove rules

```sh
nerve-node rule ls            # all three lists
nerve-node rule ls allow
nerve-node rule edit allow 'exec.run:git status' 'git status --short'
nerve-node rule rm allow 'git status'
nerve-node rule rm allow 'git status' --wildcard
```

`rule edit` changes one entry in its place, as one change in the audit: the
entry as `rule ls` prints it, then what it becomes. That is an entry in the
same form (`'exec.run:git *'`, `'fs.read:~/notes/*'`), or a plain command
line, which becomes the rule `rule add` makes of it. It works on every list,
and on the rules of the guard too. The desktop app's Permissions page edits a
rule the same way (the pencil beside it).

`rule rm` takes the same arguments as `rule add`. It also takes an entry as
`rule ls` prints it, such as `'exec.run:git *'`. When the arguments could mean two entries on the list, `rule rm`
removes none and tells you the two commands that remove them one after the
other.

## Rules for files and other actions

`rule add` writes command rules, and refuses an entry in the pattern form
(`fs.read:...`, `fs:...`, and also `exec.run:...` and `exec:...`, the form
`rule ls` prints), which would never match as a command. Give `rule add` the
bare command (`'git *'`), not that form. (`rule rm` does take it.) For files and
other actions, add the rule to the policy by name. `lab` is the center's name on this machine (see
`nerve-node center ls`).

```sh
nerve-node config add center.lab.policy.allow 'fs.read:~/notes/*'
nerve-node config add center.lab.policy.deny  'fs:~/private/*'
```

The web UI's [Audit](web-ui.md#audit) page writes the same rules with four
buttons. That needs the [settings grant](settings-grant.md).

`--action` makes the rule such a button makes for an audit entry of that
action: the entry's path, or the folder it is in with `--wildcard`. An action
without a path takes `''`, and covers its capability with `--wildcard`.

```sh
nerve-node rule add allow /srv/data/report.txt --action fs.read
nerve-node rule add deny /srv/data/report.txt --action fs.write --wildcard   # fs.write:/srv/data/*
```

## Rule syntax

A rule is `<scope>` or `<scope>:<pattern>`.

- The scope is a capability (`fs`, `exec`) or one action (`fs.read`,
  `exec.run`).
- The pattern is a glob over the call's target. `*` matches across `/` and
  spaces.
- Without a pattern the rule covers every target of its scope.
- A pattern ending in ` *` also matches the bare program. One ending in `/*`
  also matches the folder itself.

| Target of | Is |
|---|---|
| `exec.run` | The whole command line |
| every `fs` action | The resolved path. `~/` is your home. On Windows the form is `/c/Users/x` |
| any other action | `<cap>.<action>` |

| Rule | Covers |
|---|---|
| `exec.run:git status` | That command line, exactly |
| `exec.run:git *` | `git` and anything after it |
| `fs.read:/home/u/notes/*` | Reading the folder and below (not `list` or `grep`) |
| `fs:~/private/*` | Every `fs` action on the folder and below |
| `exec` | Every `exec` action, so every command |

Commands and paths never mix: `fs:/tmp/*` is not a command rule. An unknown
rule shape is refused when you add it.

## What a wildcard covers

A wildcard allow rule covers plain commands only. A command is plain when it
has none of these:

- shell characters: `; & | $ ` ( ) < > @ { } % ' " # , \`
- a line break or another control character
- a word that starts another shell or runs text as code, such as `powershell`,
  `pwsh`, `cmd`, `sh`, `bash`, `eval`, `iex`, `Invoke-Expression`,
  `Start-Process`, `-Command`, `-EncodedCommand`, `-File`, `/c`, `/k`

Only an allow rule that names the whole line covers such a command. This keeps
`git *` from allowing `git x; rm -rf ~`. A Windows path with `\` needs an exact
rule, or `/` in the path.

## Switch a capability off

`cap set` turns a capability or one action on, off or hidden for a center.

```sh
nerve-node cap set exec.run off
nerve-node cap set fs hidden
nerve-node cap ls
```

| Setting | Effect |
|---|---|
| `on` | Normal. Rules and mode decide |
| `off` | Calls are refused with `disabled`. The center lists it as off |
| `hidden` | The node leaves it out of what it tells the center, and refuses it |

A capability is `fs` or `exec`. An action is `fs.write` or `exec.run`. A
switch applies in every mode.
