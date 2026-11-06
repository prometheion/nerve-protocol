# Rules

Rules say which calls a center may make and which are refused. Each pairing
has three lists:

| List | Counts in | Does |
|---|---|---|
| `allow` | `allowlist` mode only | A matching call may run |
| `deny` | every mode | A matching call is refused; it beats every other rule and mode |
| `sudo` | every mode, while [sudo](#sudo) is on | A matching `sudo` command may run |

In `folder` and `user` mode, allow rules do nothing; `rule add allow` says
so there. With several centers, add `--center <name>`.

## Allow and deny a command

```sh
nerve-node rule add allow 'git status'
nerve-node rule add allow 'git status *'
nerve-node rule add deny 'git push origin main'
nerve-node rule                        # all three lists
nerve-node rule rm 'git status *'      # the entry as `rule` shows it
nerve-node rule edit allow 'exec.run:git status' 'git status --short'
```

A rule applies to one command line. An allow rule covers a line only when
every command in it matches. `rule rm` needs the list only when the entry is
on two lists.

A deny rule matches the whole command line. It does not see `rm` inside a
script, in `/bin/rm` or in another program that deletes files. In `folder`
and `user` mode it guards against mistakes; it is not a sandbox.

## Wildcards

A trailing ` *` is the wildcard. `rule add` prints what a wildcard rule
covers.

| Rule | Covers |
|---|---|
| `git status` | that exact line, not `git status --short` |
| `git status *` | `git status` with anything after it |
| `rm *` | every `rm` command, not the files of a folder |
| `/srv/data/*` with `--action fs.read` | that folder and all below it |
| `lamp.set:room=office` | a call of `lamp.set` with that argument |

A wildcard covers plain commands only. A line with shell characters
(`; & | $ ( ) < > { } ' "`), or one that starts another shell (`sh`,
`bash`, `eval`), needs a rule that names the whole line. So `git *` does not
allow `git x; rm -rf ~` ([what a wildcard covers](../dev/policy-engine.md#what-a-wildcard-covers)).

## Rules for files and other actions

`--action` makes a rule for one action, as the audit page's buttons do. An
action without a path takes `''`. `--arg FIELD=VALUE` holds the rule to one
argument of the call.

```sh
nerve-node rule add allow /srv/data/report.txt --action fs.read
nerve-node rule add deny '/srv/data/*' --action fs.write
nerve-node rule add deny '' --action lamp.set --arg room=bedroom
```

`--exact` takes the text as it is, a `*` at its end too. Rules on an
action's arguments (`room=office`, `brightness<=50`) are in
[rule syntax](../dev/policy-engine.md#rules-on-an-actions-arguments).

## The guard

The guard is built in: deny rules that keep a center's commands off Nerve
itself. They refuse a command that runs, replaces or deletes `nerve-node`,
names the node's socket or its folders, or stops its service. `rule` shows
`guard: 8 rules, built in`. They cannot be removed, and the node keeps them
current.

- The action checker's blocklist and the node's guard catch mistakes by
  name, not someone who hides the name. The mode, the rules and the account
  are the protection ([guard](../dev/policy-engine.md#the-guard)).

## Protected paths

Some places hold secrets or start programs later. File calls that touch
them are refused in every mode, `user` mode too, whatever a rule says.

| Group | Examples |
|---|---|
| Keys and credentials | `~/.ssh`, `~/.gnupg`, keyrings, `~/.git-credentials`, `~/.aws`, `~/.kube` |
| Browser and mail profiles | `~/.mozilla`, `~/.thunderbird`, `~/.config/google-chrome` |
| Shell start-up | `~/.bashrc`, `~/.profile`, `~/.zshrc`, `~/.config/fish` |
| Autostart and services | `~/.config/autostart`, `~/.config/systemd` |
| System files | `/etc/shadow`, `/etc/sudoers`, `/etc/ssh`, `/etc/pam.d`, `/etc/systemd` |

`~/.gitconfig`, `~/.config/git` and `~/.local/bin` are protected against
writes only. The node's own folders are closed harder: nothing opens them.

```sh
nerve-node folder add ~/.ssh r                                    # releases reads there
nerve-node config add center.lab.policy.protected.allow '~/.ssh/config'
nerve-node config add center.lab.policy.protected.extra '~/secrets'
```

Only you can release a protected path. A center with the settings grant can
add one, never remove one. `lab` is the center's name here.

- Protection covers file calls and a command's working folder. A `user`
  mode command runs as you and reaches them
  ([protection](../dev/policy-engine.md#what-protection-covers)).
- A command that asks another program for something, such as the keyring
  over D-Bus, names no protected path.

## Sudo

Sudo is a switch on the machine, off by default. While it is on, a `sudo`
command runs only if the sudo list names it.

```sh
nerve-node rule add allow 'sudo apt update'   # goes on the sudo list
nerve-node rule add allow 'sudo apt *'
sudo nerve-node sudo on                       # asks for your sudo password
nerve-node sudo                               # on or off
nerve-node sudo off
```

`sudo on` asks your password to show that you may run commands as root here.
On the installed node it needs `sudo` in front. The password stays in
memory only, so a restart turns sudo off.

- Commands on the sudo list run as root, outside the folders. Put on the
  list only what you would run as root yourself
  ([sudo](../dev/policy-engine.md#sudo-as-the-owner-uses-it)).
- With the network off, no sudo-list command runs ([network](network.md)).
- Turning sudo on in the center's web UI puts your password into a page the
  center serves. If you do not trust the center, run `sudo nerve-node sudo on`
  on the machine
  ([from the web UI](../dev/policy-engine.md#from-the-web-ui)).

## The settings grant

A center cannot change anything on a machine at first. The grant lets it.

```sh
nerve-node center settings on lab
nerve-node center settings off lab
nerve-node center                      # shows the grant
```

With the grant a center may change its own pairing's mode (up to `user`),
folders, rules and capability switches, and turn sudo on and off. It may add
rules with the audit page's buttons, and capabilities of its own: fixed
commands that run as `nerve-run`. It turns those on itself; one that senses
or acts waits for your `on`. To stop it adding commands, take the grant back. That leaves what it added,
still on: `cap rm NAME --center <name>` removes it
([the grant](../dev/settings-and-config.md#without-the-grant)).

No grant lets it pair or unpair, touch the keys, the grant itself, `panic`
or another center's pairing, or change the proxy or a machine setting (the
shell, `allow_root`, the sudo path, where the keys are, the log level). Nor
may it turn its network on or release a protected path
([the grant](../dev/settings-and-config.md#the-settings-grant)).

- A center with the grant can widen its rights up to `user` mode. Give it
  only to a center you would also give a shell.
- With root as the owner, a center with the settings grant can switch
  itself to `user` mode and so run commands as root
  ([root as the owner](../dev/service.md#root-as-the-owner)).

## Switch a capability off

```sh
nerve-node cap set exec.run off
nerve-node cap set fs hidden
nerve-node cap
```

| Setting | Effect |
|---|---|
| `on` | Normal: the rules and the mode decide |
| `off` | Calls are refused with `disabled`; the center sees it as off |
| `hidden` | The center is not told of it, and calls are refused |

A switch applies in every mode, to a capability (`fs`) or one action
(`exec.run`).
