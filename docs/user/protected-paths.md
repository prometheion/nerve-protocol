# Protected paths

Some places hold secrets or start programs later. The node refuses file calls
that touch them, in every mode, `user` mode too, whatever a rule says.

## What is protected

On Linux:

| Group | Examples |
|---|---|
| Keys and credentials | `~/.ssh`, `~/.gnupg`, keyrings, password managers, `~/.git-credentials`, `~/.netrc`, `~/.aws`, `~/.kube`, `~/.docker`, `~/.npmrc`, `~/.pypirc` |
| Browser and mail profiles | `~/.mozilla`, `~/.thunderbird`, `~/.config/google-chrome`, `~/.config/chromium` |
| Shell start-up | `~/.bashrc`, `~/.profile`, `~/.zshrc`, `~/.config/fish` |
| Autostart and user services | `~/.config/autostart`, `~/.config/systemd` |
| System files | `/etc/shadow`, `/etc/sudoers`, `/etc/sudoers.d`, `/etc/ssh`, `/etc/pam.d`, `/etc/cron.d`, `/etc/systemd`, `/etc/profile` |

These are protected against writes only: `~/.gitconfig`, `~/.config/git`,
`~/.local/bin`, `~/.local/share/applications`. Tools need to read them.

On Windows the list also holds the OpenSSH server's files in
`%ProgramData%\ssh`, the registry hives in `%SystemRoot%\System32\config`, the
all-users Startup folder, Windows PowerShell's home and its profiles, PowerShell
7's install folder, the user's PowerShell profiles and modules in `Documents`,
and `NTUSER.DAT`. PowerShell 7 counts when installed with the MSI or winget. A
copy unpacked from a zip file, installed as a .NET tool or put in a folder of
your choice is not covered.

Names are matched without regard to case.

## What protection covers

- The file actions (`fs`) and the working directory of a command.
- It does not cover what a command reads or writes by itself. In `folder` mode
  (Landlock on Linux, the AppContainer on Windows), a command's sandbox leaves
  protected paths out. In `user`
  mode a command runs as you, without a sandbox, and can reach them.
- It does not see a path a command builds while it runs
  ([modes](modes.md#paths-a-command-builds-at-run-time)).
- It does not cover what a command asks another program for. With the keys
  in the system keyring, a command that asks the keyring (`secret-tool`,
  `busctl --user`, `gdbus`, `dbus-send`) names no protected path, so an
  allow rule for it reaches the node's keys
  ([keys](config.md#where-the-node-keeps-its-keys)).

## The node's own folders

The node's config and state folders are closed harder. No rule, mode, folder or
release opens them. The node also checks the paths a command line names
plainly. In `folder` mode (Landlock on Linux, the AppContainer on Windows) the
command's sandbox leaves the folders out. A `user` mode command runs as you and can still reach them.

## Release a protected path

Only you can release one, on the machine.

Grant a folder at or inside the protected path. The folder releases it for the
rights it has, and no more: `r` for reads, `w` for writes, `x` for commands.

```sh
nerve-node folder add ~/.ssh r       # reads of ~/.ssh may now pass
```

Or release a path by name:

```sh
nerve-node config add center.lab.policy.protected.allow '~/.ssh/config'
```

A folder at a protected path does not release the rest. `~/` as a folder does
not release `~/.ssh`.

## Protect more

```sh
nerve-node config add center.lab.policy.protected.extra '~/secrets'
```

A center with the [settings grant](settings-grant.md) can add paths here. It
cannot remove one or release one.
