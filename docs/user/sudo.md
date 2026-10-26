# Sudo

Sudo is a switch on the machine, not a mode. It works on Linux, and on
Windows on the node [installed as a service](service.md#windows) ([sudo on
Windows](#sudo-on-windows)). It is off by default.

| Switch | What happens to a `sudo` command |
|---|---|
| Off | Refused, even if the sudo list names it. The node holds no password |
| On | Runs only if the sudo list names it, in every mode. Deny rules and protected paths still apply |

A sudo command is one whose first word is `sudo` (or a path ending in
`/sudo`). It has its own list, `sudo`. The normal allow list does not count
for it.

## Turn it on

1. Put the commands on the sudo list. `sudo` in front is optional:

   ```sh
   nerve-node rule add sudo 'apt update'
   nerve-node rule add sudo 'apt update' --wildcard   # sudo apt, and anything after it
   ```

2. Switch sudo on. The node must be running. It asks for your own sudo
   password, which shows that you may run commands as root on this machine
   (on the node installed as a service on Linux with `sudo` in front, as this
   command stays root's):

   ```sh
   nerve-node sudo on
   ```

   A sudo command is yours: it runs as root, in every mode, and the folders
   do not hold it. Put on the sudo list only what you would run yourself.
   Who raises it depends on the account the pairing's commands run as
   ([service](service.md#the-accounts-commands-run-as)):

   - **as you** (`user` mode, `allowlist` mode as you, a node you run
     yourself): through your sudo, with your password.
   - **as `nerve-run`** (`folder` mode and `allowlist` mode on the installed
     Linux node): the node starts the command as root itself. `nerve-run`
     has no sudo and no password of its own, and your password is not used
     for it: the sudo list is the only way to root for it. Switching sudo on
     still asks for your password: it shows that you, who give these
     commands root, may run commands as root on this machine yourself.

3. Look or turn it off:

   ```sh
   nerve-node sudo status
   nerve-node sudo off
   ```

`rule add allow 'sudo …'` is refused. A sudo command goes on the sudo list.

## What the node does

On Linux (Windows differs, see [sudo on Windows](#sudo-on-windows)):

- It checks the password with `sudo -S -k -v`, run as you (the owner on the
  installed node), so sudo checks your password and your sudoers entries. A wrong password is refused and the switch stays as it was.
- It keeps the password in memory only. Turning sudo off drops it. A node that
  restarts has sudo off.
- It never sends the password to a center. It replaces any copy in a frame,
  also in a command's output stream, or in the audit log with `[redacted]`.
  This holds on Windows too.
- A sudo command must be one simple command. One with `; & | $ ` ( ) < >` or a
  line break is refused. This holds on Windows too.
- A `--wildcard` entry covers plain commands only, as a [wildcard allow
  rule](rules.md#what-a-wildcard-covers) does. A line with `@ { } % ' " # , \`
  or a word that starts another command, such as `start`, `sh`, `powershell`,
  `cmd`, `iex` or `-Command`, runs only when an entry names the whole line.
  So `sudo systemctl *` does not cover `sudo systemctl start nginx`, and
  `sudo net *` does not cover `sudo net start spooler`: add
  `nerve-node rule add sudo 'systemctl start nginx'` without `--wildcard`.
  The refusal names the character or word. This holds on Windows too.
- For a pairing whose commands run as you, it starts the command as you, as
  `sudo -S -k -p <prompt> …`, so sudo raises it from your account. It runs
  without the Landlock sandbox, which would stop sudo from gaining
  privileges. It writes the password only after sudo prints the prompt.
- For a pairing whose commands run as `nerve-run`, it starts the command as
  root, with root's own group, through `/bin/sh`, in the command's working
  folder, without the Landlock sandbox. The shell gets the allowed line and
  nothing else, with a fixed environment (the system's `PATH`, root's
  `HOME`); it reads the line as root, so `~` is root's home there. The node
  enters the working folder for it as you, so a folder in your closed home
  works. The sudo program and its sudoers rules play no part in it. So the
  line takes no option of sudo: a leading `-n` and `--` are dropped, as
  they change nothing here, and a command that starts with any other one,
  such as `sudo -E …` or `sudo -u bob …`, is refused with the reason. Allow
  and send it without the option.
- Every other command runs with `no_new_privs`. A `sudo` later in a command
  line, or any setuid program, cannot gain privileges.

## From the web UI

A center with the [settings grant](settings-grant.md) can turn sudo on and off.
In Settings, open the machine and press **Turn sudo on**. The browser seals the
password for the node, and the center only passes it on. The center cannot read
it.

The center serves the form that takes the password. A tampered center could
capture the password before the browser seals it. Turn sudo on from the
machine if you do not trust the center.

Where root is the node's owner ([service](service.md#root-as-the-owner)), no
center turns sudo on: sudo checks no password of root's, so the password
would show nothing. Root does, with `nerve-node sudo on` on the machine. That
does not keep a center from root there: a center with the
[settings grant](settings-grant.md) may switch itself to `user` mode, whose
commands run as root, with no password at all.

## Sudo on Windows

Windows has no `sudo` program. A sudo command runs as the
[account commands run as](service.md#the-account-commands-run-as-on-windows),
with that account's administrator rights: the elevated token that "Run as
administrator" gives, not the token UAC gives its other commands. So:

- It works only on the node installed as a service. A node you start
  yourself refuses to switch sudo on.
- The account commands run as must be an administrator. Otherwise the switch
  refuses to turn on. An administrator's other commands run with the token
  UAC filtered, but UAC is no security boundary: any command of that account,
  not only a sudo command, can get the administrator rights back and read the
  node's keys. While the account is an administrator, allow commands only to
  centers you trust with the whole machine.
- `sudo on` asks for that account's password, the one `install` stored. A
  wrong password is refused and the switch stays as it was.
- The node keeps the password with DPAPI in the config folder, as `install`
  keeps it (`sudo.dpapi`). Unlike on Linux, sudo stays on when the service
  restarts. `sudo off` removes the file, and `uninstall` removes it too.
  Neither takes the account out of Administrators: do that yourself to close
  the other way to the administrator rights again. `sudo off` reminds you.

Run the commands in a terminal opened with "Run as administrator". The
[control pipe](platforms.md#the-control-pipe) on Windows takes folder changes
only, so `sudo on` takes effect when the service starts again. `sudo off` takes effect at once: the running service drops the
password within a second.

```powershell
& "C:\Program Files\Nerve\nerve-node.exe" rule add sudo 'net session'
& "C:\Program Files\Nerve\nerve-node.exe" sudo on
Restart-Service nerve-node
& "C:\Program Files\Nerve\nerve-node.exe" sudo off
```

A center with the settings grant switches the running service at once, as on
Linux.

The node starts the command line after `sudo` with the shell
(`machine.shell`, Windows PowerShell 5.1 by default), logged on as a batch
job: the logon Windows uses for a scheduled task that runs with highest
privileges. The account needs the right "Log on as a batch job", which
administrators have unless a policy takes it. The command runs in a Job
Object like every other command, so a timeout ends it.

A sudo command can change anything on the machine and read the node's keys.
Put only the commands you mean on the sudo list. On Windows the sudo list is
not the only way to those rights: see the administrator above.
