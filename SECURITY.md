# Security policy

Nerve lets an agent read, write and run commands on your machines. A hole in
it can give an agent, a center or another account more than the owner
allowed. Please report one privately, so it can be fixed before it is
public.

## How to report

Use GitHub's private vulnerability reporting: on the repository's
**Security** tab, **Report a vulnerability**
(<https://github.com/prometheion/nerve-protocol/security/advisories/new>).
Only the maintainers see the report.

If the Security tab has no such button, do not put the hole in a public issue.
Open an [issue](https://github.com/prometheion/nerve-protocol/issues/new) that
says only that you have a security report, with nothing about the hole in it.
A maintainer answers there and gives you a private way to send it.

Please say:

- which program and version (`nerve-node --version`, `nerve-center --version`,
  or the desktop app's About dialog), and the platform;
- what you did, what happened, and what should have happened;
- what an attacker needs for it (an agent's command, a paired center, a local
  account, the network).

You get an answer within a week. Once a fix is released, the advisory is
published, with your name if you want it there. Please keep the hole to
yourself until then, or for 90 days, whichever comes first.

Only the latest release gets fixes.

## In scope

- `nerve-node`, `nerve-node-desktop` and `nerve-center`, as released and as
  built from this repository: whatever lets a center, an agent's call or a
  command it runs get past the owner's mode, folders, rules or the account it
  runs as (`nerve-run`); whatever lets another local account control a node or
  a center it does not own; the pairing, the TLS pinning and the link between
  center and node; the web UIs and their login; the installer, `update` and
  `uninstall`.
- The protocol (`docs/dev/spec/`) where it makes a secure implementation
  impossible.
- The release workflow (`.github/workflows/release.yml`), where it could ship
  something other than what was built from the tagged commit.

## Not in scope

- What the owner allowed: a command run in `user` mode, by an allow rule or
  with sudo can do what the owner can. That is what those settings are for
  ([folders and modes](docs/user/folders-and-modes.md)).
- The known limits below, and those in [safety](docs/user/safety.md), unless you get past what they say.
- A wrong answer of the action checker's model. The checker is an extra gate
  in front of the machine's own policy and can only refuse
  ([action checker](docs/user/action-checker.md)).
- The harness and the model: what an agent asks for, and what a harness does
  with the answers.
- A hole in a dependency alone: report it to its project. Tell us too when
  Nerve is affected.

## How releases are made, and what `update` trusts

Release signing is postponed. The released programs are not signed. Each
release lists their checksums in a file `SHA256SUMS` beside them.
`nerve-node update`, `nerve-center update` and the desktop app's update
download the program and that `SHA256SUMS` from the same GitHub release, over
TLS, and install the program only when its checksum matches. So the checksum
guards against a broken or cut download, not against someone who can change
the release itself: whoever can publish a release on the repository (or
take over GitHub's delivery of it) can change both. `--from <file>` installs a
program you downloaded and checked yourself.

Releases are built by the repository's release workflow on GitHub's runners,
from a tagged commit of `main`, and tested there before they are published
([releasing](docs/dev/releasing.md)).

## Known limits

These are by design or not solved yet. The pages named say more.

- **The guard against changing the node catches mistakes.** The built-in
  deny rules of every pairing keep an agent's command from changing the node
  by mistake. They read the command line; a command that hides what it does
  gets past them. The boundary is the mode, the folders and the account a
  command runs as ([rules](docs/user/rules.md#the-guard)).
- **Folder mode limits files, not the network.** By default a `folder` mode
  command may connect out, to other machines and to services on the same
  machine (loopback). `nerve-node network off` closes it for one center
  ([network](docs/user/network.md)).
- **Landlock decides how much folder mode holds on Linux.** Without Landlock
  (some containers and LXC guests), the installed node runs folder mode
  commands as `nerve-run` with its account alone: they reach what any account
  may reach, and the folders of every pairing of that node, not only their
  own. `nerve-node status` says which Landlock version the kernel has, and
  the docs say what each version holds
  ([modes](docs/dev/sandbox-linux.md#the-account-nerve-run)).
- **A node you run yourself runs commands as you.** Only the installed node
  has `nerve-run`. Landlock holds a command's own processes, not the other
  programs of your account that run things on request
  ([modes](docs/dev/sandbox-linux.md#what-a-command-can-reach-in-folder-mode)).
- **Root, the administrators and the owner are trusted.** Whoever is root
  on the machine, on Windows an administrator or a Backup Operator, or the
  node's owner, controls the node and can read its keys. The node keeps its
  keys from the commands it runs, not from them.

On Windows ([Windows](docs/user/windows.md#limits)):

- **UAC is no boundary.** A command that runs as an administrator owner
  (`user` mode, `--as-owner`) can take the full rights back and read the
  node's keys.
- **The owner's Windows password is on disk.** It is sealed with DPAPI for
  the machine, so the config folder's access list is its only guard.
- **A folder mode command reads more than its folders.** The Windows folder,
  Program Files and what Windows opens to every AppContainer: pipes, RPC and
  COM servers. A program that offers itself to all AppContainers can act for
  a command, as that program's account.
- **Some work leaves the command's job.** What WMI, the task scheduler or a
  service starts for a command runs outside its job and its limits. A
  `folder` mode command's container keeps it from them
  ([what the container does not stop](docs/dev/windows.md#what-the-appcontainer-does-not-stop)).
- **Sudo commands run outside the container.** They run as the owner, with
  the administrator's rights, and the folders do not hold them.
- **The network switch needs the Windows Firewall service.** Without it a
  pairing whose network is off runs no command.
- **The guard has named holes.** A service or task made by writing the
  registry or the Tasks folder directly, the Startup folder and WMI are not
  covered.
- **The programs are not signed.** SmartScreen warns, and Smart App Control
  can block them ([#219](https://github.com/prometheion/nerve-protocol/issues/219)).
