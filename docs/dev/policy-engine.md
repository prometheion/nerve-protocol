# The policy engine

The node decides every call. The engine is `crates/nerve-policy/src/decide.rs`.
The exact rules are in [spec/node-local.md](spec/node-local.md) §2 to §4.
For how it looks to an owner, see the user guide ([modes](../user/modes.md),
[rules](../user/rules.md)).

## Three layers

A call passes three layers of policy, each able only to refuse (design rule 1):

1. The **center's action checker** — an optional gate on the center: a
   deterministic blocklist, saved allow rules and an optional decision model
   ([action-checker](action-checker.md)). It runs before the call leaves the
   center and can only make it stricter.
2. The **node's policy** (this page) — the authority. Whatever the center let
   through, the node decides by the calling center's modes and rules.
3. The **sandbox** (`nerve-sandbox`) — confinement for commands the node runs.

The rest of this page is the second layer, the node.

## One policy per pairing

A pairing is a **center entry**. Its policy holds:

| Field | Meaning |
|---|---|
| `mode` | `allowlist` (default), `folder` or `user` |
| `until` | Optional end of `folder` or `user` mode. Then the entry is back in `allowlist` |
| `folders` | A path and `access`: three independent flags `r`, `w`, `x` |
| `places` | The folders (by path) `folder add` recorded at their real place. The owner's: a center's write keeps it |
| `caps` | `on`, `off` or `hidden`, per capability or action |
| `allow`, `deny` | Rules for every action |
| `sudo_allow` | Rules for `sudo` commands |
| `protected` | Extra protected paths, and the owner's releases |

The entry also holds the settings grant (`off` or `write`) and the `paused`
flag. The sudo switch and the limits belong to the machine, not to an entry.

## The answer

A decision is **allowed** or **forbidden**. There is no third outcome. A call
that no rule and no mode allows is refused at once. Nothing is held for a
person.

The refusal names what is missing, so the model can pass it on and the owner
can add the rule. Every decision, allowed or refused, goes to the audit log
with the center and the session. A center that subscribed gets it as an
`audit/decision` event.

## Order

A `locked` node (after `panic`) runs nothing. A paused, revoked or unknown
center is not dialled. For a call that arrives, the engine goes through these
steps in order.

| # | Step | Result |
|---|---|---|
| 1 | The command line is over 64 KiB | `forbidden` |
| 2 | The call touches the node's own folders: any path of an `fs` call, a working directory, a path a command line names plainly | `forbidden`. No rule, mode, folder or release lifts this |
| 3 | The capability or action is `off` or `hidden` | `disabled` |
| 4 | A `sudo` command and the sudo switch is off | `forbidden` |
| 5 | A deny rule matches | `forbidden`, in every mode |
| 6 | The mode decides. A `sudo` command: the sudo list. `allowlist`: an allow rule for every target. `folder`: the folders' flags. `user`: allowed | Allowed or `forbidden` |
| 7 | A protected path is touched | `forbidden`, whatever allowed the call |

The order only narrows. Step 6 is the only one that allows, and steps 1 to 5 and
7 can only refuse.

## Rules

A rule is `<scope>` or `<scope>:<pattern>`. The pattern is a glob over the
call's target: the whole command line, the resolved path, or `<cap>.<action>`.

- A rule matches the whole target. `exec.run:rm *` refuses `rm -rf x`. It does
  not see `rm` inside `git status; rm -rf x` or in `/bin/rm`.
- In `allowlist` mode a **wildcard** allow rule covers plain commands only.
  Commands run unconfined there, so a wildcard must not cover `git x; rm -rf ~`
  or PowerShell's `echo @{a=<command>}`. A line with shell control characters,
  expression characters or a word that starts another shell or runs text as
  code is covered only by an allow rule that names the whole line.
- A `sudo` command must be one simple command. Control characters are refused.
  A wildcard sudo entry covers plain lines only, as a wildcard allow rule
  does; any other line needs an entry that names it whole.

## The guard

A new pairing's deny list starts with the guard (`nerve_policy::rules::GUARD`,
[rules](../user/rules.md#the-guard-against-changing-the-node)): three rules
`guard:node-programs`, `guard:node-paths` and `guard:node-service`
(`nerve_policy::guard::Guard`), and five `fs.write` globs for the node's
folders. A `guard:` rule covers `exec.run` and looks at commands, not at the
text:

- `nerve_policy::command::parse` splits the line as the node's shell reads it
  (`Shell::Sh`, `Fish`, `PowerShell`, `Cmd`; `Env::shell`, from `machine.shell` as
  `exec::shell_command` picks it, and `sh` for a sudo command off Windows).
  It gives the commands of the line with their words (quotes and escapes off,
  `literal` false where a variable or substitution stays), redirect targets,
  here-document text and, as `inner`, what runs inside a command:
  substitutions, groups, PowerShell blocks and the text a shell runs
  (`sh -c`, `eval`, `su -c`, `powershell -Command`, `cmd /c`,
  `Invoke-Expression`, a here-document fed to a shell). cmd reads the text
  after `/c` from the line, so a cmd `Word` keeps its source (`raw`, also for
  the words of `Start-Process`' argument string) and `cmd_text` reads that
  text as it stands and without its first and last quote.
- `command::run` finds the program behind keywords, assignments and wrappers
  (`sudo` and its options, `env`, `timeout`, `nohup`, `nice`, `ionice`,
  `time`, `stdbuf`, `xargs`, `exec`, `command`, `setsid`; `&`,
  `Start-Process`, cmd's `start`, `call`, `if` and `for`).
- `Guard::refuses` visits every command at any depth: `node-programs` by the
  program's name, `node-paths` by any word or redirect target that holds one
  of the node's paths (not after a blank in the same word),
  `node-service` by the program and its arguments (`systemctl`'s verb and
  unit, `sc`, `net`, `pkill`'s pattern) and, for the stopping cmdlets,
  `kill` and `taskkill`, by a name, a substitution that names the node, or
  an earlier command of the same pipe that does (one forward pass per script
  keeps that linear). `node-programs` also refuses a redirect target that
  names the node's programs, and `cp`, `mv`, `rm`, `install`, `ln` and the
  other tools that copy, delete, overwrite, download into or change the mode
  of a file (`FILE_TOOLS`: `tee`, `dd`, `sed`, `chmod`, `curl`, `wget`,
  `Set-Content`, `Out-File`, `gzip`, `objcopy` …) on a file named as the node's programs.
  A word with a brace group is also read expanded in sh and fish
  (`nerve-node{,.bak}`, bounded to a few times the word's length in bytes, each word built counting a fixed amount too; what is over stays as written), and the tools that take
  paths (`TAKES_PATHS`, not the writers) are refused when an earlier
  command of their pipe names the program, also in a bracket or group of
  that command (`… | xargs rm`, `Get-Item … | Remove-Item`, `(Get-Item …) |
  Remove-Item`), as `node-service` does with a name.
  Programs that only look at a file (`ls`, `sha256sum`) are not on the
  list, and neither are the ones that write a file in ways a list cannot
  cover (an interpreter, a .NET call). Each
  `Script` knows the shell it was read as, so a `powershell -Command` body in
  a line for sh is checked as PowerShell.

The parser is bounded: 16 levels of nesting, 10 000 commands and 2 Mi
characters read (a shell's text is read again at each level). A line past a
bound, or one it cannot read with confidence (an open quote or bracket, a
shell fed by a pipe, `-EncodedCommand`, a command wrapped in more than
`unwrap` takes apart), is `Unparsed`. The error carries the commands read
before it (`Unparsed::read`, nested as the line nests them), and each
`guard:` rule then checks those as a parsed line and also matches the whole
line with its share of the text patterns of 0.0.6 (`rules::TEXTS`), so it
refuses at least what they refused. Those texts are
also in `GUARD_OLD`, which `rule guard` takes off a deny list when it puts the
three rules on. A `guard:` rule on the allow list is refused by the config
check. The center's action checker has its own splitter
(`checker/normalize.rs`); it is meant to move onto this parser.

## Modes

- **`allowlist`.** Default deny. Only allow rules count.
- **`folder`.** The folders' flags decide. Reads need `r`, writes need `w`,
  commands need `x` on their working directory. The deepest folder that holds
  a path decides. Commands are confined where the platform can confine them.
- **`user`.** Everything the user could do, protected paths aside. Commands are
  not confined.

`folder` and `user` mode give full access in their area, and deny rules narrow
it. Allow rules are not looked at there.

An action that names no path and no command, which is what a [capability
provider](spec/node-local.md#7-capability-providers) adds, lies in no folder:
`folder` mode allows it only where the owner set it `on`. `user` mode allows
it as it allows the node's own actions, and `allowlist` mode by an allow rule
on `<cap>.<action>`.

## Protected paths

Protected paths apply to the file actions and to a command's working directory,
not to what a command reads. They hold keys, credentials, shell start-up files
and, per platform, system files that open the machine.

- A folder at or inside a protected entry releases it, for the access the call
  needs there: `r` for a read, `w` for a write, `x` for a command. This holds in
  every mode.
- A center may add to `protected.extra`. It may not remove from it, change
  `protected.allow`, or add a folder at or inside a protected entry that the
  owner's folders did not release already.
- Places are compared by path, not as text, so another spelling of the same
  place gives nothing. A folder that is, or passes through, a link into a
  protected entry is refused unless the owner's folders release the place it
  leads to.
- A command with `w` on a folder can replace a folder inside it by a link,
  and Landlock follows a link in a rule's path. So a folder whose path, taken
  a link at a time, crosses a link that lies inside a `w` folder of any center
  is left out of the Landlock rules (`exec::led_away`). A link of the owner's
  that leads into a `w` folder is followed to its end and judged on the way.
  Links above the `w` folder, and the `w` folder itself, are the owner's and
  are followed. Only the `w` folders in the config count there, so a link
  made while a folder had `w` would be followed again once `w` is taken off,
  and a command that runs without Landlock (`user` mode, `sudo`, an
  `allowlist` command) can make a link where no `w` folder is. The record
  closes both for the folders `folder add` stored: it stores the resolved
  path and lists it in `policy.places`, and `exec::replaced` leaves a
  recorded folder out whenever its path resolves to another place now,
  whoever made the link and whatever `w` is left. A folder without an
  entry (older, set by a center, or written with `config set`) is followed as
  before.
- A folder that holds a protected entry gives a command none of it. Landlock
  cannot deny inside a rule, so the sandbox takes the folder's other entries,
  level by level, down to the protected one.
- A folder spelled so that it matches nothing (a `..` segment, and on Windows an
  8.3 short name or a name that ends in a dot or a space) is refused.

## The sandbox

On Linux, `folder` mode runs commands under Landlock:

| Access | Allowed |
|---|---|
| Read | The system folders and the `r` folders |
| Write | The `w` folders and a few devices (`/dev/null`) |
| Run programs | The system folders and the `x` folders |

Landlock restricts the process that applies it. Doing that between `fork` and
`exec` in the multi-threaded node is not safe. So the node starts a small
single-threaded shim per command, `nerve-node __exec-shim`, which applies the
rules and runs the command.

- Landlock cannot run a file it may not read. The rule of an `x` folder carries
  the right to read files by name, but not to list.
- The node's own folders are in none of the sets.
- A `sudo` command runs without Landlock, which would stop sudo from gaining
  privileges. Every other command runs with `no_new_privs`.
- Without Landlock (`confinement none`), `folder` mode on a node run by hand
  refuses every command. The installed Linux node runs them as `nerve-run`
  without Landlock, held back by that account alone (`daemon::folder_refusal`).
- In every mode a command runs in a cgroup of its own, with the memory, CPU
  and processes of `limits.command` (`crate::cgroup`, node-local §2,
  Commands). That is a bound on what it uses, not on what it reaches.

On Windows, each command runs in a Job Object that ends all its processes with
it. A Job Object limits no file access. So in `folder` mode the shim starts the
command in an AppContainer, one per pairing (`nerve_sandbox::appcontainer`;
`grants::container` names it from the state folder and the pairing's
`node_id`, which the node makes fresh at each pairing, never from the
center's local name):

| Access | Allowed |
|---|---|
| Read, write, run programs | What carries a grant for the container's SID: the center's folders, by their flags |
| Read, run programs | What Windows opens to every AppContainer: the Windows folder, Program Files |

- The node puts the grants on the folders for the container's SID
  (`crates/nerve-node/src/grants.rs`), inherited by everything below. The sets
  are Landlock's (`exec::folder_sets`), the own folders and protected entries
  cut out the same way. The grants follow the folders, whatever the mode: the
  node syncs them at start, on a change of its config and before each
  `folder` command, and the CLI when it writes the config. `uninstall` takes
  off those of the node in the invoking user's own folders; the installed
  service puts none on.
- Windows writes inherited entries into each object when it is made, and a
  later change of a folder's list reaches what is below it only when that
  is written again. `SetSecurityInfo` does so for the whole tree, as
  `icacls` does (#54). `appcontainer::set_below` works out the folder's
  list as `SetSecurityInfo` did (the container's entries replaced, the
  inherited ones from the folder it is in now, so a granted folder moved
  out of another one loses that one's entries), writes it with
  `SetKernelObjectSecurity`, which passes nothing down, and passes the
  change down itself (`nerve_sandbox::inherit`): each object is listed and
  opened through its folder's handle (`NtOpenFile`, as itself, never
  through a link), and opened for `WRITE_DAC` only when its list changes.
  Its new list is what Windows works out for an object made there
  (`CreatePrivateObjectSecurityEx` with `SEF_DACL_AUTO_INHERIT`, given only
  the object's own entries, since it keeps every entry it is given as one
  of the object's own): its own entries, and those it inherits from the
  folder's new list. A list in the older form, without
  `SE_DACL_AUTO_INHERITED` and with no entry marked inherited (as in folders
  made under such a folder, a test's temporary folder for one), first gets
  its inherited entries told by the list of the folder it inherited them
  from (`ConvertToAutoInheritPrivateObjectSecurity`, as `SetSecurityInfo`
  does). One whose entries do not match comes out as its own and keeps its
  list. Each write asks for `SE_DACL_AUTO_INHERIT_REQ`, without which
  Windows drops `SE_DACL_AUTO_INHERITED`. An object is written only when
  its entries change. Below an object whose list stays, or one whose list
  does not inherit, nothing changes, so the walk does not go there. Each
  folder is written after everything below it, so a folder whose list is
  right has everything below it right, also after a walk that stopped half
  way; it is listed again once written, and what was made in it meanwhile
  (with its old list, also a file saved over an old name, by its file ID)
  is walked too. The folders above what a stopped walk changed do not show
  it, so `grants::sync` marks a grant `unfinished` in the record before it
  changes its folder and takes the mark off once the change is done; the
  next change at a marked place goes into every folder (`whole`), also one
  back to flags the folder still shows; a mark counts for the object it
  was made on, not for a folder made anew where a marked one was moved
  away; a new grant is recorded with the file ID of the object at its
  path before it goes on, so a first grant that stopped part way is found
  where its folder went, as any other. Each change goes only through the
  object recorded for its place (`set_below`'s `expect`): one replaced
  since, or nothing at the path where it was moved away, is refused before
  any write, marked `acl::Untouched::Refused`, and
  the next sync looks again. Where the record cannot be marked, only
  take-offs run, here and where moved folders are now (one goes into
  every folder, and one that stops gives less, never more), so `uninstall`
  still takes the grants off; puts and replacements wait, and a grant one
  would change is stale where it may give flags that are not wanted. One
  whose folder cannot be found is stale, and one on a volume that is away
  is named, as always. The mark keeps the flags each
  stopped change was heading for (`Grant::toward`): until a change there
  finishes, the place counts as written by those flags too (the hard-link
  check, `w` without `r` for the pass), and a refused change whose place
  may give flags other than the wanted ones is stale. Taking a grant off goes into every
  folder all the same, since Windows' own walk, which earlier versions
  used, writes a folder before what is below it. A link or junction gets
  the change on its own list and is not followed. An error names the
  object it is about. A change that takes long tells how far it is
  (`grants::paced`: after 3 s, then every 15 s, and how it ended), on stderr
  in the CLI and in the log of a running node.
- A record in the state folder (`grants.json`) finds them again. It holds the
  file ID of each grant's object, since the grant is in that object's own
  access list and goes with it: a grant on a moved or renamed folder comes off
  where the folder is now. A sync checks that each wanted grant is still on,
  and puts it on again on a folder made anew. A lock file
  (`grants.json.lock`) keeps the CLI and a running node from writing over each
  other's record, and a grant is recorded before it goes on.
- `w` gives `DELETE` and `FILE_DELETE_CHILD` only with `r`, and a granted
  folder's or file's own entry has no `DELETE` (`nerve_sandbox::acl`).
  Windows grants a move by `DELETE`, and a moved object keeps its own list
  until a change on its new folder passes that folder's entries down. So a
  command moves only what it reads and writes, and a granted folder only
  out of another one it reads and writes. A move alone makes nothing
  readable that was not. A hard link is the gap: a file has one list for all
  its names, so a change the node passes down a folder (a grant put on or
  changed, one taken off, also where a moved folder is now) reaches a file
  a command linked there from a `w`-only folder. So before such a change on
  a folder commands may write in, or one that holds such a folder,
  `grants::sync` walks what the change reaches (`appcontainer::reaches`,
  the same walk without writing) and refuses while a file there has more
  than one name (a removal stays stale). The change itself judges each
  such file again on the handle it writes through, by the names that
  handle gives (`NtQueryInformationFile` with the hard-link classes, each
  name's folder found by its file ID), not by its path, and stops there,
  with the folder's own list as it was (`grants::Links`, #76); a link made
  in the granted folder itself while the walk was below it is found when
  that folder is listed again after its write, and the error says the
  folder has the change already (`inherit::Stop::top_written`). Only an
  error marked `acl::Untouched` (refused before a write, nothing at the
  path) counts as a change that changed nothing; every error from inside
  the walk is of kind `Other`, so the grant stays recorded and marked
  `unfinished`. One
  exception is for cargo: a file below a
  folder named exactly `target` passes when all its names are listed
  (as many as the file has; a failed listing refuses), every
  one, compared resolved, lies in such a folder of the walked folder, and
  each is held by exactly the same wanted and recorded grants as the walked
  name. That compares grant paths, while a grant's entry goes with its
  folder, so a sync in which a recorded grant is not at its path (moved, or
  it cannot be told) gives no pass at all. Nor does a walk of a folder
  where a wanted or recorded grant of any container, on it, above it or
  inside it, may write but not read (`grants::pass`): a command that may
  make a folder there sets its security descriptor at creation, without
  `WRITE_DAC`, and the change passes an entry of its own there (read for
  its container) down to a file it linked into that folder. Where every container that may
  write there may read too, that entry gives nothing new while the grant
  is on. What stays, here and in general: entries a command put on what it
  made (for its container's SID, for ALL APPLICATION PACKAGES, or for one
  of the capability SIDs every container is started with, S-1-15-3-1, -2
  and -3) are not the node's. Those for ALL APPLICATION PACKAGES or a
  capability count at once for every pairing and every AppContainer app. `appcontainer::set` rewrites only the granted folder's own
  list, so they outlive a take-off, a narrowing, removing the pairing and
  `uninstall`. An entry for the container's SID is bound to that pairing:
  no later pairing, also not one of the same center or under the same
  name, runs in that container. With `rw` the propagation alone can pass
  one to a linked owner's file.
  In a `w`-only folder they let a command read what is saved later into a
  folder it made. The user docs name this limit and the `icacls` clean-up.
  Taking a container's own explicit entries off below the folder in the
  take-off's walk is a follow-up; entries for other principals cannot be
  told apart from the owner's and stay a documented limit. A link to anywhere else is refused, other build tools' too (pnpm's
  store, uv's cache, a local `git clone`); the user docs give the ways
  around. A link a command of
  any pairing that may write there makes between the walk and the change
  shows on the file's handle as the change gets to it, and stops the
  change. Inside a folder with `w` a
  command can put a junction or a hard link where a granted folder was, so a
  grant goes on there only on an object of its own (its final path is its
  path, one name, an inheriting list), through the handle the check opened;
  a folder whose resolution crosses a link at or inside a writable place
  gets no grant at all (`exec::led_away`).
- A grant that should be off and cannot be taken off stops the commands of its
  container. A record that cannot be read stops the commands of every
  container, since no grant in it could be found again.
- The container's SID is derived from its name. Windows starts no process in a
  container without a profile, so the shim makes one for the user it runs as;
  the node removes it with the container's last grant.
- The command gets a window station and desktop of its own: Windows keeps an
  AppContainer out of the one it was started from, and PowerShell does not
  start without one.
- PowerShell checks every folder above its working folder, which the
  container may not see, so a PowerShell command starts with a drive `Work:`
  rooted at its working folder. Functions stand in for `Set-Location` and
  `Push-Location`: a whole or relative path goes to the Work drive it lies
  below, or to a new drive `Work2:`, `Work3:`, … rooted at that folder if the
  command can see it, and otherwise to the cmdlet as a whole path, which
  fails. Relative paths are resolved there too, since the cmdlet keeps `..`
  on its drive (`..\app` on `Work:\` is `Work:\app`). A `-Path` loses its
  escapes first; one with a wildcard has the part before its first wildcard
  resolved so and keeps the rest, unless that part is `\` or `/` alone, the
  root of the current drive. The cmdlet runs with `-ErrorAction Continue`, and
  its errors are written again as the function's under the caller's error
  action, so `$?` and the exit code stay as the cmdlet sets them
  (`nerve_sandbox::POWERSHELL_START`). An object piped to them is bound as
  the cmdlets bind it (its `Path`, or else its `PSPath` as `-LiteralPath`),
  since their untyped `Path` would take it whole. Other cmdlets still keep
  `..` on the drive they stand on.
- The container has the network, as Landlock leaves it, but not the loopback
  address. Its token carries three capabilities, `internetClient`,
  `internetClientServer` and `privateNetworkClientServer`, and nothing else
  (`appcontainer::run`).

What the container does not stop, in short (the user docs list each point with
how it was checked on Windows 11 Pro 26H2, build 10.0.26300, and what was not:
[modes](../user/modes.md#what-the-appcontainer-does-not-stop)):

- The network: out to the internet and the local network, no filter by
  address or port; not the machine itself (its loopback address, its own
  address and its name). It can listen; the Windows Firewall decides who
  reaches the port, the node adds no rule.
- The environment: the shim passes the node's own to `CreateProcessW`
  (`lpEnvironment` is null). Windows alone rewrites `TEMP`, `TMP` and
  `LOCALAPPDATA` to the container's folder under `Packages\<name>\AC`, which
  the container may write without a grant and Windows removes with the
  profile.
- What Windows opens to every AppContainer: the Windows folder, Program Files,
  parts of `HKLM` and `HKCU` (reads only), pipes and other endpoints whose
  security names ALL APPLICATION PACKAGES. Other processes of the user are not
  visible to it; WMI, the task scheduler, the service manager and `RunAs`
  refused it in the checks. The node blocks none of these itself.
- The token: low integrity, `SeChangeNotifyPrivilege` and
  `SeIncreaseWorkingSetPrivilege` only, also under an elevated node. No limit
  on memory, CPU, disk or process count: the job only ends processes
  (`JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`).
- Files a command leaves in a `w` folder are run by others outside the
  container. Links and permission entries: above.
- A `sudo` command (installed service only) is started by `winsudo` outside
  the container, whatever the folders say (`exec_run`: `folder` is false for
  it). The folders do not gate it: the switch, the sudo list, the deny rules
  and the protected paths do (`decide`), also where `folder` mode runs nothing
  else.
- Not decided yet, whether to block further: filtering the environment the
  command inherits (#89) and the reads of `HKCU\Environment` (#90). The
  network and the reads of the Windows folder and Program Files are what a
  container is for and stay.
- The refusal for keys in the keyring has a text per platform
  (`KEYRING_NOT_CONFINED`): on Windows it names the AppContainer and the
  Credential Manager, not Landlock and the session bus.
- Not checked: the Credential Manager and DPAPI for the user (the test session
  could not use them), the clipboard against a real desktop, ALPC ports and
  COM servers, network shares. With the node's keys in the Credential
  Manager, `folder` mode runs no command (`keys_kept_from_commands`).

## The sudo switch

The switch is per node, not per entry, and it is never on without a working
password.

- Off, no `sudo` command runs, even if the sudo list names it.
- On, a `sudo` command runs only if the sudo list names it, in every mode.
- On Linux the password is checked with `sudo -S -k -v` and kept in memory
  only. A restart turns the switch off.
- On Windows the password is the one of the account commands run as. The
  node checks it with a batch logon that must hold the Administrators group,
  keeps it with DPAPI in the config folder (so a restart keeps the switch
  on), and starts each sudo command with that logon's full token.
- A center with the settings grant can switch it. The password then travels
  sealed from the owner's browser to the node. The node makes a one-shot offer
  with a fresh X25519 key and signs it with its pairing key. The browser derives
  a key with HKDF-SHA256 and seals the password with AES-256-GCM. The center
  only relays the ciphertext. The node opens an offer once, within 60
  seconds. The exact steps are in
  [spec/protocol.md](spec/protocol.md) §7.4.1.
- A tampered center web UI could capture the password before it is sealed,
  because the center serves the form. The node-side guarantees hold anyway.

## What a center is shown

The descriptor follows the same policy ([capabilities](capabilities.md)). A
tool exists only for an action a call could get through.
