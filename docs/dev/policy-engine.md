# The policy engine

The node decides every call. The engine is `crates/nerve-policy/src/decide.rs`.
The exact rules are in [spec/node-local.md](spec/node-local.md) §2 to §4.
For how it looks to an owner, see the user guide ([modes](#modes-and-folders-as-the-owner-sets-them),
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
| `folders` | A path and `access`: the flags `r`, `w` (which reads too) and `x` |
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
| 2 | The call touches the node's own folders: any path of a call (an `fs` call's, an action's marked path arguments), a working directory, a path a command line names plainly | `forbidden`. No rule, mode, folder or release lifts this |
| 3 | The capability or action is `off` or `hidden` | `disabled` (a call of an `off` action is audited too) |
| 4 | A `sudo` command and the sudo switch is off | `forbidden` |
| 5 | A deny rule matches (for any action but `fs` and a command, by its conditions on the arguments, `RuleSet::find_args`, failing closed); for a path handed to a program (not `fs`, not a command), also one whose condition on that argument may match below it (`RuleSet::find_below`) | `forbidden`, in every mode |
| 6 | The mode decides, by the [effect table](#the-effect-table). A `sudo` command: the sudo list. `allowlist`: an allow rule for every target (for any other action one whose conditions the call meets). `folder`: the folders' flags, and for a read the command account's reach where the node reads as it. `user`: allowed | Allowed or `forbidden` |
| 7 | A protected path is touched | `forbidden`, whatever allowed the call |

The order only narrows. Step 6 is the only one that allows, and steps 1 to 5 and
7 can only refuse.

## Rules

A rule is `<scope>` or `<scope>:<pattern>`. The pattern of `exec.run` is a
glob over the whole command line, that of an `fs` scope a glob over the
resolved path (`RuleSet::find`, `find_path`). Any other action's pattern is
conditions on its arguments (`nerve_policy::conditions`, #152 C1):
`lamp.set:room=office,brightness<=50`. `decide::Call.args` holds the
arguments as checked against the action's schema, and a path argument
(`x-nerve-path`) is read from the call's targets, as resolved, by the argument
it came in (`Target.arg`, which a link's place keeps), so a deny rule
`notes.open:path~~/private/*` covers a provider's path as `fs:~/private/*`
covers a file call's (`~/` the owner's home, without case on Windows). A
condition the call cannot meet or fail (the argument left out, `null`, or of
another type) counts for a deny rule and not for an allow rule. The rules are
typed against the published schema when they are written (`rules::check_typed`:
the CLI's `edit_saved`, `SettingsStore::set_center_document`); the center's
checker parses and matches the same conditions (`checker::blocklist`), with
`conditions::PathStyle::AnyHome`.

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
[rules](#the-guard-against-changing-the-node)): three rules
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
also in `GUARD_OLD`; a pairing that still holds them keeps them as deny rules
of its own. The guard itself is built in: `rules::with_guard` puts its rules on
top of every pairing's deny list, and the node stores none of them. A `guard:` rule on the allow list is refused by the config
check. The center's action checker has its own splitter
(`checker/normalize.rs`); it is meant to move onto this parser.

## Modes

- **`allowlist`.** Default deny. Only allow rules count.
- **`folder`.** The folders' flags decide. Reads need `r`, writes need `w`,
  commands need `x` on their working directory. The deepest folder that holds
  a path decides. Commands are confined where the platform can confine them.
  Where the node reads as the command account (`Reads::Account`, below), a
  read in no folder at all goes where every account may read.
- **`user`.** Everything the user could do, protected paths aside. Commands are
  not confined.

`folder` and `user` mode give full access in their area, and deny rules narrow
it. Allow rules are not looked at there.

Every capability is decided by its effect, the node's own and what a
[capability provider](spec/node-local.md#7-capability-providers) adds alike.
An action names paths by marking arguments in its schema (`x-nerve-path`,
`nerve_proto::schema::path_args`); the node resolves them into `Target`s. An
action that names no path lies in no folder: `folder` mode allows it only
where the owner set it `on`, whatever its effect, and so is a write whose only
paths are ones it reads (`decide` asks the table as for no path then, and the
descriptor offers it so). Every `fs` action names its path, so a read with no
path is a program's, which the node cannot hold: an argument the program does
not mark is no path to the node, and the program reads with the owner's
rights.

A path handed to a capability other than `fs` and not a command (a
provider's) counts with what lies below it, since the program may read or
write there; `fs` walks skip such places themselves (`works_below`). Only a
path that may hold others counts so (`Target::holds`): the node sets it from
what is there as it resolves the path, a folder, or for a write a path that
does not exist yet; a file is judged by itself alone, so `notes.open:path~**/.env`
refuses no file handed to `notes.open` but a `.env`. Such a path is refused when a node-own folder lies below it (with the own-folder
check, first), when a deny rule of its action may match below it (step 5,
`RuleSet::find_below`: its `=` or `~` condition on that argument starts, up to
its first wildcard, below the path, or the path lies below that text and a
wildcard follows, and its other conditions may hold), when a
protected entry below it is not released for its access
(`Protected::entry_below`), or in `folder` mode when a folder below it lacks
the flag (`closed_below`). A program's `execute` action runs there, so for it
the entry below and the path itself need a release with `x` as well
(`entry_below_run`, `check_run`), and a folder below needs `x`. These refusals do not name what lies
below: the agent is shown no closed folder, no extra protected path and no
deny rule. A program follows links, so once `decide` allows such a call the
node walks the path (`nerve_node::fs::links_below`, as the command account,
bounded, off the link's threads) and `LinkCheck` judges each link when it is
found: a link that leads within the path it lies below, or within the
folder it was found in (`Link::found_in`, a folder a link that passed leads
to), is covered by the checks below that path or folder; any other decides the call again with the place it
leads to in the stead of that path (the call's other paths unchanged, the
rules compiled once for all links). A refusal there refuses the call and
names the link, not where it leads, and a folder a refused link leads to is
not walked. A folder the walk may not list, or an entry in one whose type
it cannot tell, is left out where the program runs as the walking account
(it could not look there either), and refuses the call where it runs as
another (`fs::Closed`, picked by `nerve_node::link::closed_for`): on the
installed node the walk runs as `nerve-run` and the program as the owner or
root, which could follow a link there. For a program's paths the link
decides by the folders the owner granted alone: `nerve-run`'s own folders
(the pairing's own home and temporary folder, `/tmp`, `/var/tmp`) count as none, since the program works with
its own account's rights, not the command account's. The
tool-config check (writes to `.git`, `.envrc`, `.vscode`, `.idea`) looks at
the path itself only, since a program may make those anywhere below a folder
it writes in.

### The effect table

What each mode lets an action do depends only on its effect and on whether it
names paths. One function holds this table, `nerve_policy::effect_rule(mode,
effect, paths, setting)`. Step 6 of `decide` follows it, and the descriptor
offers an action by it, so the two cannot drift apart. One thing lies outside
the table: on a machine that cannot confine a command, `folder` mode with an
empty sudo allow list offers no `exec` action, so `exec.signal` set to `on` is
not shown there, though `decide` would allow a call of it. No command can run
there, so there is nothing to signal.

| Effect | `allowlist` | `folder` | `user` |
|---|---|---|---|
| `read` with paths | an allow rule | every path in a folder with the matching flag (a path it reads: see `Reads` below) | allowed |
| `write`, `execute` with paths | an allow rule | every path in a folder with the matching flag (a command's working directory in one with `x`; another execute call's paths also in one with `x`) | allowed |
| `read`, `write`, `execute` without a path | an allow rule | `on` | allowed |
| `sense`, `actuate` | an allow rule | `on`, and every path in a folder with the matching flag | `on` |

- `paths` is `PathArgs::None` for an action with no path, no working directory
  and no command, else `PathArgs::Some { all_in_folders }`.
- The answer is a `Need`: `Allowed`; `AllowRule`, when the allow rules decide;
  `InFolders`, when a path lies outside the folders; `NeedsOn`, when only
  the owner's `on` allows it and it is not set; or `Off`, when the action is
  set to `off` or `hidden`.
- `on` turns `NeedsOn` into `Allowed` and changes no other cell. It never
  widens what the folders refuse. `off` and `hidden` turn every cell into
  `Off`.
- Around the table, `off` and `hidden` (step 3, before the table is asked),
  deny rules (step 5) and protected paths (step 7) win as before. A sudo command goes by the sudo list
  instead. In `folder` mode a command also needs confinement.
- `Env::reads` says what holds a read in `folder` mode. `Reads::Folders`: a
  path read needs an `r` folder. `Reads::Account(may_read)`: the node reads
  as the command account (the installed Linux node, `nerve-run`). Inside
  the folders the deepest one still decides by `r`, so a folder the owner
  closed stays closed. A `Read` target of a read call that lies in no
  folder counts as in them, and `decide` then asks `may_read` of it, which
  gives the refusal's reason. The node answers it as that account, under
  `act_as`: the path must be open to every account by its mode bits
  (`fs::open_to_all`: `o+x` on each folder above it, `o+r` on it), so the
  ACL entries the node put on for the folders (another pairing's grants, the
  pass-through on the owner's folders above a grant) reach no further than
  those folders, and it must be a file or a folder that opens (`fs::readable`,
  which asks what it is through an `O_PATH` handle first and opens only a file
  or a folder, through that handle: opening a device or a FIFO has effects of
  its own). The node's own process
  under `/proc` is refused first (`fs::own_process`): its files there are
  `0444`, and the kernel lets the node's threads read them whatever fsuid
  they switched to. `fs::may_read_outside` holds these checks. For a provider, which
  reads with the owner's rights, it must also be no folder, as the provider
  would read below it. A write or execute call that reads a path still needs
  `r` there. The link picks `Account` where the account was found and
  `Shared::separate` holds; the walk of `grep`, `find` and `list` asks
  `read_reach` of each entry with `fs::open_to_all` and `fs::own_process`, as
  the gate does, and the descriptor's `access` block says `reads_by_account`.

Each path of a call is a `Target` with an access: `Read` needs `r`, `Write`
needs `w`, and `Run` needs `x`. `Run` is the working directory of `exec.run`.
The same access picks the protected check: a `Run` target is released only by
a folder with `x`. A command's working directory is held to `x` whatever
access its call gives that path.

For the descriptor, `fs`, `exec.run` and any action whose schema marks a
path ask the table with `all_in_folders: true`, since they name their paths
per call: they are offered where a call with its paths in the folders would
be allowed. A provider's action that marks no path asks with
`PathArgs::None`. `node`, `settings` and `audit` are not governed by the
policy and are always offered. The test
`what_is_offered_follows_the_effect_table` (nerve-node `descriptor.rs`) runs
every mode, effect, setting, allow rule and confinement, and a provider's
action with a read or a write path, against `decide`.

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
  finishes, the place counts as written by those flags too, and a refused change whose place
  may give flags other than the wanted ones is stale. Taking a grant off goes into every
  folder all the same, since Windows' own walk, which earlier versions
  used, writes a folder before what is below it. A link or junction gets
  the change on its own list and is not followed. An error names the
  object it is about. A change that takes long tells how far it is
  (`grants::paced`: after 3 s, then every 15 s, and how it ended), on stderr
  in the CLI and in the log of a running node.
- The running node walks a granted folder again by itself once names in it
  changed (`grant_watch`): a file a change never reaches keeps its list, and
  an install or a clone links files in with their store's list, so commands
  could not read what the owner installed, nor the owner what a command
  installed from its own store, until a walk. Each folder the record holds a
  grant with flags on (`grants::granted_folders`) gets one handle, opened as
  the owner on the service, not through a link, not on a removable drive (a
  held handle keeps it from being ejected) or another machine, and read with
  `ReadDirectoryChangesW` over its subtree, overlapped, on one completion
  port and one thread, into a buffer of its own (64 KiB). It asks for names
  only (`FILE_NOTIFY_CHANGE_FILE_NAME | DIR_NAME`), never security, so the
  walk's own writes do not wake it; a name added or renamed to marks the
  folder (`Pending`, one entry per folder), and so does a notification that
  ran over or a read that failed (the folder went). The supervisor takes the
  folders quiet for 3 s, or waiting 30 s (`QUIET`, `AT_MOST`), the outermost
  of nested ones, and hands them to the grant sync (`Shared::sync_grants_walking`,
  `grants::Rewalk::At`), which marks their grants unfinished inside its turn
  (`mark_walks`, as `folder sync` does for every grant) and so walks each into
  every folder below it, after any change of the config before it. The first
  sync after the start walks every grant (`Rewalk::Every`), as on Linux. The
  watches follow the record before and after each sync; a folder that cannot
  be watched is logged once and left to the other syncs while it stays
  granted. On Linux a new file gets its entries from the default ACL and a
  file with a second name keeps its own rights, so nothing waits for a walk.
- A record in the state folder (`grants.json`) finds them again. It holds the
  file ID of each grant's object, since the grant is in that object's own
  access list and goes with it: a grant on a moved or renamed folder comes off
  where the folder is now. A sync checks that each wanted grant is still on,
  and puts it on again on a folder made anew. A lock file
  (`grants.json.lock`) keeps the CLI and a running node from writing over each
  other's record, and a grant is recorded before it goes on.
- `w` reads too and gives `DELETE` and `FILE_DELETE_CHILD`, and a granted
  folder's or file's own entry has no `DELETE` (`nerve_sandbox::acl`).
  Windows grants a move by `DELETE`, and a moved object keeps its own list
  until a change on its new folder passes that folder's entries down. So a
  command moves only what it reads and writes, and a granted folder only
  out of another one it reads and writes. A move alone makes nothing
  readable that was not. A hard link is the gap: a file has one list for
  all its names, so a change the node passes down a folder (a grant put on,
  changed or taken off, also where a moved folder is now) reaches a file a
  command linked there, and Windows works its list out under the folder of
  the name the walk came through. So the walk (`inherit::pass_down`) asks
  about each file with more than one name it reaches, also one whose list it
  would leave as it is (`Walk::links`), by the names its handle gives
  (`NtQueryInformationFile` with the hard-link classes, each name's folder
  opened by its file ID, as the command account where the thread may not: a
  command's own store below its profile; a name whose folder neither may
  open is left out), not by its path. The file itself is opened as the
  command account too where the thread may not look at it: one a command
  linked from its own store keeps the store's list under every name. `grants::Judge::verdict` gives:
  - `Linked::Full` where all names are listed, lie inside the changed
    folder (resolved), are held by exactly the same wanted and recorded
    grant paths of any container, and none is shut (below): every name gets
    the same from the grants, so the file changes as any file, and the
    node's own entries of an earlier cap go (`acl::uncapped`). That compares
    grant paths, while a grant's entry goes with its folder, so a sync in
    which a recorded grant is not at its path (moved, or it cannot be told)
    gives no `Full` at all. A command that may make a folder there sets its
    security descriptor at creation, without `WRITE_DAC`, and the change
    passes an entry of its own there (read for its container) down to a
    file it linked into that folder; every container that may write there
    may read too (`w` reads), so that entry gives nothing new while the
    grant is on.
  - Otherwise `Linked::Capped`, for every container of the wanted and
    recorded grants and the command account (`Judge::cap`): `Gets::Closed`
    where a name lies under a closed grant of it that no grant inside
    reopens (a wanted one, or a recorded one a command moved,
    `Grant::closed_at`), or where its pairing's `grants::Shut` closes it (a
    protected entry its folders do not release for a read, the node's own
    folders, a folder without flags, which inside a split folder has no
    grant); `Gets::Rights(cap)` where a grant of it holds a name, `cap`
    being `acl::READ_AND_EXECUTE` cut to what each name's covering grants
    give (`acl::file_cap`), counting only those inside the deepest closed
    grant that holds the name, as Windows puts that folder's denial before
    the entries of the grants around it (a split folder gives a closed
    folder in it no grant, but none of the split's grants lies around it);
    a name in the container's own folder (its `AC` folder, where its
    commands' pnpm store and uv cache are) or, for the command account, in
    that account's profile counts as held, without restricting
    (`Shut::own`), where the file's owner is the command account (one its
    commands made: no grant gives `WRITE_OWNER`, so a file of the owner's
    a command linked there keeps the owner's SID), so a container keeps
    read on its own store's files once no grant holds their other name,
    and not on the owner's file it linked into its folder. Only on the
    installed service, where the commands run as `nerve-run`; on a node run
    by hand nothing holds. The profile is compared where it resolves, the
    `AC` folder as written below it, since a command may make that a link;
    `Gets::Unheld` where nothing holds a
    name (a name under no
    grant does not restrict: pnpm's store, uv's cache and a clone's source
    are read through the granted name). `acl::capped` cuts every allowing
    entry of an `S-1-15-…` SID to read and execute (a listed one's to its
    cap) and works the node's own entries out anew from the grants alone,
    not from the list: an allow of the cap and a denial of every other
    right for `Rights`, a denial of all for `Closed`, none for `Unheld`. So
    the list does not hang on which name's folder the walk came through (two
    pairings on one store both read it), and the denial, first in the list,
    survives Explorer or `icacls` passing a folder's entries down; the next
    walk that reaches the file (`folder sync` walks every grant) puts the
    cap back. The cap works from the list the file has, not from the list
    the folder walked would give it: the file keeps what it inherited under
    its other names (the owner's store, cache or repository) and gets none
    of the walked folder's entries for other accounts, while the container's
    inherited entries go with the rest of the node's own. Where the walk
    had to open the file as the command account (a command's own store's
    list names only that account, its container and the system), the
    account the walk acts as, the owner, gets an allowing entry of read and
    execute (`acl::readable_by`), as on Linux, where the owner reads such a
    file by its mode. It goes after the other explicit entries and before
    the node's allows, where `acl::capped` keeps it on the next walk (which
    may look at the file then), so that walk changes nothing. A change as any
    file (`Linked::Full`) is the only one worked out under the folder.

  This rests on Windows letting a sandboxed process link only a file it may
  write (it asks for `FILE_WRITE_ATTRIBUTES`; probed), which read and
  execute does not hold. A grant put directly on a file with a second name
  is refused where commands may write around it (`not_own`); elsewhere (an
  entry of a split folder, a list that does not inherit) it gets the cap in
  place of its own entry, which `look` counts as granted
  (`acl::capped_within`). Not judged again: a file that lost its other
  names keeps the node's entries; a folder whose inheritance the owner
  turned off by hand counts as any folder (only a closed one closes). Only an
  error marked `acl::Untouched` (refused before a write, nothing at the
  path) counts as a change that changed nothing; every error from inside
  the walk is of kind `Other`, so the grant stays recorded and marked
  `unfinished`. What stays, here and in general: entries a command put on what it
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
  told apart from the owner's and stay a documented limit. A link a
  command makes while the walk runs is judged as the walk gets to it, by
  the names its handle gives then. Inside a folder with `w` a
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
[modes](windows.md#what-the-appcontainer-does-not-stop)):

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
  the container, whatever the folders say (`exec.run`: `folder` is false for
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

The descriptor follows the same policy ([capabilities](capabilities.md)),
through the same [effect table](#the-effect-table). `list` offers only an
action a call could get through.

The descriptor also says what the policy lets this center do now
([spec/protocol.md](spec/protocol.md) §6.2): the mode in force and when it
ends, the account its commands run as, and in folder mode whether a read
in no folder goes where every account may read (`reads_by_account`) and the folders
with their flags, the built-in ones of `nerve-run` among them and marked
`own`.
A folder with no flag is not named; the deepest named folder around it
is marked `closed_below`, as it closes what lies below it (the deepest
folder decides). A command on the sudo allow list is decided by that list
alone, so in folder mode the block says when the list names commands
while the sudo switch is on and `exec.run` is neither hidden nor off for
that center (`sudo`). It is built from
that center's pairing alone. It describes the policy; it decides nothing, and
every call is still decided as above.

## Modes and folders, as the owner sets them

Every pairing has a mode. It sets how much that center may do on the machine.

| Mode | What is allowed | Commands on the installed Linux node |
|---|---|---|
| `allowlist` | Only what an [allow rule](#rules-as-the-owner-writes-them) names | As `nerve-run`, held to the folders you grant; or as you, if you say so (as root where [root is the owner](service.md#root-as-the-owner)) |
| `folder` (default for a new pairing) | Writing and commands inside the folders you grant, by their rights; reading there too, and on the installed Linux node also what every account on the machine may read ([below](#what-each-mode-allows)) | As `nerve-run`, held to those folders |
| `user` | Everything you could do yourself | As you, not confined (as root where [root is the owner](service.md#root-as-the-owner)) |

From most to least locked down: `allowlist`, `folder`, `user`. On the node
[installed as a service](service.md#the-node-as-a-service) on Linux, `folder` and `allowlist` mode
run commands as `nerve-run`, an account of its own
([below](sandbox-linux.md#the-account-nerve-run)). A node you run yourself, and
Windows, run every command as the account that runs the node.

[Deny rules](#deny-a-command) and [protected paths](#protected-paths-as-the-owner-sees-them)
apply in every mode. A call that nothing allows is refused at once. Nothing
waits for an answer.

### What each mode allows

A mode allows the same for every capability, the node's own (`fs`, `exec`),
those a [program adds](capabilities.md#capability-providers-in-use) and [your own in
`node.toml`](capabilities.md#capabilities-of-your-own-in-nodetoml), by what the capability does (its
effect, which `list` shows the agent):

| Effect | `allowlist` | `folder` | `user` |
|---|---|---|---|
| `read` | an allow rule | allowed; each path it reads needs an `r` folder, or on the installed Linux node, outside every folder, one open to every account ([below](sandbox-linux.md#reading-in-folder-mode)); with no path, only where you set it `on` | allowed |
| `write` | an allow rule | each path it writes in a `w` folder (and each it reads in an `r` one); with no path, only where you set it `on` | allowed |
| `execute` | an allow rule | `exec.run`: its working directory in an `x` folder. Another capability: each of its paths in a folder with `x` and the flag for what it does there; with no path, only where you set it `on` | allowed |
| `sense`, `actuate` | an allow rule | only where you set it `on`, and each of its paths in the folders as above | only where you set it `on` |

`on` (`nerve-node cap set lamp on`) never lets a call out of the folders: it
allows only what names no path, and sensing and acting on the world, whose
paths stay in the folders too. A write whose only paths are ones it reads
names no place it writes, so it counts as a write with no path. Deny rules,
`off`, `hidden`, [protected paths](#protected-paths-as-the-owner-sees-them) and the node's own
files win in every mode, for the paths a capability names.

A capability names its paths by marking them in its schema
(`x-nerve-path`): `fs` marks its `path`, `exec.run` its `cwd`, and a program's
capability the arguments it reads or writes. Those paths count as an `fs`
call's do: the folders, the [rules](#rule-syntax), protected paths and
the node's own files judge them, and the [audit log](logging.md#the-audit-log-as-the-owner-reads-it) names them. A
folder handed to a program counts with everything below it, since the program
may read or write there: it is refused when a protected path, the node's own
files, a place a deny rule of that capability names or, in `folder` mode, a
folder you gave less lies below it, and when a link below it leads where the
call may not go. The node sees only the paths a program
marks: an argument it does not mark is not a path to the node, so a program's
action that marks none (it may still read files where it likes, with your
rights) needs `on` in `folder` mode, whatever it does. A program that reads or
writes files should mark its path arguments; switch an action `off` that takes
a path without the marker.

### Set the mode

```sh
nerve-node mode allowlist
nerve-node mode folder
nerve-node mode user
```

`folder` and `user` stay until you change them. To set a time limit, add
`--for` with hours. When it ends, a timed `user` goes back to the mode before
it (`folder` or `allowlist`, never `user`), a timed `folder` to `allowlist`.
`nerve-node mode` and `status` say where it ends.

```sh
nerve-node mode user --for 2
```

`--for` needs at least 1 and does not go with `allowlist`. Setting a mode
again without `--for` removes an earlier limit.

`allowlist` mode runs the allowed commands as `nerve-run`. To run them as
you instead, outside the folders' sandbox:

```sh
nerve-node mode allowlist --as-owner
```

Setting the mode again without `--as-owner` goes back to `nerve-run`.

### Folders and rights

A folder gives rights. Each right is its own flag:

| Flag | Allows |
|---|---|
| `r` | Read: `fs` stat, list, read, grep, find, and the paths another capability reads |
| `w` | Write files: `fs.write`, and the paths another capability writes |
| `x` | Run commands whose working directory is in the folder, and capabilities that run something at their paths |

The flags do not imply each other. A write needs `w` and not `r`. A read needs
`r` and not `w`. A command needs `x` and not `r`. A folder covers everything
below it. Where folders nest, the deepest one decides.

Folders count in `folder` mode. In `allowlist` mode as `nerve-run` they are
the sandbox the allowed commands run in; the allow rules decide what runs.

The agent is told each center's own mode and account, and in `folder` mode
whether it may read outside the folders what every account may read, and its folders with their
flags (the built-in ones of `nerve-run` among them,
marked as its own; a folder left without rights is not named, and the
granted folder around it is marked as having folders below it that allow
less; where the machine runs no `folder` mode command, no folder is shown
with `x`, and where your sudo list for that center names commands while
the node's [sudo switch](#sudo-as-the-owner-uses-it) is on and `exec.run` is neither hidden
nor off for that center, the agent is told that those run
by that list alone, in any folder and outside the sandbox): `list` shows
them
([harness](mcp-surface.md#the-tools-the-model-gets)). Every center is told this
of its own pairing, with the [settings grant](settings-and-config.md#the-settings-grant) or without.
A change of the folders, the mode or the account reaches the center at once.
Another center's folders are never shown. In `allowlist` mode the folders
are not shown, though they still hold the commands that run as `nerve-run`.

The folders of `nerve-run` marked as its own are, for each pairing whose
commands run as `nerve-run`, a home and a temporary folder of that pairing
alone (`/var/lib/nerve-run/<center>/home` and `…/tmp`, where `HOME`, the
`XDG_*` folders and `TMPDIR` of its commands point), and `/tmp` and
`/var/tmp`, marked `shared` as well: every pairing and every account on the
machine shares those two. With Landlock a command reaches the files of its
own pairing's home and temporary folder and no other pairing's (a socket
that a program listens on there is the exception, see
[what it does not stop](sandbox-linux.md#what-it-does-not-stop-linux)), so the settings and
caches its programs keep in its home are its own: what another center's
agent leaves in its own home cannot steer this one's `git status` or `npm
test`. What it leaves in `/tmp` or `/var/tmp` can, for programs that look
there by themselves; the agent is told to keep nothing secret there and to
change no program's settings there unless asked. Without Landlock the
folders are closed (0700) to other accounts, but every pairing's commands
run as the one account `nerve-run`, so nothing keeps one pairing out of
another's home: a center you trust less then needs a machine of its own.
A folder you give a center that holds `nerve-run`'s home (`/`, `/var`,
`/var/lib`) is cut around it: it gives that center no other pairing's home
or temporary folder, in its commands and in its file calls, and a folder you
give inside that home gives nothing. In every mode, also `allowlist`, a
file call or a program's action that names a path in another pairing's
folders is refused whatever the folders and the allow rules say, and so is
a program's action on a folder with a link in it that leads there: the node
opens such a path as `nerve-run`, which owns them all, and a program follows
links. `list`, `find`, `grep` and `stat` open each folder on their way
without following a link, so a folder that a command swaps for a link while
they run is left out, not followed. On a kernel below Landlock ABI
3 a command of another pairing can still cut a file in these folders to
nothing (see [Landlock versions](sandbox-linux.md#landlock-versions)). A pairing made again under the name of
one that went waits for the node to delete the old folders before its
commands and file calls run; where that cannot be done they say why.
Even with Landlock the pairings share more than `/tmp`: see [the account
`nerve-run`](sandbox-linux.md#the-account-nerve-run) for what it does not keep apart.
Not `--as-owner` either: that runs the allowed commands as you (as root
where root is the owner), outside the sandbox, so they reach all your
folders and credentials.

| Command | Does |
|---|---|
| `nerve-node folder add ~/proj rwx` | Add a folder, with its rights as one word (`r`, `rw`, `rx`, `rwx`) |
| `nerve-node folder add ~/proj rx` | Change the rights of a folder it has |
| `nerve-node folder add ~/proj/secret none` | Close a folder inside one it has |
| `nerve-node folder rm ~/proj` | Remove the folder |
| `nerve-node folder` | List folders and rights |

`folder add` on a path that is listed already replaces its rights. `none`
leaves a folder with no rights in the list. `folder rm` removes it. Inside a granted folder, a folder with no
rights closes what lies below it to file calls and to commands that start
there, but a command started in the folder around it still reaches it: the
sandbox is built from the folders that grant something.

### `user` mode

`user` mode allows everything you could do yourself, except
[protected paths](#protected-paths-as-the-owner-sees-them). Commands run as your user, without
confinement. A command can do what you can do, including changing the node's
own state. Use it only for a center you would trust with a shell.

On a node [installed as a service](service.md#the-node-as-a-service) the node runs as its own
user, `nerve`, and, unless root is the owner (below), `user` mode commands run as you, the owner, the account
that ran `install`. They can do what you can do. They cannot read the node's
keys, which are `nerve`'s, but they can change the node's settings as you
can without a password, through the owner socket (on Windows the owners'
pipe), as your own programs do. The node does not stop that: it is your
choice of mode. The center's [blocklist and action checker](action-checker.md#the-checker-as-the-owner-sets-it-up)
and the node's [guard](#the-guard-against-changing-the-node) catch
such a command when an agent tries it by mistake, and the node refuses a
process it sees below one of its commands, but none of that is a boundary.
The same holds for `allowlist` mode with `--as-owner`. The node's
[web UI](web-uis.md#the-nodes-web-ui), when you turn it on, adds no way for such a command:
it reaches only the login, and a token is what lets one in; a command as
`nerve-run` is closed before it can try one. The same holds for the center's
[web UI](web-uis.md#the-centers-web-ui) on a machine that also runs a node: a command reaches its
login, which asks for the owner token. That token is in the center's state
folder, which a `nerve-run` command cannot read; a `user` mode command runs
as you and can, when the center runs as you too (a center the harness
starts). A harness token, which the agent may read in its harness's
settings, does not log in.

Where root is the owner (an install that root ran itself and confirmed,
[service](service.md#root-as-the-owner)), `user` mode and `allowlist` mode
with `--as-owner` run commands as root. They can do everything on the
machine, read the node's keys and change the node itself. Nothing in Nerve
holds them back: the guard, the action checker and the refusal of the owner
socket only catch mistakes, and root needs none of them to get in. It is
your choice, as root, when you answer yes at `install`. `folder` mode and
`allowlist` mode without `--as-owner` still run as `nerve-run`. A center with
the [settings grant](settings-and-config.md#the-settings-grant) can switch itself to `user` mode,
and so to root.

### Which mode

| You want | Use |
|---|---|
| The agent may run a few known commands | `allowlist` with [rules](#rules-as-the-owner-writes-them) |
| The agent works freely in a project folder | `folder` (the default) with one folder `rwx` |
| The agent acts as you | `user`, maybe with `--for` |

## Rules, as the owner writes them

Rules say which calls are allowed and which are refused. Each pairing has
three lists.

| List | Counts in | Does |
|---|---|---|
| `allow` | `allowlist` mode only | A matching call may run |
| `deny` | every mode | A matching call is refused. A deny rule beats every other rule and mode |
| `sudo` | every mode, while [sudo](#sudo-as-the-owner-uses-it) is on | A matching `sudo` command may run |

In `folder` and `user` mode, allow rules do nothing. The mode decides.

The commands below are the CLI's, on Linux. On Windows the
[desktop app](desktop.md)'s **Permissions** page adds, edits and removes the
rules (**Allowed commands**, **Forbidden commands**, the sudo list); the
guard is built in.

### Allow a command

```sh
nerve-node rule add allow 'git status'
nerve-node rule add allow 'git status *'
```

The first allows that exact command line. The second allows `git status` with
anything after it: a trailing ` *` is the wildcard, and `rule add` says what it
covers. A rule applies to one command line, so `git status` does not allow
`git status --short`. `'rm *'` allows every `rm` command, not the files of a
folder.

### Deny a command

```sh
nerve-node rule add deny 'rm *'
nerve-node rule add deny 'git push origin main'
```

A deny rule matches the whole command line. It does not see `rm` inside
`x; rm …`, in `/bin/rm`, in a script, or in another program that deletes
files. In `folder` and `user` mode it guards against mistakes. It is not a
sandbox. (The guard's own rules read each command of a line; see below.)

### The guard against changing the node

Every pairing has built-in deny rules that keep its commands off this node
itself. `rule` shows them as one line, `guard: 8 rules, built in`; they
cannot be removed or edited, and the node keeps them current.

| Rule | Refuses |
|---|---|
| `guard:node-programs` | A command that runs `nerve-node` or `nerve-node-desktop`, by its name or a path, `.exe` too; and one that copies, moves, links, deletes or overwrites their files (`cp`, `mv`, `rm`, `install`, `ln`, `Remove-Item`, `del`, a redirection onto the file, `tee`, `dd`, `sed`, `chmod`, `curl -o`, `wget -O`, `Invoke-WebRequest -OutFile`, `Start-BitsTransfer`, `certutil`, `Set-Content`, `Clear-Content`, `Out-File`, `gzip`, `upx`, `objcopy` …), since replacing the program changes the node. The path may stand in a brace group in `sh` and fish (`mv nerve-node{,.bak}`), and may come through a pipe into the tools that take paths (`echo /usr/local/bin/nerve-node \| xargs rm`, `Get-Item …\nerve-node.exe \| Remove-Item`, `(Get-Item …\nerve-node.exe) \| Remove-Item`, `… \| Clear-Content`; not into a writer such as `tee`). Only the listed programs count, so another program or a .NET call that writes the file is not seen |
| `guard:node-paths` | A command that names the node's socket or pipes or its config and state folders (`/run/nerve-node`, `/etc/nerve`, `/var/lib/nerve`, `~/.config/nerve`, `~/.local/state/nerve`, `%ProgramData%\Nerve`) |
| `guard:node-service` | A command that stops, restarts, disables or kills the node's service or process, as the node's own `service stop` would. On Windows also `reg add`, `delete`, `copy` and `restore` and PowerShell's item cmdlets on the node's service key, its Event Log source, and the keys that start a program at sign-in or boot (the `Run` and `RunOnce` keys, `Policies\Explorer\Run`, `Winlogon`, `Image File Execution Options`, the task scheduler's `TaskCache`, of the machine and of a user, the 32-bit view too), and `sc create`, `sc config … binPath=`, `New-Service`, `schtasks /create` and `/change`, `Register-ScheduledTask`, `Set-ScheduledTask` and `Register-ScheduledJob`, where a command would start again outside the node's hold. Not covered: a service or a task made by writing the registry or the `System32\Tasks` folder, the Startup folder, WMI |
| `fs.write:…` (five rules) | A write into those folders |

`nerve-node ui …` is such a command too, so a center's command cannot turn
on the [web UI](web-uis.md#the-nodes-web-ui) or make a token for it. Its port is not a
rule's matter: the node closes a connection from a command's account itself
([who can reach it](web-uis.md#who-can-reach-it)).

The three `guard:` rules read the command line as the node's shell does
(`/bin/sh` or `machine.shell` on Linux, PowerShell or cmd on Windows) and
look at each command in it. The whole line is refused when any one of them
is a guarded command:

- in a list or a pipe: after `;`, `&&`, `||`, `&`, `|` or a line break, with
  any indent;
- in a group or block: `{ … }`, `( … )`, `(( … ))`, `if`, `for`, `while`,
  `case` (also inside another block), a function, PowerShell's `{ … }` and
  `( … )`. The words of an array (`a=(x y)`) or of a regular expression in
  `[[ … ]]` are data; a substitution in them runs;
- in a substitution: `$( … )` and backticks, also inside double quotes;
- in the text a shell runs: `sh -c`, `bash -c`, `su -c`, `runuser -c`, `eval`,
  `powershell -Command`, `cmd /c`, `Invoke-Expression`, and a here-document
  or here-string fed to a shell (`bash`, also with `-s` and arguments, `su`,
  `sudo -s`, `sudo -i`);
- behind a program that runs another: `sudo` (with its options), `env`,
  `runuser -u`,
  `timeout`, `nohup`, `nice`, `ionice`, `time`, `stdbuf`, `xargs`, `exec`, a
  path to the program, and on Windows `&`, `Start-Process` and cmd's `start`,
  `@`, `if`, `for … do` and the command in `for /f … in ('…')`. A file name or a string in the brackets of `for /f` is read as words, so a path to the node's folders in it is still refused.

fish is read as a shell of its own: its `( … )` is a command substitution
(`echo (nerve-node status)` is refused) and `and`, `or` and `not` start a
command, in a `fish -c` text and when `machine.shell` is fish. In PowerShell
a quoted string that starts a statement is a value
(`'nerve-node' | Set-Content x.txt` runs), unless `&`, `.` or
`Start-Process` runs it.

The text a shell runs is read by that shell's rules, not the line's: the
`& nerve-node` in `powershell -Command "& nerve-node"` is PowerShell's call
operator even in a line for `sh`, and `start /b nerve-node` in a `cmd /c` text
is cmd's.

So `env X=1 sudo systemctl stop nerve-node`, `timeout 30 sudo systemctl
restart nerve-node`, `bash -c 'pkill nerve-node'` and
`powershell -Command "Stop-Service nerve-node"` (or `/c`, as PowerShell
takes `/` before its switches too) are refused. cmd's `/c` text is read as cmd reads it from the line, also in the form with doubled quotes that a program path with a blank needs
(`cmd /s /c ""C:\Program Files\Nerve\nerve-node-desktop.exe" status"`), and the argument string of `Start-Process cmd`. A word of
another program is data, so a line that only mentions the node runs:
`git commit -m "refuse systemctl stop nerve-node"`, `echo`, `grep`, a
here-document written to a file. The name alone is not refused either:
`cargo build -p nerve-node`, `journalctl -u nerve-node`,
`ls -l /usr/local/bin/nerve-node`. A path in a sentence (a blank before it in
the same word) is data too. For the same reason a script text handed to
another program is seen only when no blank comes before the path in its word
(`python3 -c "print(open('/etc/nerve/node.toml').read())"` is refused,
`python3 -c "import os; print(open('/etc/nerve/node.toml').read())"` runs),
and a folder name with a blank in it (`"/home/john smith/.config/nerve"`) is
not seen: both are a program that another program runs, listed below.

| | Refused | Still runs |
|---|---|---|
| Linux | `systemctl stop`, `restart`, `try-restart`, `reload-or-restart`, `try-reload-or-restart` (and `force-reload`, `condrestart`, `condstop`, `condreload`, `reload-or-try-restart`), `freeze`, `disable`, `kill` or `mask` on `nerve-node` (or `nerve-node.service`); `service nerve-node stop`, `restart`, `try-restart`, `force-reload` or `condrestart`; `pkill` or `killall` on `nerve-node` or `nerve-node-desktop`, with flags such as `-9`, `-f` or `-x`, also as one alternative of the pattern (`pkill -f 'nerve-node\|nerve-center'`, `pkill -f 'target/debug/(nerve-node\|nerve-center)'`); `kill` with what `pidof` or `pgrep` finds in a substitution, or a pipe that goes straight into `kill` or `xargs kill` (`kill $(pidof nerve-node)`, `pgrep nerve-node \| xargs kill`) | `systemctl status`, `is-active`, `show`, `cat` on it, `service nerve-node status`, `journalctl -u nerve-node`, `pgrep`, `ps`, `pkill -f "cargo run -p nerve-node"` (another program) |
| Windows | `sc stop`, `config` or `delete`; `net stop`; `Stop-Service`, `Restart-Service`, `Set-Service` or `Remove-Service`; `Stop-Process` and `taskkill` with `nerve-node.exe` or `nerve-node-desktop.exe`, or with what `Get-Process` finds (`Stop-Process -Id (Get-Process nerve-node).Id`); `Get-Service` or `Get-Process` on the node piped into one of the cmdlets (also with the `\|` at the start of the next line); `reg add`, `delete`, `copy` or `restore` on the service's key or a key below it (`…\Services\nerve-node`, `…\nerve-node\Parameters`, which holds the node's owners), and PowerShell's `Set-ItemProperty`, `New-ItemProperty`, `Remove-ItemProperty`, `Remove-Item` (`rm`, `del`), `Clear-Item`, `Rename-Item`, `Move-Item` and their kin on them (a folder `C:\Services\nerve-node` is a folder, not that key); the service by its display name too (`net stop "Nerve node"`, `Stop-Service -DisplayName 'Nerve node'`) | `sc query`, `sc qc`, `Get-Service nerve-node`, `Get-Process nerve-node` |

The Windows commands and program names match in any case (`STOP-SERVICE`,
`NET STOP`, `sc stop Nerve-Node`, `taskkill /IM NERVE-NODE.EXE`), as Windows
reads them, and `\` separates a path there.

A line the guard cannot read with confidence (a quote or bracket left open,
a line nested deeper than 16 levels, a command wrapped in more than 256
wrappers, a shell that reads its script from a pipe such as `curl … | sh`,
PowerShell's `-EncodedCommand`, a substitution inside `${ … }`) is checked
twice: the commands read before the place that gave out are checked like any
others (so `env X=1 sudo systemctl stop nerve-node; curl … | sh` is refused),
and the whole line is checked with the guard's text patterns from before it
read commands, which look for the commands where a command starts in the
text. Such a line is refused wherever either refuses it. What stands after the
place that gave out is only seen by the text patterns.

What the guard does not see: a name built at run time
(`n=nerve-node; systemctl stop $n`), a program that another program runs
(`cargo run -p nerve-node`, `find … -exec`, `ssh`, a script file, or a
launcher outside the list above such as `systemd-run`, `taskset` or `watch`,
also with the program's path), a name
that reaches `kill` or `systemctl` through a loop or another way than a
straight pipe (`pgrep -f nerve-node | while read p; do kill $p; done`,
`echo nerve-node | xargs systemctl stop`), and `pkill` or `killall` with a
part of the name (`pkill nerve`, which matches the node too), and `reg import` or `regedit` of a file that holds the service's key.

A rule of the guard is written `guard:<name>`, and only these three exist.
The guard is built in: every pairing has its rules on top of its own deny
rules, the node keeps them current, and none can be removed. `rule` shows it
as one line (`guard: 8 rules, built in`). A pairing made before the guard
read commands may still hold its rules as text patterns: they are deny rules
of its own now, beside the guard, and `rule rm` takes them off. Those older
patterns hold tabs and
line breaks: `rule` and the app's rule lists write them as `\t`, `\r` and
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
([service](service.md#the-node-as-a-service)), and the node's own folders, which no rule or mode
opens ([protected paths](#protected-paths-as-the-owner-sees-them)).

### List, change and remove rules

```sh
nerve-node rule            # all three lists
nerve-node rule allow
nerve-node rule edit allow 'exec.run:git status' 'git status --short'
nerve-node rule rm allow 'git status'
nerve-node rule rm 'git status *'
```

`rule edit` changes one entry in its place, as one change in the audit: the
entry as `rule` prints it, then what it becomes. That is an entry in the
same form (`'exec.run:git *'`, `'fs.read:~/notes/*'`), or a plain command
line, which becomes the rule `rule add` makes of it. It works on every list,
but not on the rules of the guard. The desktop app's Permissions page edits a
rule the same way (the pencil beside it).

`rule rm` takes the command line `rule add` was given, or an entry as `rule`
prints it, such as `'exec.run:git *'`. The list is needed only when the entry
is on two lists. When the text could mean two entries on the list, `rule rm`
removes none and tells you the two commands that remove them one after the
other.

### Rules for files and other actions

`rule add` writes command rules and rules on an action's arguments
(`lamp.set:room=office`, see above). It refuses an entry in the other pattern
forms (`fs.read:...`, `fs:...`, and also `exec.run:...` and `exec:...`, the
form `rule` prints), which would never match as a command. Give `rule add` the
bare command (`'git *'`), not that form. (`rule rm` does take it.) For files and
other actions, add the rule to the policy by name. `lab` is the center's name on this machine (see
`nerve-node center`).

```sh
nerve-node config add center.lab.policy.allow 'fs.read:~/notes/*'
nerve-node config add center.lab.policy.deny  'fs:~/private/*'
```

The web UI's [Audit](web-uis.md#audit) page writes the same rules with four
buttons. That needs the [settings grant](settings-and-config.md#the-settings-grant).

`--action` makes the rule such a button makes for an audit entry of that
action: the entry's path, or a folder and all below it as `/srv/data/*`. An
action without a path takes `''`, and covers its capability as `'*'`.
`--arg FIELD=VALUE` holds such a rule to one argument of the call, as the
audit buttons that pin one do (see below). `--exact` takes the entry's text as
it is, a `*` at its end too, as the **Allow** and **Deny** buttons do: an
agent's `rm -rf *` stays that one command.

```sh
nerve-node rule add allow /srv/data/report.txt --action fs.read
nerve-node rule add deny '/srv/data/*' --action fs.write                 # fs.write:/srv/data/*
nerve-node rule add deny '' --action lamp.set --arg room=bedroom          # lamp.set:room=bedroom
```

### Rules on an action's arguments

A rule for any action but the `fs` ones and `exec.run` may name values of
the call's arguments, and a rule for a program's stream the values of its
parameters. Its pattern is one or more conditions, joined by `,`. The rule
covers a call that meets all of them; the other arguments are free.

```sh
nerve-node rule add allow 'lamp.set:room=office,brightness<=50'
nerve-node rule add deny  'lamp.set:room=bedroom'
nerve-node rule add deny  'notes.save:path~~/private/*'
```

| Condition | Meets a call whose argument |
|---|---|
| `room=office` | is `office` (a string, number or boolean: `level=3`, `on=true`) |
| `room!=office` | is not `office` |
| `brightness<=50` | is a number up to 50; also `<`, `>`, `>=` |
| `label~desk*` | is a string the glob matches |

- A field is a top-level argument of the action, as its schema in
  `cap --json` names it. A value is read as that argument's type.
- A `,` in a value is written `\,`, a `\` before it `\\`. The `,` inside a
  glob's `{a,b}` or `[...]` needs none. In the value of `=` and `!=` a `[` or
  `{` is a character like any other.
- An argument the schema marks as a path (`x-nerve-path`) is matched as a
  path, as an `fs` rule matches one: as the node resolved it, `~/` is your
  home, and on Windows case does not count. `path=/srv/a` names that path,
  `path~/srv/*` a folder and below. As a deny rule it also refuses a call
  handed a folder above that place, such as `~`, since the program works
  below it. A path condition starts with `/` or `~` (a `~` glob also with a
  wildcard, such as `path~**/.env`), as the paths the node resolves do. A
  plain string has no home: a `~` glob that starts at the home (`~/…`) on
  one is flagged (see below), since the rule was written for a path argument
  that is a plain string now. An exact string, such as an audit pins, may
  start with `~/` like any text.
- Conditions name the arguments of one action: `lamp.set:…`, not `lamp:…`.
  A rule without a pattern (`lamp.set`, `lamp`) still covers every call.

The node checks the conditions against the action's schema when the rule is
written, by `rule add`, `rule edit`, `config add`, the desktop app or a center
with the [settings grant](settings-and-config.md#the-settings-grant). An argument the action does not
take, a value not of its type (`brightness=high`), an operator its type does
not take (`room<3`), a value its schema does not list, and an action nothing
offers now are refused. So a rule for a [program's](capabilities.md#capability-providers-in-use) action goes
on once the program is attached.

A call that gives such an argument a value of another type, or leaves it
out, cannot be told by the rule. Then a deny rule refuses it and an allow rule
does not cover it: `lamp.set:brightness>50` on the deny list also refuses a
`lamp.set` call without `brightness`.

When a capability changes and its schema no longer fits a rule (an argument
the rule names is gone or has another type, or a value it names is no longer
one the schema lists), the rule stays and decides as written, which is no
longer what you meant. Where its argument is gone it fails closed: as a deny
rule it refuses every call of that action, as an allow rule it covers none.
Where its value is no longer listed, `room=bedroom` holds for no call. `rule
ls` says so after the rules, `rule --json` lists them under `stale`, and the
desktop app marks the row:

```text
warning: the deny rule "lamp.set:room=bedroom" no longer fits: lamp.set has no argument room; it takes level; as a deny rule it may refuse calls of lamp.set it was not meant for until you change it
```

The audit keeps the arguments a rule may pin (top-level strings of up to 200
characters, numbers and booleans, at most 16) on each entry of such an
action. The audit pages of the desktop app and the web UI offer each of them:
pick one, then **Allow with this value** or **Deny with this value**. A path
argument is kept as the node resolved it, so the rule names the place the call
reached, however the agent spelt it; a call refused before its path was
resolved (an action that is off, a path that does not resolve) keeps none, and
neither does one for an argument the schema does not name. A value is compared
as written, so a deny on a free string covers that exact value only
(`mail.send:to=boss@example.com` does not refuse `Boss@Example.com`, which a
program may read as the same person). Where a program reads values more
loosely, let its schema list the allowed ones (`enum`), or use the allow list.

### Rule syntax

A rule is `<scope>` or `<scope>:<pattern>`.

- The scope is a capability (`fs`, `exec`) or one action (`fs.read`,
  `exec.run`).
- The pattern of `exec.run` and of an `fs` scope is a glob over the call's
  target. `*` matches across `/` and spaces. Any other action's pattern is
  conditions on its arguments (see above).
- Without a pattern the rule covers every call of its scope.
- A pattern ending in ` *` also matches the bare program. One ending in `/*`
  also matches the folder itself.

| Pattern of | Is |
|---|---|
| `exec.run` | A glob over the whole command line |
| every `fs` action | A glob over the resolved path. `~/` is your home. On Windows the form is `/c/Users/x`, and case does not count |
| any other action | Conditions on its arguments, a path argument (`x-nerve-path`) read as an `fs` path is |

| Rule | Covers |
|---|---|
| `exec.run:git status` | That command line, exactly |
| `exec.run:git *` | `git` and anything after it |
| `fs.read:/home/u/notes/*` | Reading the folder and below (not `list` or `grep`) |
| `fs:~/private/*` | Every `fs` action on the folder and below |
| `notes.open:path~~/private/*` | The program's `notes.open` with its path there; as a deny rule also one handed a folder above it, such as `~` |
| `lamp.set:room=office,brightness<=50` | `lamp.set` in the office, up to half bright |
| `exec` | Every `exec` action, so every command |

Commands and paths never mix: `fs:/tmp/*` is not a command rule. A path rule
covers the capability it names only: `fs:~/private/*` does not keep a
[program's capability](capabilities.md#paths-it-takes) that takes paths out of
that folder. Deny each such action too (`notes.open:path~~/private/*`), or
make the place a [protected path](#protected-paths-as-the-owner-sees-them), which every capability
respects. A
program handed a folder works below it, so a deny rule of its capability that
may cover a place below that folder refuses the folder as well (and a new
path it would write to, where it may make a folder; a file it is handed holds
nothing below it); an `fs` walk
(`grep`, `find`, `list`) skips the denied place instead. A path rule covers
only the paths a program marks as such. An unknown rule shape is refused
when you add it, and so is an `fs` rule written as conditions
(`fs.read:path~~/private/*`): an `fs` rule names the path itself
(`fs.read:~/private/*`).

### What a wildcard covers

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

### Switch a capability off

`cap set` turns a capability or one action on, off or hidden for a center.

```sh
nerve-node cap set exec.run off
nerve-node cap set fs hidden
nerve-node cap
```

`cap` lists every capability, each action with its effect and, per
center, whether it may use it now and the switch you set
([providers](capabilities.md#see-what-is-there)).

| Setting | Effect |
|---|---|
| `on` | Normal. Rules and mode decide |
| `off` | Calls are refused with `disabled`. The center lists it as off |
| `hidden` | The node leaves it out of what it tells the center, and refuses it |

A capability is `fs` or `exec`. An action is `fs.write` or `exec.run`. A
switch applies in every mode.

## Protected paths, as the owner sees them

Some places hold secrets or start programs later. The node refuses file calls
that touch them, in every mode, `user` mode too, whatever a rule says.

### What is protected

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
and `NTUSER.DAT`. `Documents` counts in its usual place and where Windows has
it (OneDrive's backup or a redirect moves it); the installed service reads that
from your registry, and remembers the last place it saw for when you are not
signed in. A `Documents` on another machine (a share) is not looked at, and only
the usual place counts. PowerShell 7 counts when installed with the MSI or winget. A
copy unpacked from a zip file, installed as a .NET tool or put in a folder of
your choice is not covered.

Names are matched without regard to case.

### What protection covers

- The file actions (`fs`) and the working directory of a command.
- Each call builds the list once, as the owner sees the files, when it
  starts: its decision, the walk of an `fs` call and a command's Landlock
  rules go by that one list. It is not kept from one call to the next, so a
  link put in the home meanwhile counts at the next call.
- It does not cover what a command reads or writes by itself. In `folder` mode
  (Landlock on Linux, the AppContainer on Windows), a command's sandbox leaves
  protected paths out. In `user`
  mode a command runs as you, without a sandbox, and can reach them.
- It does not see a path a command builds while it runs
  ([modes](sandbox-linux.md#paths-a-command-builds-at-run-time)).
- It does not cover what a command asks another program for. With the keys
  in the system keyring, a command that asks the keyring (`secret-tool`,
  `busctl --user`, `gdbus`, `dbus-send`) names no protected path, so an
  allow rule for it reaches the node's keys
  ([keys](settings-and-config.md#where-the-node-keeps-its-keys)).

### The node's own folders

The node's config and state folders are closed harder. No rule, mode, folder or
release opens them. The node also checks the paths a command line names
plainly. In `folder` mode (Landlock on Linux, the AppContainer on Windows) the
command's sandbox leaves the folders out. A `user` mode command runs as you and can still reach them.

### Release a protected path

Only you can release one, on the machine.

Grant a folder at or inside the protected path. The folder releases it for the
rights it has, and no more: `r` for reads, `w` for writes and reads, `x` for commands.

```sh
nerve-node folder add ~/.ssh r       # reads of ~/.ssh may now pass
```

Or release a path by name:

```sh
nerve-node config add center.lab.policy.protected.allow '~/.ssh/config'
```

A folder at a protected path does not release the rest. `~/` as a folder does
not release `~/.ssh`.

### Protect more

```sh
nerve-node config add center.lab.policy.protected.extra '~/secrets'
```

A center with the [settings grant](settings-and-config.md#the-settings-grant) can add paths here. It
cannot remove one or release one.

## Sudo, as the owner uses it

Sudo is a switch on the machine, not a mode. It works on Linux, and on
Windows on the node [installed as a service](windows.md#the-node-as-a-service-on-windows) ([sudo on
Windows](windows.md#sudo-on-windows)). It is off by default.

| Switch | What happens to a `sudo` command |
|---|---|
| Off | Refused, even if the sudo list names it. The node holds no password |
| On | Runs only if the sudo list names it, in every mode. Deny rules and protected paths still apply |

A sudo command is one whose first word is `sudo` (or a path ending in
`/sudo`). It has its own list, `sudo`. The normal allow list does not count
for it.

### Turn it on

1. Put the commands on the sudo list: a rule that starts with `sudo` goes
   there.

   ```sh
   nerve-node rule add allow 'sudo apt update'
   nerve-node rule add allow 'sudo apt *'   # sudo apt, and anything after it
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
   ([service](sandbox-linux.md#the-accounts-commands-run-as)):

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
   nerve-node sudo
   nerve-node sudo off
   ```

`rule add allow 'sudo …'` puts the command on the sudo list.

### What the node does

On Linux (Windows differs, see [sudo on Windows](windows.md#sudo-on-windows)):

- It checks the password with `sudo -S -k -v`, run as you (the owner on the
  installed node), so sudo checks your password and your sudoers entries. A wrong password is refused and the switch stays as it was.
- It keeps the password in memory only. Turning sudo off drops it. A node that
  restarts has sudo off.
- It never sends the password to a center. It replaces any copy in a frame,
  also in a command's output stream, or in the audit log with `[redacted]`.
  This holds on Windows too.
- No sudo command runs for a center whose [network you turned
  off](sandbox-linux.md#no-network-for-a-centers-commands): it would run outside
  what keeps that center's commands off the network, with full rights. The
  node refuses it and says why, and `list` tells the agent.
- A sudo command must be one simple command. One with `; & | $ ` ( ) < >` or a
  line break is refused. This holds on Windows too.
- A wildcard entry (a trailing ` *`) covers plain commands only, as a [wildcard allow
  rule](#what-a-wildcard-covers) does. A line with `@ { } % ' " # , \`
  or a word that starts another command, such as `start`, `sh`, `powershell`,
  `cmd`, `iex` or `-Command`, runs only when an entry names the whole line.
  So `sudo systemctl *` does not cover `sudo systemctl start nginx`, and
  `sudo net *` does not cover `sudo net start spooler`: add
  `nerve-node rule add allow 'sudo systemctl start nginx'` without the `*`.
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

### From the web UI

A center with the [settings grant](settings-and-config.md#the-settings-grant) can turn sudo on and off.
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
[settings grant](settings-and-config.md#the-settings-grant) may switch itself to `user` mode, whose
commands run as root, with no password at all.
