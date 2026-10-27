# Troubleshooting

Start with `nerve-node status`, `nerve-node center ls` and
`nerve-node audit --denied` on the machine. The refusal in the audit log is
the same text the agent saw. A refusal that starts with `the center's action
checker` comes from the center, not the machine, so it is not in the
machine's audit log: see [below](#the-centers-action-checker-refuses-a-call).

For a link that drops, a pairing that fails or an error, open the center's
[log](logs.md), in the web UI under **Log** or in `log.jsonl`, and the node's
`log.jsonl` on the machine. Raise the level to `debug` for more.

## A call is refused

The agent sees `error forbidden: …` or `error disabled: …`. Every refusal
names its reason. One the machine gave reads
`error forbidden: node box-1 answered: …`.

| Message | Cause | Fix |
|---|---|---|
| `no allow rule matches …` | `allowlist` mode and no rule covers it | [Add a rule](rules.md) or choose a [mode](modes.md) |
| `… chains commands or holds an expression …` | A wildcard rule does not cover commands with `;`, `&`, `\|`, `$`, quotes and the like | Add an exact rule for the whole line, or use `folder` mode |
| `outside the folders that allow reading` or `… writing` | `folder` mode, and no folder grants `r` or `w` there | `nerve-node folder add <path> +r +w` |
| `the working directory is not in a folder that allows running` | `folder` mode, and no folder with `x` holds the working directory | `nerve-node folder set <path> +x` |
| `commands cannot be confined on this machine` | `folder` mode on a node you run yourself on a machine without Landlock, or on the installed Windows service. The installed Linux node runs `folder` mode as `nerve-run` without Landlock (`status`: `as nerve-run, without Landlock`) | Install the node as a service (`sudo nerve-node install`), or use `allowlist` or `user` mode. See [platforms](platforms.md) |
| `warning: Without Landlock, nerve-run can read every file in your home …` (`status`, `install`), **nerve-run can read more of your home** (app) | The kernel has no Landlock, and your home is open to others (mode 755 or 711) or a folder you gave lies in your home, which `nerve-run` passes through: it reads there what every account may | Give folders outside your home, `chmod 750 ~` where it is open, `umask 027`, or a kernel with Landlock. `umask 027` narrows what it reads, but the warning stays while a folder in your home is given. See [modes](modes.md#your-home-and-other-accounts) |
| `nerve-run did not get every folder` (app, `status`, `folder add`) | The installed Linux node could not give `nerve-run` a folder: a file system without POSIX ACLs, or a folder of another account's on its way | Give a folder on another file system, or open the folder on the way. See [modes](modes.md#the-account-nerve-run-linux) |
| `the command was not run: the access of nerve-run to … could not be taken off`, `nerve-run keeps its access to …, which it should have lost` (`status`, `folder rm`), **nerve-run keeps access it should have lost** (app) | The node could not take `nerve-run`'s ACL entry off a folder you removed, or could not read its record of them, so no command of `nerve-run` runs, for any pairing, and `uninstall` stops | See the reason in `status`; fix it (`getfacl`, `setfacl -x u:nerve-run <path>`), the node tries again before each command |
| `commands cannot be confined on this machine while the node's keys are in the system keyring: …` | `folder` mode with `machine.secret_storage = "keyring"`, where a command could reach the keyring: a Linux node you run yourself (commands run as you), and the Windows node you run yourself. The node logs `folder mode runs no command: …` and `status` says so | `nerve-node config set machine.secret_storage file`, as the message says. See [keys](config.md#where-the-node-keeps-its-keys) |
| `... keeps a grant for this center's commands that its folders no longer give` | Windows: the node could not take a removed folder's grant off, or a granted folder was moved or renamed and the node could not take its entry off where it is now (the message names its old path) | Check that you may change that folder's permissions. For a moved or renamed folder, the node's log names the reason, often hard links: see the row on hard links below (a built Rust project needs `cargo clean`). The node tries again before each command |
| `the node cannot tell which folders carry grants for the commands` | Windows: the record of the folder grants (`grants.json` in the state folder) cannot be read, so no `folder` command runs | See the reason. If the file is damaged: `icacls <folder>` lists a folder's grants as `S-1-15-2-…` entries, `icacls <folder> /remove *S-1-15-2-…` takes one off. Once none is left, delete the file |
| `the node puts no grant on it, since …` | Windows: a folder granted inside another folder with `w` is now a junction or link to elsewhere, a file with a second name, or has permissions that do not inherit ([modes](modes.md#what-a-command-can-reach-in-folder-mode-windows)) | Put a plain folder there again (remove the junction; `icacls <path> /reset` makes its permissions inherit), or take the folder off the pairing. The node grants it at its next sync |
| `folder … left out of the command's sandbox: it was added at its own place and its path leads to … now` | The folder was added with `folder add`, and a link or junction now stands in its path (a command with `w` on the folder above may have put it there). The node keeps the folder out until the path leads to the place you added again ([modes](modes.md#a-folder-keeps-the-place-you-added)) | Look at the link (`ls -l`, `dir /AL`). If you did not mean it, remove it. If the new place is the one you want, `nerve-node folder rm <path>` (the path `folder ls` shows; the one you gave to `folder add` too, except on the installed node when it went through a link) and `folder add` the place the path leads to now |
| `the node does not change the permissions of …, since … below it has … names (hard links)`, or `… below it has … names (hard links), and the change would reach them all; it stopped there` | Windows: a file below a folder the commands may write in has a second name, and the change of the folder's permissions would reach it under every name ([modes](modes.md#what-a-command-can-reach-in-folder-mode-windows)) | `fsutil hardlink list <file>` shows its names. Links between names in `target` folders of the same folder, under the same grants, pass where no pairing has `w` without `r` on that folder or one above or inside it, except in a sync after a granted folder was moved or renamed: a built Rust project you renamed or moved needs `cargo clean` first. Others do not pass. Build tools make such links: pnpm's `node_modules` to its store, uv's `.venv` to its cache, a local `git clone`. Remove them (delete `node_modules` or `.venv`) or keep them out of the folder (pnpm `package-import-method=copy`, `UV_LINK_MODE=copy`, `git clone --no-hardlinks`) ([modes](modes.md#what-a-command-can-reach-in-folder-mode-windows)). A refused removal stops the pairing's commands until then. The node tries again before each command |
| `the config is saved, but the folder grants do not follow it` | Windows: a folder's permissions could not be changed | See the reason. The node tries again when it starts and before each command |
| `… is protected (…)` | The path is [protected](protected-paths.md) | Grant a folder at it, with the right it needs |
| `… is denied (…)` | A deny rule matches | `nerve-node rule rm deny …` |
| `… holds a place that is denied` | A program was handed a folder, and a deny rule of its capability names a place below it | Hand it a folder beside that place, or `nerve-node rule ls deny` |
| `… holds a link (…) that leads where this call may not reach` | A program was handed a folder that holds a link to a place the call may not use: outside the folders, a protected path or a denied place ([providers](providers.md#paths-it-takes)) | Hand it a folder without that link, or remove the link if you did not mean it |
| `… holds a link (…) the node cannot follow` | A program was handed a folder that holds a link the node cannot resolve: a loop, or one into a place the account the node checks as may not look into ([providers](providers.md#paths-it-takes)) | Remove or fix the link, or hand the program a folder without it |
| `the paths this call hands over hold more than 200000 entries in all, counting those of the folders their links lead to; …` | A program was handed folders that, with the folders their links lead to, are too big together for the node to check every link in them. A small folder with a link to a big one (an SDK, the home) counts that one too ([providers](providers.md#paths-it-takes)) | Hand it a smaller folder, or one whose links do not lead to big folders |
| `… is a link; name the place it leads to` | A program was asked to write at a path that is a link, which would act on the place the link leads to | Name that place, or remove the link yourself |
| `… belongs to the node itself; no rule or mode reaches it` | The call touched the node's config or state folder | Nothing opens these |
| `sudo is off on this node` | A `sudo` command, and the switch is off | [Turn sudo on](sudo.md) |
| `a sudo command runs only when the sudo allow list names it` | The sudo list lacks it | `nerve-node rule add sudo '<command>'` |
| `a wildcard sudo entry does not cover a line with …` | A wildcard sudo entry covers no expression character (`@ { } % ' " # , \`), no invisible character (named as `U+…`) and no word that starts another command, such as `start`, `sh` or `powershell` | `nerve-node rule add sudo` with the whole line, without `--wildcard`. Quote the line for your shell: `"sudo choco install 'abc'"` keeps its `'` |
| `disabled: exec.run is off` | `cap set` switched it off or hid it | `nerve-node cap set exec.run on` |
| `the command line is … bytes, longer than …` | A command over 64 KiB | Use a shorter command |
| `unavailable` | The machine is offline | Check the link, below |
| `connection_lost` | The link dropped during the call and did not come back within 30 s, or the node or the center restarted | Run it again |
| `the answer is … bytes, more than the center takes` (`too_large`) | The result is over the 4 MiB message limit, mostly from output full of control characters, which take six bytes each | Write the output to a file, or cut it down (`head -c`, `base64`) |
| `busy` | Too many commands or calls at once (`limits.max_running`, 16 by default, for all centers together); an agent's [jobs](harness.md#long-calls-become-jobs) hold their places until their commands end, and the message names the session's running jobs | Wait, stop jobs nobody waits for with `job.cancel`, or raise the limit |
| `timeout`: `the command ran past …` | The command ran longer than its `timeout_ms`, than the node's default (10 minutes, when the call gave none), or than the node's maximum (1 hour). It was killed. The message says which | Give a larger `timeout_ms`. Above the maximum, you raise `limits.max_timeout_secs` ([how long a command may run](config.md#how-long-a-command-may-run)) |
| `memory_mb … is more than this node lets a command have: at most …` (also `cpu_percent`, `processes`) | The call asked for more than the most you set | Ask for less, or raise `limits.command.*_max*` ([limits](limits.md)) |
| `killed: "memory"` in a result | The command went past its own memory limit (a command the machine's OOM killed has only `signal: "kill"`) | Ask for more `memory_mb`, up to the most, or raise `limits.command.memory_mb` |
| `commands run WITHOUT these limits: …` in `status` | The node has no cgroup of its own: started in a terminal | [Where the limits hold](limits.md#where-the-limits-hold) |
| `the cgroup … no longer passes on the controllers the node turned on`, or `NO COMMAND RUNS` in `status` | Something turned a limit off in the node's cgroup while it ran, such as a reload of a service manager that did not delegate it | Start the node again; give its unit `Delegate=yes` ([limits](limits.md#where-the-limits-hold)) |

`list` shows only the capabilities a machine could allow. If it shows none
for a machine, nothing is allowed yet: in `allowlist` mode, add a
[rule](rules.md) or choose a [mode](modes.md).

## The center refuses a call itself

These come from the center, before the machine gets the call, so they are not
in the machine's audit log. The model can mostly fix them by itself.

| Message | Cause | Fix |
|---|---|---|
| `list_first: call list with node "…" and capability ["…"] first` | The model ran a capability without asking `list` for its details in this session | The model calls `list` with that node and capability, then runs it again |
| `list_first: "…" on node … changed since list gave its details` | The capability's arguments or description changed since, for example after a change of the machine's limits | The model lists it again |
| `invalid_args: <field>: expected …` | The arguments do not fit the capability's schema | The model fixes that field |
| `unknown_capability: node … offers no "…"` | The machine offers no capability of that name, maybe with `(did you mean "…"?)`. Or the center left it out: then the Overview names it under **Not offered to the agent** ([web UI](web-ui.md#overview)) | Check the name with `list`. If it should be offered, allow it on the machine |
| `unknown_node: there is no node "…"` | No paired machine has that name or id; the message names the ones there are | Use one of those names |
| `unavailable: node … is disabled in the center` | You disabled the machine in the center | **Enable** it on the Overview |
| `forbidden: "…" is turned off on node … by its owner` | `cap set … off` on the machine | `nerve-node cap set <capability> on` |
| `unknown_job: node … has no job "j-…" of this session` | The id is wrong or another session's, or the job's result was given already, or not read within 10 minutes ([long calls](harness.md#long-calls-become-jobs)) | Run the call again if its result is still needed |
| `unknown_stream: node … has no stream "s-…" of this session` | The id is wrong or another session's, or the stream went: it was closed, its job's result was read, or it ended 10 minutes ago ([long calls](harness.md#a-commands-output-while-it-runs)) | Read the job's result with `job.status`; it carries the output from its start |
| `busy: this session has 16 calls running` | The session runs 16 calls at once already, jobs included; the message names its running jobs | Wait for one with `job.status`, or stop one with `job.cancel` |
| `busy: node … runs 56 calls already` | Agents' calls of all sessions hold the places the center gives them on that machine ([limits](limits.md#calls-of-one-agent-session)) | Wait for a job to end, stop one with `job.cancel` (the message names the session's running jobs), or end a session in the web UI |

## The center's action checker refuses a call

The [action checker](action-checker.md) runs on the center, before the
machine gets the call. Its refusals are `forbidden` too, and start with
`the center's action checker`. They are on the center's Audit page, marked as
the checker's, and in its [log](logs.md); the machine never saw the call.
Change them on the **Action checker** page of the web UI.

| Message | Cause | Fix |
|---|---|---|
| `… refused this call: it is on the center's blocklist for every node — …` or `… on this node's own blocklist in the center — …` | A blocklist entry matches; the message names it | If the call should run, switch the entry off (for this machine only or for every machine) or remove it. An allow rule does not get past the blocklist. **Per machine** switches the whole blocklist off for one machine |
| `… refused this call: it nests more than 16 levels of …` or `… it holds more than 100000 commands, which is past what the checker takes apart …` | The command line is too deep or too long for the checker to read | Split the command, or switch the blocklist off |
| `… decision model judged this call dangerous (score …, threshold …)` | The model scored the call at or above the threshold | On the Audit page, **Allow** or **Allow as wildcard** saves an allow rule for that machine. Or raise the threshold, or switch the model off |
| `… could not reach its decision model, so it refused the call (fail closed): the model is not reachable` | The model is on, but the local model is not installed, still starting or failed, or no endpoint URL is set. After a center restart the local model refuses calls until it has loaded | See the model's state on the Action checker page and the Log. Install the local model, set the endpoint, or switch the model off |
| `… (fail closed): the action checker's model cannot be reached: timed out after … ms` | The model took longer than its timeout. A small CPU is much slower than a desktop one | Raise the timeout, run the model on the GPU, use d1-3B instead of Kev-4B, or use an endpoint |
| `… (fail closed): the action checker's model gave no usable answer: 401: the model endpoint refused the token` | The endpoint's token is wrong or missing. A backup does not hold it | Enter the token again |
| `… gave no usable answer: 501: the loaded model is not a decision model …` | The endpoint serves a model that is not a System One model | Load a decision model there, or name one as the model |
| `… gave no usable answer: 429: …` or `529: …` | The endpoint is rate-limiting or overloaded | Wait, or switch the model to allow-and-log |

To let calls through while the model is down, switch it from fail closed to
allow-and-log; each such call is then logged and on the Audit page.

## The local model does not install or run

The Action checker page shows `The last install failed: …`, and the center's
log `the action checker's local model install failed: …`.

| Message | Cause | Fix |
|---|---|---|
| `downloading …: …`, `no data for … s; the download stalled` | The center cannot reach GitHub or Hugging Face, or the connection stopped | Check the network. The center uses `HTTPS_PROXY` when it is set. Install again |
| `the download does not match its pinned SHA-256`, `the download is … bytes, not the pinned …` | The file is not the one the center pins: a damaged download, or a proxy that changes files | Install again. Nothing unverified is used |
| `cannot run tar: …`, `tar could not unpack the archive: …` | The center unpacks with the system `tar` | Install `tar` (and `gzip` on Linux); Windows 10 and later have it |
| `This machine has no prebuilt local model for it.` (on the page, with no install button) | The center pins llama.cpp builds for Linux and Windows on x86_64 and arm64 only | Use a System One endpoint |
| `no GPU device was found; running on the CPU` | The GPU build found no device. The installed center service on Linux sees no GPU | Keep it on the CPU, or use an endpoint on a machine with a GPU |
| `the action checker cannot start its local model: …` in the log, or the model's state `failed` with its last lines of output | The installed server does not start | See its output on the page. **Remove** and install again |

A failed install keeps the model installed before it, which goes on checking
calls.

## Pairing fails

| Message | Cause | Fix |
|---|---|---|
| `the pairing code is unknown, used, expired or out of tries` | Wrong, old or used code | Make a new link in the web UI |
| `another node already has this name` | Two machines have the same name | `nerve-node config set node.name <other>`, then pair again |
| `this name is a node's id` | The machine's name is a paired machine's id (or its own), which the agent could mistake for that machine | `nerve-node config set node.name <other>`, then pair again |
| `another node is named like this node's id` | A paired machine's name is this machine's id | Rename that machine in the web UI, then pair again |
| `this center is paired already as …` | The machine already has a pairing with this center | Use it, or `nerve-node center rm` it first |
| `a center named … is paired already` | You already use this local name | Pass `--name <other>` |
| A link or TLS error | The address in the link does not reach the center, or the center's certificate changed | Check `--public-url` and the port. Make a new link |

## The link is down

`nerve-node center ls` shows flags:

| Flag | Meaning | Fix |
|---|---|---|
| `[paused]` | You or the center paused the link | `nerve-node center resume` |
| `[revoked]` | The center removed this machine | `nerve-node center rm`, then pair again |
| `[unknown]` | The center does not know this machine any more | `nerve-node center rm`, then pair again |

Without a flag, the node is dialling. The wait grows from 1 to 60 seconds. If
`nerve-node status` says `LOCKED (panic)`, run `nerve-node unlock`.

Through a [relay](relay.md), `status` names what the relay answered:

| Message | Cause | Fix |
|---|---|---|
| `the proxy refused the tunnel to …: 400 …` | The node speaks plain HTTP to the relay, which speaks TLS only | `proxy set 'https://…' --pin=<pin>`, the line `relay add` showed |
| `TLS with the proxy …: its certificate does not carry the pinned key` | The pin in `proxy set` is not the relay's, or the relay made a new certificate | On the relay, `nerve-node relay ls` shows the pin |
| `the proxy refused the tunnel to …: 407 …` | The relay does not know the name and token in `proxy set` | On the relay, `nerve-node relay ls`; give the node a new token with `relay token <name>`; on Windows the relay knows a new token only after `Restart-Service nerve-node` |
| `the proxy refused the tunnel to …: 403 …` | The center's address is not one the relay is paired with over https, or not one the relay's owner picked for this node | Pair with the URL the relay uses for that center; on the relay, `relay ls` shows the node's centers |
| `the proxy refused the tunnel to …: 503 …` | The relay is off, locked, carries as many tunnels as it may (all of them, or this node's), or this node opened as many as it may in a minute | On the relay, `nerve-node relay ls` and `status`, and its log: the node sees only `503`, the relay's log says which limit |
| `the proxy refused the tunnel to …: 502 …` | The relay cannot reach the center, or the relay's own proxy or relay refused it (in a chain, the outer relay's limits for the inner one) | Check the relay's own link and its log; in a chain, give the inner relay limits of its own on the outer relay with `relay set-limits` ([relay](relay.md#limits)) |

If `status` says `daemon: not running`, start `nerve-node run`. On Windows
`status` asks the node over its [control pipe](platforms.md#the-control-pipe).
There a running node takes only folder changes at once; the others count from
its next start. On a node
[installed as a service](service.md), start the service instead:
`sudo systemctl start nerve-node`, on Windows `Start-Service nerve-node`. A
node started there by hand lacks the privileges the service has, so it
cannot switch to the account commands run as and runs no command at all.

## The node will not start

| Message | Fix |
|---|---|
| `refusing to run as root; set machine.allow_root = true to allow it` | Run as a normal user (on Windows: not elevated), or set `machine.allow_root` |
| `node.toml is refused: its MAC does not match …` | Look at the file, then `nerve-node config accept`. See [config](config.md) |
| `node.toml is refused: its version … is older than the last this node accepted …` | An earlier `node.toml` is back, from a backup or a sync tool. Look at it, then `nerve-node config accept`. See [config](config.md#an-older-file-put-back) |
| `… config.version holds no version number` | The record of the last version in the state folder is damaged. Delete it, or take the file with `nerve-node config accept`. See [config](config.md#an-older-file-put-back) |
| `machine.secret_storage is "keyring", but the system keyring cannot be reached …` | The keys are in a keyring that does not answer. Start it, or run `nerve-node setup`, which offers to install one on a Linux without a desktop. See [keys](config.md#where-the-node-keeps-its-keys) |
| `… this running node found no keyring and does not look again until it is restarted …` | The node asked for a keyring before one answered. Restart the node (`nerve-node service restart`), then change the setting again. `setup` run without sudo stops here and asks for that restart, then for `nerve-node setup` again; `sudo nerve-node setup` restarts the installed node itself |
| `… keeps the node's keys in the system keyring (machine.secret_storage = "keyring"), but … So the node does not start` (also from `install`) | The keys may not be in the keyring here: the installed node on Windows. Run the `config set machine.secret_storage file` command the message names, as it says, then start the node. See [Windows](service.md#windows) |
| `machine.secret_storage cannot be "keyring" here: …` (from `config set`) | The same reasons. Keep the keys in files |

A node installed as a service says why in its [log](logs.md):
`journalctl -u nerve-node` on Linux. On Windows the Event Viewer has an error
from the source `nerve-node` under **Windows Logs > Application**, and
`C:\ProgramData\Nerve\state\log.jsonl` has the rest
([Windows Event Log](logs.md#the-windows-event-log)).

## The center will not start

| Message | Cause | Fix |
|---|---|---|
| `another nerve-center already runs the center in …` | Another center uses this state folder, and this one is not `--mcp stdio` | Use another `--state-dir`, or stop the other center |
| `the web UI at … is beyond loopback and logs in with a harness token, but there is none` | `--ui` is not on loopback | Set `--harness-token`, or use `--ui 127.0.0.1:7480` |
| `… always needs a login; drop --ui-no-login …` | `--ui-no-login` with a UI beyond loopback | Drop `--ui-no-login` |
| The MCP endpoint refuses every client | No harness token yet | Set `--harness-token`, or make one in the web UI |

## Output is cut

A command returns at most 1 MiB of stdout and 1 MiB of stderr. The result has
`truncated: true`. A file read returns at most 2 MiB. A write takes at most
3 MiB.

## The CLI refuses a change

These come from `nerve-node` commands that talk to the running node, not from an
agent's call.

| Message | Cause | Fix |
|---|---|---|
| `refused: this request comes from a command the node runs for a center` | The request came from below a command the node started for a center, for example from a command that ran `nerve-node` itself. The node refuses every request from there, the reading ones too | Run the command in your own terminal, not through an agent |
| `refused: this request does not carry the control socket's token …` | Linux: the request has no token: the CLI cannot read `run/ctl.token` in the node's state folder (it runs as an account that may not) | Run it as the account that owns the node's state (the node's own user for the [installed node](service.md)). See [platforms](platforms.md) |
| `<path>: … A command may have put a link there: look at it …` | `folder add` refused the path: it crosses a link inside a folder with `w`, a link to nothing,, a place that changed while it was looked at, or a path that is not absolute (on Windows, not on a drive). The text before the link advice says which | Look at the link (`ls -l`, `dir /AL`), add the place you mean by its own path, or remove the link ([modes](modes.md#a-folder-keeps-the-place-you-added)) |
| `<path> is not a folder of this center; this account cannot look into it, so if it is a link, use the path … folder ls shows for the folder` | `folder rm` or `folder set` was given a path the CLI cannot look into (the installed node's CLI and your home), and the folder was stored where a link led | Give the path `nerve-node folder ls` shows; the message names the folders that could be it |
| `note: … is stored as given and not recorded …` (from `folder add`, not an error) | The folder was stored, but neither the CLI nor a running node could tell where its path leads, so the place is not recorded | Start the node and `folder add` the folder again ([modes](modes.md#a-folder-keeps-the-place-you-added)) |
| `the node does not take connections now; try again` | Linux: the node runs, but its control socket is busy or its queue is full | Try again. For `panic` see [stop](stop.md) |
| `the node did not answer in time; try again` | Linux: the node took the connection and did not answer it within 90 seconds | Try again; if it keeps failing, look in the node's [log](logs.md) |

## A change did not apply

If a command says `takes effect at the next start of the node`, no node was
running to take it. Start `nerve-node run`. On Windows a running node takes
only folder changes at once; every other change it takes at its next start.

### Restart the node, then change the folder again (Windows)

`folder add`, `set` or `rm` says `node.toml holds changes the running node
takes at its next start`: an earlier command changed something else, which
waits in the file for the next start. The node saves its whole config with a
folder change and would undo that change, so it refuses. Restart the node
(`Restart-Service nerve-node` for the installed node) and run the folder
command again.

### The control pipe is not the node's (Windows)

`folder add`, `set` or `rm` says `the control pipe is not the node's`: another
process made a pipe of the node's name before the node started, and the node
runs without its pipe (its log says `the control pipe … is taken`). The CLI
sends that pipe nothing. Find the process with Sysinternals
`handle.exe -a nerve-node-`, end it, and restart the node. With the node
stopped, folder changes go to `node.toml` as every other change does.
