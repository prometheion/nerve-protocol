# The web UIs

The center's web UI and the node's web UI: the login model, the throttle,
the `Host` rule, sessions, TLS beyond loopback, and a tour of each page. The
user guide's [web UIs page](../user/web-uis.md) is the short version.

The web UI is one more GUI beside the desktop app: every function of the
pages is a command of the CLI too, and the app reaches the center the way the
CLI does, over its owner channel ([the center's pages in the
app](desktop.md#the-centers-pages)), not through the web UI. So each is on or
off by itself:

| Web UI | Linux | Windows |
|---|---|---|
| The center's | on, at `127.0.0.1:7480`, for the `nerve-center` program and for the app | off |
| The node's | on for the `nerve-node` program: its `install` turns it on at `127.0.0.1:7470` and shows the first token once; off in the app | off |

On Windows, and for the node in the app, a switch in the app's Settings turns
it on (the center's under **This machine**, the node's under **Network**).
Off, the center serves no web page and no browser login; the loopback API
stays for the app, which it asks only with the owner token. The center's
default is `--ui` (`NERVE_CENTER_UI`), `set ui` changes the installed one.

## How the pages are built

Both web UIs are one frontend project, [`webui/`](../../webui) at the
repository's root: TypeScript, React and Vite, with no UI library. It has
three pages: `center.html` (the center's web UI), `node.html` (the node's)
and `login.html` (the login of both).

- **Layout.** The pages follow the desktop app's layout B (#231, #232): a
  list on the left and the picked row's details on the right, side by side
  from a 1100 px window, in turns with **Back to the list** on a smaller one,
  and a third pane from 1800 px where a page has one. Adding is a form in the
  details pane, pairing an overlay, and a removal asks in its row. The shared
  pieces are in `webui/src/ui.tsx` (buttons, switches, the rows of choices,
  fields, the list and its details, the inline question, overlays, the
  searchable picker) and `webui/src/frame.tsx` (the sidebar, the page the
  address names, the polls); each UI's pages are in `webui/src/center/` and
  `webui/src/node/`.
- **Look.** `webui/src/styles/tokens.css` holds the app's design tokens, the
  values of `crates/nerve/ui/theme.slint`, and a test checks each one
  against the app's (`webui/src/tokens.test.ts`). The icons are the app's own
  (`crates/nerve/ui/icons`), written into `webui/src/icons.ts` as data by
  `node scripts/icons.mjs`.
- **The build is committed.** `npm run build` writes `webui/dist`, which is in
  the repository. `nerve-transport`'s `build.rs` lists every file there for
  `include_bytes!`, so `cargo build` needs no Node, and both servers serve the
  same files (`nerve_transport::webui`): their page at `/`, the login at
  `/login`, the scripts and the stylesheet at `/assets/…` with a hash of
  their content in the name, and the icon.
- **The CSP stays strict.** Every script and style is a file of the build;
  the pages hold no inline script, style or handler, and no source writes
  markup from text (`webui/src/sources.test.ts`;
  `nerve_transport::webui::tests::the_pages_load_only_files_of_the_build`).
  What a server says to a page goes in as data: the login's words and the
  user guide's ref are `<meta>` tags the page reads.
- **CI.** The `webui` job of `ci.yml` runs `npm ci`, the type check, the
  tests and the build, fails when `webui/dist` is not what the sources build,
  and runs `npm audit` (high for what the pages ship, critical for the build tools).

### Changing the pages

```sh
cd webui
npm ci                 # once
npm run check          # the type check
npm test               # the page tests, against a fake API
npm run build          # writes dist/: commit it with the change
```

A page test renders a page with a fake server (`webui/src/test/fake.ts`) and
acts on it as a person does (`webui/src/test/dom.tsx`); every change of a page
gets one. To try a page against a real center or node, run it and point the
dev server at it, then open `http://localhost:5173/center.html` (or
`node.html`) and log in at `/login`:

```sh
NERVE_DEV_UI=http://127.0.0.1:7480 npm run dev
```

A new npm dependency needs a reason: the project has React and React DOM,
and for the build and the tests Vite, its React plugin, TypeScript, Vitest,
happy-dom (the DOM of the page tests) and React's type definitions.

## The center's web UI

`nerve-center` serves a web UI at `http://127.0.0.1:7480` (`--ui`, on by
default on Linux, off on Windows). Its pages,
scripts and styles are built into the program. It loads nothing from another
host. The installed node, on Linux and Windows, has a web UI of its own:
[node web UI](#the-nodes-web-ui).

### Log in

The UI always asks for the **owner token**, on loopback too. It is not a
[harness token](mcp-surface.md#tokens): those open the HTTP MCP endpoint only.
A harness keeps its token in its own settings, where the agent may read it,
and this UI can switch the action checker off and change what the machines
allow, so a harness token never logs in here.

- The center makes the owner token at its first start. It prints it on
  stderr, and keeps it in `owner-token` in the state folder (mode 0600):
  `~/.local/state/nerve-center/owner-token` for a center you run yourself,
  `/var/lib/nerve-center/owner-token` for the [service](service.md#the-center-as-a-service),
  whose `install` prints it. The log says where it is, never the token.
  Where stderr is the systemd journal (the service), the token is not
  printed at all.
- `nerve-center owner-token` prints it again. `nerve-center owner-token --new`
  makes a new one: the old one stops at once, also on a running center, and
  the sessions it opened end. Run it as the center's user (`--state-dir` for
  another state folder), or with `sudo` for the service.
- You may write a token of your own into the file: one word of 20 to 200
  characters. A shorter one, or a file without a token, stops the center
  when its web UI is on (`--ui off` only warns), and the file is left as it
  is. It must not also be a harness token: one that is both is refused
  at the login, and a center with a web UI does not start on it.
- The owner token keeps an agent out of this UI only when the agent cannot
  read the center's state folder. That holds for the
  [service](service.md#the-center-as-a-service), which runs as its own account.
  A center your harness starts runs as you, and an agent with file or shell
  tools runs as you too: it can read the token file as easily as the
  harness's settings. When the harness gives the agent such tools, run the
  center as the service.
- Beyond loopback (`--ui 0.0.0.0:7480`) the UI uses TLS.
- On loopback the UI answers only to a loopback host name (`127.0.0.1`,
  `localhost`, `[::1]`), so a web page cannot reach it through a name it
  points at this machine. A reverse proxy that passes its own `Host` on
  (Caddy and Traefik do by default) is refused with 403: let the proxy send
  the loopback host, or serve the UI beyond loopback with its TLS.
- A browser without a session goes to `/login` and posts the token once.
- The session lasts 12 hours. **Sign out** ends it.
- The session belongs to the browser tab. A new tab, or the browser opened
  again, logs in again (a password manager can fill the token). No cookie is
  kept: a cookie would also go to every other program that listens on a port
  of the same host in your browser.
- A wrong token is answered after a short wait. It never locks the login, so
  nobody can keep you out by trying wrong tokens.
- A [backup](backup.md#back-up-restore-and-move-step-by-step) does not hold the owner token. A restored center
  makes a new one at its next start.

To reach a UI that listens on loopback from another machine, use an SSH tunnel:

```sh
ssh -L 7480:127.0.0.1:7480 user@center-host
```

### Where it listens

The installed center says where its web UI listens in a file every account
may read: `/run/nerve-center/ui` on Linux (the unit's runtime folder) and
`C:\ProgramData\nerve-center\run\ui` on Windows (made by `install`). It holds
JSON with no secret: the URL to open on this machine, the address it was
bound to, and the certificate's pin beyond loopback; `"url": null` while the
web UI is off. The file goes when the center stops.

The file says where to look, not who listens: any account may listen on a
free port while the center is stopped. So before a program of this machine
sends the owner token there (the desktop app's **Open the web UI** opens the
browser only after this check; the app's own log-in goes over the owner
channel, [with its own peer check](desktop.md#the-centers-pages)), it checks
that every listener a connection could reach is the center's service
(`nerve_center::holder`): on Linux a socket of the `nerve-center` account in
`/proc/net/tcp` and `tcp6`; on Windows a socket of the process the service
control manager names for `nerve-center`, in the table of TCP listeners. A
port held by anyone else gets nothing; one held by nobody means the center is
not running.

### Look

The web UI has the desktop app's design and layout: the same colours, type,
controls and motion, a list and its details on every page. The switch at the foot of the menu picks **System**, **Light** or
**Dark**; the choice stays in this browser. When the system asks for less
motion, nothing moves. On a phone the menu opens from the button at the top.

### Pages

#### Overview and Nodes

The Overview shows the center's state, Get started while a new center has
steps left, alerts, and the machines as a list; from 1800 px the sessions
stand beside them. **Nodes** lists the machines too, with **Pair a machine**.
A picked machine's details:


- **Machines.** Each paired machine with its state (online, offline,
  disabled), platform, a short summary and what it offers. Buttons: Rename,
  Disable or Enable, Remove. Under **Not offered to the agent** a card lists
  the actions the center left out, each with the reason: a name with a
  character other than letters, digits, `-` and `_` or longer than 64
  characters, or a schema the center cannot check (arguments or result, for
  example one with `oneOf`). A capability with such a name, or one the
  machine names twice, is listed once by its name (a long one cut). When a
  capability's `state` or the data of one of its events has such a schema,
  every action of it is left out, with a reason that starts with `state:` or
  `event <name>:`; a capability without actions is then listed by its own
  name. A reason is one line, cut after 300 characters. The agent never sees
  them; the rest of the machine's actions stay.
- **Pair a machine.** An overlay with a [pairing](identity-and-pairing.md#pairing-as-the-owner-does-it) command,
  `nerve-node center add -`, and the bare link it reads from stdin (also for the desktop
  app), each with Copy; for a Windows machine it says to open the link there.
  It closes once a machine used the code, and the page names the machine and
  its next step.
- Alerts, for example a machine whose key is in use twice.

#### Harnesses

- **Connect a harness.** How an AI app reaches this center: for HTTP, **Make
  a token** shows a new token once with the JSON, the URL, the header and the
  Claude Code line to paste.
- **Tokens.** Make a token with a label. It is shown once. Remove one
  to stop it: the harness sessions it opened over HTTP end at once, with
  their jobs. A token is only shown once the center has written it to its
  state file; when it cannot, the page says so and no token is made. A
  token removed while the state file cannot be written stops at once, but
  the page says the removal is not kept yet: unless the file can be written
  before the center stops, the token works again at the next start. The
  same holds for a removed machine. The token of the center's settings (`NERVE_CENTER_HARNESS_TOKEN` or
  `--harness-token`) is listed too, without **Remove**: remove it from the
  settings. A harness token does not log in to this UI.
- **Sessions.** The harnesses connected now, each marked `tainted` once the
  [action checker](action-checker.md#taint-1) marked it. **End** stops one
  session.

The tokens and the sessions are the two lists of a **Tokens** / **Sessions**
switch above the list. **Connect a harness** and the harness tokens are on
this page, not under Settings.

A disabled machine stays paired and connected. The agent's `list` shows it as
disabled with no capabilities, and calls to it are refused. The agent's calls
that run there stop, its [jobs](mcp-surface.md#long-calls-become-jobs-1) too, and so
do the streams and event subscriptions of a program there; after **Enable**
the agent opens them again with `execute`.

#### Statistics

The list has **All machines** first and then every paired machine, also one
that has no numbers yet (its numbers are zero). The details show the picked
row's numbers: time online, links, drops, calls, failed calls, then calls per
action with the average and the longest time, and errors by code. Only counts
and times are kept, never content. They are kept for the number of days set
in Settings. When a picked machine is removed, the page goes back to all
machines.

#### Audit

The latest decisions about calls, newest first: machine, action, target and
whether it was allowed or refused, with its reason.

Each entry with a known target has four buttons:

| Button | Adds |
|---|---|
| Allow | A rule for exactly this command, path or action |
| Allow as wildcard | A rule for the program and anything after it, the folder and everything below it, or the whole capability |
| Deny | The exact deny rule |
| Deny as wildcard | The wide deny rule |

An entry whose call has arguments a rule may pin (any action but a command
and a file action: strings, numbers and booleans) also offers them: pick one
(`room=office`), then **Allow with this value** or **Deny with this value**
adds `lamp.set:room=office` and the like
([rules](policy-engine.md#rules-on-an-actions-arguments)). The machine checks it
against the action's arguments as it saves it.

A sudo command goes on the sudo list when you press Allow. A button adds the
rule on the machine, so it works only if the machine gave the center the
[settings grant](settings-and-config.md#the-settings-grant). Otherwise the buttons are off and the
entry says why. Even with the grant, Allow for something that senses or acts
on the world (a camera, a lock), or for a capability no program on the machine
offers now, is refused: that is the owner's, on the machine
([providers](capabilities.md#capability-providers-in-use)). A target that was cut to its start gets no
buttons.

A decision the center's [action checker](action-checker.md#the-checker-as-the-owner-sets-it-up) made shows here
too, marked as the checker's and with whether the entry or switch was the one
for every machine or this machine's own. A model refusal gets **Trust this** and **Trust as
wildcard** buttons that save a skip rule (center-side, so no settings
grant is needed), and **Trust with this value** for an argument it pins.
**Trust this** saves the refused command line exactly. A blocklist refusal has none: it is a hard deny, so its
**Switch this entry off for this machine** leads to the Action checker page. Only the center marks
an entry as the checker's: a machine's own entry that claims to be one shows
as that machine's.

#### Action checker

The center's gate on every call ([action-checker](action-checker.md#the-checker-as-the-owner-sets-it-up)): a
deterministic blocklist, saved allow rules, and an optional decision model,
each with its own switch. A switch above the list picks the group it shows:
**Blocklist**, **Skip the model**, **Decision model** or **Per machine**; the
two groups of rules have an **Add a rule…** entry, which opens the rule's form
in the details. The page lets you edit the blocklist (add, remove,
switch single entries off, reset to the defaults) with entries for every
machine or one, keep allow rules for every machine or one, set the blocklist
and the model on or off per machine, switch single entries off for one
machine and write a note on it that `list()` shows the agent (**Per
machine**), and set up the model (a System One endpoint, or a
local model the center installs with one click, d1-2B or Kev-4B) with its
threshold, timeout, question and which calls it sees. It shows the install's
progress and the local model's state, and names each model's size and
licence. Taint, which marks a session once a call of it returned content, has
its switch here too. Under each **Add a rule** field it names the arguments
of the action typed so far (`lamp.set:` shows `room (a string)` and the like),
which a rule may pin, and it warns about a rule whose action no longer takes
an argument it names. Everything is kept in the center's state, except the
endpoint token and the local model's files. A save sends the whole page with
the version it loaded: when the settings changed since (an allow rule from
the Audit page, another tab), the save is refused and the page reloads, so
make the change again.

#### Capabilities

What each machine offers the agent, and the capabilities this center added
there itself. Pick the machine from the **Machine** list under the page
header. A machine whose list
does not load says why there, and one removed meanwhile drops out of the
list.

- **Offered.** Each unit the agent may be offered on that machine: its name,
  what it does (its effect), whether it is an action, a state, an event or a
  stream, and where it comes from: built in, your `node.toml`, this center,
  or a program you allow ([providers](capabilities.md#capability-providers-in-use)). One the owner switched
  off is marked off.
- **Left out.** The units the center does not offer the agent, each with the
  reason (a name it cannot carry, or a schema it cannot check).
- **Added by this center.** Only for a machine that gave the center the
  [settings grant](settings-and-config.md#the-settings-grant) and is online:
  the [capabilities this center added](capabilities.md#capabilities-a-center-adds),
  each with what it says it does, its command and, where the machine leaves
  it out, why. One the machine takes but does not offer the agent yet is
  marked **not offered**, with what turns it on: the machine decides it as
  a command, so in `folder` mode (a new pairing's) it needs an `on` for it
  and in `allowlist` mode an allow rule, both set on the Settings page under
  Machines by its full name (`say.back`, not `say`); one that senses or acts
  waits for the owner's `on`. **Add a
  capability** opens a form; **Edit** fills it with one; **Remove** asks
  first. After a change the page shows what the machine offers then.

The form has the fields of `nerve-node cap add`: the name (`cap.action`), the
time limit, what it does, a summary, the command (the program first; a word
`{field}` is the argument `field`, and a word with blanks goes in quotes),
the JSON Schema of its arguments and of its result (empty for none and for
the printed text), and where it runs. While you type, the center checks each
field with the machine's own rules and shows what is wrong under it. On
**Add** or **Save** the center checks it once more and sends it, and the
machine checks it again against its own limits (the time limit against its
`limits.max_timeout_secs`). A refusal of the machine shows in the form with
its reason, for example a name of the owner's. The machine also refuses to
add one under a name this center has an `on` or allow rule for (or, for its
first one under a capability, one for the capability as a whole), set for
something else, say a program that is away for now: the center's removal
would take that switch along. Take it away first on the Settings page under
Machines, or ask the machine's owner.

A capability the center adds runs as `nerve-run`, counts as `execute`, and
one that senses or acts stays off until the machine's owner turns it on. A
machine on Linux or Windows takes them (on Windows it runs them as `nerve-run`
in the pairing's AppContainer), and one its owner runs by hand has no
`nerve-run`: the page says so and offers no form.

A machine without the settings grant is shown read only: its units and the
left-out ones, and a note that the center may change nothing there.

#### Log

What the center did and saw, newest first: links that dropped and came back,
pairing, changes, refused and failed calls, and errors. A line shows the time,
its level, the machine it is about and what happened. The page is the center's
own [log](logging.md#the-log-as-the-owner-reads-it); it is not the audit page above.

- **Level.** Pick how much to show: everything, info and above, warnings and
  errors, or errors only. This narrows the view. The level the center keeps
  the log at is set in Settings.
- **Machine.** Pick one machine, all machines, or **The center itself** for the
  lines that are about no machine. A machine that was removed stays in the list
  while the log still has lines about it.
- **Search.** Shows the lines whose text or machine name contains what you
  type, in any letter case.
- **Live.** The page asks the center every two seconds and shows new lines at
  the top. Press **Live** to stop that, so the lines do not move while you read
  them; it then reads **Paused**. Press it again to go on. Leaving the page
  resumes it.
- **Download the file.** Saves the log file, `log.jsonl.1` and `log.jsonl` in
  one file with a JSON object per line. The page shows the latest 500 lines
  that match; the file has all the center kept.

The two lists work as every picker of the web UI: type in the search field
to narrow a list, **Down** and **Up** move through it, **Enter** picks the
marked entry and **Escape** closes it.

#### Help

Its sections as a list:

- **Tasks.** What you may want to do, and the page where it is done.
- **nerve-center commands.** The center's own commands, one line each; its
  options and the advanced ones fold.
- **nerve-node commands.** The commands of `nerve-node`, the program on each
  machine. The center reads them from the node's own command definition, so
  they match `nerve-node --help` of the same build. Type in the filter to keep
  the commands whose name, explanation or arguments contain it, and list them
  **By topic** or **A to Z**. A row opens on its commands, one line each, with
  their options folded, and a link to its page of this guide.
- **Keyboard shortcuts.** The keys of the web UI.

**User guide** at the top opens these pages on GitHub.

#### Settings

- **Center.** Its name, how many days to keep statistics, how long a
  pairing code is valid (1 to 1440 minutes, 10 by default), and the **log
  level**: error, warn, info (the default) or debug. The level applies at once
  and stays for the next start. If the center was started with `--log`, that
  level holds for this run and the one you pick is kept for the next start.
- **Center key.** The pin of the key the center serves. **Rotate key** makes
  a new key and shows its pin once; **Serve the new key now** ends the 7 days
  in which the old key is still served ([center](identity-and-pairing.md#rotate-the-centers-key)).
- **Machines.** For each online machine that gave the center the settings
  grant: its settings as JSON, with **Reload** and **Save**, and the sudo
  switch. The capabilities the center adds are on the Capabilities page, not
  in this document. A save sends the whole document with its version. If the version is
  stale, the machine refuses it. Reload and try again. A machine without the
  grant says it keeps its settings to itself.

## The node's web UI

The installed node, on Linux and Windows, can serve a web UI like the desktop
app: the same pages, the same look. On Linux, `nerve-node install` (the
program `nerve-node`, not the app) turns it on at `127.0.0.1:7470` and shows
the first token once, where the node had none; installed by the app, and on
Windows, it is off until you turn it on. The CLI keeps working beside it. It
is part of the service: no other program runs for it.

The desktop app turns it on and off in **Settings › Network › Web UI**, makes
and revokes its tokens there (by `ui` commands), and opens it with **Open**,
which first checks that the node's service holds the port (as the center's
**Open the web UI** does, [where it listens](#where-it-listens)). On Windows, where there
is no terminal, that is the way; listening beyond loopback is an
administrator's step there (`ui on --listen` needs one, and so does a
change of the setting `ui.listen` to such an address, by `config set`, a
changed node.toml or a restore), with a Windows
Firewall rule for the service `nerve-node` and its port, not for the program.

### Turn it on

```sh
nerve-node ui on
```

- The UI listens on `http://127.0.0.1:7470`. `--listen ADDRESS` picks another.
- With no token yet, `ui on` makes one named `first` and shows it once. Keep
  it in a password manager: node.toml keeps only its SHA-256.
- The running node takes the change at once. `ui on` waits up to 3 seconds and
  says what the node did: `listening on 127.0.0.1:7470`, or why it cannot
  (`cannot listen on 127.0.0.1:7470: …`).
- Open the UI after `nerve-node ui` says `listening` (in the app, with
  **Open**, which checks the port's holder). Until then another program could
  hold the port.
- On `127.0.0.1` the node holds `[::1]` at the same port too (and on `[::1]`,
  `127.0.0.1`), so `http://localhost:7470` reaches the node whichever address
  the browser tries first. If another account has the port at the other
  address, the UI does not listen and says so; a machine without IPv6 has only
  the one.

From another machine, keep the UI on loopback and use an SSH tunnel:

```sh
ssh -L 7470:127.0.0.1:7470 you@node-host
```

Then open `http://127.0.0.1:7470` on your machine.

```sh
nerve-node ui off
```

turns it off: the node stops listening, and every session ends. The tokens
and the certificate stay. Off, the node listens on nothing and does nothing
for the UI.

`nerve-node ui` (or `ui`) shows whether it is on, where it listens, the
node's state of it, and the labels of the tokens.

A node you run by hand (`nerve-node run`) serves no web UI.

### Tokens

| Command | Does |
|---|---|
| `nerve-node ui token add <label>` | Makes a token and shows it once. A label is 1 to 32 of `a-z`, `0-9` and `-`, and does not start with `-` |
| `nerve-node ui token` | Lists the labels and when each was made, never a token |
| `nerve-node ui token rm <label>` | Revokes a token. The sessions it opened end at once |

Tokens are made only at the CLI (the app's **New token** runs it). In the UI
you can revoke one
(**Settings › Web UI**), but not make one: a browser session must not be able
to give itself a login that outlives it.

Lost a token? Make a new one with `ui token add`, and `ui token rm` the old
one.

### Log in

- The login is always on, on loopback too.
- A wrong token costs 300 ms. It never locks the login: any program on this
  machine could otherwise keep you out. The log says how many were refused,
  once a minute.
- The session lasts 12 hours and belongs to the browser tab. A new tab, or the
  browser opened again, logs in again. No cookie is kept.
- A session ends with **Sign out**, when its token is revoked, with `ui off`,
  when the node restarts, and with **panic**.
- **Sign out** also clears what the page kept in this browser for the UI's
  address, so its other tabs of the UI sign in again too.

### Panic

**Panic** (on the Overview, or `nerve-node panic`) ends every web UI session
too. Maybe a browser or a session leaked; a leaked session must not undo the
panic. A command a session started just before it is stopped, and changes no
setting after the node is locked. (A `log clear` or `audit clear` that was
already running may still land.) To unlock in the UI, log in again with a
token, or run `nerve-node unlock`.

Run `nerve-node panic` again when a session started while the node was
locked may have leaked: it ends every session also when the node is locked
already.

A panic stops a leaked session, not a leaked token: whoever holds the token can
log in again and unlock. If a browser or a machine that kept the token (a
password manager fills it) is lost, first run `nerve-node ui token rm LABEL`
(its sessions end at once), or `nerve-node ui off`, and make a new token. Then
run `nerve-node panic` (again, if you ran it already), and check
`nerve-node status`: between a panic and the revoke the token's holder can
still log in and unlock.

### Who can reach it

| Who | Can | Cannot |
|---|---|---|
| A command of a center as `nerve-run` (`folder`, `allowlist` mode) | Open a connection, which is closed at once | Read a byte of the UI or try a token |
| A command of a center as you (`user` mode, `--as-owner`) | Reach the login page and try tokens, 300 ms each | Read a token or a session: the hashes are in the node's own folder, sessions only in the node's memory |
| Another account of this machine | The same as `nerve-run` | |
| Another machine | Only beyond loopback (below), and then only with a token | |

From this machine, only your account and root may connect. The token is what
keeps the commands of `user` mode out. A command of `user` mode can already
change the node's settings as you can (see [modes](policy-engine.md#modes-and-folders-as-the-owner-sets-them)); the web UI adds
no way for it.

On Windows the node runs as `nerve`, which cannot open another account's
process to read its account, so a local peer is told by its session:

- the process at the other end, from Windows' table of connections; its
  session, from the system's list of processes (which names it without
  opening it); and the account signed in to that session, from the logon
  screen's record of it (`LoggedOnSAMUser` under
  `HKLM\…\Authentication\LogonUI\SessionData\<session>`). The Terminal
  Services would name it too, but refuse an account like `nerve`, which is no
  administrator. Every account may read the record, and only administrators
  write it, which is what the rule rests on; it is written at each logon.
  Only a process of a session of yours gets in.
- Session 0 is closed: it holds every service, and the node's own commands.
- A process in one of the node's job objects is closed, beside the
  AppContainer's own block of loopback.
- The 16 places per peer are kept per session.

What remains on Windows: a program of another account started inside your
session (`runas`) reaches the login, where it needs a token. So may a
connection whose socket outlived the process that made it: the table names
that process's number, which Windows may give to a process of yours later.
The other account still needs a token at the login, but it can hold your
session's places while it waits there.

### What the web UI does

Every change in the UI is one `nerve-node` command, run for you by the node,
with every check the CLI makes. So the UI may do what you may do as the owner,
and nothing more.

| Page | Does |
|---|---|
| **Overview** | Status, the centers and their links, the root-as-owner warning, the warning that nothing keeps the pairings apart (the installed node without Landlock, with two or more pairings as `nerve-run`; on **Centers** too), **Panic** and **Unlock** |
| **Centers** | Pair from a pasted link (it goes to the node as the command's input, never in a command line), pause and resume, the settings grant, a new key, remove |
| **Permissions** | Mode (also for some hours, and as the owner), **No network for its commands** (`network off`, in every mode), folders (a whole path), allow, deny and sudo rules (an edit is one `rule edit` of the entry as listed), the guard, sudo off |
| **Audit** | What the node allowed and refused, refused only, Live; **Allow**, **Allow as wildcard** and **Deny** show the rule each one stores, made by the same code as `rule add`, and the list it goes to (the sudo list for a sudo command), with hidden characters written out; a wildcard is wider than the entry (`python3 *` for a `python3` call, the whole folder for a file), and the preview says so |
| **Log** | Problems only, Live, clear |
| **Capabilities** | A center's switches (on, off, hidden), your own capabilities (add, edit and remove, with the same checks as the desktop app's form), the programs that may add capabilities |
| **Relay** | Connect through a relay, or let other nodes reach this node's centers through it; a new node's link is shown once |
| **Settings** | The name, the log level, any setting by its name (**Advanced**), and **Web UI**: where it listens and its tokens, with **Revoke** |
| **Help** | The command reference |

Done only at the CLI: `install`, `update`, `uninstall`, `service …`, `setup`,
`sudo on`, `backup` and `restore`, `config accept`, every `ui …` change but
revoking a token, the settings that decide which account commands run as
(`machine.allow_root`, `machine.sudo_path`, `machine.shell`;
shown in the UI), and any setting under `ui`. The Overview shows the command
to start, stop or restart the service; a page served by the service cannot
restart it.

### Beyond loopback

```sh
nerve-node ui on --listen 0.0.0.0:7470
```

- Any address but loopback makes the UI reachable from the network. `ui on`
  says so, and how to keep it on loopback with the SSH tunnel instead.
- The UI is then served over HTTPS with a certificate of its own, made the
  first time. It names the address (when it is a specific one), this
  machine's name, `localhost`, and each `--host HOST`. Giving `--host` makes a
  new one.
- `ui on` and `ui` print its SHA-256 fingerprint. Your browser warns
  about the certificate the first time: compare the fingerprint it shows with
  the printed one before you sign in.
- `--new-cert` makes a new certificate: every session ends, and the browser
  asks again.
- Without its certificate the UI does not listen beyond loopback at all;
  `ui` says why.
- One address has at most 16 connections at once (an IPv6 /64 counts as one
  address, and on this machine each account counts as one). A browser opens
  six to load a page. A wrong token's 300 ms hold none of them.

The UI's certificate is its own, not the relay's. Its key is kept with the
node's other keys (`machine.secret_storage`). It is not in a backup: a restore
says when the restored config turns the UI on, and when it needs a new
certificate, which `ui on --new-cert` makes.

### node.toml

```toml
[ui]
listen = "127.0.0.1:7470"   # absent: off
pin = "…"                   # the certificate's pin, beyond loopback

[[ui.token]]
label = "laptop"
token_sha256 = "…"
made = "2026-11-02T10:00:00Z"
```

Change it with `nerve-node ui`, not by hand: a node.toml the node did not sign
is refused. A center never sees or changes `[ui]`.
