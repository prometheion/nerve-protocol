# The web UI

`nerve-center` serves a web UI at `http://127.0.0.1:7480` (`--ui`). Its pages,
scripts and styles are built into the program. It loads nothing from another
host. The installed node on Linux has a web UI of its own:
[node web UI](node-web-ui.md).

## Log in

The UI always asks for the **owner token**, on loopback too. It is not a
[harness token](harness.md#tokens): those open the HTTP MCP endpoint only.
A harness keeps its token in its own settings, where the agent may read it,
and this UI can switch the action checker off and change what the machines
allow, so a harness token never logs in here.

- The center makes the owner token at its first start. It prints it on
  stderr, and keeps it in `owner-token` in the state folder (mode 0600):
  `~/.local/state/nerve-center/owner-token` for a center you run yourself,
  `/var/lib/nerve-center/owner-token` for the [service](center.md#run-it-as-a-service),
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
  [service](center.md#run-it-as-a-service), which runs as its own account.
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
- A [backup](backup.md) does not hold the owner token. A restored center
  makes a new one at its next start.

To reach a UI that listens on loopback from another machine, use an SSH tunnel:

```sh
ssh -L 7480:127.0.0.1:7480 user@center-host
```

## Look

The web UI has the desktop app's design: the same colours, type, controls and
motion. The switch at the foot of the menu picks **System**, **Light** or
**Dark**; the choice stays in this browser. When the system asks for less
motion, nothing moves. On a phone the menu opens from the button at the top.

## Pages

### Overview

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
- **Pair a machine.** Makes a [pairing](pairing.md) command and its bare link
  (for the desktop app), each with Copy.
- **Sessions.** The harnesses connected now, each marked `tainted` once the
  [action checker](action-checker.md#taint) marked it. **End** stops one
  session.
- Alerts, for example a machine whose key is in use twice.

A disabled machine stays paired and connected. The agent's `list` shows it as
disabled with no capabilities, and calls to it are refused. The agent's calls
that run there stop, its [jobs](harness.md#long-calls-become-jobs) too, and so
do the streams and event subscriptions of a program there; after **Enable**
the agent opens them again with `execute`.

### Statistics

The numbers of all machines together: time online, links, drops, calls, failed
calls, then calls per action with the average and the longest time, and errors
by code. Only counts and times are kept, never content. They are kept for the
number of days set in Settings.

To see one machine, open the **Machine** list under the page header and pick it.
The header then names the machine ("Statistics: web-1") and the page shows its
numbers alone.

- Type in the search field to narrow the list to the entries whose name
  contains what you typed, in any letter case. The list shows a few entries at a
  time and scrolls, so it stays short with many machines.
- With the keyboard: **Down** or **Up** on the list's button opens it, **Down**
  and **Up** move through the entries (**Page Down** and **Page Up** by six),
  **Enter** picks the marked one and **Escape** closes the list without a
  change.
- **All machines**, the first entry, goes back to the numbers of all machines
  together. It is filtered like the others: clear the search field to see it.

The list names every paired machine, also one that has no numbers yet. Its
numbers are then zero. When a picked machine is removed or renamed, the page
goes back to all machines. The choice lasts until you reload the page.

### Audit

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
([rules](rules.md#rules-on-an-actions-arguments)). The machine checks it
against the action's arguments as it saves it.

A sudo command goes on the sudo list when you press Allow. A button adds the
rule on the machine, so it works only if the machine gave the center the
[settings grant](settings-grant.md). Otherwise the buttons are off and the
entry says why. Even with the grant, Allow for something that senses or acts
on the world (a camera, a lock), or for a capability no program on the machine
offers now, is refused: that is the owner's, on the machine
([providers](providers.md)). A target that was cut to its start gets no
buttons.

A decision the center's [action checker](action-checker.md) made shows here
too, marked as the checker's and with whether the entry or switch was the one
for every machine or this machine's own. A model refusal gets **Allow** and **Allow as
wildcard** buttons that save a checker allow rule (center-side, so no settings
grant is needed), and **Allow with this value** for an argument it pins.
**Allow** saves the refused command line exactly. A blocklist refusal has none: it is a hard deny, so you
change or remove the entry on the Action checker page. Only the center marks
an entry as the checker's: a machine's own entry that claims to be one shows
as that machine's.

### Action checker

The center's gate on every call ([action-checker](action-checker.md)): a
deterministic blocklist, saved allow rules, and an optional decision model,
each with its own switch. The page lets you edit the blocklist (add, remove,
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

### Capabilities

What each machine offers the agent, and the capabilities this center added
there itself. Pick the machine from the **Machine** list under the page
header (it works like the one on the Statistics page). A machine whose list
does not load says why there, and one removed meanwhile drops out of the
list.

- **Offered.** Each unit the agent may be offered on that machine: its name,
  what it does (its effect), whether it is an action, a state, an event or a
  stream, and where it comes from: built in, your `node.toml`, this center,
  or a program you allow ([providers](providers.md)). One the owner switched
  off is marked off.
- **Left out.** The units the center does not offer the agent, each with the
  reason (a name it cannot carry, or a schema it cannot check).
- **Added by this center.** Only for a machine that gave the center the
  [settings grant](settings-grant.md) and is online:
  the [capabilities this center added](config-capabilities.md#capabilities-a-center-adds),
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
machine on Windows takes none yet, and one its owner runs by hand has no
`nerve-run`: the page says so and offers no form.

A machine without the settings grant is shown read only: its units and the
left-out ones, and a note that the center may change nothing there.

### Log

What the center did and saw, newest first: links that dropped and came back,
pairing, changes, refused and failed calls, and errors. A line shows the time,
its level, the machine it is about and what happened. The page is the center's
own [log](logs.md); it is not the audit page above.

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

The two lists work like the one on the Statistics page: type in the search
field to narrow a list, **Down** and **Up** move through it, **Enter** picks
the marked entry and **Escape** closes it.

### Help

Built like the desktop app's Help: two parts that open and close on their own.

- **Keyboard shortcuts.** The keys of the web UI.
- **Command reference.** The commands of `nerve-node`, the program on each
  machine. The center reads them from the node's own command definition, so
  they match `nerve-node --help` of the same build. Type in the filter to keep
  the commands whose name, explanation or arguments contain it, and list them
  **By topic** or **A to Z**. A topic opens and closes its commands; a command
  opens on what it does, how it is written and its arguments.

**User guide** at the top opens these pages on GitHub.

### Settings

- **Center.** Its name, how many days to keep statistics, how long a
  pairing code is valid (1 to 1440 minutes, 10 by default), and the **log
  level**: error, warn, info (the default) or debug. The level applies at once
  and stays for the next start. If the center was started with `--log`, that
  level holds for this run and the one you pick is kept for the next start.
- **Center key.** The pin of the key the center serves. **Rotate key** makes
  a new key and shows its pin once; **Serve the new key now** ends the 7 days
  in which the old key is still served ([center](center.md#rotate-the-key)).
- **Harness tokens.** Make a token with a label. It is shown once. Delete one
  to stop it: the harness sessions it opened over HTTP end at once, with
  their jobs. A token is only shown once the center has written it to its
  state file; when it cannot, the page says so and no token is made. A
  token deleted while the state file cannot be written stops at once, but
  the page says the delete is not kept yet: unless the file can be written
  before the center stops, the token works again at the next start. The
  same holds for a removed machine. The token of the center's settings (`NERVE_CENTER_HARNESS_TOKEN` or
  `--harness-token`) is listed too, without **Delete**: remove it from the
  settings. A harness token does not log in to this UI.
- **Machines.** For each online machine that gave the center the settings
  grant: its settings as JSON, with **Reload** and **Save**, and the sudo
  switch. The capabilities the center adds are on the Capabilities page, not
  in this document. A save sends the whole document with its version. If the version is
  stale, the machine refuses it. Reload and try again. A machine without the
  grant says it keeps its settings to itself.
