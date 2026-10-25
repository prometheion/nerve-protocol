# The web UI

`nerve-center` serves a web UI at `http://127.0.0.1:7480` (`--ui`). Its pages,
scripts and styles are built into the program. It loads nothing from another
host.

## Log in

The UI logs in with a [harness token](harness.md#tokens), the same secret the
HTTP endpoint takes.

| Where the UI listens | Login |
|---|---|
| Loopback, no token yet | None. This lets you make the first token |
| Loopback, a token exists | On. `--ui-no-login` turns it off |
| Any other address (`--ui 0.0.0.0:7480`) | Always on, and the UI uses TLS. The center refuses to start without a token or with `--ui-no-login` |

- A browser without a session goes to `/login` and posts the token once.
- The session lasts 12 hours. **Sign out** ends it.
- Five wrong tokens in a minute lock the login for the rest of that minute.
- Deleting a token ends the sessions that used it.
- Lost the token? Start the center once with `--ui-no-login` on loopback and
  make a new one.

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
  character other than letters, digits and `-`, or a schema the center
  cannot check (arguments or result, for example one with `oneOf`). When a
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

A disabled machine stays paired and connected. The agent gets none of its tools
and calls to it are refused.

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

A sudo command goes on the sudo list when you press Allow. A button adds the
rule on the machine, so it works only if the machine gave the center the
[settings grant](settings-grant.md). Otherwise the buttons are off and the
entry says why. Even with the grant, Allow for something that senses (a
camera), or for a capability no program on the machine offers now, is
refused: that is the owner's, on the machine
([providers](providers.md)). A target that was cut to its start gets no
buttons.

A decision the center's [action checker](action-checker.md) made shows here
too, marked as the checker's and with whether the entry or switch was the one
for every machine or this machine's own. A model refusal gets **Allow** and **Allow as
wildcard** buttons that save a checker allow rule (center-side, so no settings
grant is needed). A blocklist refusal has none: it is a hard deny, so you
change or remove the entry on the Action checker page.

### Action checker

The center's gate on every call ([action-checker](action-checker.md)): a
deterministic blocklist, saved allow rules, and an optional decision model,
each with its own switch. The page lets you edit the blocklist (add, remove,
switch single entries off, reset to the defaults) with entries for every
machine or one, keep allow rules for every machine or one, set the blocklist
and the model on or off per machine and switch single entries off for one
machine (**Per machine**), and set up the model (a System One endpoint, or a
local model the center installs with one click, d1-3B or Kev-4B) with its
threshold, timeout, question and which calls it sees. It shows the install's
progress and the local model's state, and names each model's size and
licence. Taint, which marks a session once a call of it returned content, has
its switch here too. Everything is kept in the center's state, except the
endpoint token and the local model's files.

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
  to stop it.
- **Machines.** For each online machine that gave the center the settings
  grant: its settings as JSON, with **Reload** and **Save**, and the sudo
  switch. A save sends the whole document with its version. If the version is
  stale, the machine refuses it. Reload and try again. A machine without the
  grant says it keeps its settings to itself.
