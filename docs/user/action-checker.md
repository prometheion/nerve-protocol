# The action checker

The action checker is a gate on the center. It looks at each call before the
machine gets it, and can only refuse: the machine's own rules still decide
what runs. Set it up on the web UI's **Action checker** page.

For each call it stops at the first step that decides:

1. **Blocklist** (on by default): dangerous commands and paths, such as
   `rm -rf ~` or `mkfs`. A match is refused at once.
2. **Skip the model**: calls you trust. A match skips the decision model,
   never the blocklist.
3. **Decision model** (off by default): a small model that judges whether
   the call is dangerous. At or above its threshold, the call is refused.

A refused call comes back to the agent as `forbidden`, saying that the
center's action checker refused it and why. Each decision is on the
center's Audit and Log pages. A block anywhere wins: a call the machine
denies is refused, whatever the center allows.

- The action checker's blocklist and the node's guard catch mistakes by
  name, not someone who hides the name. The mode, the rules and the account
  are the protection ([blocklist](../dev/action-checker.md#the-blocklist)).

## The blocklist

A new center has the default entries. On the page, switch one off, add your
own, or **Reset** to the defaults. An entry may hold for every machine or
for one. A refusal on the Audit page links to "switch this entry off for
this machine". Entries use the machine's rule syntax:
`exec.run:rm -rf /*`, `fs.write:/etc/sudoers`
([entries](../dev/action-checker.md#the-blocklist)).

## Skip the model

Rules in the same syntax, for every machine or one. The Audit page's
**Trust this** and **Trust as wildcard** add one from a call.

- An `exec.run` rule covers a command line only when every command in it
  matches: `exec.run:make *` covers `make test && make lint`, not
  `make test && ./deploy.sh`.
- A pattern without `*` covers no flag it does not name: `exec.run:git
  status` does not cover `git status --porcelain`.

## The decision model

Turn it on with one of two sources:

- **A local model** the center installs for you: pick it, then press
  **Install on CPU** (or **Install on GPU**). The download goes into the
  center's own state folder. **Remove** deletes it.
- **An endpoint**: a URL, an optional bearer token and a model name. The
  token is kept in a file of its own, never shown back.

| Model | Size | Memory | Speed and quality on a desktop CPU |
|---|---|---|---|
| **d1-2B** (default) | 1.1 GB | about 2 GB | about 2 s a call; catches about 55 % of dangerous actions |
| **Kev-4B** | 3.0 GB | about 6 GB | about 5 s a call; catches about 80 % |

Check that a model's licence suits you: d1-2B is under the LFM Open License,
Kev-4B under Apache-2.0. On a small machine, raise the timeout or use an
endpoint ([measured](../dev/action-checker.md#the-evaluation)).

The settings are under **Advanced**: which calls the model sees (by default
every execute, write and actuate call), the threshold, the timeout, and what
an error or a timeout does.

- The decision model fails closed by default: while it is on and not
  running, every call it checks is refused. The page shows a red banner
  then ([decision model](../dev/action-checker.md#the-decision-model)).
- The installed center sees no GPU. Its local model runs on the CPU
  ([the service](../dev/service.md#settings-of-the-service)).
- A backup holds neither the endpoint token nor the local model. After a
  restore elsewhere, enter the token again or install the model.

## Taint

A session becomes **tainted** once a call returned outside content: a read,
a search, a command's output. The Overview marks it. The model can be set to
see only the calls of tainted sessions
([taint](../dev/action-checker.md#taint)).
