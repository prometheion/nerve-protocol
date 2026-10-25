# Run the center

The harness starts `nerve-center` itself, like any MCP server. Every setting is
a flag or an environment variable. The only subcommands are `backup` and
`restore`, which you run by hand ([backup](backup.md)), and `install`,
`update` and `uninstall`: on Linux the center can also
[run as a service](#run-it-as-a-service) that starts with the machine.

## Add it to the harness

```json
{
  "mcpServers": {
    "nerve": {
      "command": "nerve-center",
      "env": {
        "NERVE_NAME": "lab"
      }
    }
  }
}
```

The center then listens on:

| Port | For | Flag |
|---|---|---|
| 7443 | nodes | `--listen` |
| 7480 | the [web UI](web-ui.md), on this machine only | `--ui` |

Open `http://127.0.0.1:7480` to [pair a machine](pairing.md).

## Settings

| Flag | Variable | Default | Meaning |
|---|---|---|---|
| `--name` | `NERVE_NAME` | `nerve-center` | Name shown to nodes and in the web UI |
| `--state-dir` | `NERVE_STATE_DIR` | see [install](install.md#where-files-live) | Identity, paired machines, statistics |
| `--listen` | `NERVE_LISTEN` | `0.0.0.0:7443` | Where nodes connect |
| `--public-url` | `NERVE_PUBLIC_URL` | `https://<host name>:<port>` | The address written into pairing links |
| `--plain-loopback` | `NERVE_PLAIN_LOOPBACK` | off | Plain HTTP for nodes; only with a loopback `--listen` |
| `--ui` | `NERVE_UI` | `127.0.0.1:7480` | Web UI address, or `off` |
| `--ui-no-login` | `NERVE_UI_NO_LOGIN` | off | No login for the web UI; refused beyond loopback |
| `--mcp` | `NERVE_MCP` | `stdio` | `stdio`, `http` or `none` |
| `--mcp-listen` | `NERVE_MCP_LISTEN` | `127.0.0.1:7481` | Address of the HTTP MCP endpoint |
| `--harness-token` | `NERVE_HARNESS_TOKEN` | none | A [harness token](harness.md#tokens) |
| `--log` | `NERVE_LOG` | the level set in the web UI, `info` at first | `error`, `warn`, `info` or `debug`; wins over the stored level for this run. The [log](logs.md) goes to stderr and to `log.jsonl` |

`nerve-center --help` prints the same list.

Set `--public-url` when nodes reach the center under another name than its
host name, such as a DNS name or a forwarded port.

## TLS

Nodes connect over TLS. The center makes a self-signed certificate on its
first start. The pairing link carries the certificate's pin, so a node
trusts exactly that certificate.

The web UI and the HTTP MCP endpoint use plain HTTP on loopback. On any other
address they use TLS with the same certificate. `--plain-loopback` turns TLS
off for nodes too, but only for a loopback `--listen`.

## Rotate the key

In the web UI, Settings, **Center key**, press **Rotate key**. The center makes
a new key and shows its pin once. It tells every machine that is linked, and
every machine that links in the next 7 days, signed with the old key; each
machine then trusts the new key too. The center keeps serving the old key for
those 7 days, then switches to the new one. **Serve the new key now** switches
at once.

- A machine that does not link during the 7 days does not learn the new key.
  After the switch it cannot connect and has to be [paired again](pairing.md).
- New pairing links carry the pin of the key the center serves.
- The switch also changes the certificate of the web UI and the HTTP MCP
  endpoint when they use TLS. A browser asks to trust it again.
- The center's [log](logs.md) says when the key was rotated and when the new
  one is served. The keys are `tls.pem` and, during the 7 days, `tls.next.pem`
  in the state folder.

## Run it without a harness

The default `--mcp stdio` ends when the harness closes its input. To keep a
center running on its own, pick another mode:

```sh
nerve-center --mcp http --harness-token "$TOKEN"   # MCP over HTTP
nerve-center --mcp none                            # nodes and web UI only
```

On Linux with systemd, let it [run as a service](#run-it-as-a-service).

## One center per state folder

The first `nerve-center` on a state folder runs the center. A second one with
`--mcp stdio` finds it and attaches, so several harnesses on one machine share
one center, each with its own session. The first one keeps running until the
attached harnesses have ended too.

A second one with `--mcp http` or `--mcp none` refuses to start. On Windows a
second instance cannot attach and fails.

## Back it up

`nerve-center backup <file>` writes `tls.pem` and `state.json` to one file
that a passphrase protects; `nerve-center restore <file>` puts them back, on
this machine or another. The nodes then find the same center by the same pin
and need not pair again ([backup](backup.md)). The action checker's settings
come with `state.json`; its endpoint token and its local model do not.

## What the center keeps

In the state folder:

| File | Holds |
|---|---|
| `tls.pem` | The center's key and certificate |
| `tls.next.pem` | The new key, during the 7 days after a [key rotation](#rotate-the-key) |
| `state.json` | Center id and name, paired machines with their public keys and last descriptions, hashed harness tokens, daily statistics, the settings of the [action checker](action-checker.md) |
| `log.jsonl` | The [log](logs.md): links, pairing, changes, refused and failed calls, the action checker's decisions, errors. `log.jsonl.1` is the older half |
| `checker-model.token` | The bearer token of the action checker's model endpoint, when you set one (mode 0600) |
| `checker/` | The action checker's local model, when you installed it: the llama.cpp build and the model file, 1.7 or 3.0 GB |

It never stores file contents, command output or arguments. The one secret is
the endpoint token, which is in a file of its own and not in a
[backup](backup.md#the-center).

## Run it as a service

On Linux with systemd, `nerve-center` installs itself as a service, as the
node does ([service](service.md)). The service starts with the machine and
runs under a user of its own, `nerve-center`, with MCP over HTTP: harnesses
connect to it with a [harness token](harness.md#tokens) instead of starting
it. `install`, `update` and `uninstall` need root and take none of the
center's flags: the service's settings are in its
[settings file](#settings-of-the-service). Windows is not supported yet.

### Install

Download the program for your machine (`nerve-center-x86_64-linux` or
`nerve-center-aarch64-linux`, [install](install.md)) and run it once as
root:

```sh
curl -LO https://github.com/prometheion/nerve-protocol/releases/latest/download/nerve-center-x86_64-linux
chmod +x nerve-center-x86_64-linux
sudo ./nerve-center-x86_64-linux install
```

`install` does this, and says each step:

1. Makes the system user `nerve-center`, with its own group, no login and the
   home `/var/lib/nerve-center`. A `nerve-center` user that `install` did
   not make is refused.
2. Makes the state folder `/var/lib/nerve-center`, private to that user
   (mode 0700). A folder an earlier install left behind is given to the new
   user.
3. Writes the settings file `/etc/nerve-center/center.env`, which belongs to
   root (mode 0600), with a new harness token. A settings file that is there
   already is kept as it is.
4. Copies the program to `/usr/local/bin/nerve-center`.
5. Writes the unit `/etc/systemd/system/nerve-center.service`, enables it
   and starts it. It waits until the center answers.

Running `install` again repairs what is missing and restarts the service.

Then open the web UI, `http://127.0.0.1:7480`, and log in with the harness
token:

```sh
sudo grep NERVE_HARNESS_TOKEN /etc/nerve-center/center.env
```

The web UI asks for it from the start, so no other user of the machine gets
in before you. Harnesses on this machine use the HTTP MCP endpoint,
`http://127.0.0.1:7481/mcp`, with that token or one made in the web UI
([harness](harness.md)). A harness cannot start its own `nerve-center` on
this machine while the service runs: the node port is taken.

| What | Where |
|---|---|
| Identity and TLS key, paired machines, statistics, the [action checker](action-checker.md)'s settings and local model, [log](logs.md), harness socket | `/var/lib/nerve-center` |
| Settings | `/etc/nerve-center/center.env` |
| The program | `/usr/local/bin/nerve-center` |
| The unit | `/etc/systemd/system/nerve-center.service` |

Nothing else is written. `journalctl -u nerve-center` shows the center's
output.

The service starts with a new center. To move a center you ran yourself
into it, with its pairings, [back it up](backup.md#the-center) and restore
it into the service's state folder while the service is stopped:

```sh
nerve-center backup ~/nerve-center.bak     # as you, on the center you ran
sudo systemctl stop nerve-center
sudo nerve-center --state-dir /var/lib/nerve-center restore ~/nerve-center.bak --replace
sudo systemctl start nerve-center
```

Stop the center you ran yourself for good: the service has its key now.

### Settings of the service

The settings are the variables of the [table above](#settings), in
`/etc/nerve-center/center.env`. Change them there and restart the service:

```sh
sudo nano /etc/nerve-center/center.env
sudo systemctl restart nerve-center
```

The service runs with `--mcp http` unless the file sets `NERVE_MCP`;
`stdio` does not work there, as no harness gives it an input. The state
folder is fixed. The settings file belongs to root, so the center cannot
change how it is started.

The service has no privilege: no capability, and no new privileges through
a setuid program. It may write its state folder and nothing else on the
machine, and sees no home folders, no shared memory (`/dev/shm`) and no
hardware devices, so the action checker's local model runs on the CPU there. The
unit also keeps it from the kernel interfaces a center never needs: it may
not make namespaces, open other sockets than IPv4, IPv6 and Unix ones, or
make system calls outside systemd's `@system-service` set, and it cannot
see other processes or change kernel settings, the clock or the host name.
A `NERVE_LISTEN` on a port below 1024 fails; use a higher port, or forward
one to it.

### Update

```sh
sudo nerve-center update
```

`update` downloads `nerve-center-x86_64-linux` or
`nerve-center-aarch64-linux` from the latest release on GitHub, checks it
against the release's `SHA256SUMS`, puts it in place as
`/usr/local/bin/nerve-center` and restarts the service. `HTTPS_PROXY` is used
when it is set. `--from <file>` takes a program you downloaded and checked
yourself.

The state folder and the settings are not touched. `update` refuses a file
that is not `nerve-center` and a program older than the installed one. If the
new program does not start, the old one is put back and started again.

### Uninstall

```sh
sudo nerve-center uninstall           # keeps the state and the settings
sudo nerve-center uninstall --purge   # deletes them too
```

`uninstall` stops and disables the service, removes the unit, the user
`nerve-center` and `/usr/local/bin/nerve-center`. Without `--purge`,
`/var/lib/nerve-center` and `/etc/nerve-center` stay and belong to root from
then on, so no later user with the old uid gets the center's key. A later
`install` takes them up again: the center comes back with its pairings and
its harness token. `--purge` deletes them.

`install`, `update` and `uninstall` are refused from a command that the node
installed on the same machine runs for a center, as the node's own are
([service](service.md#the-rules-for-these-commands)).
