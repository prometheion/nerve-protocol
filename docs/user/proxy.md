# Reach the center through a proxy

A node can dial its centers through an HTTP proxy. The proxy is one setting
for the whole node, for every center.

```sh
nerve-node proxy set http://proxy.example:3128
nerve-node proxy ls
nerve-node proxy rm
```

The node opens the TLS link to the center inside a `CONNECT` tunnel. The
center's pin is still checked on that inner link, so the proxy sees only TLS
records. `center add` pairs through the proxy too.

Another node can be the proxy: see [relay](relay.md).

## A proxy over TLS

An `https://` proxy is reached over TLS of its own, and the `CONNECT` and its
login travel inside it. A relay is one: paste the link `relay add` on the
relay shows, which holds the relay's address, this node's name and token,
and the pin of the relay's certificate:

```sh
nerve-node proxy set 'nerve://relay?address=relay.example%3A7490&node=lab-pc&token=...&pin=...'
```

It is the same as the URL with the login and the pin:
`proxy set 'https://lab-pc:<token>@relay.example:7490' --pin=<pin>`.

Give the pin as `--pin=<pin>`: a pin can start with `-`, which would be read
as an option after a space.

Without `--pin` the proxy's certificate must be one this machine trusts. The
user name and password of an `https://` proxy are kept with the node's own
keys, where `machine.secret_storage` says: a file in the config folder by
default, or the system keyring ([config](config.md)). `proxy ls` shows the
pin and the user name, never the password.

## A proxy that wants a login

Put the user name and password in the URL, or send extra header lines on the
`CONNECT` request:

```sh
nerve-node proxy set 'http://user:password@proxy.example:3128'
nerve-node proxy set http://proxy.example:3128 --header 'X-Proxy-Token: abc'
```

Write special characters of the password as `%XX`. `--header` can be given
more than once.

An argument shows in the process list while the command runs. To keep the
secrets out of it, give the user name alone in the URL and the password on
stdin, and the headers after it, one a line (the desktop app does this):

```sh
printf '%s\n' "$PASSWORD" 'X-Proxy-Token: abc' |
  nerve-node proxy set http://user@proxy.example:3128 --password-stdin --headers-stdin
```

The values are secrets. The node keeps them in the system keyring (Keychain,
Credential Manager, Secret Service), in one entry named `proxy:<config folder>`
under the service `nerve`. `node.toml` keeps the URL without the login and the
header names. The values never reach a file, the audit log, a log line or an
error. `proxy ls` prints header names only.

A user name and password in the URL become a `Proxy-Authorization: Basic`
header. Do not give that header yourself in the same call.

## On the node installed as a service on Windows

The installed node on Windows runs as the account `nerve`, and the Credential
Manager is one per account. A header value or a password would go to the
Credential Manager of the account that sets the proxy, where the service does
not find it. The node keeps them nowhere else (not in a file), so the
installed node on Windows takes a proxy that needs neither: set it in the
[desktop app](desktop.md) under **Settings**, **Network**, **Proxy**, as
`http://proxy.example:3128`.

A proxy with a header, or with a user name and password in the URL, is
refused there and changes nothing. If the proxy needs a login, the installed
node on Windows cannot use it.

A header in `node.toml` is not read by the service: the link stays down. The
app's **Overview** shows it as `bad proxy:` with the reason, which it asks the
running node over its [control pipe](platforms.md#the-control-pipe). The
service's [log](logs.md) has the reason as an `error` line with `bad proxy:`, in
`C:\ProgramData\Nerve\state\log.jsonl`. Set the proxy again without the header,
or remove it; either deletes the old entry from the Credential Manager of the
account that does it.

## Environment variables

Without `proxy set`, the node uses `HTTPS_PROXY` and `NO_PROXY`. A user name or
password in `HTTPS_PROXY` is refused. Use `proxy set` for those.

## When the proxy fails

The node does not fall back to a direct connection. If the proxy is down, the
link stays down. If a keyring entry is missing or unreadable, the link stays
down and `nerve-node status` shows `bad proxy:` with the reason (on Windows the
app's **Overview**, which asks the node over its
[control pipe](platforms.md#the-control-pipe)). `proxy ls` and
the node's [log](logs.md) have the reason too.

On a Linux machine with no Secret Service (no desktop session), `proxy set`
with a header or a password refuses and changes nothing. A proxy without
either works there. The same holds for the node installed as a service on
Windows ([above](#on-the-node-installed-as-a-service-on-windows)).

A `node.toml` that holds header values or a login in the file is refused when
it loads. Take the values out of the file, run `nerve-node config accept`,
then run `proxy set` again.
