---
title: Configuration
description: Every environment variable mcfortigate reads, how a host string is parsed, and how the two configuration styles interact.
---

All configuration is environment variables, read once at startup. Credentials
never appear in a tool argument or a tool response, and the dataclass holding
them excludes the secret fields from its `repr`, so a stray log line or a
traceback cannot leak them either.

## Single appliance

The common case. Two variables are enough.

```bash
FORTIGATE_HOST=fgt-edge1.example.com
FORTIGATE_TOKEN=your-token
```

| Variable | Default | Meaning |
|---|---|---|
| `FORTIGATE_HOST` | — | Hostname, or a full URL. Required for this style |
| `FORTIGATE_TOKEN` | — | REST API token. Preferred over username and password |
| `FORTIGATE_USERNAME` | — | Legacy auth, used only when no token is set |
| `FORTIGATE_PASSWORD` | — | Legacy auth, used only when no token is set |
| `FORTIGATE_NAME` | the host | The alias tools use for this appliance |
| `FORTIGATE_VDOM` | `root` | Which VDOM to query |
| `FORTIGATE_PORT` | from the host URL, else the scheme default | Management port |
| `FORTIGATE_VERIFY_SSL` | `true` | Verify the appliance's TLS certificate |
| `FORTIGATE_TIMEOUT` | `30` | Per-request timeout in seconds |

A target with neither a token nor a complete username and password pair is a
configuration error, raised by name at startup.

### Truthiness

`FORTIGATE_VERIFY_SSL` accepts the spellings people actually write in a `.env`
file. `1`, `true`, `yes`, and `on` are true, case-insensitively. Everything
else is false. There is no clever coercion here and no attempt to guess: a typo
in this variable turns verification *off*, which is the failure direction you
can detect rather than the one that silently succeeds.

### How the host string is parsed

`fortigate-api` wants host, port, and scheme as three separate arguments rather
than one URL, and operators write the host every possible way, so all of them
are normalized to the same thing.

| You write | Host | Port | Scheme |
|---|---|---|---|
| `fgt.example.com` | `fgt.example.com` | none | `https` |
| `https://fgt.example.com` | `fgt.example.com` | none | `https` |
| `https://fgt.example.com:8443/` | `fgt.example.com` | `8443` | `https` |
| `http://fgt.lab:8080` | `fgt.lab` | `8080` | `http` |

A bare hostname is assumed to be HTTPS, which is the only sane default for a
firewall management interface. An explicit `FORTIGATE_PORT` wins over a port
embedded in the host URL.

## Several appliances

Set `FORTIGATE_TARGETS` to a JSON object mapping a short alias to that
appliance's connection details. The keys become the `target` argument on every
tool, so short and memorable beats descriptive.

```bash
FORTIGATE_TARGETS='{
  "edge":   {"host": "fgt-edge1.example.com", "token": "..."},
  "branch": {"host": "fgt-br2.example.com", "token": "...", "verify_ssl": false},
  "lab":    {"host": "https://fgt.lab:8443", "username": "readonly", "password": "..."}
}'
```

Per-target keys, all optional except the host:

| Key | Default | Meaning |
|---|---|---|
| `host` | — | Hostname or full URL. `url` is accepted as a synonym |
| `token` | — | REST API token |
| `username` / `password` | — | Legacy auth, used only when no token is set |
| `port` | from the host URL | Management port. Wins over a port in `host` |
| `vdom` | `root` | Which VDOM to query |
| `verify_ssl` | `true` | Verify the appliance's TLS certificate |
| `timeout` | `30` | Per-request timeout in seconds |

Malformed JSON here is a startup error naming the parse failure, rather than a
silently empty target list.

## How the two styles interact

They are not exclusive. `FORTIGATE_TARGETS` is read first, then
`FORTIGATE_HOST` is added to the same registry if it is set. A single-appliance
setup can therefore grow a second appliance by adding `FORTIGATE_TARGETS`
without moving the first, which is the direction these configurations usually
grow.

One consequence worth knowing: the single-appliance block is registered *after*
the JSON block, so if `FORTIGATE_NAME` matches a key in `FORTIGATE_TARGETS`,
the single-appliance settings win. Give them different names unless you mean
the override.

## Target resolution

With exactly one appliance configured, `target` can be omitted on every tool,
and `list_targets` reports it as `default_target`.

With several, omitting `target` is an error whose message lists the valid
aliases. That is a deliberate choice about how a model recovers. An error
naming `branch, edge, lab` lets the next call be correct, where a silent pick
of the first alphabetically would produce a confident answer about the wrong
firewall.

An unknown alias fails the same way, listing what is configured.

## When nothing is configured

The server still starts. An empty registry is not treated as a fatal error at
import time, because an MCP client showing nothing but *failed to connect*
tells an operator far less than a tool that answers with an explanation. The
misconfiguration is reported through `list_targets`, through the first tool
call that needs a target, and on stderr at startup for clients that surface
server logs.

## Sessions

A session is opened per tool call rather than pooled. With token auth this
costs nothing, because the token travels on every request and there is no login
round-trip to amortize. With username and password there is one login per call,
which is the price of never holding a stale session across an MCP server that
may sit idle for hours between questions.

When `verify_ssl` is false, urllib3's unverified-HTTPS warning is suppressed
for the duration of that call. A lab appliance with a self-signed certificate
is a deliberate configuration, not something worth warning about on every
single request.
