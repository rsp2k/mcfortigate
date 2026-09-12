---
title: Troubleshooting
description: Symptoms, what each one actually means, and the order to check things in.
---

Work from the outside in. Most failures are the client not passing the
environment, the appliance not trusting the source address, or the profile not
granting a read — in roughly that order of frequency.

## Start here: the startup line

The server writes one line to stderr when it starts, and it answers the first
question worth asking:

```
mcfortigate v2026.9.12.1 | targets: fgt.example.com
```

If that names your appliance, the environment reached the process. Everything
still broken is between the server and the firewall.

If it says `targets: none configured`, the environment did *not* reach the
process, and nothing about the FortiGate is relevant yet.

Claude Code surfaces this in its MCP logs. Other clients vary; if yours hides
server output, run the command by hand to see it:

```bash
printf 'FortiGate API token: '; read -rs FORTIGATE_TOKEN; echo
FORTIGATE_HOST=fgt.example.com FORTIGATE_TOKEN="$FORTIGATE_TOKEN" uvx mcfortigate
```

It will sit there waiting for stdio, which is correct. Ctrl-C out.

## An upgrade appears to have changed nothing

The most confusing failure in this list, because nothing about it looks like a
failure.

**A running MCP server serves the code it launched with.** `uvx mcfortigate`
resolves the latest release *at process start*, so after a new version is
published the old behaviour persists — a fixed bug stays fixed only for
processes started afterwards, and a new tool argument is rejected as unknown.
There is no error, no warning, and nothing in any response that says the code
is stale.

Restart the client, or restart the server from within it, and check the banner:

```
mcfortigate v2026.9.12.1 | targets: fgt.example.com
```

That version is the resolved one, not the one you meant to install. If it reads
older than the release you expect, the process predates it and everything you
are observing is the old behaviour, correctly.

Worth knowing because the symptom mimics a real bug precisely: a tool argument
documented here comes back rejected, or a response is missing a field this
reference says it carries. The first thing to check is the banner, not the
documentation.

## The server shows as failed in the client

**`uvx` is not on the client's PATH.** MCP clients often launch with a minimal
environment that is not your login shell's. `which uvx` in your terminal
proving it exists proves nothing about what the client sees. Use the absolute
path in the client configuration:

```bash
claude mcp add fortigate \
  --env FORTIGATE_HOST=fgt.example.com \
  --env FORTIGATE_TOKEN="$FORTIGATE_TOKEN" \
  -- /home/you/.local/bin/uvx mcfortigate
```

**The package could not be fetched.** `uvx` downloads on first run, so a
machine with no route to PyPI fails at startup. `uvx mcfortigate --help` in a
terminal tells you which it is.

**A brand-new release reports `no version of mcfortigate`.** If a version was
published within the last minute or so, this is propagation rather than a bad
upload, and `--refresh` does not help. PyPI's simple index carries the new files
before its JSON API does, and installers read the JSON-backed path — so the
release is genuinely there and genuinely not yet resolvable. Wait a minute and
retry unchanged.

To tell the two apart, ask the index that updates first:

```bash
curl -s https://pypi.org/simple/mcfortigate/ | grep -o 'mcfortigate-[0-9.]*'
```

If your version is listed there, it exists and you are waiting on propagation.
If it is not, the upload did not land.

## `targets: none configured`

The environment variables did not arrive.

For `claude mcp add`, each variable needs its own `--env` flag and they must
come *before* the `--` separator. Anything after `--` is the command, not
configuration.

For a JSON client configuration, the variables go in an `env` object inside the
server's entry, not at the top level of the file.

For `FORTIGATE_TARGETS`, malformed JSON is a startup error naming the parse
failure rather than an empty list — so if you are seeing `none configured` with
`FORTIGATE_TARGETS` set, the variable itself did not arrive.
[The quoting rules](/guides/several-appliances/#the-quoting) are where this
usually goes wrong.

## HTTP 401 from the appliance

Two causes, and they are indistinguishable from the response.

**The token is wrong.** API tokens are shown once at creation and cannot be
retrieved afterwards. If you are not certain of it, generate a new one:
`execute api-user generate-key <name>`.

**The source address is not in the trusted hosts list.** This is the more
common one, and it moves: a laptop on a different network, a container with a
different address than the host, a machine that got a new DHCP lease.

Check what the appliance actually sees:

```
diagnose debug enable
diagnose debug application httpsd -1
```

Then make a request and watch for the source address in the output. Turn it off
afterwards with `diagnose debug disable`.

Confirm the credential independently of everything else:

```bash
curl -sk "https://fgt.example.com/api/v2/cmdb/system/global?access_token=YOUR_TOKEN" | head -c 200
```

Success there and failure through the server means the server is not sending
what you think it is. Failure in both means the credential or the trusted host.

## HTTP 403, or an empty result where there should be data

The API admin's profile does not grant read on that part of the tree. A profile
granting System but not Firewall answers `get_system_status` and returns
nothing useful for policies, which looks like an empty firewall rather than a
permissions problem.

Grant read on System, Network, Firewall, and — if the box has radios —
WiFi & Switch Controller.
[The profile in full](/tutorials/getting-started/).

## Certificate errors

A FortiGate with the factory self-signed certificate fails verification, which
is correct behaviour and not a bug.

For a lab appliance, turn verification off for that target:

```bash
FORTIGATE_VERIFY_SSL=false
```

or per-target in the JSON: `{"host": "...", "token": "...", "verify_ssl": false}`.

For anything carrying production traffic, install a real certificate on the
management interface instead. The variable accepts `1`, `true`, `yes`, and `on`
as true and treats everything else as false, so a typo turns verification off
rather than on — check the value if you expected verification and are not
getting certificate errors.

## Wireless tools return nothing

If the appliance has no radios, `monitor/wifi/client` does not exist, and an
absent endpoint
[yields no rows rather than an error](/explanation/config-vs-live/#fail-soft-on-absence-never-on-denial).
Empty is the correct answer on a wired-only box.

If it *does* have radios and the list is still empty, check that the profile
grants read on WiFi & Switch Controller, and that you are querying the VDOM the
radios live in.

## The wrong appliance answered

With several targets configured, omitting `target` is an error rather than a
guess — so a wrong-appliance answer means the wrong alias was passed.

`list_targets` is the fastest way to see what the server actually has. It makes
no network calls, so it answers instantly and answers even when everything is
unreachable.

If two aliases share a prefix, that is usually the cause.
[Choosing aliases](/guides/several-appliances/#choosing-aliases).

## Timeouts

The default is 30 seconds per request. A `list_policies` call against a very
large ruleset, or any call across a slow WAN link to a branch appliance, can
exceed it.

```bash
FORTIGATE_TIMEOUT=60
```

or per-target in the JSON. Before raising it much further, check whether the
question can be narrowed — a filtered `list_policies` transfers a fraction of
what an unfiltered one does, and `search_config` with `include_policies: false`
drops most of its payload.

## Everything works but answers look wrong

Check the VDOM. Every call is scoped to one, `root` by default, and an
appliance with multiple VDOMs will cheerfully answer about the wrong one. The
VDOM in use is reported by `list_targets` and by `get_system_status`.

Check the firmware. The
[version-dependent field shapes](/explanation/fortios-quirks/#relational-fields-change-shape-by-version)
are handled for the versions they were observed on, and a version nobody has
tested may have its own. `get_system_status` reports it; an unexpected shape is
worth [an issue](https://github.com/rsp2k/mcfortigate/issues) with the raw
response attached.
