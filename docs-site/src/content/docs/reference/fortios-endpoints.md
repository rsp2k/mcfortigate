---
title: Tool to endpoint map
description: Which FortiOS REST endpoints each tool calls, and how many calls a question actually costs.
---

Useful for three things: sizing the read-only API profile you grant, reading a
FortiGate's own API audit log and recognizing what produced each line, and
knowing which questions are cheap and which are not.

## Configuration tree (`cmdb`)

| Tool | Endpoints |
|---|---|
| `get_system_status` | `cmdb/system/global`, plus `monitor/system/status` for uptime |
| `list_address_objects` | `cmdb/firewall/address` |
| `list_address_groups` | `cmdb/firewall/addrgrp` |
| `list_services` | `cmdb/firewall.service/custom` |
| `list_policies` | `cmdb/firewall/policy` |
| `list_vips` | `cmdb/firewall/vip` |
| `list_interfaces` | `cmdb/system/interface` |
| `list_vlans` | `cmdb/system/interface` |
| `list_static_routes` | `cmdb/router/static`, plus `cmdb/firewall/address` when any route names an address object |

## Monitor tree

| Tool | Endpoints |
|---|---|
| `get_routing_table` | `monitor/router/ipv4` |
| `list_dhcp_leases` | `monitor/system/dhcp` |
| `get_arp_table` | `monitor/network/arp` |
| `list_wifi_clients` | `monitor/wifi/client`, `monitor/system/dhcp`, `monitor/network/arp` |
| `find_device` | `monitor/wifi/client`, `monitor/system/dhcp`, `monitor/network/arp` |

## Multi-call tools

Two tools are worth more than one REST call each by design, because the
question they answer spans object types that FortiOS keeps apart.

`find_references` issues five calls: `cmdb/firewall/policy`,
`cmdb/firewall/addrgrp`, `cmdb/firewall.service/group`, `cmdb/firewall/vip`,
and `cmdb/router/static`. Ask *is this safe to delete* and all five run, because
a reference in any one of them is a reason the answer is no.

`search_config` issues six by default: `cmdb/firewall/address`,
`cmdb/firewall/addrgrp`, `cmdb/firewall.service/custom`,
`cmdb/system/interface`, `cmdb/router/static`, and `cmdb/firewall/policy`.
Passing `include_policies: false` drops the last one, which on a large
appliance is most of the transferred bytes.

`list_targets` makes no calls at all. It reports what the server was
configured with, not what it can currently reach, so it answers instantly and
also answers when every appliance is unreachable.

## Status handling

The monitor tree varies by platform and firmware in ways the configuration tree
does not. A FortiGate with no wireless hardware has no `monitor/wifi/client` at
all; some endpoints appear only above a given firmware version.

Monitor reads therefore carry a status alongside their rows rather than
returning a bare list:

| Status | Cause | Treated as |
|---|---|---|
| `ok` | HTTP 200 | Data |
| `unsupported` | HTTP 404 or 405 | Absence, safe to carry on |
| `denied` | HTTP 401 or 403 | A permissions problem, reported |
| `error` | Any other status, or a transport failure | A failure, reported |

Only `unsupported` is treated as *nothing there*. That is what lets
`find_device` keep working on a wired-only appliance while a denied read still
gets surfaced instead of quietly reading as an empty network.

Configuration reads do not degrade at all — any status other than 200 raises.

## Why status has to be checked here

The client library's connector does the equivalent of
`if not response.ok: return []`. Every 401, 403, 404, and 500 arrives as an
empty list, with no exception and no status. So `api.cmdb.*.get()` is not used
anywhere in this package; reads go through helpers that check status first and
normalize the `results` payload afterwards.

The same helper also handles a second library problem. FortiOS returns a list
for table endpoints and a bare object for singular ones such as
`system/global`, and the library coerces with `list()` — which on an object
yields its *keys* as strings, so callers receive a list of meaningless strings
rather than a record.

## Errors that arrive as HTTP 500

FortiOS answers many user-fixable mistakes with HTTP 500 and a body like:

```json
{ "status": "error", "error": -23, "cli_error": "..." }
```

rather than with a 4xx. Losing that body turns a diagnosable problem into a
silent no-op, so the HTTP status and the FortiOS error code are kept as
attributes on the raised error rather than only as text, which is what lets a
partially-failed tool report *denied: http=403* in `sources_checked` without
parsing an error message back apart.

## Sizing the API profile

Every endpoint above is read with `GET`. A read-only administrator profile with
read access to System, Firewall, Router, and Network — plus Wi-Fi if the
appliance has radios — covers the whole tool surface. Nothing needs write access
anywhere, and granting it would not enable any additional tool, because
[there is no write path in the codebase to reach](/explanation/read-only/).
