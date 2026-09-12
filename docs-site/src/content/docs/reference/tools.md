---
title: Tool reference
description: Every tool mcfortigate exposes, with its arguments, its return shape, and the FortiOS behaviour it accounts for.
---

Seventeen tools, in four groups. Every one of them takes an optional `target`
argument naming which appliance to query, which can be omitted entirely when
only one is configured. When several are configured and `target` is left out,
the error names the valid aliases so the model can correct itself on the next
call rather than guessing.

Every tool issues `GET` requests only. There is no write path anywhere in the
codebase, and every tool carries the MCP `readOnlyHint` annotation so a client
knows that before it calls one.

Responses name both the appliance and the VDOM they were read from, since every
call is scoped to a single VDOM and an answer about the wrong one is otherwise
indistinguishable from an answer about yours.

## Orientation

### `list_targets`

Which FortiGate appliances this server can reach. Call it first when several
may be configured. Credentials never appear in the response.

Takes no arguments.

```json
{
  "count": 2,
  "default_target": null,
  "targets": [
    {
      "name": "branch",
      "url": "https://fgt-br2.example.com",
      "vdom": "root",
      "auth_mode": "token",
      "verify_ssl": false,
      "timeout": 30
    },
    {
      "name": "edge",
      "url": "https://fgt-edge1.example.com",
      "vdom": "root",
      "auth_mode": "token",
      "verify_ssl": true,
      "timeout": 30
    }
  ]
}
```

`default_target` is populated only when exactly one appliance is configured.
When it is `null`, every other tool requires an explicit `target`.

### `get_system_status`

Appliance identity and health: model, serial, firmware version, build,
hostname, and current load.

| Argument | Type | Default | Meaning |
|---|---|---|---|
| `target` | string | only appliance | Which FortiGate to query |

```json
{
  "target": "lab",
  "url": "https://fgt-edge1.example.com",
  "hostname": "fgt-edge1",
  "model": "FortiWiFi 61E",
  "serial": "FWF61ETK00000000",
  "version": "v7.0.14",
  "build": 601,
  "vdom": "root",
  "runtime_status": "ok",
  "model_number": "61E",
  "log_disk": "available",
  "cpu_percent": 4,
  "memory_percent": 41,
  "sessions": 87
}
```

| Field | Always | Meaning |
|---|---|---|
| `target`, `url`, `vdom` | yes | Which appliance answered, and the scope |
| `hostname` | yes | From the monitor tree, falling back to the configuration |
| `model` | yes | `model_name`, falling back to `model` |
| `serial`, `version`, `build` | yes | From the response envelope |
| `runtime_status` | yes | Status of the `monitor/system/status` read |
| `alias`, `timezone`, `model_number`, `log_disk` | no | Present only when reported |
| `cpu_percent`, `memory_percent`, `sessions` | no | Current load, present only when reported |
| `uptime_seconds` | no | Present only on firmware that carries it |
| `load_status` | no | Present only when the load read failed |

The serial, version, and build come from the *envelope* of the cmdb response
rather than from `results`. FortiOS puts them as siblings of `results` on every
cmdb call, and any helper that unwraps straight to `results` throws them away,
which is why the serial looks absent from the API until you read the raw
response. See [identity lives in the envelope](/explanation/fortios-quirks/#identity-lives-in-the-envelope).

#### Absent fields are omitted, not null

An absent key means the appliance did not offer the value, rather than the
value being zero or unknown-but-present.

That distinction was settled the expensive way. `uptime_seconds` was documented
and returned for weeks as a permanent `null`, which read like a parsing bug.
Probing a FortiWiFi-61E on FortiOS 7.0.14 found it is not a bug at all —
**that firmware reports no uptime anywhere**:

| Endpoint | What it returns | Uptime? |
|---|---|---|
| `monitor/system/status` | `hostname`, `model`, `model_name`, `model_number`, `log_disk_status` | no |
| `monitor/system/resource/usage` | `cpu`, `mem`, `disk`, `session`, `setuprate`, lograte counters | no |
| `monitor/system/time` | `time`, as epoch seconds | no, that is wall clock |

The lookup is kept because newer firmware does carry it, so the key appears
where it exists and is absent where it does not.

There is one trap in reading this shape, and it is worth stating because it is
easy to reintroduce: **filter on `is not None`, never on truthiness**. A
genuinely idle appliance reports `cpu_percent: 0`, and a truthiness filter
discards that as though the appliance never answered.

#### Two reasons a load figure can be missing

`runtime_status` and `load_status` exist to separate them. A firmware that does
not implement the endpoint and a token that is not allowed to read it both
produce no numbers, and they call for completely different responses from you.
`load_status` appears only in the second case, carrying the reason —
`denied: http=403`, say. See [fail soft on absence, never on
denial](/explanation/config-vs-live/#fail-soft-on-absence-never-on-denial).

### `search_config`

Where a term appears, across every object type at once. This is the tool for an
open question when you do not yet know which kind of object holds the answer.

| Argument | Type | Default | Meaning |
|---|---|---|---|
| `term` | string | required | Case-insensitive substring to look for |
| `target` | string | only appliance | Which FortiGate to query |
| `include_policies` | boolean | `true` | Search policy names, comments, and member lists |

It looks through address objects, address groups, services, interfaces, static
routes, and optionally policies, matching against names, values, comments, and
member lists. Only the categories that matched appear in the response, so an
empty category is absent rather than present and empty.

```json
{
  "target": "edge",
  "term": "10.20.30.0",
  "total_matches": 3,
  "matches": {
    "addresses": [
      { "name": "LAN-USERS", "type": "ipmask", "value": "10.20.30.0/24" }
    ],
    "address_groups": [
      { "name": "INTERNAL", "members": ["LAN-USERS", "LAN-SERVERS"] }
    ],
    "routes": [
      { "seq_num": 3, "destination": "10.20.30.0/24", "gateway": "192.0.2.1", "interface": "wan1", "enabled": true }
    ]
  }
}
```

Policies are the largest table on most appliances, so `include_policies: false`
is worth passing when only object definitions matter.

## Firewall

### `list_address_objects`

Named addresses that policies reference, each with one readable value
regardless of its type.

| Argument | Type | Default | Meaning |
|---|---|---|---|
| `target` | string | only appliance | Which FortiGate to query |
| `name_contains` | string | none | Case-insensitive substring filter on the name |
| `address_type` | string | none | Exact FortiOS type: `ipmask`, `fqdn`, `iprange`, `geography`, `mac` |

Each FortiOS address type keeps its value in a differently named field. A
subnet object holds `subnet`, an FQDN object holds `fqdn`, a range holds
`start-ip` and `end-ip`. The type discriminator is resolved once here so every
object reports a single `value` string.

```json
{
  "target": "edge",
  "count": 2,
  "addresses": [
    { "name": "LAN-USERS", "type": "ipmask", "value": "10.20.30.0/24" },
    { "name": "UPDATE-SERVER", "type": "fqdn", "value": "updates.example.com", "comment": "vendor patch mirror" }
  ]
}
```

### `list_address_groups`

Groups and their members.

| Argument | Type | Default | Meaning |
|---|---|---|---|
| `target` | string | only appliance | Which FortiGate to query |
| `name_contains` | string | none | Case-insensitive substring filter on the group name |

```json
{
  "target": "edge",
  "count": 1,
  "groups": [
    { "name": "INTERNAL", "members": ["LAN-USERS", "LAN-SERVERS", "MGMT"] }
  ]
}
```

### `list_services`

Service objects with their protocols and ports.

| Argument | Type | Default | Meaning |
|---|---|---|---|
| `target` | string | only appliance | Which FortiGate to query |
| `name_contains` | string | none | Case-insensitive substring filter on the service name |

FortiOS scatters the port range across `tcp-portrange`, `udp-portrange`, and
`sctp-portrange`, populating only the ones that apply, while `protocol` itself
may read `TCP/UDP/SCTP` meaning *any of the populated ones*. Multi-port values
are space-separated, which is how Kerberos arrives as `88 464`.

```json
{
  "target": "edge",
  "count": 3,
  "services": [
    { "name": "HTTPS", "protocol": "TCP", "ports": { "tcp": "443" } },
    { "name": "KERBEROS", "protocol": "TCP/UDP", "ports": { "tcp": "88,464", "udp": "88,464" } },
    { "name": "PING", "protocol": "ICMP", "icmp_type": 8 }
  ]
}
```

Services defined as `protocol: IP` report a named protocol where one is known,
so GRE comes back as `"protocol": "GRE", "protocol_number": 47`. Protocol
number 0 reports as `any`, because FortiOS uses *IP with no protocol number* to
mean any IP protocol in its built-in `ALL` service, and reading it as IANA's
HOPOPT would be technically defensible and operationally wrong.

### `list_policies`

Firewall rules in evaluation order, with filters.

| Argument | Type | Default | Meaning |
|---|---|---|---|
| `target` | string | only appliance | Which FortiGate to query |
| `enabled_only` | boolean | `false` | Drop policies whose status is disabled |
| `interface` | string | none | Exact match on source or destination interface |
| `address` | string | none | Exact match on an address object or group, either side |
| `service` | string | none | Exact match on a service object name |

Policies come back in the order FortiOS evaluates them, which is configuration
order rather than sorted by ID. That order *is* the meaning of a ruleset, so it
is preserved rather than normalized away.

Each policy also carries an explicit `order` index, starting at zero. A list
position is not something downstream is obliged to preserve — a filter, a
re-serialization, or a model rewriting the answer into a table can all lose
it — so the index travels with the record rather than being implied by it.

`total_policies` reports the size of the unfiltered ruleset alongside `count`,
so a filtered answer says what it was filtered *from*.

```json
{
  "target": "edge",
  "vdom": "root",
  "count": 2,
  "total_policies": 37,
  "policies": [
    {
      "id": 4,
      "name": "guest-to-internet",
      "enabled": true,
      "action": "accept",
      "from": ["guest"],
      "to": ["wan1"],
      "source": ["GUEST-NET"],
      "destination": ["all"],
      "service": ["HTTP", "HTTPS", "DNS"],
      "nat": true,
      "log": "all",
      "order": 3
    },
    {
      "id": 9,
      "name": "block-legacy-smb",
      "enabled": true,
      "action": "deny",
      "from": ["lan"],
      "to": ["dmz"],
      "source": ["all"],
      "destination": ["DMZ-SERVERS"],
      "service": ["SMB"],
      "order": 8
    }
  ]
}
```

An unnamed policy reports as `policy-<id>`, which is what a FortiGate with one
default rule looks like: `{"id": 1, "name": "policy-1", "order": 0}`.

:::caution[Filters match names directly and do not expand indirection]
They are exact-match rather than substring, because policy filtering is usually
asked as *show me everything touching this specific object*, and a substring
match on `LAN` would quietly pull in `LAN-GUEST` too.

The sharper limitation is indirection. A policy referencing a **group** that
contains your address will not match `address`, and a policy referencing a
**zone** that contains your interface will not match `interface`. Neither is
expanded.

For *what touches this object*, which is nearly always the better question, use
[`find_references`](#find_references). For substring matching across every
object type, use [`search_config`](#search_config).
:::

### `list_vips`

Virtual IPs, which are FortiOS's destination NAT rules.

| Argument | Type | Default | Meaning |
|---|---|---|---|
| `target` | string | only appliance | Which FortiGate to query |

A VIP maps an external address, optionally with a port, to an internal one.
FortiOS stores the addresses inline on the VIP rather than as references to
address objects, so nothing here needs a second lookup.

```json
{
  "target": "edge",
  "count": 1,
  "vips": [
    {
      "name": "web-in",
      "external_ip": ["198.51.100.20"],
      "mapped_ip": ["10.20.40.10"],
      "interface": ["wan1"],
      "port_forward": { "protocol": "tcp", "external_port": "443", "mapped_port": "8443" }
    }
  ]
}
```

`port_forward` appears only when port forwarding is enabled on the VIP. Its
absence means the whole address is mapped.

### `find_references`

What points at an address, group, service, or interface, and whether that can
be answered at all.

| Argument | Type | Default | Meaning |
|---|---|---|---|
| `object_name` | string | required | Exact name of the object |
| `target` | string | only appliance | Which FortiGate to query |

This is the question that precedes every configuration change on a firewall.
Behind it are five reads covering policies on both the address and the service
side, address group and service group membership, virtual IPs, and static
routes.

The answer is deliberately three-valued rather than a boolean, and
[the reason is the whole point of the tool](#why-the-verdict-is-three-valued).

```json
{
  "target": "edge",
  "vdom": "root",
  "object": "DMZ-SERVERS",
  "verdict": "referenced",
  "total_references": 3,
  "sources_checked": {
    "policies": "ok",
    "address_groups": "ok",
    "service_groups": "ok",
    "vips": "ok",
    "routes": "ok"
  },
  "checked_scopes": [
    "firewall policies", "address groups", "service groups",
    "virtual IPs", "static routes"
  ],
  "safe_to_delete": false,
  "policies": [
    { "id": 9, "name": "block-legacy-smb", "enabled": true, "action": "deny", "referenced_as": ["destination"] },
    { "id": 12, "name": "dmz-mgmt", "enabled": false, "action": "accept", "referenced_as": ["destination", "source"] }
  ],
  "groups": [{ "name": "ALL-SERVERS", "kind": "address_group" }],
  "vips": [],
  "routes": []
}
```

| `verdict` | Meaning |
|---|---|
| `referenced` | Every source answered and at least one reference was found |
| `no_references` | Every source answered and none of them mentions the object |
| `indeterminate` | At least one source could not be read, so no conclusion is available |

`safe_to_delete` is present **only when every source answered**. On an
`indeterminate` verdict the key is absent entirely rather than set to `false`,
and a `note` explains which reads failed:

```json
{
  "object": "DMZ-SERVERS",
  "verdict": "indeterminate",
  "total_references": 1,
  "sources_checked": {
    "policies": "ok",
    "address_groups": "ok",
    "service_groups": "ok",
    "vips": "ok",
    "routes": "denied: http=403"
  },
  "note": "Could not read: routes. The reference count is a lower bound and no conclusion about deletion safety is possible."
}
```

Omitting the key rather than setting it false is deliberate. A `false` invites
a reader to stop there and conclude *not safe*; an absent key forces it to
consult the verdict and discover the answer was never available.

#### Why the verdict is three-valued

A token scoped to firewall objects gets HTTP 403 on `router/static`, and the
underlying client library turns every error status into an empty list — no
exception, no status. A naive implementation therefore counts zero references
and reports that a heavily-used object is safe to delete.

Doing least privilege correctly makes that outcome *more* likely, not less,
which is what makes it worth this much machinery. Each source is read with its
status checked, and a table that could not be read can never support a claim
that nothing references the object.

`total_references` on an `indeterminate` verdict is a lower bound, not a count.

#### What is not checked

`checked_scopes` lists what was actually examined, and the list is not
exhaustive even when every source answers. Proxy policies, local-in policies,
SD-WAN rules, zones, IP pools, and DHCP server settings can all reference an
object and are not consulted. **Group membership is not expanded
transitively**, so an object inside a referenced group reports the group and
not the policies that point at it.

[Before you delete](/guides/before-you-delete/) turns that into a workflow.

`referenced_as` names the field the object appeared in, so a policy that lists
an object as both source and destination reports both rather than being counted
twice.

## Network

### `list_interfaces`

Interfaces with addresses, VLAN tags, and link state.

| Argument | Type | Default | Meaning |
|---|---|---|---|
| `target` | string | only appliance | Which FortiGate to query |
| `include_internal` | boolean | `false` | Include FortiOS-generated interfaces |
| `interface_type` | string | none | Exact type: `physical`, `vlan`, `aggregate`, `hard-switch`, `switch`, `vap-switch`, `tunnel` |
| `with_ip_only` | boolean | `false` | Keep only interfaces carrying a static IP |

FortiOS creates bookkeeping interfaces alongside real ones — a quarantine
interface accompanies every wireless VAP, and SSL-VPN and tunnel roots appear
the same way. Those are hidden by default because nobody configured them and
nobody can meaningfully act on them.

`hidden_internal` **names** what was omitted rather than counting it, so the
omission is auditable rather than merely acknowledged.

Abridged from a FortiWiFi-61E on FortiOS 7.0.14, which reports 22 interfaces
and hides 7:

```json
{
  "target": "lab",
  "vdom": "root",
  "count": 22,
  "interfaces": [
    {
      "name": "dmz", "type": "physical", "status": "up", "vdom": "root",
      "ip": "10.10.10.1/24",
      "management_access": "ping https fgfm fabric", "mtu": 1500
    },
    {
      "name": "lan", "type": "switch", "status": "up", "vdom": "root",
      "ip": "192.168.99.99/24",
      "management_access": "ping https ssh fgfm fabric", "mtu": 1500
    },
    {
      "name": "wan2", "type": "physical", "status": "up", "vdom": "root",
      "addressing": "dhcp",
      "note": "address assigned by dhcp; see get_routing_table for the runtime value",
      "management_access": "ping fgfm", "mtu": 1500
    },
    {
      "name": "modem", "type": "physical", "status": "down", "vdom": "root",
      "addressing": "pppoe",
      "note": "address assigned by pppoe; see get_routing_table for the runtime value",
      "mtu": 1500
    },
    {
      "name": "ssot_test_vlan1", "type": "vlan", "status": "up", "vdom": "root",
      "ip": "198.51.100.1/24", "vlan_id": 100, "parent": "wan1",
      "description": "[Synced from Nautobot] v3.3 push test",
      "management_access": "ping", "mtu": 1500
    },
    {
      "name": "wifi", "type": "vap-switch", "status": "up", "vdom": "root",
      "mtu": 1500
    }
  ],
  "hidden_internal": [
    "naf.root", "ssl.root", "wqtn.16.wifi", "wqtn.21.e2e-vap",
    "wqtn.23.e2e-vap", "wqtn.25.xxxxxxx", "wqtn.27.xxxxxxx"
  ]
}
```

Two things in that output are worth noticing because they are easy to get
wrong. `wqt.root` — the quarantine soft switch, without the `n` — is a real
interface and is *not* hidden, while `wqtn.*` are. And a `vap-switch` carries
no address of its own, so an SSID shows up here as an interface with nothing
but a name and an MTU.

The `ip` field keeps the host address rather than collapsing to the network,
which is the opposite of what an address object needs from the same dotted-mask
format. That distinction has
[its own entry in the quirks list](/explanation/fortios-quirks/#the-same-format-means-two-things).

**An interface addressed by DHCP or PPPoE reports no `ip`.** The configuration
genuinely holds no address for it, so instead it carries `addressing` naming
the method and a `note` pointing at `get_routing_table` for the runtime value.
Reporting only the absence of `ip` would answer *what is my WAN address* with
*it has none*, which is the wrong kind of true.

:::caution[`ssl.root` is hidden but real]
The prefix rule that hides FortiOS bookkeeping also hides `ssl.root`, which is
a genuine policy endpoint. A policy can therefore name an interface this tool
omits by default. Pass `include_internal: true` when reconciling policy
interfaces against the interface list.
:::

### `list_vlans`

VLAN sub-interfaces with their tags and parents, sorted by tag.

| Argument | Type | Default | Meaning |
|---|---|---|---|
| `target` | string | only appliance | Which FortiGate to query |

A focused view of the VLAN subset of the interface table, because *what VLANs
exist and what are they attached to* gets asked far more often than the full
interface list. FortiOS quarantine VLANs are excluded, since they are
`type: vlan` too and are otherwise indistinguishable from a real one by
anything except the name prefix.

### `list_static_routes`

Routes an operator configured, sorted by sequence number.

| Argument | Type | Default | Meaning |
|---|---|---|---|
| `target` | string | only appliance | Which FortiGate to query |

```json
{
  "target": "edge",
  "count": 2,
  "routes": [
    { "seq_num": 1, "destination": "0.0.0.0/0", "distance": 10, "priority": 0, "enabled": true, "gateway": "198.51.100.1", "interface": "wan1" },
    { "seq_num": 2, "destination": "10.20.50.0/24", "distance": 10, "priority": 0, "enabled": true, "destination_address_object": "REMOTE-SITE", "gateway": "10.20.30.254", "interface": "vlan30" }
  ]
}
```

When a route's destination is a named address object, FortiOS writes the
all-zeros sentinel into `dst` and the real destination lives in `dstaddr`.
Reading `dst` first turns every named-destination route into a bogus default
route, so `dstaddr` wins wherever it is populated. This tool resolves the name
back to CIDR with a second lookup where it can, keeping the object name
alongside it under `destination_address_object`.

A route with `"blackhole": true` reports no gateway or interface, because it
has neither.

### `get_routing_table`

Routes the appliance is forwarding on right now.

| Argument | Type | Default | Meaning |
|---|---|---|---|
| `target` | string | only appliance | Which FortiGate to query |
| `protocol` | string | none | Filter by route type: `static`, `connect`, `dhcp` |

This is live state, so it includes connected routes, dynamically learned
routes, and routes handed over by DHCP, none of which appear in the static
route configuration. A DHCP-assigned default route is the clearest case:
present here, absent from `list_static_routes`, and not a bug in either.

```json
{
  "target": "edge",
  "count": 3,
  "routes": [
    { "destination": "0.0.0.0/0", "gateway": "198.51.100.1", "interface": "wan1", "type": "static", "distance": 10, "metric": 0 },
    { "destination": "10.20.30.0/24", "gateway": "0.0.0.0", "interface": "vlan30", "type": "connect", "distance": 0, "metric": 0 },
    { "destination": "203.0.113.0/24", "gateway": "192.0.2.1", "interface": "wan2", "type": "dhcp", "distance": 5, "metric": 0 }
  ]
}
```

## Live state

Everything in this group reads the FortiOS monitor tree, which reports what the
appliance currently observes rather than what it was configured to do. None of
it is persisted anywhere, so these answers are true only at the moment of the
call.

### `list_wifi_clients`

Wireless clients currently associated, enriched with DHCP and ARP.

| Argument | Type | Default | Meaning |
|---|---|---|---|
| `target` | string | only appliance | Which FortiGate to query |
| `ssid` | string | none | Keep only clients on this SSID |

Each client is joined against the DHCP lease table and the ARP table by MAC,
which is what turns an anonymous MAC into a recognizable device. The hostname
comes from the DHCP lease, falling back to the vendor class identifier when the
client did not send one.

```json
{
  "target": "edge",
  "count": 1,
  "clients": [
    {
      "mac": "aa:bb:cc:dd:ee:01",
      "hostname": "kevins-laptop",
      "ip": "10.20.30.84",
      "ssid": "office",
      "signal_dbm": -54,
      "data_rate_mbps": 433.3,
      "authenticated": true,
      "interface": "vlan30"
    }
  ]
}
```

On an appliance with no wireless hardware there is no `monitor/wifi/client`
endpoint at all, and an absent endpoint yields no rows rather than an error —
otherwise the joins in `find_device` would break entirely on a wired-only box.

An endpoint that *refused* the read is a different matter and is never treated
as emptiness. [Fail soft on absence, never on
denial](/explanation/config-vs-live/#fail-soft-on-absence-never-on-denial).

### `list_dhcp_leases`

Leases the appliance is currently handing out.

| Argument | Type | Default | Meaning |
|---|---|---|---|
| `target` | string | only appliance | Which FortiGate to query |
| `interface` | string | none | Keep only leases issued on this interface |
| `hostname_contains` | string | none | Case-insensitive substring filter on the hostname |

```json
{
  "target": "edge",
  "count": 1,
  "leases": [
    {
      "mac": "aa:bb:cc:dd:ee:01",
      "ip": "10.20.30.84",
      "hostname": "kevins-laptop",
      "interface": "vlan30",
      "expires": 1789000000,
      "reserved": false
    }
  ]
}
```

### `get_arp_table`

IP-to-MAC bindings the appliance can see.

| Argument | Type | Default | Meaning |
|---|---|---|---|
| `target` | string | only appliance | Which FortiGate to query |
| `interface` | string | none | Keep only entries learned on this interface |

ARP catches devices that DHCP does not, meaning anything with a statically
configured address. It is the fallback when a device is demonstrably on the
network but holds no lease.

### `find_device`

Who a MAC, IP, or hostname fragment belongs to.

| Argument | Type | Default | Meaning |
|---|---|---|---|
| `query` | string | required | A MAC, an IP, or part of a hostname |
| `target` | string | only appliance | Which FortiGate to query |

Searches the wireless client list, the DHCP lease table, and the ARP table
together, then merges everything known about each matching device into one
record. A device seen in all three places produces one result rather than three
partial ones, and `seen_in` says which sources contributed.

```json
{
  "target": "edge",
  "query": "10.20.30.84",
  "count": 1,
  "devices": [
    {
      "mac": "aa:bb:cc:dd:ee:01",
      "seen_in": ["dhcp", "arp", "wifi"],
      "ip": "10.20.30.84",
      "hostname": "kevins-laptop",
      "interface": "vlan30",
      "lease_expires": 1789000000,
      "ssid": "office",
      "signal_dbm": -54,
      "wireless": true
    }
  ]
}
```

Matching is case-insensitive and substring-based, so a partial MAC, a bare
hostname prefix, or a full IP all work. Once a MAC has matched in any one
source, the other two contribute their fields for that MAC whether or not the
query itself matched there — which is the entire point, since the wifi endpoint
frequently knows a MAC and nothing else useful about it.

The three endpoints disagree about MAC casing, so every MAC is lowercased
before the join. Skip that and the join silently matches nothing, producing
three partial records that look like three devices.
