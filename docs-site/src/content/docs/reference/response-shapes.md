---
title: Response shapes
description: Field-by-field definitions of the summarized objects every tool returns, including which fields are conditional.
---

Every tool returns a JSON object with `target` naming the appliance that
answered, `vdom` naming the VDOM it was scoped to, `count` where a list is
involved, and one named collection.

Listing tools add the paging envelope — `total_available` always, plus
`truncated`, `next_offset`, and `paging_note` when there is more behind the
page. `count` is the rows you were given; `total_available` is the rows that
matched. [The full contract](/reference/tools/#paging). The
objects inside those collections are summaries rather than raw FortiOS
records — a raw policy carries eighty-plus fields, most of them empty strings,
unused IPv6 arrays, and internal UUIDs, and
[dropping them is the whole point](/explanation/question-shaped-tools/).

One convention runs through all of it: **conditional fields are absent, not
null**. A policy with no comment has no `comment` key. An interface with no
address has no `ip` key. Reading a summary means checking for presence, not for
emptiness, and it means a model never spends attention on a field that had
nothing to say.

## Address

From `list_address_objects` and the `addresses` section of `search_config`.

| Field | Always | Meaning |
|---|---|---|
| `name` | yes | Object name |
| `type` | yes | FortiOS type, defaulting to `ipmask` |
| `value` | yes | One readable value, resolved by type. May be `null` |
| `comment` | no | Present only when set |
| `interface` | no | The `associated-interface`, when set |

`value` resolves differently per type, which is the work this summary exists to
do: `ipmask` and `interface-subnet` give CIDR, `fqdn` gives the hostname,
`iprange` gives `start-end`, `geography` gives the country code, `mac` gives a
comma-joined MAC list, and `dynamic` gives its sub-type or the literal
`external-connector`.

## Service

From `list_services` and the `services` section of `search_config`.

| Field | Always | Meaning |
|---|---|---|
| `name` | yes | Object name |
| `protocol` | yes | `TCP`, `UDP`, `TCP/UDP`, `ICMP`, `IPv6-ICMP`, a named IP protocol, `any`, or `unknown` |
| `ports` | no | Object keyed `tcp`, `udp`, `sctp`; only populated protocols appear |
| `icmp_type` | no | ICMP services only, when set |
| `protocol_number` | no | `protocol: IP` services only |
| `comment` | no | Present only when set |
| `category` | no | Present only when set |

Port values are comma-joined strings rather than arrays, because FortiOS writes
them space-separated and a range like `6000-6063` is a single value that would
survive splitting badly. A `:src-range` qualifier — FortiOS appends one on
services that also constrain the source port, as RLOGIN's `513:512-1023` does —
is stripped, since nothing downstream models source ports.

## Policy

From `list_policies` and the `policies` section of `search_config`.

| Field | Always | Meaning |
|---|---|---|
| `id` | yes | `policyid` |
| `order` | yes | Zero-based evaluation position, carried explicitly so it survives filtering and re-serialization |
| `name` | yes | Policy name, or `policy-<id>` when unnamed |
| `enabled` | yes | Boolean. Defaults true when `status` is absent |
| `action` | yes | `accept` or `deny`. Defaults to `deny` |
| `from` / `to` | yes | Source and destination interface names, as lists |
| `source` / `destination` | yes | Address object and group names, as lists |
| `service` | yes | Service object names, as list |
| `nat` | no | Present and `true` only when source NAT is on |
| `schedule` | no | Present only when it is not `always` |
| `log` | no | Present only when logging is not disabled |
| `comment` | no | From FortiOS's `comments`, present only when set |
| `source_negated`, `destination_negated`, `service_negated` | no | Present and `true` when the list means *everything except* |
| `destination_internet_service`, `source_internet_service` | no | Internet Service names, which **replace** the address match |
| `destination_internet_service_negated`, `source_internet_service_negated` | no | Present and `true` when that match is inverted |
| `source_v6`, `destination_v6` | no | IPv6 members, when set |
| `identity_groups`, `identity_users`, `identity_fsso_groups` | no | Identity scope narrowing the rule |
| `match_note` | no | Prose describing any of the above that applies |
| `unsummarized` | no | Non-default keys the summarizer neither read nor ignored |

The fields from `source_negated` down are the ones that change what the rule
*means* rather than adding detail to it. `match_note` restates them in prose
precisely because a flag beside a list is easy to miss — see
[fields that invert a rule](/reference/tools/#fields-that-invert-a-rule).

The five list fields are always lists even when FortiOS returned a bare string,
which it does for some relational fields on 7.0.x. A policy is
<span class="verdict allow">accept</span> or
<span class="verdict deny">deny</span> in `action`, and separately on or off in
`enabled`; a disabled accept rule allows nothing.

## Interface

From `list_interfaces`, `list_vlans`, and the `interfaces` section of
`search_config`.

| Field | Always | Meaning |
|---|---|---|
| `name` | yes | Interface name |
| `type` | yes | FortiOS type, defaulting to `physical` |
| `status` | yes | `up` or `down` |
| `vdom` | yes | Owning VDOM, defaulting to `root` |
| `ip` | no | Host address in CIDR. Absent when unaddressed, `0.0.0.0`, or dynamically addressed |
| `addressing` | no | `dhcp` or `pppoe`, when the address is not static |
| `note` | no | Where to find the runtime address, alongside `addressing` |
| `secondary_ips` | no | List of additional host addresses |
| `vlan_id` | no | Present only when the tag is greater than zero |
| `parent` | no | Parent interface, for sub-interfaces |
| `description` | no | Present only when set |
| `management_access` | no | FortiOS's `allowaccess` string, such as `ping https` |
| `mtu` | no | Present only when set |

`ip` keeps the host address rather than collapsing to the network. FortiOS
writes `203.0.113.10 255.255.255.0` here and the same dotted-mask format in an
address object's `subnet`, but the two mean different things, and collapsing
this one invents addresses that do not exist.

A dynamically addressed interface reports `addressing` and `note` instead of
`ip`, because the configuration genuinely holds no address for it. The two can
also coexist: an interface set to DHCP that currently has a lease recorded in
its configuration carries both.

The enclosing response from `list_interfaces` adds `hidden_internal`, a **list
of the names** it omitted rather than a count of them.

## Static route

From `list_static_routes` and the `routes` section of `search_config`.

| Field | Always | Meaning |
|---|---|---|
| `seq_num` | yes | FortiOS `seq-num` |
| `destination` | yes | CIDR, or `null` when the destination is a named object that could not be resolved |
| `distance` | yes | Administrative distance |
| `priority` | yes | Route priority |
| `enabled` | yes | Boolean. Defaults true |
| `destination_address_object` | no | Name, or list of names, when the destination is named |
| `blackhole` | no | Present and `true` only on blackhole routes |
| `gateway` | no | Absent on blackhole routes and when the gateway is `0.0.0.0` |
| `interface` | no | FortiOS `device`. Absent on blackhole routes |
| `comment` | no | Present only when set |

`list_static_routes` resolves `destination_address_object` back to CIDR with a
second lookup where the referenced object is a plain subnet, filling in
`destination` and keeping the object name alongside it. When both are present
they describe the same network two ways, and the object name is the one an
operator will recognize.

## Live routing entry

From `get_routing_table`. Not a summary of a configuration object — these come
from the monitor tree and have a different shape entirely.

| Field | Meaning |
|---|---|
| `destination` | FortiOS `ip_mask` |
| `gateway` | Next hop, `0.0.0.0` on connected routes |
| `interface` | Outgoing interface |
| `type` | `static`, `connect`, `dhcp`, or a routing protocol name |
| `distance` | Administrative distance |
| `metric` | Metric |

## Device

From `find_device`. The merged record, assembled from up to three monitor
endpoints.

| Field | Always | Meaning |
|---|---|---|
| `mac` | yes | Lowercased MAC, which is the join key |
| `seen_in` | yes | Which sources contributed: `dhcp`, `arp`, `wifi` |
| `ip` | no | First address any source reported |
| `hostname` | no | DHCP hostname, falling back to the vendor class identifier |
| `interface` | no | Interface the device was seen on |
| `lease_expires` | no | DHCP lease expiry, Unix seconds |
| `ssid` | no | Wireless clients only |
| `signal_dbm` | no | Wireless clients only |
| `wireless` | no | Present and `true` only for wireless clients |

Results are sorted by IP where known and by MAC otherwise, so a device with no
address still has a stable position rather than floating.
