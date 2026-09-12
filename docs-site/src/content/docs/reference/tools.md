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

## Choosing a VDOM

Every tool takes an optional `vdom` argument overriding the configured default
for that one call, and every response reports the VDOM it **actually read**
rather than the one you asked for.

That is checked rather than assumed. Every cmdb and monitor endpoint returns a
top-level `vdom`, and a disagreement between what was requested and what came
back raises instead of being reported.

:::caution[HTTP 424 does not mean the VDOM is wrong]
A nonexistent VDOM answers **424**, not 404. But so does
`monitor/wifi/spectrum` on an appliance with a perfectly valid VDOM, so 424 is
not evidence of a bad VDOM name.

The error text therefore names the VDOM it was reading and leaves the diagnosis
to you, rather than asserting a cause it cannot actually distinguish.
:::

## What the filters removed

A filtered response reports what the filter took out, which turns a silent
empty result into a legible one.

| Field | Meaning |
|---|---|
| `filters_applied` | Which filters were active |
| `filtered_out` | How many rows each one removed |
| `total_before_filters` | Rows before any filtering |
| `filter_note` | Prose summary of the above |

None of these appear when no filter ran, so an unfiltered response stays clean.

The case this closes: `get_arp_table(interface="lann")` — a typo — used to
return an empty list indistinguishable from a genuinely empty ARP table. Now
the response says the filter removed every row, and the typo is visible in
`filters_applied`.

**Hiding internal interfaces counts as a filter**, and is reported as one. It
is on by default, which makes it the single easiest filter to forget is
running.

## Paging

Twelve of the seventeen tools bound their results. Five do not, and the split
is a rule rather than a list worth memorizing:

**Listing tools page**, because they answer *what is there* and a page is a
smaller true answer.

**Analysis tools do not page.** `find_references`, `search_config`,
`find_device`, `get_system_status`, and `list_targets` scan in order to reach a
verdict, and a verdict from a partial scan is not a shorter answer — it is a
wrong one. Those report what they scanned instead.

| Argument | Type | Default | Meaning |
|---|---|---|---|
| `limit` | integer | `200` | Rows in this page, capped at `1000` |
| `offset` | integer | `0` | Rows to skip before the page starts |

Every bounded response carries `count`, the rows in this page, and
`total_available`, the rows matching your filters. A page with more behind it
adds three more fields:

```json
{
  "count": 3,
  "total_available": 22,
  "truncated": true,
  "next_offset": 4,
  "paging_note": "showing rows 1 to 3 of 22. Call again with offset=4 for the rest, and do not treat this page as the whole table.",
  "interfaces": ["…"]
}
```

The `paging_note` is a sentence rather than a flag on purpose. A boolean beside
a list is easy for a model to skim past; an instruction naming the next offset
is not.

### Why bound at all

Not memory. A FortiGate with four thousand ARP entries produces a response
Python handles without noticing.

What breaks is further down the chain. An MCP client with a response size limit
truncates the payload, the model reads whatever survived as though it were the
whole answer, and **nothing in the data contradicts it**. *Which hosts are on
this subnet* then gets answered confidently from the first eight hundred
entries.

Bounding the result here makes that same truncation visible. The response
always knows how many rows exist, so a partial answer says it is partial.

### Bad arguments are clamped, not rejected

An out-of-range argument costs a row, not the task. Each correction is
explained in `paging_note` rather than applied silently.

| You pass | What happens |
|---|---|
| `offset` past the end | Empty window, `total_available` intact, note says the offset is past the end |
| `offset` negative | Read as `0`, noted |
| `limit` of `0` or less | Default of `200` used, noted |
| `limit` above `1000` | Capped at `1000`, noted |

Asking for `offset=5000` on the 22-interface lab box returns exactly that:

```json
{
  "count": 0,
  "total_available": 22,
  "paging_note": "offset 5000 is past the end of 22 rows, so the window is empty",
  "interfaces": []
}
```

A model that guesses badly gets a usable correction and can try again. An error
would end the task over an arithmetic mistake.

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
| `limit`, `offset` | integer | `200`, `0` | One page of rows — [see paging](#paging) |
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
| `limit`, `offset` | integer | `200`, `0` | One page of rows — [see paging](#paging) |
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
| `limit`, `offset` | integer | `200`, `0` | One page of rows — [see paging](#paging) |
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
| `limit`, `offset` | integer | `200`, `0` | One page of rows — [see paging](#paging) |
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

:::caution[Three counts, three meanings]
This tool returns all three, and they answer different questions:

| Field | Counts |
|---|---|
| `count` | Rows **in this page** |
| `total_available` | Rows **matching your filters** |
| `total_policies` | Rows **in the whole ruleset** |

`count: 20, total_available: 63, total_policies: 412` means: you are looking at
twenty of the sixty-three policies that matched, out of four hundred and twelve
on the appliance.

Read the wrong one and you get a plausible sentence that is badly wrong —
*there are twenty policies on this firewall* when there are four hundred.
:::

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

#### Fields that invert a rule

Two classes of FortiOS field do not shorten a policy's meaning, they **reverse**
it. Both sit at their default on nearly every policy, which is exactly what
makes them dangerous to omit — you can read a thousand summaries without
meeting one.

**Negation.** With `srcaddr-negate` enabled, the policy matches every source
*except* those listed. A summary that prints the list without the flag states
the precise opposite of the rule. These surface as `source_negated`,
`destination_negated`, and `service_negated`.

**Internet Service.** With `internet-service` enabled, FortiOS ignores
`dstaddr` entirely and matches against its Internet Service database instead.
A rule scoped to Office 365 would otherwise be described as reaching
everything. This surfaces as `destination_internet_service`, with
`source_internet_service` for the source-side equivalent, and a `_negated`
companion for each.

Both also write plain prose into `match_note`:

```json
{
  "id": 7,
  "name": "block-all-but-partners",
  "action": "accept",
  "source": ["PARTNER-NETS"],
  "source_negated": true,
  "destination_internet_service": ["Microsoft-Office365"],
  "match_note": "This rule matches every source EXCEPT the ones listed in 'source'. Destination matching uses the Internet Service database, so the 'destination' address list is ignored by the appliance."
}
```

A boolean sitting beside a list is easy to skim past. A sentence saying *this
rule matches every source EXCEPT the ones listed* is not, which is the entire
reason the field exists.

Three more fields narrow a rule below what its address lists suggest:
`source_v6` and `destination_v6` carry the IPv6 members, and
`identity_groups`, `identity_users`, and `identity_fsso_groups` carry the
identity scope. A policy restricted to one AD group is not the policy its
address lists describe.

#### `unsummarized`

Any non-default policy key the code neither reads nor explicitly ignores lands
here verbatim.

It is the backstop for whatever a future firmware adds. The summarizing
approach [buys a lot](/explanation/question-shaped-tools/), and its one real
risk is that a field added next year silently changes what a rule means while
the summary keeps looking correct. This field means that shows up as data
rather than as nothing.

Empty on the lab appliance's real policy, and verified to fire when an unknown
field is injected.

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
| `limit`, `offset` | integer | `200`, `0` | One page of rows — [see paging](#paging) |

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

What points at an address, group, service, virtual IP, or interface, and
whether that can be answered at all.

| Argument | Type | Default | Meaning |
|---|---|---|---|
| `object_name` | string | required | Exact name of the object. Matching is exact, not a search |
| `target` | string | only appliance | Which FortiGate to query |

This is the question that precedes every configuration change on a firewall,
and **the authority for it is the appliance itself**. FortiOS exposes the same
reference lookup its web UI uses, and this tool asks that endpoint rather than
inferring an answer from a handful of tables.

It also scans policies, address groups, service groups, virtual IPs, and static
routes directly, because those yield readable detail the lookup does not — a
policy's name, whether it is enabled, whether it accepts or denies.

So the response has two halves. `references` is what the appliance says, and is
authoritative. `policies`, `groups`, `vips`, and `routes` are the readable
detail, and they cover five tables out of many.

#### Why asking beats scanning

On FortiOS 7.0.14, the number of tables that can hold a reference to an object:

| Object kind | Tables that can reference it |
|---|---|
| System interface | 234 |
| Firewall address | 74 |
| Service | 17 |

A five-table scan covers five of 234 for an interface. An address used only by
a web-proxy profile came back clean, and `safe_to_delete: true` on an object
that is very much in use is the worst answer this tool can give.

A real case off the lab appliance, asking about `wan1`, abridged:

```json
{
  "object": "wan1",
  "verdict": "referenced",
  "resolved_as": ["interface"],
  "total_references": 2,
  "candidate_tables": 234,
  "references": [
    { "table": "system.interface", "object": "ssot_test_vlan1", "looked_up_as": "interface", "attribute": "name" },
    { "table": "firewall.policy", "object": "1", "looked_up_as": "interface", "attribute": "dstintf" }
  ],
  "policies": [
    { "id": 1, "name": "policy-1", "enabled": true, "action": "accept", "referenced_as": ["to_interface"] }
  ],
  "safe_to_delete": false
}
```

The second row a scan would have found — it is the same policy that shows up in
`policies` with its name and action attached. **The first it would not.**
`ssot_test_vlan1` is a VLAN sub-interface parented to `wan1`, and no amount of
policy, group, VIP, or route scanning reaches it. Deleting `wan1` would have
taken the VLAN with it.

:::note[The two halves count differently]
`total_references` counts authoritative **rows**, and one object can produce
several. Asking about the address `all` on the same appliance returns
`total_references: 2` — both rows are policy 1, once as `srcaddr` and once as
`dstaddr` — while `policies` holds a single entry with
`referenced_as: ["source", "destination"]`.

Neither is more correct. The reference list counts the **sites** a reference
appears at; the detail lists count the **objects** that hold one. They measure
different things, so comparing them looks like a discrepancy when it is not.

Which to reach for depends on the question. Use `references` and
`total_references` when reporting what has to be changed before a delete — two
fields on one policy are two edits. Use `policies`, `groups`, `vips`, and
`routes` when naming what an operator has to go and open, since that same
policy is one thing to open.

Resist the urge to make the two numbers agree. Collapsing sites hides that two
separate fields need changing; expanding objects lists the same policy twice
for someone who only needs to open it once. Both directions lose information.
:::

#### The appliance's answer is not transitive

Asking the appliance is necessary and still not sufficient, because its lookup
reports only the **direct** holder of a reference and stops there.

There is a real three-level chain on the lab appliance:

```
internal1  →  system.virtual-switch:internal  →  system.interface:lan  →  firewall.policy:1
```

Ask about `internal1` and the appliance returns exactly one row: the virtual
switch. The policy that would actually break never appears, and the answer is
not wrong — it is complete for the question it was asked, which is a narrower
question than the one you had.

So containers are walked through, and the two lists are kept deliberately
separate:

| Field | Holds |
|---|---|
| `references` | What the appliance named directly. Every row carries `depth: 0` |
| `transitive_references` | What was reached through a group, zone, or switch. Each row carries `depth` and a `via` chain of container names |
| `total_transitive_references` | Count of the second list |

They are never merged, because the **remedy differs**. A direct reference is
removed from the object holding it. A transitive one is removed by editing a
container or a member list — and the policy that stops matching is not the
object you edit.

##### How far the walk got

`expansion` answers that, and it is the field to check before trusting the
list as a blast radius.

| `status` | Meaning |
|---|---|
| `complete` | The chain ran out. The transitive list is everything |
| `depth_capped` | The ceiling was hit with containers still unopened, named in `unexpanded` |
| `incomplete` | Something along the way could not be read |

It also reports `max_depth`, `deepest_depth`, and `unexpanded` when there is
anything left unopened. **Only `complete` means you are looking at the whole
blast radius.**

The ceiling is three, for two reasons that happen to agree. The deepest real
chain measured is switch port → hardware switch → software switch interface →
policy, which puts the policy at depth two, so three leaves one level of
headroom. And the cost is multiplicative: each level issues one usage call per
container found at the level above, so a config with wide groups pays
branching-factor-cubed at three and must not be allowed to pay it at ten.
Deeper configurations exist in principle, and when one turns up the tool says
`depth_capped` rather than pretending it finished.

#### The verdict

Five values, and `safe_to_delete` is present for only two of them.

| `verdict` | Meaning | `safe_to_delete` |
|---|---|---|
| `referenced` | Something points at it | `false` |
| `no_references` | The appliance confirmed nothing does | `true` |
| `object_not_found` | No object of any kind carries this name, so probably a typo | absent |
| `no_references_in_checked_scopes` | The authoritative lookup was unavailable and the partial scan found nothing | absent |
| `indeterminate` | Something needed could not be read | absent |

The two middle values are the ones worth slowing down for.

**`object_not_found`** means the question was about a *name* rather than an
object. Without it, a misspelling reports zero references and
`safe_to_delete: true` — a confident yes to a question containing a typo.

**`no_references_in_checked_scopes`** is a fact about four tables rather than
about the appliance. The authoritative lookup was unavailable and the fallback
scan found nothing, which is a much weaker claim than *nothing references this*.
The `note` field says so in as many words.

#### Response fields

| Field | Always | Meaning |
|---|---|---|
| `verdict` | yes | The five values above. Read this, not the count |
| `total_references` | yes | Authoritative row count when the lookup answered, otherwise the scan's count |
| `resolved_as` | yes | Kinds the name matched, as a list: `address`, `interface`, `service`, and so on. Empty on `object_not_found` |
| `references` | yes | Authoritative rows: `table`, `object`, `looked_up_as` (the kind), `attribute` (the field holding the reference) |
| `sources_checked` | yes | Per-source status, including `object_usage` and the three kind-resolution reads |
| `policies`, `groups`, `vips`, `routes` | yes | Readable detail from the direct scan |
| `candidate_tables` | no | How many tables could reference this kind. Present only when the kind was identified |
| `safe_to_delete` | no | Only on `referenced` and `no_references` |
| `note` | no | Present on the other three verdicts, explaining the limit |

`sources_checked` carries nine keys. Five are the detail scan — `policies`,
`address_groups`, `service_groups`, `vips`, `routes`. Three more come from
working out what kind of object the name is — `addresses`, `services`,
`interfaces` — which has to happen before the usage lookup can be asked
correctly. The last is `object_usage`, the authoritative lookup itself, and it
is the one whose failure downgrades the verdict.

Nine rather than fourteen, because kind resolution also needs the address
group, service group, and VIP tables, and those are shared with the detail
scan. They are read once and reported once.

`referenced_as` inside `policies` names the field the object appeared in, so a
policy listing it as both source and destination reports both rather than being
counted twice.

**Group membership is not expanded transitively.** An object inside a group
that a policy uses is reported as referenced by the group, not by the policy.

#### Two FortiOS traps behind this

Both silent, both the kind that produce a confident wrong answer.

**Every row reports `reference_count: 0`**, including rows that are real
references. Counting that field reports zero for an object with two of them.
The row's *existence* is the signal; its count is not.

**Asking the wrong table succeeds.** Query the address table about a name that
is actually an interface, and FortiOS answers HTTP 200 with an empty list
rather than an error. An interface with two references reports zero, and
nothing anywhere indicates the question was malformed. That is why the tool
resolves the object's kind from its defining cmdb table *before* querying, and
why `resolved_as` is in the response at all.

## Network

### `list_interfaces`

Interfaces with addresses, VLAN tags, and link state.

| Argument | Type | Default | Meaning |
|---|---|---|---|
| `target` | string | only appliance | Which FortiGate to query |
| `limit`, `offset` | integer | `200`, `0` | One page of rows — [see paging](#paging) |
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

#### Hiding is decided by the appliance, not by the name

Which interfaces are bookkeeping is a question the appliance can answer, and
guessing from name prefixes gets it wrong.

`monitor/system/available-interfaces` carries `valid_in_policy` per interface,
which *is* the answer to "can a policy name this". The tool asks, and reports
`hidden_internal_basis` as `appliance` when it got an answer or `name_prefix`
when it had to fall back, with a note saying so.

The prefix guess was wrong in both directions on FortiOS 7.0.14:

| Interface | Names suggest | Appliance says |
|---|---|---|
| `ssl.root` | a real policy endpoint | **not** offered to policies |
| `naf.root` | bookkeeping | **is** offered to policies |

Exactly backwards, twice. And `wqt.root` and `l2t.root` were never hidden at
all, because the prefix list reads `wqtn.` with an `n` — a one-character
difference doing load-bearing work, which is its own argument against
name-based inference.

### `list_vlans`

VLAN sub-interfaces with their tags and parents, sorted by tag.

| Argument | Type | Default | Meaning |
|---|---|---|---|
| `target` | string | only appliance | Which FortiGate to query |
| `limit`, `offset` | integer | `200`, `0` | One page of rows — [see paging](#paging) |

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
| `limit`, `offset` | integer | `200`, `0` | One page of rows — [see paging](#paging) |

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
| `limit`, `offset` | integer | `200`, `0` | One page of rows — [see paging](#paging) |
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
| `limit`, `offset` | integer | `200`, `0` | One page of rows — [see paging](#paging) |
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
| `limit`, `offset` | integer | `200`, `0` | One page of rows — [see paging](#paging) |
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
| `limit`, `offset` | integer | `200`, `0` | One page of rows — [see paging](#paging) |
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

Every MAC is canonicalized to lowercase colon-separated form before the join.

Two honest notes about that. On FortiOS 7.0.14, every endpoint that returned
populated rows already used the colon form, so the normalization is insurance
against a disagreement rather than a fix for an observed one. It costs nothing
and removes a whole class of silent failure, where a key normalized on only one
axis — case but not punctuation — indexes one device as two and reports it as
unknown with nothing in the output hinting why.

Where it demonstrably earns its keep is the **query** side. A MAC pasted from a
switch CLI as `2047.477d.db7b`, or from a vendor label as `20-47-47-7D-DB-7B`,
previously matched nothing at all. Both now work.

The matcher also refuses to read an IPv4 address as a MAC fragment, since an
address is nothing but hex digits and dots and would otherwise match one.
