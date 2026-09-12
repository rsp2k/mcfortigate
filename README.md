# mcfortigate

An MCP server that lets a language model read a FortiGate firewall and answer
questions about it.

Read-only. Nothing in this server can change a configuration.

Full documentation: **[mcfortigate.warehack.ing](https://mcfortigate.warehack.ing)**

## Why not just wrap the REST API

The obvious way to build this is one tool per FortiOS endpoint returning raw
JSON, and that turns out to work badly. A single FortiOS policy object carries
more than eighty fields, most of them empty strings, unused IPv6 arrays, and
internal UUIDs. Ask a model "which policies allow traffic into the DMZ" against
a raw wrapper and it spends most of its attention on `"srcaddr6": []` before it
finds anything useful.

So the tools here are shaped around the questions operators actually ask rather
than around the endpoints FortiOS happens to expose. Three examples.

**"Is this address object safe to delete?"** is `find_references`, and it is the
tool that shaped the rest of this server.

The obvious implementation scans the tables that obviously hold references:
policies, groups, virtual IPs, routes. The appliance disagrees about what
"obviously" covers. Asked directly, FortiOS 7.0.14 reports 74 tables that can
reference a firewall address and 234 that can reference an interface. An object
used only by a web-proxy profile comes back from the obvious implementation as
unreferenced, which is a wrong answer in the direction that destroys data.

So the authority here is the appliance's own reference lookup, the one behind
the reference counter in its web UI. Two things about it are worth knowing.
Every row it returns carries `reference_count: 0`, genuine references included,
so the presence of a row is the signal and the count is a trap. And asked about
a key that is absent from the table you named, it answers success with an empty
list, so guessing the wrong table reports an in-use object as free. Querying
the address table about `wan1` finds nothing while the interface table finds
two references, which is why this tool works out what kind of object a name
refers to before it asks.

The answer is five-valued rather than a boolean, because there are genuinely
five things that can be true. Beyond `referenced` and `no_references` there is
`object_not_found` for a name that matches nothing,
`no_references_in_checked_scopes` for when the authoritative lookup was
unavailable and only the partial scan ran, and `indeterminate` for when the
scan itself was incomplete. `safe_to_delete` appears only for the first two.
A token scoped to firewall objects gets 403 on the routing table, and the
client library turns every error status into an empty list, so doing least
privilege correctly makes a false clean bill of health *more* likely, not less.

**"What is 192.168.1.47?"** is `find_device`. It searches the wireless client
list, the DHCP lease table, and the ARP table, then merges what each one knows
about a MAC into a single record. FortiOS reports MAC addresses in different
cases across those three endpoints, so joining them requires normalizing first
or the join silently matches nothing.

**"Where does 10.20.30.0/24 appear?"** is `search_config`, which looks through
addresses, groups, services, interfaces, routes, and policies at once, for when
you do not yet know which kind of object holds the answer.

## Install

```bash
uvx mcfortigate
```

Add it to Claude Code:

```bash
claude mcp add fortigate \
  --env FORTIGATE_HOST=fgt.example.com \
  --env FORTIGATE_TOKEN=your-token \
  -- uvx mcfortigate
```

## Configuration

Create a read-only REST API admin on the FortiGate under **System >
Administrators > Create New > REST API Admin**, give it a read-only profile, and
restrict its trusted hosts to whatever runs this server. Then set two variables:

```bash
FORTIGATE_HOST=fgt.example.com
FORTIGATE_TOKEN=your-token
```

A username and password pair works as a fallback on older firmware, via
`FORTIGATE_USERNAME` and `FORTIGATE_PASSWORD`, but a token is better because it
avoids a login round-trip on every call.

For several appliances, set `FORTIGATE_TARGETS` to a JSON object. The keys
become the `target` argument on every tool, so short aliases are worth it:

```bash
FORTIGATE_TARGETS='{
  "edge":   {"host": "fgt-edge1.example.com", "token": "..."},
  "branch": {"host": "fgt-br2.example.com", "token": "...", "verify_ssl": false}
}'
```

With one appliance configured the `target` argument can be omitted everywhere.
With several it is required, and omitting it produces an error listing the valid
aliases so the model can correct itself.

See `.env.example` for the optional settings, which are `FORTIGATE_NAME`,
`FORTIGATE_VDOM`, `FORTIGATE_VERIFY_SSL`, `FORTIGATE_TIMEOUT`, and
`FORTIGATE_PORT`.

## Tools

### Orientation

| Tool | Answers |
|---|---|
| `list_targets` | Which appliances can this server reach |
| `get_system_status` | Model, serial, firmware, hostname, CPU and memory |
| `search_config` | Where does this term appear, anywhere in the config |

### Firewall

| Tool | Answers |
|---|---|
| `list_address_objects` | What named addresses exist, with readable values |
| `list_address_groups` | What groups exist and what is in them |
| `list_services` | What services exist, with protocols and ports |
| `list_policies` | What rules exist, in evaluation order, with filters |
| `list_vips` | What destination NAT is configured |
| `find_references` | What points at this object, and is it safe to delete |

### Network

| Tool | Answers |
|---|---|
| `list_interfaces` | What interfaces exist, with addresses and link state |
| `list_vlans` | What VLANs exist, with tags and parent interfaces |
| `list_static_routes` | What routes were configured |
| `get_routing_table` | What routes are actually in use right now |

### Live state

| Tool | Answers |
|---|---|
| `list_wifi_clients` | Who is on the wireless right now, with hostnames |
| `list_dhcp_leases` | What leases are currently issued |
| `get_arp_table` | What IP-to-MAC bindings the appliance sees |
| `find_device` | Who is this MAC, IP, or hostname |

Configuration tools read what the appliance was told to do. Live tools read what
it currently observes, and those answers are true only at the moment of the
call. The distinction matters more than it sounds: a DHCP-assigned default route
shows up in `get_routing_table` and never in `list_static_routes`, because it was
never configured.

### Why the listing tools page and the others do not

Every listing tool takes `limit` and `offset`, defaults to 200 rows, and always
reports `total_available`. A partial page additionally carries `truncated` and
`next_offset`.

The problem this solves is not memory. A FortiGate with four thousand ARP
entries produces a response Python handles without noticing; what breaks is an
MCP client with a size limit truncating the payload on the way to the model,
which then reads whatever survived as the whole answer. Nothing in the data says
otherwise. Bounding the result here makes the same truncation visible instead of
silent.

The analysis tools — `find_references`, `search_config`, `find_device` — take no
`limit` on purpose. They scan in order to reach a verdict, and a verdict from a
partial scan is not a shorter answer, it is a wrong one.

## FortiOS behaviors handled here

These were found against real hardware rather than in documentation, and each
one fails silently rather than loudly, which is what makes them worth writing
down.

**Boolean fields are strings.** FortiOS writes `"enable"` and `"disable"` where
JSON would use `true` and `false`. Passing those through `bool()` reads every
disabled thing as enabled, since `bool("disable")` is `True`. That single
mistake once flipped every non-blackhole route to blackhole.

**The same format means two things.** A dotted-mask string like
`10.0.0.0 255.255.255.0` is a network in `firewall.address.subnet` but the
interface's own address in `system.interface.ip`. Collapsing the second to its
network address invents IPs that do not exist.

**Relational fields change shape by version.** Fields such as `dstaddr` arrive
as `[{"name": "X"}]` on FortiOS 7.2 and later, but as a bare string on 7.0.x.
Both are handled.

**`dst` is a placeholder when `dstaddr` is set.** When a route points at a named
address object, FortiOS writes the all-zeros sentinel into `dst`. Reading `dst`
first turns every named-destination route into a bogus default route.

**Identity lives in the envelope, not the body.** The appliance serial, firmware
version, and build number are siblings of `results` on every cmdb response, not
inside it. Helpers that unwrap straight to `results` discard them, which makes
the serial look absent from the API entirely.

**FortiOS creates its own interfaces.** Names prefixed `wqtn.`, `vap.`, `ssl.`,
and `naf.` are bookkeeping, generated alongside VAPs and VPN tunnels. They are
hidden by default, since no operator made them and none can act on them. Pass
`include_internal=true` to see them.

## Development

```bash
uv venv && uv pip install -e ".[dev]"
uv run pytest
uv run ruff check src/ tests/
```

The reading layer in `fortios.py` and the configuration layer in `config.py` are
pure functions with no network or framework coupling, so the test suite runs in
under a second with no fixtures and no mock appliance.

## Related

The FortiOS behaviors above were learned while building
[nautobot-ssot-fortinet](https://github.com/rsp2k/nautobot-ssot-fortinet), which
syncs FortiGate configuration into Nautobot in both directions. This server
reuses that knowledge for a different purpose.

## License

Apache-2.0
