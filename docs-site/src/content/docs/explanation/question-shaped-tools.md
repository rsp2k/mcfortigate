---
title: Tools shaped like questions
description: Why mcfortigate does not expose one tool per FortiOS endpoint, what that costs, and what it buys.
---

The obvious way to build an MCP server over a REST API is one tool per
endpoint, returning the response verbatim. It is easy to write, easy to keep
current, and it fails in a specific way that is worth understanding before you
build your own.

## What a raw wrapper actually hands a model

A single FortiOS policy object carries more than eighty fields. Here is a
representative sample of what is in one, lightly abridged:

```json
{
  "policyid": 4,
  "name": "guest-to-internet",
  "uuid": "8f1c0e2a-0000-0000-0000-000000000000",
  "srcintf": [{ "name": "guest", "q_origin_key": "guest" }],
  "dstintf": [{ "name": "wan1", "q_origin_key": "wan1" }],
  "srcaddr": [{ "name": "GUEST-NET", "q_origin_key": "GUEST-NET" }],
  "srcaddr6": [],
  "dstaddr6": [],
  "internet-service": "disable",
  "internet-service-name": [],
  "internet-service-group": [],
  "internet-service-custom": [],
  "internet-service-custom-group": [],
  "reputation-minimum": 0,
  "reputation-direction": "destination",
  "rtp-nat": "disable",
  "rtp-addr": [],
  "…": "…seventy more"
}
```

Ask a model *which policies allow traffic into the DMZ* against a wrapper that
returns this, and a real fraction of its attention goes to `"srcaddr6": []`
before it finds anything that bears on the question. Multiply by the number of
policies on a production firewall. The information is all there; it is just
buried in enough noise that retrieval gets unreliable in exactly the way that
is hardest to notice, because the model still answers, and the answer is still
usually right.

The summarized form of the same policy:

```json
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
  "log": "all"
}
```

Nothing an operator would read has been dropped. What is gone is the empty
IPv6 arrays, the UUIDs nobody is going to type, and the eleven
internet-service fields that are disabled on the overwhelming majority of
policies.

## Questions span endpoints

The second problem with endpoint-shaped tools is that the questions people ask
do not respect endpoint boundaries.

*Is this address object safe to delete?* touches policies on the source side,
policies on the destination side, address group membership, service group
membership, virtual IPs, and static routes. As endpoint tools, that is five
calls the model has to know to make, in the right combination, and then
correlate. Miss one and the answer is wrong in the dangerous direction. As one
tool, `find_references`, it is a single call returning a `safe_to_delete`
boolean with the supporting evidence attached.

*What is 192.168.1.47?* touches the wireless client list, the DHCP lease table,
and the ARP table. Each knows something different and each is keyed by MAC. As
endpoint tools that is three calls and a join the model has to perform in its
own head, on a key that has to be canonical on case *and* punctuation at once.
Get either axis wrong and the comparison silently matches nothing: three
partial records come back looking like three separate devices, with nothing in
the output saying why. As one tool, `find_device` canonicalizes first and
returns one record per device with `seen_in` naming the sources.

That one is worth being precise about, because it is easy to oversell. Every
endpoint on the lab appliance already agreed on the colon form, so the
normalization is insurance rather than a fix for a disagreement anyone has
observed. It earns its place anyway — insurance against a silent join failure
is cheap, and it is what lets a MAC pasted in any of the three common spellings
find its device.

*Where does 10.20.30.0/24 appear?* is the case where you do not yet know which
kind of object holds the answer, which means an endpoint-shaped interface
cannot be used correctly until after you already know the thing you are asking.
`search_config` covers addresses, groups, services, interfaces, routes, and
policies at once.

## What this costs

Three things, and they are real.

The tool surface has to be **designed**, which means someone has to know what
operators ask. That knowledge is not in the FortiOS API documentation. It comes
from having run these boxes.

The summaries **drop fields**, and eventually someone wants one that was
dropped. The mitigation is that the summaries are honest about their scope:
[the response shapes page](/reference/response-shapes/) lists every field that
survives, so nobody has to discover a gap by having an answer come back empty.

The layer **has to track FortiOS**. A raw wrapper inherits upstream changes for
free; this one has to notice them. That is the price of handling the
[version-dependent field shapes](/explanation/fortios-quirks/#relational-fields-change-shape-by-version)
rather than passing them through for the model to trip over.

## Does the argument generalize

It is fair to ask whether this shape is a FortiOS-specific accident. It is not,
and the evidence is that the same approach was worth building a second time
against completely different hardware.

[mcidrac](https://mcidrac.warehack.ing) does this for Dell iDRAC over Redfish:
the same question-shaped surface, the same refusal to hand a model raw vendor
JSON, the same insistence on validating against real appliances rather than a
schema. Different vendor, different protocol, and the same three problems —
responses too noisy to reason over, questions that span endpoints, and vendor
behaviours that fail silently.

The one instructive difference is where the risk sits. mcidrac can power-cycle
a server, so its design effort goes into confirmation and verify-by-read-back.
This one cannot change anything, so the effort goes into never reporting a
confident answer it did not actually establish. Same philosophy, aimed at the
failure mode each domain actually has.

## Where the work lives

The reading and normalizing layer is pure functions — no network, no framework,
no FastMCP imports. Every one of them takes a dict that FortiOS returned and
gives back a dict that is safe to read.

That is what makes the quirks testable. A recorded response from a FortiWiFi-61E
running 7.0.14 is a dict; a test that asserts `member_names` flattens its
bare-string `dstaddr` correctly needs no fixtures, no mock appliance, and no
network. The whole suite runs in under a second.

It also means the tool functions stay thin enough to read in one pass. A tool
resolves a target, opens a session, makes its calls, and maps the results
through the summarizers. When one of them is longer than that, it is because
the question genuinely spans several sources, and the joining is the entire
reason the tool exists.
