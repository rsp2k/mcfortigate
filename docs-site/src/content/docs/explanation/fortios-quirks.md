---
title: FortiOS behaviours handled here
description: Six FortiOS quirks that fail silently rather than loudly, why each one is dangerous, and what mcfortigate does about it.
---

These were found against real hardware rather than in documentation. What they
have in common is the property that makes them worth writing down: each one
fails *silently*. Nothing errors, nothing logs, and the answer you get back is
confidently wrong in a way that reads as plausible.

## Boolean fields are strings

FortiOS writes `"enable"` and `"disable"` where JSON would use `true` and
`false`, and it is not consistent about it — some endpoints use real booleans
for the same concept.

The trap is that `bool("disable")` is `True`. Python evaluates the string's
truthiness, not its meaning, so every disabled thing reads as enabled and
nothing anywhere complains.

```python
bool("disable")           # True   — wrong, and silent
fortios_bool("disable")   # False
```

In the sibling SSoT project this exact mistake flipped every non-blackhole
route to blackhole, and it survived until someone compared the sync output
against the appliance by hand. A disabled policy reported as enabled is the
same class of error, and on a firewall it is the more expensive one.

`fortios_bool` handles the strings, real booleans, and numerics, and takes an
explicit default for the case where FortiOS omits the field entirely. Policies
and routes default to *enabled* when `status` is absent, because that is what
FortiOS itself means by the omission.

## The same format means two things

FortiOS writes IPv4 in a dotted-mask pair, space-separated, in both of these
places:

```
firewall.address.subnet    "10.0.0.0 255.255.255.0"
system.interface.ip        "10.0.0.1 255.255.255.0"
```

Identical format, different meaning. The first is a network, and collapsing it
to `10.0.0.0/24` is correct. The second is *this interface's own address within
that network*, and collapsing it to the network address throws away the host
and invents an IP that does not exist on the box.

So there are two conversions, deliberately not one:

```python
subnet_to_cidr("10.0.0.0 255.255.255.0")       # '10.0.0.0/24'
interface_ip_to_cidr("10.0.0.1 255.255.255.0") # '10.0.0.1/24'
```

The interface form also returns nothing for `0.0.0.0`, since an unaddressed
interface should report no address rather than report `0.0.0.0/0` and look like
it owns the internet.

## Relational fields change shape by version

Fields such as `srcaddr`, `dstaddr`, and `service` normally arrive as a list of
objects:

```json
"dstaddr": [{ "name": "DMZ-SERVERS" }]
```

On FortiOS 7.0.x some of the same fields come back as a bare string holding one
name instead. This was observed on a FortiWiFi-61E running 7.0.14, on the
`dstaddr` field of a static route.

Both shapes mean the same thing, so both are flattened to a list of names.
Code that assumes the list form crashes on 7.0.x, and code that assumes the
string form quietly iterates the characters of the name — which produces a list
of single letters and no error at all.

## `dst` is a placeholder when `dstaddr` is set

A static route states its destination one of two ways. Usually `dst` holds a
dotted-mask literal. When the operator points the route at a named address
object instead, the real destination lives in `dstaddr` and FortiOS writes the
all-zeros sentinel into `dst`.

```json
{ "seq-num": 4, "dst": "0.0.0.0 0.0.0.0", "dstaddr": [{ "name": "REMOTE-SITE" }] }
```

Read `dst` first and every named-destination route becomes a default route.
Not an error — a default route, which is a perfectly valid thing for a route to
be, and which will be believed. `dstaddr` has to win wherever it is populated.

## Identity lives in the envelope

The appliance serial, firmware version, and build number are siblings of
`results` on every cmdb response, not fields inside it:

```json
{
  "results": { "hostname": "fgt-edge1", "…": "…" },
  "serial": "FGT60FTK00000000",
  "version": "v7.4.4",
  "build": 2662
}
```

Helper functions that unwrap straight to `results` discard all three, which
makes the serial look absent from the API entirely — you can read every cmdb
endpoint in the tree and never find it.

`get_system_status` reads the raw response for this reason. The same read
sidesteps a second problem in the same helper, which coerces `results` with
`dict()` and therefore raises on any endpoint whose results are a list.

## FortiOS creates its own interfaces

Names prefixed `wqtn.`, `vap.`, `ssl.`, and `naf.` are bookkeeping. A
quarantine interface is generated alongside every wireless VAP, `ssl.` is the
SSL-VPN tunnel root, and `naf.` turns up on 7.4 and later.

They are hidden by default, because no operator made them and none can act on
them. `include_internal: true` shows them.

The filtering has to happen by *name*, not by type, and that is the part worth
remembering. A quarantine interface and an operator's VLAN are both
`type: vlan` and are otherwise indistinguishable in the API. There is no flag
that says *this one is mine*.

## `reference_count` is zero on real references

The reference-usage endpoint returns a `currently_using` list, and every row in
it carries `reference_count: 0` — including rows that are genuine, load-bearing
references.

Sum that field and an object with two references reports zero. The row's
*existence* is the signal; the count on it is decoration.

This is the quirk most likely to be reintroduced, because summing a field named
`reference_count` to get a reference count is the obvious thing to write, and
the result looks plausible on an object that genuinely has none.

## Asking the wrong table succeeds

The same endpoint is asked about an object *within a named table*. Ask about a
name that does not exist in the table you named, and FortiOS does not complain
— it answers **HTTP 200 with an empty list**.

So querying `firewall/address` about `wan1`, which is an interface, reports zero
references for something with two. No error, no warning, no hint that the
question was malformed.

That is why `find_references` resolves what kind of object a name is by reading
its defining cmdb table *before* asking about usage, and why `resolved_as`
appears in the response — it is the tool showing its work on the step where
being wrong is invisible.

## Why this list exists

Every entry here shares a shape: the wrong reading produces a valid-looking
answer. No exception, no warning, no empty result to notice. A firewall
answering confidently and wrongly about what it permits is worse than a
firewall that fails to answer, which is why this work happens once, in a
[layer of pure functions with no network coupling](/explanation/question-shaped-tools/#where-the-work-lives),
where it can be tested against recorded responses rather than rediscovered per
appliance.
