---
title: What read-only means here
description: Read-only is structural rather than a setting, what that does and does not protect against, and where the real exposure is.
---

Nothing in this server can change a FortiGate configuration. That is worth
stating precisely, because *read-only* gets used to mean several different
things and only one of them is a property you can rely on.

## It is structural, not a setting

There is no write path in the codebase. Not a disabled one, not one behind a
flag, not one gated on an environment variable somebody could set. Every tool
issues `GET` and there is no `create`, `update`, or `delete` anywhere to
misconfigure, to reach by accident, or to talk a model into using.

This matters because the alternative — a server that can write, with writes
turned off — has a failure mode this one does not. A flag can be wrong. A flag
can be right in your environment and wrong in the copy somebody made of it. A
capability that does not exist cannot be enabled by mistake.

Every tool also *declares* it. Each carries the MCP `readOnlyHint` annotation,
along with `destructiveHint: false` and `idempotentHint: true`, so a client
deciding whether a call needs human approval can read that from the tool rather
than inferring it from the name. `openWorldHint` is true as well, which is the
less obvious one: the answers describe an external system that changes without
our involvement, so a result is a snapshot rather than a fact worth caching.

It also means prompt injection has a smaller target. A model reading a
firewall's configuration is reading text that other people wrote — policy
comments, object names, interface descriptions — and text from an appliance is
not automatically trustworthy just because the appliance is yours. If one of
those comments contains an instruction, the worst it can direct this server to
do is read something else.

## Defence in depth anyway

Structural read-only is the last line, not the only one. Two more are worth
having, and both live on the appliance rather than here.

**A read-only REST API admin.** Create the API user under System >
Administrators with a read-only profile. If a future version of this server
grew a write path, or if the token leaked into something that has one, the
appliance still refuses. Details are in
[getting started](/tutorials/getting-started/).

**Trusted hosts.** Restrict the API admin to the source address of whatever
runs the server. A FortiGate API token is a bearer credential: anything holding
it is that admin. Trusted hosts is what makes a leaked token useless from
anywhere but one address, and it is the single highest-value control on this
list.

Set both. Each covers a failure the other does not.

## What read-only does not protect

Being honest about this is more useful than the reassurance would be.

**This server can read your entire firewall configuration and hand it to a
language model.** Every policy, every address object, every interface
description and comment, every lease and every associated wireless client.
Read-only constrains what can be *changed*, and constrains nothing at all about
what can be *seen*.

That has consequences worth thinking through before you point it at a
production edge device:

The lease and ARP tables are a device inventory of the people on your network,
by hostname. `find_device` is useful precisely because it resolves *who is
192.168.1.47* into an answer with a person's name attached to it, and that is
exactly the property that makes it worth thinking about where the answer goes
afterwards.

Policy comments carry more than people expect — ticket numbers, vendor names,
the reason a temporary exception was granted and who asked for it.

The configuration describes your topology, which is the reconnaissance phase of
an attack handed over pre-summarized.

None of that argues against using this. It argues for knowing which model
provider sees the traffic, whether the conversation is retained, and whether
that is acceptable for the specific appliance you are pointing at. A lab box
and a client's production edge are not the same decision.

## What a compromised token gets

If the token leaks, an attacker gets read access to the appliance's
configuration as that API admin — through this server or around it, since a
token works fine with `curl`. Trusted hosts is what makes that hard to use.
A read-only profile is what caps the damage if it is used.

If the *host running the server* is compromised, the token is on it, and you
are in the same position. There is no key management here: the token is an
environment variable, and the process that can read its own environment can
read the token. Treat the host running an MCP server with appliance credentials
the way you would treat any jump host.

## Audit trail

Every call shows up in the FortiGate's own API audit log as a `GET` from the
API admin, with the source address you restricted it to. The
[tool-to-endpoint map](/reference/fortios-endpoints/) is what turns those log
lines back into the questions that produced them — a single
`find_references` call appears as a usage lookup plus five cmdb reads in the
space of a second, and
recognizing that pattern is the difference between an audit review that makes
sense and one that looks like scraping.
