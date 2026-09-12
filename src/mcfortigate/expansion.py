"""Walking a reference chain past the object that directly holds it.

`monitor/system/object/usage` reports the direct referrer and stops. Measured
on the lab FortiWiFi-61E running 7.0.14: `internal1` is a port of the hardware
switch `internal`, `internal` is a member of the software switch `lan`, and
`lan` is policy 1's source interface. Asking the appliance about `internal1`
returns exactly one row, naming `internal`, and never mentions the policy.

That is the right answer to the question the endpoint was asked and the wrong
answer to the question an operator has. "What breaks if I delete this" is about
the policy, and the container between them is not what stops matching.

So this module walks the containers. It is pure: the caller supplies a `lookup`
callable that performs the REST call, which keeps the walk unit-testable
against recorded shapes and keeps this file free of transport concerns.

Three things the walk has to get right, each of which has a failure mode that
looks like working code:

- **Termination.** FortiOS permits a group inside a group and nothing observed
  here rules out a loop, so a visited set is mandatory rather than defensive.
  Without one, a cycle runs until the depth cap and then reports a fabricated
  truncation, which reads as a legitimate answer.
- **Bounding.** Every level costs one REST call per container discovered at the
  level before it. The cap exists so a deeply nested config cannot turn one
  tool call into a fan-out.
- **Labelling.** A reference reached through two containers must never be
  shaped like one the appliance named directly, because the remedy differs:
  a direct reference is removed from the object that holds it, a transitive one
  is removed by editing the container or the member list.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

#: How many rounds of container expansion to perform beyond the direct lookup.
#:
#: Three, for two reasons that happen to agree. The deepest containment chain
#: on the lab appliance is switch port -> hardware switch -> software switch
#: interface -> policy, which puts the policy at depth two, so three leaves one
#: level of headroom over the worst real nesting measured. And the cost is
#: multiplicative: each level issues one usage call per container found at the
#: level above, so a config with wide groups pays branching-factor-cubed at
#: three and cannot be allowed to pay it at ten. Configs nested deeper than
#: this exist in principle; when one turns up the tool says `depth_capped`
#: rather than pretending it finished.
MAX_EXPANSION_DEPTH = 3

#: Which reference rows name a *container* of the object, and what to ask the
#: appliance about that container next.
#:
#: Keyed by the referencing table and the field holding the reference, because
#: the table alone is not enough: `system.interface` referencing an interface
#: through `member` is a switch holding a port, while the same table
#: referencing it through `name` is a VLAN naming its parent, and only the
#: first means "this stands in for the object in a policy".
#:
#: The value is the `q_path` / `q_name` / kind to look the container up as,
#: spelled out rather than derived from the referencing table's own name. That
#: derivation is wrong for exactly one entry and wrong silently: measured on
#: 7.0.14, `q_path=system&q_name=virtual-switch&mkey=internal` answers HTTP 200
#: with an empty list, while `q_name=interface` with the same key returns the
#: membership that continues the chain. A hard switch is listed in both tables
#: and only one of them knows what uses it.
CONTAINERS: dict[tuple[str, str], tuple[str, str, str]] = {
    ("firewall.addrgrp", "member"): ("firewall", "addrgrp", "address group"),
    ("firewall.service.group", "member"): ("firewall.service", "group", "service group"),
    ("system.zone", "interface"): ("system", "zone", "zone"),
    ("system.interface", "member"): ("system", "interface", "interface"),
    ("system.virtual-switch", "port"): ("system", "interface", "interface"),
}

#: `lookup(q_path, q_name, kind, name)` returns the described reference rows for
#: one object, or a short failure description when the appliance did not answer.
Lookup = Callable[[str, str, str, str], "tuple[list[dict[str, Any]], str | None]"]


class Expansion:
    """What the walk found, and how much of the truth it is.

    `status` is a word rather than a boolean on purpose. "Did it finish" has
    three answers here — it ran out, it hit the ceiling, or something refused to
    be read — and collapsing those into `truncated: true/false` loses the one
    distinction a reader acts on.
    """

    __slots__ = ("rows", "failures", "unexpanded", "deepest")

    def __init__(self) -> None:
        """Start empty; the walk fills this in as it goes."""
        self.rows: list[dict[str, Any]] = []
        self.failures: list[str] = []
        self.unexpanded: list[str] = []
        self.deepest = 0

    @property
    def status(self) -> str:
        """Complete, stopped at the ceiling, or missing something it could not read.

        Failures outrank the cap. Both mean the answer is a lower bound, and the
        weaker claim is the honest one to report when both apply.
        """
        if self.failures:
            return "incomplete"
        if self.unexpanded:
            return "depth_capped"
        return "complete"

    def describe(self) -> dict[str, Any]:
        """Summarize the walk for the tool response.

        `unexpanded` is omitted when empty rather than reported as an empty
        list, so that a reader scanning for it finds either names to chase or
        nothing to think about.
        """
        summary: dict[str, Any] = {
            "max_depth": MAX_EXPANSION_DEPTH,
            "status": self.status,
            "deepest_depth": self.deepest,
        }
        if self.unexpanded:
            summary["unexpanded"] = self.unexpanded
        return summary


def containers_in(rows: list[dict[str, Any]]) -> list[tuple[str, tuple[str, str, str]]]:
    """Pick out the rows that name something standing in for the object.

    Takes rows already through `describe_usage_row`, so `table` is the rejoined
    `path.name` and `object` is the referencing object's primary key.

    >>> containers_in([{"table": "firewall.addrgrp", "object": "G Suite", "attribute": "member"}])
    [('G Suite', ('firewall', 'addrgrp', 'address group'))]
    >>> containers_in([{"table": "firewall.policy", "object": "1", "attribute": "srcaddr"}])
    []
    """
    found: list[tuple[str, tuple[str, str, str]]] = []
    for row in rows:
        query = CONTAINERS.get((row.get("table", ""), row.get("attribute", "")))
        if query is None:
            continue
        name = row.get("object")
        if isinstance(name, str) and name:
            found.append((name, query))
    return found


def expand(
    direct_rows: list[dict[str, Any]],
    origin: str,
    lookup: Lookup,
    *,
    seeds_complete: bool = True,
    max_depth: int = MAX_EXPANSION_DEPTH,
) -> Expansion:
    """Walk outward from the containers the direct lookup named.

    Args:
        direct_rows: The described reference rows for the object itself.
        origin: The object the question was asked about. Seeds the visited set,
            so a container that loops back to it is not walked a second time.
        lookup: Performs one usage call. See :data:`Lookup`.
        seeds_complete: False when the direct lookup was itself partial. A walk
            that starts from an incomplete set of containers cannot be called
            complete however cleanly it runs, and saying otherwise would let a
            denied read upstream be laundered into a confident answer here.
        max_depth: Rounds of expansion to perform. See :data:`MAX_EXPANSION_DEPTH`.

    Returns:
        An :class:`Expansion` holding the reached rows, each carrying `depth`
        and the `via` chain of container names that led to it.

    """
    result = Expansion()
    if not seeds_complete:
        result.failures.append("the direct lookup was partial, so the containers to walk are a lower bound")

    # The origin is visited before the walk starts. A group that contains the
    # object and is itself contained by it is a cycle of length two, and this
    # is the half of the guard that catches it.
    visited = {origin}
    frontier = [(name, query, [name]) for name, query in containers_in(direct_rows)]

    for depth in range(1, max_depth + 1):
        if not frontier:
            break
        next_frontier: list[tuple[str, tuple[str, str, str], list[str]]] = []
        for name, (q_path, q_name, kind), via in frontier:
            # The one place termination is decided. It catches a back edge, a
            # group that contains a group that contains it again, and equally a
            # diamond, one container reached down two different paths in the
            # same round. Both would otherwise cost a repeated REST call and
            # emit the same rows twice.
            if name in visited:
                continue
            visited.add(name)
            rows, failure = lookup(q_path, q_name, kind, name)
            if failure is not None:
                result.failures.append(f"{name}: {failure}")
                continue
            for row in rows:
                reached = dict(row)
                reached["depth"] = depth
                reached["via"] = list(via)
                result.rows.append(reached)
                result.deepest = max(result.deepest, depth)
            next_frontier.extend((found, query, [*via, found]) for found, query in containers_in(rows))
        frontier = next_frontier

    # Anything still on the frontier is a container we know about and did not
    # open. Naming it is the difference between a bounded answer and a wrong one
    # that looks bounded. Names already visited are dropped: a loop back to a
    # container we did open is not something left undone, and listing it would
    # invent work and overstate how much of the chain is missing.
    result.unexpanded = sorted({name for name, _, _ in frontier if name not in visited})
    return result
