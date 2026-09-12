"""Bounding and narrowing results so the caller is told what it is not seeing.

Two ways a listing lies by omission, handled the same way.

The failure this exists to prevent is not memory. A FortiGate with four
thousand ARP entries produces a response that Python handles without noticing.
What breaks is further down: an MCP client with a response size limit truncates
the payload, and the model reads whatever survived as though it were the whole
answer. Nothing in the data says otherwise. "Which hosts are on this subnet"
then gets answered from the first eight hundred entries with total confidence.

So results are bounded here, deliberately and visibly, rather than being
bounded somewhere else silently. A bounded response always carries
`total_available`, and a truncated one additionally carries `truncated` and
`next_offset`, so a reader can tell "that is all of them" from "that is the
first page" without having to infer it from a count.

Analysis tools do not use this. `find_references` and `search_config` scan in
order to reach a verdict, and a verdict from a partial scan is wrong rather
than short. Those report what they scanned instead.

The second way is filtering, and it is worse because it leaves no trace at all.
A caller that passes `interface_type=vlan` and gets one row back cannot tell
whether the appliance has one interface or twenty-nine, and neither can a
caller that passes nothing and gets a list quietly shortened by a filter that
defaults to on. `FilterTally` makes the narrowing as visible as the paging:
which filters ran, what each removed, and how many rows there were before any
of them did.
"""

from __future__ import annotations

from typing import Any

#: Applied when the caller names no limit. High enough that most installs never
#: reach it, low enough to keep a response inside a typical client's ceiling.
DEFAULT_LIMIT = 200

#: The largest window a caller may request. A caller asking for everything on a
#: very large table is the case this module exists for, so the ceiling holds
#: even when it is raised explicitly.
MAX_LIMIT = 1000


def paginate(
    rows: list[Any],
    limit: int | None = None,
    offset: int | None = None,
) -> tuple[list[Any], dict[str, Any]]:
    """Return one window of ``rows`` plus the fields that describe it.

    Callers splice the returned mapping into their response and put the window
    under their own key, so that a tool listing addresses still says
    ``addresses`` rather than something generic.

    Out-of-range arguments are clamped rather than rejected. A model that
    guesses `offset=5000` on a table of twelve should get an empty window and a
    `total_available` telling it what went wrong, not an error that ends the
    task. The clamping is reported in `paging_note` so the correction is
    visible rather than mysterious.

    >>> window, fields = paginate(list(range(5)), limit=2)
    >>> window
    [0, 1]
    >>> fields["truncated"], fields["next_offset"], fields["total_available"]
    (True, 2, 5)

    >>> _, fields = paginate(list(range(5)))
    >>> "truncated" in fields, fields["count"]
    (False, 5)
    """
    total = len(rows)
    notes: list[str] = []

    if offset is None:
        start = 0
    elif offset < 0:
        start = 0
        notes.append(f"offset {offset} is negative, so it was read as 0")
    else:
        start = offset

    if limit is None:
        size = DEFAULT_LIMIT
    elif limit <= 0:
        size = DEFAULT_LIMIT
        notes.append(f"limit {limit} is not positive, so the default of {DEFAULT_LIMIT} was used")
    elif limit > MAX_LIMIT:
        size = MAX_LIMIT
        notes.append(f"limit {limit} exceeds the maximum of {MAX_LIMIT}, which was used instead")
    else:
        size = limit

    if start >= total and total:
        notes.append(f"offset {start} is past the end of {total} rows, so the window is empty")

    window = rows[start : start + size]
    fields: dict[str, Any] = {"count": len(window), "total_available": total}

    end = start + len(window)
    if end < total:
        fields["truncated"] = True
        fields["next_offset"] = end
        notes.append(
            f"showing rows {start} to {end - 1} of {total}. "
            f"Call again with offset={end} for the rest, and do not treat this page as the whole table."
        )

    if notes:
        fields["paging_note"] = " ".join(notes)
    return window, fields


class FilterTally:
    """Records which filters ran and how many rows each one removed.

    Built around the observation that made the paging work necessary: a number
    the caller can compare against is worth more than prose it has to trust. A
    response saying three rows matched out of twenty-nine read, with the
    twenty-six accounted for by name, cannot be mistaken for a small appliance.

    Filters are declared with the value they were given, and only a filter that
    is actually doing something counts as active. `None`, an empty string, and
    `False` all mean "the caller did not ask for this", so declaring every
    parameter unconditionally is the intended usage.

    >>> tally = FilterTally(interface_type="vlan", with_ip_only=False)
    >>> tally.drop("interface_type")
    >>> tally.drop("interface_type")
    >>> fields = tally.describe(total=10)
    >>> fields["filters_applied"], fields["filtered_out"]
    ({'interface_type': 'vlan'}, {'interface_type': 2})
    >>> fields["total_before_filters"]
    10

    With nothing active it contributes nothing, because `total_available`
    already answers the question on its own.

    >>> FilterTally(name_contains=None).describe(total=10)
    {}
    """

    __slots__ = ("active", "removed")

    def __init__(self, **filters: Any) -> None:
        """Declare each filter with the value the caller supplied for it."""
        self.active: dict[str, Any] = {
            name: value for name, value in filters.items() if value is not None and value != "" and value is not False
        }
        self.removed: dict[str, int] = dict.fromkeys(self.active, 0)

    def drop(self, name: str) -> None:
        """Record that the named filter removed one row.

        Counting an undeclared filter is a programming error rather than a data
        problem, and silently tolerating it would produce a report that omits a
        filter which really ran, which is the exact dishonesty this class
        exists to remove.
        """
        if name not in self.removed:
            raise KeyError(f"filter {name!r} was counted but never declared")
        self.removed[name] += 1

    def describe(self, total: int) -> dict[str, Any]:
        """Fields describing the narrowing, ready to splice into a response.

        ``total`` is the row count before any filter ran. Returns an empty
        mapping when no filter was active, so an unfiltered listing stays as
        plain as it was.
        """
        if not self.active:
            return {}
        removed_total = sum(self.removed.values())
        detail = ", ".join(f"{name} removed {count}" for name, count in self.removed.items())
        note = (
            f"{total} rows were read and {removed_total} removed by filters ({detail}). "
            "The rows below are what matched, not what exists."
        )
        return {
            "filters_applied": dict(self.active),
            "filtered_out": dict(self.removed),
            "total_before_filters": total,
            "filter_note": note,
        }
