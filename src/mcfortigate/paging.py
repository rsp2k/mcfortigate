"""Bounding long results so the caller is told when there are more.

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
