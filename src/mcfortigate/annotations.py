"""Shared MCP tool annotations.

Annotations are how a tool tells a client what it does before the client calls
it. That matters most for the hint a client uses to decide whether a call needs
human approval: a tool that cannot change anything should say so, rather than
leaving the client to infer it from a name.

Every tool in this server is a read. There is no code path that writes to an
appliance, so all of them carry the same shape, differing only in title.
"""

from __future__ import annotations

from mcp.types import ToolAnnotations


def read_only(title: str) -> ToolAnnotations:
    """Annotate a tool that only reads from a FortiGate.

    `openWorldHint` is true because the answers describe an external system
    whose state changes without our involvement, so a result is a snapshot
    rather than a fact a client may cache indefinitely. `idempotentHint` is true
    in the sense the specification means, which is that repeating the call has
    no additional effect, not that it returns identical data.
    """
    # Snake case rather than the camelCase of the wire format: MCP SDK v2
    # renamed these fields and warns on the old spelling. The serialized output
    # is camelCase either way.
    return ToolAnnotations(
        title=title,
        read_only_hint=True,
        destructive_hint=False,
        idempotent_hint=True,
        open_world_hint=True,
    )
