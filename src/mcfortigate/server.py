"""Server construction and CLI entry point."""

from __future__ import annotations

import sys

from fastmcp import FastMCP

from mcfortigate import __version__
from mcfortigate.config import ConfigError, TargetRegistry
from mcfortigate.tools import register_all

INSTRUCTIONS = """\
Read-only access to FortiGate firewalls over the FortiOS REST API.

Start with list_targets when you do not know which appliances are reachable.
Every other tool takes an optional `target` argument naming one of them, which
can be omitted when only one appliance is configured.

For open questions where the object type is not yet known, search_config looks
across addresses, services, interfaces, routes, and policies at once. Before
suggesting any configuration change, find_references reports everything that
points at a given object, which is what determines whether it is safe to touch.

Configuration tools read what the appliance was told to do. Live tools read
what it currently observes, and those answers are only true at the moment of
the call. A DHCP-assigned default route, for example, appears in the live
routing table but never in the static route configuration.

This server cannot modify any configuration.\
"""


def build_server(registry: TargetRegistry | None = None) -> FastMCP:
    """Construct the server with every tool registered.

    Target loading happens here rather than at import time so a configuration
    mistake surfaces as a readable tool error rather than a stack trace during
    module import, where an MCP client would show nothing but a failed
    connection.
    """
    mcp = FastMCP("mcfortigate", instructions=INSTRUCTIONS)
    register_all(mcp, registry if registry is not None else TargetRegistry())
    return mcp


def main() -> None:
    """Run the server over stdio."""
    try:
        registry = TargetRegistry()
    except ConfigError as exc:
        print(f"mcfortigate: configuration error: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc

    target_summary = ", ".join(registry.names) if len(registry) else "none configured"
    print(f"mcfortigate v{__version__} | targets: {target_summary}", file=sys.stderr)
    if not len(registry):
        print(
            "mcfortigate: no targets found. Set FORTIGATE_HOST and FORTIGATE_TOKEN, "
            "or FORTIGATE_TARGETS with a JSON object. Tools will report this too.",
            file=sys.stderr,
        )

    build_server(registry).run()


if __name__ == "__main__":
    main()
