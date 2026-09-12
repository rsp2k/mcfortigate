"""Tool modules, each registering its own tools against the shared server."""

from __future__ import annotations

from fastmcp import FastMCP

from mcfortigate.config import TargetRegistry
from mcfortigate.tools import firewall, live, meta, network


def register_all(mcp: FastMCP, registry: TargetRegistry) -> None:
    """Register every tool module against the server."""
    meta.register(mcp, registry)
    firewall.register(mcp, registry)
    network.register(mcp, registry)
    live.register(mcp, registry)


__all__ = ["register_all"]
