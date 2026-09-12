"""Server construction smoke tests.

The sibling SSoT project shipped a release whose navigation module raised a
TypeError at import time. Every unit test passed, because the test fixtures
stubbed the framework out, and the crash only appeared when a real process
tried to start. These tests exist so the equivalent failure here is caught by
``pytest`` rather than by a user whose MCP client just says "server failed to
start" with no further detail.

Nothing here touches a network. Registration and schema generation are enough
to catch the whole class of import-time and decorator-time errors.
"""

from __future__ import annotations

import asyncio

import pytest

from mcfortigate.config import FortiGateTarget, TargetRegistry
from mcfortigate.server import build_server

EXPECTED_TOOLS = {
    # Orientation
    "list_targets",
    "get_system_status",
    "search_config",
    # Firewall
    "list_address_objects",
    "list_address_groups",
    "list_services",
    "list_policies",
    "list_vips",
    "find_references",
    # Network
    "list_interfaces",
    "list_vlans",
    "list_static_routes",
    "get_routing_table",
    # Live state
    "list_wifi_clients",
    "list_dhcp_leases",
    "get_arp_table",
    "find_device",
}


@pytest.fixture
def registry() -> TargetRegistry:
    """A registry with one target, so tools resolve without a network."""
    return TargetRegistry({"lab": FortiGateTarget(name="lab", host="fgt.example", token="x")})


@pytest.fixture
def tools(registry: TargetRegistry) -> dict:
    """Every registered tool, keyed by name."""
    server = build_server(registry)
    return {tool.name: tool for tool in asyncio.run(server.list_tools())}


class TestServerConstruction:
    def test_server_builds(self, registry: TargetRegistry):
        assert build_server(registry) is not None

    def test_builds_with_no_targets_configured(self):
        """A misconfigured environment must still produce a running server.

        Failing at construction would surface to the operator as an opaque
        connection failure in their MCP client. Failing inside a tool call
        surfaces as a message telling them which variables to set.
        """
        assert build_server(TargetRegistry({})) is not None

    def test_instructions_are_present(self, registry: TargetRegistry):
        server = build_server(registry)
        assert server.instructions
        assert "read-only" in server.instructions.lower()


class TestToolRegistration:
    def test_every_expected_tool_is_registered(self, tools: dict):
        assert set(tools) == EXPECTED_TOOLS

    def test_no_tool_is_missing_a_description(self, tools: dict):
        undocumented = [name for name, tool in tools.items() if not (tool.description or "").strip()]
        assert undocumented == []

    def test_every_tool_exposes_an_object_schema(self, tools: dict):
        """A malformed annotation surfaces here rather than at call time."""
        for name, tool in tools.items():
            schema = tool.parameters
            assert schema.get("type") == "object", f"{name} has schema type {schema.get('type')!r}"

    def test_target_argument_is_optional_everywhere_it_appears(self, tools: dict):
        """Single-appliance installs should never have to name their target."""
        for name, tool in tools.items():
            schema = tool.parameters
            if "target" in schema.get("properties", {}):
                assert "target" not in schema.get("required", []), f"{name} requires target"

    def test_most_tools_accept_a_target(self, tools: dict):
        """Only list_targets, which enumerates them, has no target argument."""
        without_target = {name for name, tool in tools.items() if "target" not in tool.parameters.get("properties", {})}
        assert without_target == {"list_targets"}

    def test_query_style_tools_require_their_subject(self, tools: dict):
        """A search with no term and a lookup with no subject are user errors."""
        assert "term" in tools["search_config"].parameters.get("required", [])
        assert "query" in tools["find_device"].parameters.get("required", [])
        assert "object_name" in tools["find_references"].parameters.get("required", [])


class TestToolAnnotations:
    """Every tool must declare what it does before a client calls it.

    A client deciding whether a call needs human approval reads these hints. A
    server that writes nothing should say so rather than leaving that to be
    inferred from a tool name.
    """

    def test_every_tool_is_annotated(self, tools: dict):
        unannotated = [name for name, tool in tools.items() if not tool.annotations]
        assert unannotated == []

    def test_every_tool_declares_itself_read_only(self, tools: dict):
        """There is no write path in this package, so there is no exception."""
        writable = [name for name, tool in tools.items() if not tool.annotations.read_only_hint]
        assert writable == []

    def test_no_tool_claims_to_be_destructive(self, tools: dict):
        destructive = [name for name, tool in tools.items() if tool.annotations.destructive_hint]
        assert destructive == []

    def test_every_tool_is_open_world(self, tools: dict):
        """Answers describe an appliance that changes without our involvement."""
        closed = [name for name, tool in tools.items() if not tool.annotations.open_world_hint]
        assert closed == []

    def test_every_tool_has_a_human_title(self, tools: dict):
        untitled = [name for name, tool in tools.items() if not (tool.annotations.title or "").strip()]
        assert untitled == []
