"""Network tools: interfaces, VLANs, and routing."""

from __future__ import annotations

from typing import Any

from fastmcp import FastMCP

from mcfortigate.client import connect, fetch_monitor
from mcfortigate.config import TargetRegistry
from mcfortigate.fortios import (
    is_internal_interface,
    member_names,
    subnet_to_cidr,
    summarize_interface,
    summarize_route,
)


def register(mcp: FastMCP, registry: TargetRegistry) -> None:
    """Attach the network tools to the server."""

    @mcp.tool
    def list_interfaces(
        target: str | None = None,
        include_internal: bool = False,
        interface_type: str | None = None,
        with_ip_only: bool = False,
    ) -> dict[str, Any]:
        """List interfaces with their addresses, VLAN tags, and link state.

        FortiOS auto-creates bookkeeping interfaces alongside real ones, such as
        the quarantine interface that accompanies every wireless VAP. Those are
        hidden by default because an operator did not create them and cannot
        meaningfully act on them.

        Args:
            target: Which FortiGate to query. Optional when only one is configured.
            include_internal: Include FortiOS-generated interfaces, which are the
                ones prefixed wqtn., vap., ssl., and naf.
            interface_type: Exact FortiOS type filter, such as physical, vlan,
                aggregate, hard-switch, switch, or tunnel.
            with_ip_only: Keep only interfaces that carry an IP address.

        """
        fgt = registry.resolve(target)
        with connect(fgt) as api:
            raw_interfaces = api.cmdb.system.interface.get()

        results: list[dict[str, Any]] = []
        hidden = 0
        for raw in raw_interfaces:
            name = raw.get("name", "")
            if not name:
                continue
            if not include_internal and is_internal_interface(name):
                hidden += 1
                continue
            if interface_type and raw.get("type", "physical") != interface_type:
                continue
            summary = summarize_interface(raw)
            if with_ip_only and "ip" not in summary:
                continue
            results.append(summary)

        response: dict[str, Any] = {"target": fgt.name, "count": len(results), "interfaces": results}
        if hidden:
            response["hidden_internal"] = hidden
        return response

    @mcp.tool
    def list_vlans(target: str | None = None) -> dict[str, Any]:
        """List VLAN sub-interfaces with their tags and parent interfaces.

        This is a focused view of the VLAN subset of the interface table, since
        "what VLANs exist and what are they attached to" is asked far more often
        than the full interface list. FortiOS quarantine VLANs are excluded.

        Args:
            target: Which FortiGate to query. Optional when only one is configured.

        """
        fgt = registry.resolve(target)
        with connect(fgt) as api:
            raw_interfaces = api.cmdb.system.interface.get()

        results = [
            summary
            for raw in raw_interfaces
            if raw.get("type") == "vlan"
            and not is_internal_interface(raw.get("name", ""))
            and (summary := summarize_interface(raw))
        ]
        results.sort(key=lambda item: item.get("vlan_id") or 0)
        return {"target": fgt.name, "count": len(results), "vlans": results}

    @mcp.tool
    def list_static_routes(target: str | None = None) -> dict[str, Any]:
        """List configured static routes.

        These are the routes an operator configured, which is not the same as
        the routes currently in use. A DHCP-assigned default route, for example,
        never appears here because it was never configured. Use
        get_routing_table for what the appliance is actually forwarding on.

        Routes whose destination is a named address object are resolved to the
        underlying CIDR where possible, with the object name kept alongside it.

        Args:
            target: Which FortiGate to query. Optional when only one is configured.

        """
        fgt = registry.resolve(target)
        with connect(fgt) as api:
            raw_routes = api.cmdb.router.static.get()
            needs_resolution = any(member_names(raw.get("dstaddr")) for raw in raw_routes)
            address_by_name: dict[str, dict] = {}
            if needs_resolution:
                address_by_name = {
                    raw.get("name", ""): raw for raw in api.cmdb.firewall.address.get()
                }

        results: list[dict[str, Any]] = []
        for raw in raw_routes:
            summary = summarize_route(raw)
            named = summary.get("destination_address_object")
            if named and isinstance(named, str) and summary.get("destination") is None:
                referenced = address_by_name.get(named)
                if referenced and referenced.get("type", "ipmask") in {"ipmask", "interface-subnet"}:
                    summary["destination"] = subnet_to_cidr(referenced.get("subnet", ""))
            results.append(summary)

        results.sort(key=lambda item: item.get("seq_num") or 0)
        return {"target": fgt.name, "count": len(results), "routes": results}

    @mcp.tool
    def get_routing_table(target: str | None = None, protocol: str | None = None) -> dict[str, Any]:
        """Show the active IPv4 routing table as the appliance is forwarding it.

        This is live state rather than configuration, so it includes connected
        routes, dynamically learned routes, and routes handed over by DHCP, none
        of which appear in the static route configuration.

        Args:
            target: Which FortiGate to query. Optional when only one is configured.
            protocol: Filter by route type, such as static, connect, or dhcp.

        """
        fgt = registry.resolve(target)
        with connect(fgt) as api:
            entries = fetch_monitor(api, "api/v2/monitor/router/ipv4")

        results = [
            {
                "destination": entry.get("ip_mask"),
                "gateway": entry.get("gateway"),
                "interface": entry.get("interface"),
                "type": entry.get("type"),
                "distance": entry.get("distance"),
                "metric": entry.get("metric"),
            }
            for entry in entries
            if not protocol or entry.get("type") == protocol
        ]
        return {"target": fgt.name, "count": len(results), "routes": results}
