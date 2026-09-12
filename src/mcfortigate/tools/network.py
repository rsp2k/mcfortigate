"""Network tools: interfaces, VLANs, and routing."""

from __future__ import annotations

from typing import Any

from fastmcp import FastMCP

from mcfortigate.annotations import read_only
from mcfortigate.client import (
    ADDRESSES,
    INTERFACES,
    MON_ROUTING_TABLE,
    STATIC_ROUTES,
    connect,
    fetch_monitor,
    fetch_table,
)
from mcfortigate.config import TargetRegistry
from mcfortigate.fortios import (
    is_internal_interface,
    resolve_route_destinations,
    summarize_interface,
    summarize_route,
)
from mcfortigate.paging import paginate


def register(mcp: FastMCP, registry: TargetRegistry) -> None:
    """Attach the network tools to the server."""

    @mcp.tool(annotations=read_only("List interfaces"))
    def list_interfaces(
        target: str | None = None,
        include_internal: bool = False,
        interface_type: str | None = None,
        with_ip_only: bool = False,
        limit: int | None = None,
        offset: int | None = None,
    ) -> dict[str, Any]:
        """List interfaces with their addresses, VLAN tags, and link state.

        FortiOS creates bookkeeping interfaces alongside real ones, such as the
        quarantine interface that accompanies every wireless VAP. Those are
        hidden by default and named in `hidden_internal` so the omission is
        visible. Note that `ssl.root` is hidden by that rule but is a genuine
        policy endpoint, so a policy may name an interface this tool omits.

        An interface that takes its address by DHCP or PPPoE reports no `ip` and
        carries `addressing` instead, because the configuration genuinely holds
        no address. Use get_routing_table for the runtime value.

        Args:
            target: Which FortiGate to query. Optional when only one is configured.
            include_internal: Include FortiOS-generated interfaces, meaning those
                prefixed wqtn., vap., ssl., and naf.
            interface_type: Exact FortiOS type filter, such as physical, vlan,
                aggregate, hard-switch, switch, or tunnel.
            with_ip_only: Keep only interfaces carrying a static IP address.
            limit: Maximum interfaces to return. Defaults to 200, capped at 1000.
            offset: Index to start from, for paging through a large table.

        """
        fgt = registry.resolve(target)
        with connect(fgt) as api:
            raw_interfaces = fetch_table(api, INTERFACES)

        results: list[dict[str, Any]] = []
        hidden: list[str] = []
        for raw in raw_interfaces:
            name = raw.get("name", "")
            if not name:
                continue
            if not include_internal and is_internal_interface(name):
                hidden.append(name)
                continue
            if interface_type and raw.get("type", "physical") != interface_type:
                continue
            summary = summarize_interface(raw)
            if with_ip_only and "ip" not in summary:
                continue
            results.append(summary)

        window, paging = paginate(results, limit, offset)
        response: dict[str, Any] = {
            "target": fgt.name,
            "vdom": fgt.vdom,
            **paging,
            "interfaces": window,
        }
        if hidden:
            response["hidden_internal"] = sorted(hidden)
        return response

    @mcp.tool(annotations=read_only("List VLANs"))
    def list_vlans(
        target: str | None = None,
        limit: int | None = None,
        offset: int | None = None,
    ) -> dict[str, Any]:
        """List VLAN sub-interfaces with their tags and parent interfaces.

        A focused view of the VLAN subset of the interface table, since what
        VLANs exist and what they attach to is asked far more often than the full
        interface list. FortiOS quarantine VLANs are excluded.

        Args:
            target: Which FortiGate to query. Optional when only one is configured.
            limit: Maximum rows to return. Defaults to 200, capped at 1000.
            offset: Index to start from, for paging through a large table.

        """
        fgt = registry.resolve(target)
        with connect(fgt) as api:
            raw_interfaces = fetch_table(api, INTERFACES)

        results = [
            summarize_interface(raw)
            for raw in raw_interfaces
            if raw.get("type") == "vlan" and not is_internal_interface(raw.get("name", ""))
        ]
        results.sort(key=lambda item: (item.get("vlan_id") is None, item.get("vlan_id") or 0))
        window, paging = paginate(results, limit, offset)
        return {"target": fgt.name, "vdom": fgt.vdom, **paging, "vlans": window}

    @mcp.tool(annotations=read_only("List configured static routes"))
    def list_static_routes(
        target: str | None = None,
        limit: int | None = None,
        offset: int | None = None,
    ) -> dict[str, Any]:
        """List configured static routes.

        These are the routes an operator configured, which is not the same as the
        routes in use. A DHCP-assigned default route never appears here because
        it was never configured. Use get_routing_table for what the appliance is
        actually forwarding on.

        A route whose destination is a named address object is resolved to the
        underlying CIDR where possible, with the object name kept alongside it.

        Args:
            target: Which FortiGate to query. Optional when only one is configured.
            limit: Maximum rows to return. Defaults to 200, capped at 1000.
            offset: Index to start from, for paging through a large table.

        """
        fgt = registry.resolve(target)
        with connect(fgt) as api:
            raw_routes = fetch_table(api, STATIC_ROUTES)
            summaries = [summarize_route(raw) for raw in raw_routes]
            # Only pay for the address table when a route actually needs it.
            if any(summary.get("destination_address_object") for summary in summaries):
                resolve_route_destinations(summaries, fetch_table(api, ADDRESSES))

        summaries.sort(key=lambda item: item.get("seq_num") or 0)
        window, paging = paginate(summaries, limit, offset)
        return {"target": fgt.name, "vdom": fgt.vdom, **paging, "routes": window}

    @mcp.tool(annotations=read_only("Show the active routing table"))
    def get_routing_table(
        target: str | None = None,
        protocol: str | None = None,
        limit: int | None = None,
        offset: int | None = None,
    ) -> dict[str, Any]:
        """Show the active IPv4 routing table as the appliance is forwarding it.

        This is live state rather than configuration, so it includes connected
        routes, dynamically learned routes, and routes handed over by DHCP, none
        of which appear in the static route configuration.

        Args:
            target: Which FortiGate to query. Optional when only one is configured.
            protocol: Filter by route type, such as static, connect, or dhcp.
            limit: Maximum rows to return. Defaults to 200, capped at 1000.
            offset: Index to start from, for paging through a large table.

        """
        fgt = registry.resolve(target)
        with connect(fgt) as api:
            monitor = fetch_monitor(api, MON_ROUTING_TABLE)

        results = [
            {
                "destination": entry.get("ip_mask"),
                "gateway": entry.get("gateway"),
                "interface": entry.get("interface"),
                "type": entry.get("type"),
                "distance": entry.get("distance"),
                "metric": entry.get("metric"),
            }
            for entry in monitor.rows
            if not protocol or entry.get("type") == protocol
        ]
        window, paging = paginate(results, limit, offset)
        response: dict[str, Any] = {
            "target": fgt.name,
            "vdom": fgt.vdom,
            **paging,
            "routes": window,
            "source_status": monitor.describe(),
        }
        if not monitor.ok:
            response["warning"] = (
                f"The routing table could not be read ({monitor.describe()}), so this is not "
                "evidence that no routes exist."
            )
        return response
