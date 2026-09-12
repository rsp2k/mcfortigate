"""Network tools: interfaces, VLANs, and routing."""

from __future__ import annotations

from typing import Any

from fastmcp import FastMCP

from mcfortigate.annotations import read_only
from mcfortigate.client import (
    ADDRESSES,
    INTERFACES,
    MON_AVAILABLE_INTERFACES,
    MON_ROUTING_TABLE,
    STATIC_ROUTES,
    MonitorResult,
    connect,
    fetch_monitor,
    fetch_table,
    resolve_vdom,
    use_vdom,
)
from mcfortigate.config import TargetRegistry
from mcfortigate.fortios import (
    is_internal_interface,
    resolve_route_destinations,
    summarize_interface,
    summarize_route,
)
from mcfortigate.paging import FilterTally, paginate


def _policy_endpoints(available: MonitorResult) -> set[str] | None:
    """Names FortiOS offers as policy source or destination interfaces.

    Returns None when the appliance did not answer, which is different from an
    empty set and has to stay different: an empty set would hide every
    prefix-matched interface on the grounds that the appliance confirmed none of
    them are usable, when in fact it was never asked.
    """
    if not available.ok:
        return None
    return {
        str(row.get("name"))
        for row in available.rows
        if row.get("name") and row.get("valid_in_policy") is True
    }


def register(mcp: FastMCP, registry: TargetRegistry) -> None:
    """Attach the network tools to the server."""

    @mcp.tool(annotations=read_only("List interfaces"))
    def list_interfaces(
        target: str | None = None,
        vdom: str | None = None,
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
        visible.

        Which ones count as bookkeeping is decided by the appliance rather than
        by the name. FortiOS reports whether each interface is offered as a
        policy endpoint, and anything it offers is shown regardless of what it
        is called, so this tool cannot hide an interface a policy could name.
        `hidden_internal_basis` says whether that lookup succeeded; when it did
        not, the fallback is the name and the omission is less trustworthy.

        Filters narrow the list silently unless you read `filtered_out`, which
        names each active filter and how many rows it removed. `with_ip_only`
        keeps interfaces carrying an IPv4 address in the configuration, which
        includes a DHCP interface that has taken a lease, because FortiOS writes
        the leased address back into the config.

        An interface that holds no address reports `addressing` instead of `ip`.
        Use get_routing_table for the runtime view.

        Args:
            target: Which FortiGate to query. Optional when only one is configured.
            vdom: Virtual domain to read. Defaults to the one configured for this
                target. The `vdom` field in the response names the one actually
                read.
            include_internal: Include FortiOS-generated interfaces, meaning those
                the appliance does not offer as policy endpoints and whose names
                carry a generated prefix such as wqtn., vap., ssl., or naf.
            interface_type: Exact FortiOS type filter, such as physical, vlan,
                aggregate, hard-switch, switch, or tunnel. Not a substring match.
            with_ip_only: Keep only interfaces carrying an IPv4 address in the
                configuration.
            limit: Maximum interfaces to return. Defaults to 200, capped at 1000.
            offset: Index to start from, for paging through a large table.

        """
        fgt = registry.resolve(target)
        scope = resolve_vdom(fgt, vdom)
        with connect(fgt) as api:
            use_vdom(api, vdom)
            raw_interfaces = fetch_table(api, INTERFACES)
            # Asked rather than inferred. On 7.0.14 the appliance offers
            # naf.root to policies and does not offer ssl.root, which is the
            # reverse of what either name suggests.
            available = fetch_monitor(api, MON_AVAILABLE_INTERFACES)

        endpoints = _policy_endpoints(available)
        tally = FilterTally(
            internal_hidden=not include_internal,
            interface_type=interface_type,
            with_ip_only=with_ip_only,
        )

        results: list[dict[str, Any]] = []
        hidden: list[str] = []
        for raw in raw_interfaces:
            name = raw.get("name", "")
            if not name:
                continue
            if not include_internal and _is_bookkeeping(name, endpoints):
                hidden.append(name)
                tally.drop("internal_hidden")
                continue
            if interface_type and raw.get("type", "physical") != interface_type:
                tally.drop("interface_type")
                continue
            summary = summarize_interface(raw)
            if with_ip_only and "ip" not in summary:
                tally.drop("with_ip_only")
                continue
            results.append(summary)

        window, paging = paginate(results, limit, offset)
        response: dict[str, Any] = {
            "target": fgt.name,
            "vdom": scope,
            **tally.describe(len(raw_interfaces)),
            **paging,
            "interfaces": window,
        }
        if hidden:
            response["hidden_internal"] = sorted(hidden)
            response["hidden_internal_basis"] = "name_prefix" if endpoints is None else "appliance"
            response["hidden_internal_note"] = (
                "Hidden by name prefix because the appliance's policy-endpoint list "
                f"could not be read ({available.describe()}), so one of these may be usable "
                "in a policy. Pass include_internal=true to see them."
                if endpoints is None
                else (
                    "FortiOS generates these and does not offer them as policy endpoints. "
                    "Pass include_internal=true to see them."
                )
            )
        return response

    @mcp.tool(annotations=read_only("List VLANs"))
    def list_vlans(
        target: str | None = None,
        vdom: str | None = None,
        limit: int | None = None,
        offset: int | None = None,
    ) -> dict[str, Any]:
        """List VLAN sub-interfaces with their tags and parent interfaces.

        A focused view of the VLAN subset of the interface table, since what
        VLANs exist and what they attach to is asked far more often than the full
        interface list. FortiOS quarantine VLANs are excluded, and `filtered_out`
        says how many that was.

        Args:
            target: Which FortiGate to query. Optional when only one is configured.
            vdom: Virtual domain to read. Defaults to the one configured for this
                target. The `vdom` field in the response names the one actually
                read.
            limit: Maximum rows to return. Defaults to 200, capped at 1000.
            offset: Index to start from, for paging through a large table.

        """
        fgt = registry.resolve(target)
        scope = resolve_vdom(fgt, vdom)
        with connect(fgt) as api:
            use_vdom(api, vdom)
            raw_interfaces = fetch_table(api, INTERFACES)
            available = fetch_monitor(api, MON_AVAILABLE_INTERFACES)

        endpoints = _policy_endpoints(available)
        tally = FilterTally(vlans_only=True, internal_hidden=True)

        results: list[dict[str, Any]] = []
        for raw in raw_interfaces:
            if raw.get("type") != "vlan":
                tally.drop("vlans_only")
                continue
            if _is_bookkeeping(raw.get("name", ""), endpoints):
                tally.drop("internal_hidden")
                continue
            results.append(summarize_interface(raw))

        results.sort(key=lambda item: (item.get("vlan_id") is None, item.get("vlan_id") or 0))
        window, paging = paginate(results, limit, offset)
        return {
            "target": fgt.name,
            "vdom": scope,
            **tally.describe(len(raw_interfaces)),
            **paging,
            "vlans": window,
        }

    @mcp.tool(annotations=read_only("List configured static routes"))
    def list_static_routes(
        target: str | None = None,
        vdom: str | None = None,
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
            vdom: Virtual domain to read. Defaults to the one configured for this
                target. Routes are per-vdom, so this changes the answer on a
                multi-VDOM appliance. The `vdom` field names the one actually read.
            limit: Maximum rows to return. Defaults to 200, capped at 1000.
            offset: Index to start from, for paging through a large table.

        """
        fgt = registry.resolve(target)
        scope = resolve_vdom(fgt, vdom)
        with connect(fgt) as api:
            use_vdom(api, vdom)
            raw_routes = fetch_table(api, STATIC_ROUTES)
            summaries = [summarize_route(raw) for raw in raw_routes]
            # Only pay for the address table when a route actually needs it.
            if any(summary.get("destination_address_object") for summary in summaries):
                resolve_route_destinations(summaries, fetch_table(api, ADDRESSES))

        summaries.sort(key=lambda item: item.get("seq_num") or 0)
        window, paging = paginate(summaries, limit, offset)
        return {"target": fgt.name, "vdom": scope, **paging, "routes": window}

    @mcp.tool(annotations=read_only("Show the active routing table"))
    def get_routing_table(
        target: str | None = None,
        vdom: str | None = None,
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
            vdom: Virtual domain to read. Defaults to the one configured for this
                target. The `vdom` field in the response names the one actually
                read.
            protocol: Filter by route type, such as static, connect, or dhcp.
                Matched exactly; `filtered_out` reports how many rows it removed.
            limit: Maximum rows to return. Defaults to 200, capped at 1000.
            offset: Index to start from, for paging through a large table.

        """
        fgt = registry.resolve(target)
        scope = resolve_vdom(fgt, vdom)
        with connect(fgt) as api:
            use_vdom(api, vdom)
            monitor = fetch_monitor(api, MON_ROUTING_TABLE)

        tally = FilterTally(protocol=protocol)
        results: list[dict[str, Any]] = []
        for entry in monitor.rows:
            if protocol and entry.get("type") != protocol:
                tally.drop("protocol")
                continue
            results.append(
                {
                    "destination": entry.get("ip_mask"),
                    "gateway": entry.get("gateway"),
                    "interface": entry.get("interface"),
                    "type": entry.get("type"),
                    "distance": entry.get("distance"),
                    "metric": entry.get("metric"),
                }
            )

        window, paging = paginate(results, limit, offset)
        response: dict[str, Any] = {
            "target": fgt.name,
            "vdom": scope,
            **tally.describe(len(monitor.rows)),
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


def _is_bookkeeping(name: str, endpoints: set[str] | None) -> bool:
    """Decide whether an interface is FortiOS bookkeeping rather than config.

    The name is the fallback, not the authority. `ssl.`, `naf.`, `vap.`, and
    `wqtn.` are all FortiOS-generated prefixes, but so are `wqt.` and `l2t.`
    which the prefix list never covered, and on 7.0.14 the appliance offers
    `naf.root` to policies while refusing `ssl.root`. Guessing from the name
    therefore hides interfaces a policy can reference and shows ones it cannot.

    When the appliance answered, anything it offers as a policy endpoint is real
    config by definition. When it did not, fall back to the prefix and let the
    caller see that the omission is a guess.
    """
    if endpoints is not None and name in endpoints:
        return False
    return is_internal_interface(name)
