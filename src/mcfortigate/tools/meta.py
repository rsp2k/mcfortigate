"""Server-level tools: target discovery, appliance identity, and config search."""

from __future__ import annotations

from typing import Any

from fastmcp import FastMCP

from mcfortigate.annotations import read_only
from mcfortigate.client import (
    ADDRESS_GROUPS,
    ADDRESSES,
    INTERFACES,
    MON_SYSTEM_STATUS,
    POLICIES,
    SERVICES,
    STATIC_ROUTES,
    SYSTEM_GLOBAL,
    connect,
    fetch_envelope,
    fetch_monitor,
    fetch_table,
)
from mcfortigate.config import TargetRegistry
from mcfortigate.fortios import (
    FortiOSError,
    is_internal_interface,
    member_names,
    resolve_route_destinations,
    summarize_address,
    summarize_interface,
    summarize_policy,
    summarize_route,
    summarize_service,
)


def _hit(text: Any, needle: str) -> bool:
    """Case-insensitive substring test tolerant of non-string values."""
    return needle in str(text).lower() if text else False


def register(mcp: FastMCP, registry: TargetRegistry) -> None:
    """Attach the meta tools to the server."""

    @mcp.tool(annotations=read_only("List configured FortiGates"))
    def list_targets() -> dict[str, Any]:
        """List the FortiGate appliances this server can reach.

        Call this first when several appliances may be configured, since every
        other tool takes an optional target argument naming one of these. When
        exactly one is configured, that argument can be omitted entirely.

        Credentials are never included in the response.
        """
        targets = registry.all()
        return {
            "count": len(targets),
            "default_target": targets[0].name if len(targets) == 1 else None,
            "targets": [target.describe() for target in targets],
        }

    @mcp.tool(annotations=read_only("Show appliance identity and firmware"))
    def get_system_status(target: str | None = None) -> dict[str, Any]:
        """Report appliance identity: model, serial, firmware, hostname, uptime.

        The serial and firmware version come from the response envelope rather
        than the body. FortiOS puts them as siblings of the results object on
        every cmdb call, and helpers that unwrap straight to results discard
        them, which is why they appear missing from the API until you read the
        raw response.

        Args:
            target: Which FortiGate to query. Optional when only one is configured.

        """
        fgt = registry.resolve(target)
        with connect(fgt) as api:
            envelope = fetch_envelope(api, SYSTEM_GLOBAL)
            status = fetch_monitor(api, MON_SYSTEM_STATUS)

        results = envelope.get("results") or {}
        runtime = status.rows[0] if status.rows else {}

        return {
            "target": fgt.name,
            "url": fgt.url,
            "hostname": results.get("hostname"),
            "alias": results.get("alias"),
            "serial": envelope.get("serial"),
            "version": envelope.get("version"),
            "build": envelope.get("build"),
            "vdom": fgt.vdom,
            "timezone": results.get("timezone"),
            "uptime_seconds": runtime.get("uptime"),
            "runtime_status": status.describe(),
        }

    @mcp.tool(annotations=read_only("Search the whole configuration"))
    def search_config(
        term: str,
        target: str | None = None,
        include_policies: bool = True,
    ) -> dict[str, Any]:
        """Search the whole configuration for a term, across every object type.

        Looks through address objects and groups, services, interfaces, static
        routes, and optionally policies, matching names, values, comments, and
        member lists. This is the tool for an open question such as "where does
        10.20.30.0/24 appear" or "what mentions guest", when you do not yet know
        which kind of object holds the answer.

        Check `sources_checked` before concluding from a zero result. A source
        that could not be read contributes no matches, so no matches is not the
        same as nothing found.

        Args:
            term: Case-insensitive substring to look for.
            target: Which FortiGate to query. Optional when only one is configured.
            include_policies: Search policy names, comments, and member lists.
                Policies are the largest table, so this can be turned off when
                only object definitions matter.

        """
        fgt = registry.resolve(target)
        needle = term.strip().lower()
        if not needle:
            return {
                "target": fgt.name,
                "term": term,
                "total_matches": 0,
                "matches": {},
                "error": "search term was empty",
            }

        sources: dict[str, str] = {}

        def read(label: str, path: str) -> list[dict[str, Any]]:
            """Read one source, recording its status rather than raising."""
            try:
                rows = fetch_table(api, path)
            except FortiOSError as exc:
                sources[label] = exc.summary()
                return []
            sources[label] = "ok"
            return rows

        with connect(fgt) as api:
            raw_addresses = read("addresses", ADDRESSES)
            raw_groups = read("address_groups", ADDRESS_GROUPS)
            raw_services = read("services", SERVICES)
            raw_interfaces = read("interfaces", INTERFACES)
            raw_routes = read("routes", STATIC_ROUTES)
            raw_policies = read("policies", POLICIES) if include_policies else []

        matches: dict[str, list[dict[str, Any]]] = {}

        addresses = []
        for raw in raw_addresses:
            summary = summarize_address(raw)
            if (
                _hit(summary["name"], needle)
                or _hit(summary["value"], needle)
                or _hit(summary.get("comment"), needle)
                # An unparsed type has no readable value, so fall back to the
                # raw record rather than making it unsearchable.
                or (summary.get("unparsed_type") and _hit(raw, needle))
            ):
                addresses.append(summary)
        if addresses:
            matches["addresses"] = addresses

        groups = [
            {"name": raw.get("name", ""), "members": member_names(raw.get("member"))}
            for raw in raw_groups
            if _hit(raw.get("name"), needle)
            or any(needle in member.lower() for member in member_names(raw.get("member")))
        ]
        if groups:
            matches["address_groups"] = groups

        services = []
        for raw in raw_services:
            summary = summarize_service(raw)
            if _hit(summary["name"], needle) or _hit(summary.get("comment"), needle):
                services.append(summary)
        if services:
            matches["services"] = services

        interfaces = []
        for raw in raw_interfaces:
            if is_internal_interface(raw.get("name", "")):
                continue
            summary = summarize_interface(raw)
            if (
                _hit(summary["name"], needle)
                or _hit(summary.get("ip"), needle)
                or _hit(summary.get("description"), needle)
            ):
                interfaces.append(summary)
        if interfaces:
            matches["interfaces"] = interfaces

        # Resolve named destinations the same way list_static_routes does, so
        # the two tools cannot report different destinations for one route.
        route_summaries = [summarize_route(raw) for raw in raw_routes]
        if any(summary.get("destination_address_object") for summary in route_summaries):
            resolve_route_destinations(route_summaries, raw_addresses)
        routes = [
            summary
            for summary in route_summaries
            if _hit(summary.get("destination"), needle)
            or _hit(summary.get("gateway"), needle)
            or _hit(summary.get("comment"), needle)
            or _hit(summary.get("destination_address_object"), needle)
        ]
        if routes:
            matches["routes"] = routes

        if include_policies:
            policies = []
            for raw in raw_policies:
                summary = summarize_policy(raw)
                if (
                    _hit(summary["name"], needle)
                    or _hit(summary.get("comment"), needle)
                    or any(
                        needle in value.lower()
                        for key in ("source", "destination", "service", "from", "to")
                        for value in summary[key]
                    )
                ):
                    policies.append(summary)
            if policies:
                matches["policies"] = policies

        total = sum(len(hits) for hits in matches.values())
        unreadable = [label for label, status in sources.items() if status != "ok"]
        response: dict[str, Any] = {
            "target": fgt.name,
            "vdom": fgt.vdom,
            "term": term,
            "total_matches": total,
            "matches": matches,
            "sources_checked": sources,
        }
        if unreadable:
            response["warning"] = (
                f"Could not read: {', '.join(unreadable)}. This search was incomplete, so a "
                "zero or low match count is not evidence of absence."
            )
        return response
