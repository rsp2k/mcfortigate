"""Server-level tools: target discovery, appliance identity, and config search."""

from __future__ import annotations

from typing import Any

from fastmcp import FastMCP

from mcfortigate.client import connect, fetch_envelope, fetch_monitor
from mcfortigate.config import TargetRegistry
from mcfortigate.fortios import (
    is_internal_interface,
    member_names,
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

    @mcp.tool
    def list_targets() -> dict[str, Any]:
        """List the FortiGate appliances this server can reach.

        Call this first when several appliances may be configured, since every
        other tool takes an optional target argument naming one of these. When
        exactly one is configured, the target argument can be omitted entirely.

        Credentials are never included in the response.
        """
        targets = registry.all()
        return {
            "count": len(targets),
            "default_target": targets[0].name if len(targets) == 1 else None,
            "targets": [target.describe() for target in targets],
        }

    @mcp.tool
    def get_system_status(target: str | None = None) -> dict[str, Any]:
        """Report appliance identity: model, serial, firmware, hostname, uptime.

        The serial and firmware version come from the response envelope rather
        than the response body. FortiOS puts them as siblings of the results
        object on every cmdb call, and helper functions that unwrap straight to
        results discard them, which is why they appear to be missing from the
        API until you look at the raw response.

        Args:
            target: Which FortiGate to query. Optional when only one is configured.

        """
        fgt = registry.resolve(target)
        with connect(fgt) as api:
            envelope = fetch_envelope(api, "api/v2/cmdb/system/global")
            status_entries = fetch_monitor(api, "api/v2/monitor/system/status")

        results = envelope.get("results") or {}
        status = status_entries[0] if status_entries else {}

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
            "uptime_seconds": status.get("uptime"),
        }

    @mcp.tool
    def search_config(
        term: str,
        target: str | None = None,
        include_policies: bool = True,
    ) -> dict[str, Any]:
        """Search the whole configuration for a term, across every object type.

        Looks through address objects and groups, services, interfaces, static
        routes, and optionally policies, matching against names, values,
        comments, and member lists. This is the tool for an open question like
        "where does 10.20.30.0/24 appear" or "what mentions the word guest",
        when you do not yet know which kind of object holds the answer.

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
            return {"target": fgt.name, "term": term, "total_matches": 0, "matches": {}}

        with connect(fgt) as api:
            raw_addresses = api.cmdb.firewall.address.get()
            raw_groups = api.cmdb.firewall.addrgrp.get()
            raw_services = api.cmdb.firewall_service.custom.get()
            raw_interfaces = api.cmdb.system.interface.get()
            raw_routes = api.cmdb.router.static.get()
            raw_policies = api.cmdb.firewall.policy.get() if include_policies else []

        matches: dict[str, list[dict[str, Any]]] = {}

        addresses = [
            summary
            for raw in raw_addresses
            if (summary := summarize_address(raw))
            and (
                _hit(summary["name"], needle)
                or _hit(summary["value"], needle)
                or _hit(summary.get("comment"), needle)
            )
        ]
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

        services = [
            summary
            for raw in raw_services
            if (summary := summarize_service(raw))
            and (_hit(summary["name"], needle) or _hit(summary.get("comment"), needle))
        ]
        if services:
            matches["services"] = services

        interfaces = [
            summary
            for raw in raw_interfaces
            if not is_internal_interface(raw.get("name", ""))
            and (summary := summarize_interface(raw))
            and (
                _hit(summary["name"], needle)
                or _hit(summary.get("ip"), needle)
                or _hit(summary.get("description"), needle)
            )
        ]
        if interfaces:
            matches["interfaces"] = interfaces

        routes = [
            summary
            for raw in raw_routes
            if (summary := summarize_route(raw))
            and (
                _hit(summary.get("destination"), needle)
                or _hit(summary.get("gateway"), needle)
                or _hit(summary.get("comment"), needle)
                or _hit(summary.get("destination_address_object"), needle)
            )
        ]
        if routes:
            matches["routes"] = routes

        if include_policies:
            policies = [
                summary
                for raw in raw_policies
                if (summary := summarize_policy(raw))
                and (
                    _hit(summary["name"], needle)
                    or _hit(summary.get("comment"), needle)
                    or any(
                        needle in value.lower()
                        for key in ("source", "destination", "service", "from", "to")
                        for value in summary[key]
                    )
                )
            ]
            if policies:
                matches["policies"] = policies

        total = sum(len(hits) for hits in matches.values())
        return {"target": fgt.name, "term": term, "total_matches": total, "matches": matches}
