"""Firewall object tools: addresses, services, policies, and cross-references."""

from __future__ import annotations

from typing import Any

from fastmcp import FastMCP

from mcfortigate.client import connect
from mcfortigate.config import TargetRegistry
from mcfortigate.fortios import (
    member_names,
    summarize_address,
    summarize_policy,
    summarize_service,
)


def _matches(haystack: str, needle: str | None) -> bool:
    """Case-insensitive substring test that passes everything when no needle."""
    return True if not needle else needle.lower() in (haystack or "").lower()


def register(mcp: FastMCP, registry: TargetRegistry) -> None:
    """Attach the firewall tools to the server."""

    @mcp.tool
    def list_address_objects(
        target: str | None = None,
        name_contains: str | None = None,
        address_type: str | None = None,
    ) -> dict[str, Any]:
        """List firewall address objects, optionally filtered.

        Address objects are the named source and destination values that policies
        reference. Each one is reported with its type and a single readable value,
        so a subnet object shows CIDR, an FQDN object shows the hostname, and a
        MAC object shows the MAC addresses.

        Args:
            target: Which FortiGate to query. Optional when only one is configured.
            name_contains: Case-insensitive substring filter on the object name.
            address_type: Exact FortiOS type filter, such as ipmask, fqdn, iprange,
                geography, or mac.

        """
        fgt = registry.resolve(target)
        with connect(fgt) as api:
            raw_objects = api.cmdb.firewall.address.get()

        results = [
            summary
            for raw in raw_objects
            if _matches(raw.get("name", ""), name_contains)
            and (not address_type or raw.get("type", "ipmask") == address_type)
            and (summary := summarize_address(raw))
        ]
        return {"target": fgt.name, "count": len(results), "addresses": results}

    @mcp.tool
    def list_address_groups(target: str | None = None, name_contains: str | None = None) -> dict[str, Any]:
        """List firewall address groups and their members.

        Args:
            target: Which FortiGate to query. Optional when only one is configured.
            name_contains: Case-insensitive substring filter on the group name.

        """
        fgt = registry.resolve(target)
        with connect(fgt) as api:
            raw_groups = api.cmdb.firewall.addrgrp.get()

        results = [
            {
                "name": raw.get("name", ""),
                "members": member_names(raw.get("member")),
                **({"comment": raw["comment"]} if raw.get("comment") else {}),
            }
            for raw in raw_groups
            if _matches(raw.get("name", ""), name_contains)
        ]
        return {"target": fgt.name, "count": len(results), "groups": results}

    @mcp.tool
    def list_services(target: str | None = None, name_contains: str | None = None) -> dict[str, Any]:
        """List firewall service objects with their protocols and ports.

        Args:
            target: Which FortiGate to query. Optional when only one is configured.
            name_contains: Case-insensitive substring filter on the service name.

        """
        fgt = registry.resolve(target)
        with connect(fgt) as api:
            raw_services = api.cmdb.firewall_service.custom.get()

        results = [
            summarize_service(raw) for raw in raw_services if _matches(raw.get("name", ""), name_contains)
        ]
        return {"target": fgt.name, "count": len(results), "services": results}

    @mcp.tool
    def list_policies(
        target: str | None = None,
        enabled_only: bool = False,
        interface: str | None = None,
        address: str | None = None,
        service: str | None = None,
    ) -> dict[str, Any]:
        """List firewall policies in evaluation order, optionally filtered.

        Policies are returned in the order FortiOS evaluates them, which is the
        order they appear in the configuration rather than sorted by ID. That
        order is the whole meaning of a firewall ruleset, so it is preserved.

        Args:
            target: Which FortiGate to query. Optional when only one is configured.
            enabled_only: Drop policies whose status is disabled.
            interface: Keep only policies whose source or destination interface
                matches this name exactly.
            address: Keep only policies referencing this address object or group
                by name, on either the source or the destination side.
            service: Keep only policies referencing this service object by name.

        """
        fgt = registry.resolve(target)
        with connect(fgt) as api:
            raw_policies = api.cmdb.firewall.policy.get()

        results: list[dict[str, Any]] = []
        for raw in raw_policies:
            summary = summarize_policy(raw)
            if enabled_only and not summary["enabled"]:
                continue
            if interface and interface not in (*summary["from"], *summary["to"]):
                continue
            if address and address not in (*summary["source"], *summary["destination"]):
                continue
            if service and service not in summary["service"]:
                continue
            results.append(summary)

        return {"target": fgt.name, "count": len(results), "policies": results}

    @mcp.tool
    def list_vips(target: str | None = None) -> dict[str, Any]:
        """List virtual IPs, which are the destination NAT rules.

        A VIP maps an external address, and optionally an external port, to an
        internal one. FortiOS stores the addresses inline on the VIP rather than
        as references to address objects.

        Args:
            target: Which FortiGate to query. Optional when only one is configured.

        """
        fgt = registry.resolve(target)
        with connect(fgt) as api:
            raw_vips = api.cmdb.firewall.vip.get()

        results: list[dict[str, Any]] = []
        for raw in raw_vips:
            mapped = [m.get("range", "") for m in raw.get("mappedip", []) or [] if isinstance(m, dict)]
            entry: dict[str, Any] = {
                "name": raw.get("name", ""),
                "external_ip": member_names(raw.get("extip")) or raw.get("extip"),
                "mapped_ip": mapped,
                "interface": member_names(raw.get("extintf")) or raw.get("extintf"),
            }
            if raw.get("portforward") == "enable":
                entry["port_forward"] = {
                    "protocol": raw.get("protocol"),
                    "external_port": raw.get("extport"),
                    "mapped_port": raw.get("mappedport"),
                }
            if raw.get("comment"):
                entry["comment"] = raw["comment"]
            results.append(entry)

        return {"target": fgt.name, "count": len(results), "vips": results}

    @mcp.tool
    def find_references(object_name: str, target: str | None = None) -> dict[str, Any]:
        """Find everywhere an address, service, or interface is referenced.

        This answers the question that precedes every config change on a
        firewall, which is whether something is safe to modify or delete. It
        checks policies on both the address and service sides, address group and
        service group membership, virtual IPs, and static routes, in one call.

        An empty result across every category means nothing points at the object.
        A non-empty result is the list of things that would be affected by
        changing it.

        Args:
            object_name: Exact name of the address, group, service, or interface.
            target: Which FortiGate to query. Optional when only one is configured.

        """
        fgt = registry.resolve(target)
        with connect(fgt) as api:
            raw_policies = api.cmdb.firewall.policy.get()
            raw_addr_groups = api.cmdb.firewall.addrgrp.get()
            raw_svc_groups = api.cmdb.firewall_service.group.get()
            raw_vips = api.cmdb.firewall.vip.get()
            raw_routes = api.cmdb.router.static.get()

        policy_hits: list[dict[str, Any]] = []
        for raw in raw_policies:
            summary = summarize_policy(raw)
            fields = {
                "source": summary["source"],
                "destination": summary["destination"],
                "service": summary["service"],
                "from_interface": summary["from"],
                "to_interface": summary["to"],
            }
            matched = [field for field, values in fields.items() if object_name in values]
            if matched:
                policy_hits.append(
                    {
                        "id": summary["id"],
                        "name": summary["name"],
                        "enabled": summary["enabled"],
                        "action": summary["action"],
                        "referenced_as": matched,
                    }
                )

        group_hits = [
            {"name": raw.get("name", ""), "kind": "address_group"}
            for raw in raw_addr_groups
            if object_name in member_names(raw.get("member"))
        ]
        group_hits += [
            {"name": raw.get("name", ""), "kind": "service_group"}
            for raw in raw_svc_groups
            if object_name in member_names(raw.get("member"))
        ]

        vip_hits = [
            {"name": raw.get("name", ""), "referenced_as": "external_interface"}
            for raw in raw_vips
            if object_name in member_names(raw.get("extintf"))
        ]

        route_hits = []
        for raw in raw_routes:
            as_destination = object_name in member_names(raw.get("dstaddr"))
            as_interface = raw.get("device") == object_name
            if as_destination or as_interface:
                route_hits.append(
                    {
                        "seq_num": raw.get("seq-num"),
                        "referenced_as": "destination_address" if as_destination else "interface",
                    }
                )

        total = len(policy_hits) + len(group_hits) + len(vip_hits) + len(route_hits)
        return {
            "target": fgt.name,
            "object": object_name,
            "total_references": total,
            "safe_to_delete": total == 0,
            "policies": policy_hits,
            "groups": group_hits,
            "vips": vip_hits,
            "routes": route_hits,
        }
