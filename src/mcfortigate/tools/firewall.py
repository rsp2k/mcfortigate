"""Firewall object tools: addresses, services, policies, and cross-references."""

from __future__ import annotations

from typing import Any

from fastmcp import FastMCP

from mcfortigate.annotations import read_only
from mcfortigate.client import (
    ADDRESS_GROUPS,
    ADDRESSES,
    POLICIES,
    SERVICE_GROUPS,
    SERVICES,
    STATIC_ROUTES,
    VIPS,
    connect,
    fetch_table,
)
from mcfortigate.config import TargetRegistry
from mcfortigate.fortios import (
    FortiOSError,
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

    @mcp.tool(annotations=read_only("List address objects"))
    def list_address_objects(
        target: str | None = None,
        name_contains: str | None = None,
        address_type: str | None = None,
    ) -> dict[str, Any]:
        """List firewall address objects, optionally filtered.

        Address objects are the named source and destination values that policies
        reference. Each is reported with its type and a single readable value, so
        a subnet object shows CIDR, an FQDN object shows the hostname, and a MAC
        object shows the MAC addresses.

        Args:
            target: Which FortiGate to query. Optional when only one is configured.
            name_contains: Case-insensitive substring filter on the object name.
            address_type: Exact FortiOS type filter, such as ipmask, fqdn, iprange,
                geography, or mac.

        """
        fgt = registry.resolve(target)
        with connect(fgt) as api:
            raw_objects = fetch_table(api, ADDRESSES)

        results = []
        for raw in raw_objects:
            if not _matches(raw.get("name", ""), name_contains):
                continue
            if address_type and raw.get("type", "ipmask") != address_type:
                continue
            results.append(summarize_address(raw))
        return {"target": fgt.name, "vdom": fgt.vdom, "count": len(results), "addresses": results}

    @mcp.tool(annotations=read_only("List address groups"))
    def list_address_groups(target: str | None = None, name_contains: str | None = None) -> dict[str, Any]:
        """List firewall address groups and their members.

        Args:
            target: Which FortiGate to query. Optional when only one is configured.
            name_contains: Case-insensitive substring filter on the group name.

        """
        fgt = registry.resolve(target)
        with connect(fgt) as api:
            raw_groups = fetch_table(api, ADDRESS_GROUPS)

        results = [
            {
                "name": raw.get("name", ""),
                "members": member_names(raw.get("member")),
                **({"comment": raw["comment"]} if raw.get("comment") else {}),
            }
            for raw in raw_groups
            if _matches(raw.get("name", ""), name_contains)
        ]
        return {"target": fgt.name, "vdom": fgt.vdom, "count": len(results), "groups": results}

    @mcp.tool(annotations=read_only("List services"))
    def list_services(target: str | None = None, name_contains: str | None = None) -> dict[str, Any]:
        """List firewall service objects with their protocols and ports.

        Args:
            target: Which FortiGate to query. Optional when only one is configured.
            name_contains: Case-insensitive substring filter on the service name.

        """
        fgt = registry.resolve(target)
        with connect(fgt) as api:
            raw_services = fetch_table(api, SERVICES)

        results = [summarize_service(raw) for raw in raw_services if _matches(raw.get("name", ""), name_contains)]
        return {"target": fgt.name, "vdom": fgt.vdom, "count": len(results), "services": results}

    @mcp.tool(annotations=read_only("List firewall policies"))
    def list_policies(
        target: str | None = None,
        enabled_only: bool = False,
        interface: str | None = None,
        address: str | None = None,
        service: str | None = None,
    ) -> dict[str, Any]:
        """List firewall policies in evaluation order, optionally filtered.

        Policies come back in the order FortiOS evaluates them, and each carries
        an explicit `order` index so that ordering survives filtering and
        re-serialization. Order is the entire meaning of a ruleset, and a list
        position is not something downstream is obliged to preserve.

        The filters match names exactly and do not expand indirection. A policy
        referencing a group that contains your address will not match `address`,
        and a policy referencing a zone that contains your interface will not
        match `interface`. Use find_references for the question "what touches
        this object", which is a different and usually better question.

        Args:
            target: Which FortiGate to query. Optional when only one is configured.
            enabled_only: Drop policies whose status is disabled.
            interface: Keep only policies naming this interface directly as a
                source or destination interface.
            address: Keep only policies naming this address object or group
                directly, on either side.
            service: Keep only policies naming this service object directly.

        """
        fgt = registry.resolve(target)
        with connect(fgt) as api:
            raw_policies = fetch_table(api, POLICIES)

        results: list[dict[str, Any]] = []
        for index, raw in enumerate(raw_policies):
            summary = summarize_policy(raw)
            summary["order"] = index
            if enabled_only and not summary["enabled"]:
                continue
            if interface and interface not in (*summary["from"], *summary["to"]):
                continue
            if address and address not in (*summary["source"], *summary["destination"]):
                continue
            if service and service not in summary["service"]:
                continue
            results.append(summary)

        return {
            "target": fgt.name,
            "vdom": fgt.vdom,
            "count": len(results),
            "total_policies": len(raw_policies),
            "policies": results,
        }

    @mcp.tool(annotations=read_only("List virtual IPs"))
    def list_vips(target: str | None = None) -> dict[str, Any]:
        """List virtual IPs, which are the destination NAT rules.

        A VIP maps an external address, and optionally an external port, to an
        internal one. FortiOS stores those addresses inline on the VIP rather
        than as references to address objects.

        Args:
            target: Which FortiGate to query. Optional when only one is configured.

        """
        fgt = registry.resolve(target)
        with connect(fgt) as api:
            raw_vips = fetch_table(api, VIPS)

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

        return {"target": fgt.name, "vdom": fgt.vdom, "count": len(results), "vips": results}

    @mcp.tool(annotations=read_only("Find what references an object"))
    def find_references(object_name: str, target: str | None = None) -> dict[str, Any]:
        """Find what references an address, service, or interface, before changing it.

        This answers the question that precedes every firewall change, which is
        whether something is safe to touch. It reads policies on both the address
        and service sides, address and service group membership, virtual IPs, and
        static routes.

        Read `verdict` rather than assuming, and read `sources_checked` when it is
        indeterminate. `safe_to_delete` is present only when every source was
        readable, because a table this tool could not read cannot support a claim
        that nothing references the object. A denied read is the likely outcome
        for a correctly least-privileged token, so an indeterminate answer is
        normal rather than exceptional.

        Coverage is not exhaustive even when every source is readable. Proxy
        policies, local-in policies, SD-WAN rules, zones, IP pools, and DHCP
        server settings can all reference an object and are not consulted, and
        group membership is not expanded transitively. `checked_scopes` lists
        what was actually examined.

        Args:
            object_name: Exact name of the address, group, service, or interface.
            target: Which FortiGate to query. Optional when only one is configured.

        """
        fgt = registry.resolve(target)
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
            raw_policies = read("policies", POLICIES)
            raw_addr_groups = read("address_groups", ADDRESS_GROUPS)
            raw_svc_groups = read("service_groups", SERVICE_GROUPS)
            raw_vips = read("vips", VIPS)
            raw_routes = read("routes", STATIC_ROUTES)

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
        unreadable = [label for label, status in sources.items() if status != "ok"]

        if unreadable:
            verdict = "indeterminate"
        elif total:
            verdict = "referenced"
        else:
            verdict = "no_references"

        result: dict[str, Any] = {
            "target": fgt.name,
            "vdom": fgt.vdom,
            "object": object_name,
            "verdict": verdict,
            "total_references": total,
            "sources_checked": sources,
            "checked_scopes": [
                "firewall policies",
                "address groups",
                "service groups",
                "virtual IPs",
                "static routes",
            ],
            "policies": policy_hits,
            "groups": group_hits,
            "vips": vip_hits,
            "routes": route_hits,
        }
        # Only claim decidability when every source answered. Omitting the key
        # rather than setting it false forces a reader to consult the verdict,
        # where a false would invite it to stop.
        if not unreadable:
            result["safe_to_delete"] = total == 0
        else:
            result["note"] = (
                f"Could not read: {', '.join(unreadable)}. The reference count is a lower bound "
                "and no conclusion about deletion safety is possible."
            )
        return result
