"""Firewall object tools: addresses, services, policies, and cross-references."""

from __future__ import annotations

from typing import Any

from fastmcp import FastMCP

from mcfortigate.annotations import read_only
from mcfortigate.client import (
    ADDRESS_GROUPS,
    ADDRESSES,
    OBJECT_KINDS,
    POLICIES,
    SERVICE_GROUPS,
    SERVICES,
    STATIC_ROUTES,
    VIPS,
    connect,
    fetch_object_usage,
    fetch_table,
)
from mcfortigate.config import TargetRegistry
from mcfortigate.fortios import (
    FortiOSError,
    describe_usage_row,
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
        whether something is safe to touch.

        The authority is the appliance itself. FortiOS exposes the same
        reference lookup its web UI uses, which knows every table that can hold
        a reference, seventy-four of them for a firewall address on 7.0.14. This
        tool asks that endpoint and reports what it says in `references`. It
        also scans policies, groups, virtual IPs, and static routes directly,
        because those yield readable detail the endpoint does not, such as a
        policy's name and action.

        Read `verdict` rather than inferring from a count:

        - `referenced`, something points at it
        - `no_references`, the appliance confirmed nothing does
        - `no_references_in_checked_scopes`, the authoritative lookup was
          unavailable and a partial scan found nothing, which is a fact about
          four tables rather than about the appliance
        - `object_not_found`, no address, group, service, virtual IP, or
          interface by this name exists, so the question is probably a typo
        - `indeterminate`, something needed could not be read

        `safe_to_delete` appears only for the first two, because a table this
        tool could not read cannot support a claim that nothing references the
        object. A denied read is the likely outcome for a correctly
        least-privileged token, so an incomplete answer is normal rather than
        exceptional, and `sources_checked` names what failed.

        The two lists count different things, and will disagree without being
        in conflict. `total_references` and `references` count reference
        *sites*: a policy using one address as both its source and its
        destination is two. The detail lists (`policies`, `groups`, `vips`,
        `routes`) count *objects*, so the same policy appears once there, with
        `referenced_as` naming both roles. Neither number is wrong; prefer
        `references` when reporting what must be changed before a delete, and
        the detail lists when naming the objects an operator has to open.

        Group membership is not expanded transitively: an object inside a group
        that a policy uses is reported as referenced by the group, not by the
        policy.

        Args:
            object_name: Exact name of the address, group, service, virtual IP,
                or interface. Matching is exact, not a search.
            target: Which FortiGate to query. Optional when only one is configured.

        """
        fgt = registry.resolve(target)
        sources: dict[str, str] = {}
        cached: dict[str, list[dict[str, Any]]] = {}

        def read(label: str, path: str) -> list[dict[str, Any]]:
            """Read one source once, recording its status rather than raising."""
            if path in cached:
                return cached[path]
            try:
                rows = fetch_table(api, path)
            except FortiOSError as exc:
                sources[label] = exc.summary()
                cached[path] = []
                return []
            sources[label] = "ok"
            cached[path] = rows
            return rows

        with connect(fgt) as api:
            raw_policies = read("policies", POLICIES)
            raw_addr_groups = read("address_groups", ADDRESS_GROUPS)
            raw_svc_groups = read("service_groups", SERVICE_GROUPS)
            raw_vips = read("vips", VIPS)
            raw_routes = read("routes", STATIC_ROUTES)

            # Work out which table defines this name before asking the usage
            # endpoint about it. The endpoint cannot tell us: asked about a key
            # that is absent from the table named, it answers 200 and an empty
            # list, exactly as it does for an object that genuinely has no
            # references.
            kinds: list[tuple[str, str, str]] = []
            identification_failed = False
            for kind, label, table_path, q_path, q_name in OBJECT_KINDS:
                rows = read(label, table_path)
                if sources.get(label) != "ok":
                    identification_failed = True
                    continue
                if any(row.get("name") == object_name for row in rows):
                    kinds.append((kind, q_path, q_name))

            # With no kind identified, sweep every candidate rather than give
            # up. Identification can fail because a table was denied, and a
            # reference found under some kind is still a reference.
            to_query = kinds or [(kind, q_path, q_name) for kind, _, _, q_path, q_name in OBJECT_KINDS]

            usage_rows: list[dict[str, Any]] = []
            usage_failures: list[str] = []
            candidate_tables = 0
            for kind, q_path, q_name in to_query:
                answer = fetch_object_usage(api, q_path, q_name, object_name)
                if not answer.ok:
                    usage_failures.append(f"{kind}: {answer.describe()}")
                    continue
                body = answer.rows[0] if answer.rows else {}
                candidate_tables = max(candidate_tables, len(body.get("can_use") or []))
                for row in body.get("currently_using") or []:
                    if isinstance(row, dict):
                        usage_rows.append(describe_usage_row(row, kind))

            # Partial success is not success. If any query failed, the union is
            # a lower bound and must not underwrite a clean verdict.
            sources["object_usage"] = "ok" if not usage_failures else "; ".join(usage_failures)

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

        scanned = len(policy_hits) + len(group_hits) + len(vip_hits) + len(route_hits)
        unreadable = [label for label, status in sources.items() if status != "ok"]
        usage_ok = not usage_failures
        # The authority failing and the scan failing are different problems, and
        # lumping them together makes the milder one unreachable. Every usage
        # failure lands in `unreadable`, so a verdict keyed on that alone can
        # never distinguish "we looked everywhere we could" from "we could not
        # look properly at all".
        scan_unreadable = [label for label in unreadable if label != "object_usage"]

        # Order matters. A confirmed reference outranks every doubt, since it
        # settles the only question that can cause damage. Below that, the
        # appliance's own answer outranks our partial scan, so a denied detail
        # table does not weaken a verdict the authoritative source already gave.
        if usage_rows or scanned:
            verdict = "referenced"
        elif not kinds and not identification_failed:
            verdict = "object_not_found"
        elif usage_ok:
            verdict = "no_references"
        elif not scan_unreadable:
            verdict = "no_references_in_checked_scopes"
        else:
            verdict = "indeterminate"

        result: dict[str, Any] = {
            "target": fgt.name,
            "vdom": fgt.vdom,
            "object": object_name,
            "verdict": verdict,
            "total_references": len(usage_rows) if usage_ok else scanned,
            "resolved_as": [kind for kind, _, _ in kinds],
            "references": usage_rows,
            "sources_checked": sources,
            "policies": policy_hits,
            "groups": group_hits,
            "vips": vip_hits,
            "routes": route_hits,
        }
        # Only meaningful when we know what kind of object this is. On a blind
        # sweep it would be the largest count across six unrelated kinds, which
        # describes nothing.
        if usage_ok and candidate_tables and kinds:
            result["candidate_tables"] = candidate_tables

        # Claim decidability only where it was earned. Omitting the key rather
        # than setting it false forces a reader to consult the verdict, where a
        # false would invite it to stop reading.
        if verdict == "no_references":
            result["safe_to_delete"] = True
        elif verdict == "referenced":
            result["safe_to_delete"] = False
        elif verdict == "object_not_found":
            result["note"] = (
                f"No address, group, service, virtual IP, or interface named {object_name!r} "
                "exists on this appliance, so this answer is about a name rather than an "
                "object. Check the spelling."
            )
        elif verdict == "no_references_in_checked_scopes":
            result["note"] = (
                "The appliance's own reference lookup was unavailable, so this covers only "
                "policies, groups, virtual IPs, and static routes. FortiOS reports many more "
                "tables that can hold a reference, and they were not consulted."
            )
        else:
            result["note"] = (
                f"Could not read: {', '.join(unreadable)}. The reference count is a lower bound "
                "and no conclusion about deletion safety is possible."
            )
        return result
