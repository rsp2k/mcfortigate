"""Live-state tools: connected clients, DHCP leases, ARP, and device lookup.

Everything here reads the FortiOS monitor tree, which reports what the
appliance currently observes rather than what it was configured to do. None of
it is persisted, so these answers are true only at the moment of the call.

Each tool reports the status of every source it consulted. A FortiGate with no
radio has no wireless client list at all, and joining around that absence is
correct. A FortiGate that refused the read is a different situation entirely,
and one that must never be presented as an empty network.

The join itself is the other hazard. Three tables, keyed on MAC, each free to
write the address however its subsystem happens to. Normalizing the key is not
tidiness here, it is the difference between finding a device and reporting it
absent.
"""

from __future__ import annotations

from typing import Any

from fastmcp import FastMCP

from mcfortigate.annotations import read_only
from mcfortigate.client import (
    MON_ARP,
    MON_DHCP_LEASES,
    MON_WIFI_CLIENTS,
    MonitorResult,
    connect,
    fetch_monitor,
    resolve_vdom,
    use_vdom,
)
from mcfortigate.config import TargetRegistry
from mcfortigate.fortios import mac_fragment_digits, normalize_mac
from mcfortigate.paging import FilterTally, paginate


def _index_by_mac(result: MonitorResult) -> dict[str, dict[str, Any]]:
    """Key monitor rows by normalized MAC for joining."""
    indexed: dict[str, dict[str, Any]] = {}
    for entry in result.rows:
        mac = normalize_mac(entry.get("mac", ""))
        if mac:
            indexed[mac] = entry
    return indexed


def _source_report(sources: dict[str, MonitorResult]) -> dict[str, str]:
    """Summarize each consulted source for inclusion in a response."""
    return {name: result.describe() for name, result in sources.items()}


def _unusable(sources: dict[str, MonitorResult]) -> list[str]:
    """Names of sources whose emptiness cannot be trusted."""
    return [name for name, result in sources.items() if not result.usable]


def register(mcp: FastMCP, registry: TargetRegistry) -> None:
    """Attach the live-state tools to the server."""

    @mcp.tool(annotations=read_only("List connected wireless clients"))
    def list_wifi_clients(
        target: str | None = None,
        vdom: str | None = None,
        ssid: str | None = None,
        limit: int | None = None,
        offset: int | None = None,
    ) -> dict[str, Any]:
        """List wireless clients currently associated, enriched with DHCP and ARP.

        Each client is joined against the DHCP lease and ARP tables by MAC, which
        is what turns an anonymous MAC into a recognizable device. The hostname
        comes from the DHCP lease, falling back to the vendor class identifier
        when the client sent no name. MAC addresses are reported in one
        canonical lowercase colon-separated form whatever spelling the source
        used, since that is what makes the join work at all.

        `authenticated` is true or false only when the appliance said so, and
        absent when it did not, because inferring "not authenticated" from a
        missing field would fabricate a security-relevant claim.

        Args:
            target: Which FortiGate to query. Optional when only one is configured.
            vdom: Virtual domain to read. Defaults to the one configured for this
                target. The `vdom` field in the response names the one actually
                read.
            ssid: Keep only clients associated to this SSID, matched exactly.
                `filtered_out` reports how many clients it removed.
            limit: Maximum rows to return. Defaults to 200, capped at 1000.
            offset: Index to start from, for paging through a large table.

        """
        fgt = registry.resolve(target)
        scope = resolve_vdom(fgt, vdom)
        with connect(fgt) as api:
            use_vdom(api, vdom)
            sources = {
                "wifi": fetch_monitor(api, MON_WIFI_CLIENTS),
                "dhcp": fetch_monitor(api, MON_DHCP_LEASES),
                "arp": fetch_monitor(api, MON_ARP),
            }
        leases = _index_by_mac(sources["dhcp"])
        arp = _index_by_mac(sources["arp"])

        tally = FilterTally(ssid=ssid)
        results: list[dict[str, Any]] = []
        for client in sources["wifi"].rows:
            if ssid and client.get("ssid") != ssid:
                tally.drop("ssid")
                continue
            mac = normalize_mac(client.get("mac", ""))
            lease = leases.get(mac, {})
            arp_entry = arp.get(mac, {})
            rate_bps = client.get("data_rate_bps") or 0
            entry: dict[str, Any] = {
                "mac": mac,
                "hostname": lease.get("hostname") or lease.get("vci") or None,
                "ip": client.get("ip") or lease.get("ip") or arp_entry.get("ip"),
                "ssid": client.get("ssid"),
                "signal_dbm": client.get("signal"),
                "interface": lease.get("interface") or arp_entry.get("interface"),
            }
            try:
                entry["data_rate_mbps"] = round(float(rate_bps) / 1_000_000, 1) if rate_bps else None
            except (TypeError, ValueError):
                entry["data_rate_mbps"] = None
            auth = client.get("authentication")
            if auth is not None:
                entry["authenticated"] = auth == "pass"
            results.append(entry)

        window, paging = paginate(results, limit, offset)
        response: dict[str, Any] = {
            "target": fgt.name,
            "vdom": scope,
            **tally.describe(len(sources["wifi"].rows)),
            **paging,
            "clients": window,
            "sources_checked": _source_report(sources),
        }
        blocked = _unusable(sources)
        if blocked:
            response["warning"] = (
                f"Could not read: {', '.join(blocked)}. Results are incomplete and an empty "
                "list is not evidence that nobody is connected."
            )
        return response

    @mcp.tool(annotations=read_only("List DHCP leases"))
    def list_dhcp_leases(
        target: str | None = None,
        vdom: str | None = None,
        interface: str | None = None,
        hostname_contains: str | None = None,
        limit: int | None = None,
        offset: int | None = None,
    ) -> dict[str, Any]:
        """List current DHCP leases issued by the appliance.

        Read `filtered_out` before concluding anything from a short list. Both
        filters here drop rows without saying so otherwise, and an interface
        name with a typo produces an empty list that looks exactly like an
        appliance handing out no leases.

        Args:
            target: Which FortiGate to query. Optional when only one is configured.
            vdom: Virtual domain to read. Defaults to the one configured for this
                target. The `vdom` field in the response names the one actually
                read.
            interface: Keep only leases issued on this interface, matched exactly.
            hostname_contains: Case-insensitive substring filter on the hostname,
                falling back to the vendor class identifier when the client sent
                no name. A lease with neither is dropped by this filter.
            limit: Maximum rows to return. Defaults to 200, capped at 1000.
            offset: Index to start from, for paging through a large table.

        """
        fgt = registry.resolve(target)
        scope = resolve_vdom(fgt, vdom)
        with connect(fgt) as api:
            use_vdom(api, vdom)
            monitor = fetch_monitor(api, MON_DHCP_LEASES)

        tally = FilterTally(interface=interface, hostname_contains=hostname_contains)
        results: list[dict[str, Any]] = []
        for lease in monitor.rows:
            name = lease.get("hostname") or lease.get("vci") or ""
            if interface and lease.get("interface") != interface:
                tally.drop("interface")
                continue
            if hostname_contains and hostname_contains.lower() not in name.lower():
                tally.drop("hostname_contains")
                continue
            results.append(
                {
                    "mac": normalize_mac(lease.get("mac", "")),
                    "ip": lease.get("ip"),
                    "hostname": name or None,
                    "interface": lease.get("interface"),
                    "expires": lease.get("expire_time"),
                    "reserved": lease.get("reserved"),
                }
            )

        window, paging = paginate(results, limit, offset)
        response: dict[str, Any] = {
            "target": fgt.name,
            "vdom": scope,
            **tally.describe(len(monitor.rows)),
            **paging,
            "leases": window,
            "source_status": monitor.describe(),
        }
        if not monitor.usable:
            response["warning"] = f"The lease table could not be read ({monitor.describe()})."
        return response

    @mcp.tool(annotations=read_only("Show the ARP table"))
    def get_arp_table(
        target: str | None = None,
        vdom: str | None = None,
        interface: str | None = None,
        limit: int | None = None,
        offset: int | None = None,
    ) -> dict[str, Any]:
        """Show the ARP table, which is the IP-to-MAC bindings the appliance sees.

        ARP catches devices DHCP does not, meaning anything with a static
        address, so it is the fallback when a device is present but holds no
        lease. MAC addresses are reported in one canonical form.

        Args:
            target: Which FortiGate to query. Optional when only one is configured.
            vdom: Virtual domain to read. Defaults to the one configured for this
                target. The `vdom` field in the response names the one actually
                read.
            interface: Keep only entries learned on this interface, matched
                exactly. A name that matches no interface empties the list, so
                check `filtered_out` before reading an empty result as an empty
                ARP table.
            limit: Maximum rows to return. Defaults to 200, capped at 1000.
            offset: Index to start from, for paging through a large table.

        """
        fgt = registry.resolve(target)
        scope = resolve_vdom(fgt, vdom)
        with connect(fgt) as api:
            use_vdom(api, vdom)
            monitor = fetch_monitor(api, MON_ARP)

        tally = FilterTally(interface=interface)
        results: list[dict[str, Any]] = []
        for entry in monitor.rows:
            if interface and entry.get("interface") != interface:
                tally.drop("interface")
                continue
            results.append(
                {
                    "mac": normalize_mac(entry.get("mac", "")),
                    "ip": entry.get("ip"),
                    "interface": entry.get("interface"),
                }
            )

        window, paging = paginate(results, limit, offset)
        response: dict[str, Any] = {
            "target": fgt.name,
            "vdom": scope,
            **tally.describe(len(monitor.rows)),
            **paging,
            "entries": window,
            "source_status": monitor.describe(),
        }
        if not monitor.usable:
            response["warning"] = f"The ARP table could not be read ({monitor.describe()})."
        return response

    @mcp.tool(annotations=read_only("Identify a device by MAC, IP, or hostname"))
    def find_device(query: str, target: str | None = None, vdom: str | None = None) -> dict[str, Any]:
        """Identify a device on the network by MAC, IP, or hostname fragment.

        Searches the wireless client list, the DHCP lease table, and the ARP
        table together, then merges everything known about each matching device
        into one record. A device seen in several places produces one result
        rather than three partial ones.

        This is the tool for questions like "what is 198.51.100.47", "is that
        laptop on the network", or "which SSID is this MAC on".

        A MAC query matches whatever punctuation the appliance used, so
        `20-47-47-7d-db-7b`, `2047.477d.db7b`, and `20:47:47:7d:db:7b` all find
        the same device. An IP query is never treated as a MAC.

        Args:
            query: A MAC address, an IP address, or part of a hostname. Matching
                is case-insensitive and substring-based, so a partial MAC or a
                bare hostname prefix works. Partial MACs must keep their
                separators to be recognized as MACs.
            target: Which FortiGate to query. Optional when only one is configured.
            vdom: Virtual domain to search. Defaults to the one configured for
                this target. The `vdom` field in the response names the one
                actually searched, and a device in another vdom will not be
                found from here.

        """
        fgt = registry.resolve(target)
        scope = resolve_vdom(fgt, vdom)
        needle = query.strip().lower()
        if not needle:
            return {
                "target": fgt.name,
                "vdom": scope,
                "query": query,
                "count": 0,
                "devices": [],
                "error": "query was empty; give a MAC, an IP, or part of a hostname",
            }

        # Separator-insensitive form of the query, or None when the query is not
        # MAC-shaped. Keeping these apart is what stops an IPv4 address, which
        # is also nothing but hex digits and dots, from matching a MAC.
        needle_digits = mac_fragment_digits(needle)

        with connect(fgt) as api:
            use_vdom(api, vdom)
            sources = {
                "wifi": fetch_monitor(api, MON_WIFI_CLIENTS),
                "dhcp": fetch_monitor(api, MON_DHCP_LEASES),
                "arp": fetch_monitor(api, MON_ARP),
            }

        def name_of(row: dict[str, Any]) -> str:
            return row.get("hostname") or row.get("vci") or ""

        def hit(row: dict[str, Any]) -> bool:
            mac = normalize_mac(row.get("mac", ""))
            if needle in mac:
                return True
            if needle_digits and needle_digits in mac.replace(":", ""):
                return True
            return needle in (row.get("ip") or "").lower() or needle in name_of(row).lower()

        # Two passes on purpose. Matching first, then enrichment, so a device
        # found by its ARP-visible IP still collects its DHCP hostname. A single
        # pass only ever enriched forward, and left later-matched devices bare.
        matched: set[str] = set()
        for result in sources.values():
            for row in result.rows:
                mac = normalize_mac(row.get("mac", ""))
                if mac and hit(row):
                    matched.add(mac)

        merged: dict[str, dict[str, Any]] = {mac: {"mac": mac, "seen_in": []} for mac in matched}

        for label, result in sources.items():
            for row in result.rows:
                mac = normalize_mac(row.get("mac", ""))
                if mac not in merged:
                    continue
                record = merged[mac]
                if label not in record["seen_in"]:
                    record["seen_in"].append(label)
                if row.get("ip") and not record.get("ip"):
                    record["ip"] = row["ip"]
                if row.get("interface") and not record.get("interface"):
                    record["interface"] = row["interface"]
                if label == "dhcp":
                    if name_of(row):
                        record["hostname"] = name_of(row)
                    if row.get("expire_time"):
                        record["lease_expires"] = row["expire_time"]
                elif label == "wifi":
                    record["wireless"] = True
                    record["ssid"] = row.get("ssid")
                    if row.get("signal") is not None:
                        record["signal_dbm"] = row["signal"]

        results = sorted(merged.values(), key=lambda item: item.get("ip") or item["mac"])
        response: dict[str, Any] = {
            "target": fgt.name,
            "vdom": scope,
            "query": query,
            "count": len(results),
            "devices": results,
            "sources_checked": _source_report(sources),
        }
        blocked = _unusable(sources)
        if blocked:
            response["warning"] = (
                f"Could not read: {', '.join(blocked)}. Not finding the device is not evidence that it is absent."
            )
        return response
