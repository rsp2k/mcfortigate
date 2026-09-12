"""Live-state tools: connected clients, DHCP leases, ARP, and device lookup.

Everything here reads the FortiOS monitor tree, which reports what the
appliance currently observes rather than what it was configured to do. None of
it is persisted, so these answers are true only at the moment of the call.

Each tool reports the status of every source it consulted. A FortiGate with no
radio has no wireless client list at all, and joining around that absence is
correct. A FortiGate that refused the read is a different situation entirely,
and one that must never be presented as an empty network.
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
)
from mcfortigate.config import TargetRegistry
from mcfortigate.fortios import normalize_mac


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
    def list_wifi_clients(target: str | None = None, ssid: str | None = None) -> dict[str, Any]:
        """List wireless clients currently associated, enriched with DHCP and ARP.

        Each client is joined against the DHCP lease and ARP tables by MAC, which
        is what turns an anonymous MAC into a recognizable device. The hostname
        comes from the DHCP lease, falling back to the vendor class identifier
        when the client sent no name.

        `authenticated` is true or false only when the appliance said so, and
        absent when it did not, because inferring "not authenticated" from a
        missing field would fabricate a security-relevant claim.

        Args:
            target: Which FortiGate to query. Optional when only one is configured.
            ssid: Keep only clients associated to this SSID.

        """
        fgt = registry.resolve(target)
        with connect(fgt) as api:
            sources = {
                "wifi": fetch_monitor(api, MON_WIFI_CLIENTS),
                "dhcp": fetch_monitor(api, MON_DHCP_LEASES),
                "arp": fetch_monitor(api, MON_ARP),
            }
        leases = _index_by_mac(sources["dhcp"])
        arp = _index_by_mac(sources["arp"])

        results: list[dict[str, Any]] = []
        for client in sources["wifi"].rows:
            if ssid and client.get("ssid") != ssid:
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

        response: dict[str, Any] = {
            "target": fgt.name,
            "count": len(results),
            "clients": results,
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
        interface: str | None = None,
        hostname_contains: str | None = None,
    ) -> dict[str, Any]:
        """List current DHCP leases issued by the appliance.

        Args:
            target: Which FortiGate to query. Optional when only one is configured.
            interface: Keep only leases issued on this interface.
            hostname_contains: Case-insensitive substring filter on the hostname.

        """
        fgt = registry.resolve(target)
        with connect(fgt) as api:
            monitor = fetch_monitor(api, MON_DHCP_LEASES)

        results: list[dict[str, Any]] = []
        for lease in monitor.rows:
            name = lease.get("hostname") or lease.get("vci") or ""
            if interface and lease.get("interface") != interface:
                continue
            if hostname_contains and hostname_contains.lower() not in name.lower():
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

        response: dict[str, Any] = {
            "target": fgt.name,
            "count": len(results),
            "leases": results,
            "source_status": monitor.describe(),
        }
        if not monitor.usable:
            response["warning"] = f"The lease table could not be read ({monitor.describe()})."
        return response

    @mcp.tool(annotations=read_only("Show the ARP table"))
    def get_arp_table(target: str | None = None, interface: str | None = None) -> dict[str, Any]:
        """Show the ARP table, which is the IP-to-MAC bindings the appliance sees.

        ARP catches devices DHCP does not, meaning anything with a static
        address, so it is the fallback when a device is present but holds no
        lease.

        Args:
            target: Which FortiGate to query. Optional when only one is configured.
            interface: Keep only entries learned on this interface.

        """
        fgt = registry.resolve(target)
        with connect(fgt) as api:
            monitor = fetch_monitor(api, MON_ARP)

        results = [
            {
                "mac": normalize_mac(entry.get("mac", "")),
                "ip": entry.get("ip"),
                "interface": entry.get("interface"),
            }
            for entry in monitor.rows
            if not interface or entry.get("interface") == interface
        ]
        response: dict[str, Any] = {
            "target": fgt.name,
            "count": len(results),
            "entries": results,
            "source_status": monitor.describe(),
        }
        if not monitor.usable:
            response["warning"] = f"The ARP table could not be read ({monitor.describe()})."
        return response

    @mcp.tool(annotations=read_only("Identify a device by MAC, IP, or hostname"))
    def find_device(query: str, target: str | None = None) -> dict[str, Any]:
        """Identify a device on the network by MAC, IP, or hostname fragment.

        Searches the wireless client list, the DHCP lease table, and the ARP
        table together, then merges everything known about each matching device
        into one record. A device seen in several places produces one result
        rather than three partial ones.

        This is the tool for questions like "what is 192.168.1.47", "is that
        laptop on the network", or "which SSID is this MAC on".

        Args:
            query: A MAC address, an IP address, or part of a hostname. Matching
                is case-insensitive and substring-based, so a partial MAC or a
                bare hostname prefix works.
            target: Which FortiGate to query. Optional when only one is configured.

        """
        fgt = registry.resolve(target)
        needle = query.strip().lower()
        if not needle:
            return {
                "target": fgt.name,
                "query": query,
                "count": 0,
                "devices": [],
                "error": "query was empty; give a MAC, an IP, or part of a hostname",
            }

        with connect(fgt) as api:
            sources = {
                "wifi": fetch_monitor(api, MON_WIFI_CLIENTS),
                "dhcp": fetch_monitor(api, MON_DHCP_LEASES),
                "arp": fetch_monitor(api, MON_ARP),
            }

        def name_of(row: dict[str, Any]) -> str:
            return row.get("hostname") or row.get("vci") or ""

        def hit(row: dict[str, Any]) -> bool:
            mac = normalize_mac(row.get("mac", ""))
            return needle in mac or needle in (row.get("ip") or "").lower() or needle in name_of(row).lower()

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
