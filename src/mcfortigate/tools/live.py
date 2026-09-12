"""Live-state tools: connected clients, DHCP leases, ARP, and device lookup.

Everything here reads the FortiOS monitor tree, which reports what the
appliance currently observes rather than what it was configured to do. None of
it is persisted anywhere, so these answers are true only at the moment of the
call.
"""

from __future__ import annotations

from typing import Any

from fastmcp import FastMCP

from mcfortigate.client import connect, fetch_monitor
from mcfortigate.config import TargetRegistry
from mcfortigate.fortios import normalize_mac


def _index_by_mac(entries: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """Key a monitor result list by normalized MAC.

    FortiOS is inconsistent about MAC casing across the wifi, DHCP, and ARP
    endpoints, so every join between them has to normalize first or it silently
    matches nothing.
    """
    indexed: dict[str, dict[str, Any]] = {}
    for entry in entries:
        mac = normalize_mac(entry.get("mac", ""))
        if mac:
            indexed[mac] = entry
    return indexed


def register(mcp: FastMCP, registry: TargetRegistry) -> None:
    """Attach the live-state tools to the server."""

    @mcp.tool
    def list_wifi_clients(target: str | None = None, ssid: str | None = None) -> dict[str, Any]:
        """List wireless clients currently associated, enriched with DHCP and ARP.

        Each client is joined against the DHCP lease table and the ARP table by
        MAC address, which is what turns an anonymous MAC into a recognizable
        device. The hostname comes from the DHCP lease, falling back to the
        vendor class identifier when the client did not send one.

        Args:
            target: Which FortiGate to query. Optional when only one is configured.
            ssid: Keep only clients associated to this SSID.

        """
        fgt = registry.resolve(target)
        with connect(fgt) as api:
            clients = fetch_monitor(api, "api/v2/monitor/wifi/client")
            leases = _index_by_mac(fetch_monitor(api, "api/v2/monitor/system/dhcp"))
            arp = _index_by_mac(fetch_monitor(api, "api/v2/monitor/network/arp"))

        results: list[dict[str, Any]] = []
        for client in clients:
            if ssid and client.get("ssid") != ssid:
                continue
            mac = normalize_mac(client.get("mac", ""))
            lease = leases.get(mac, {})
            arp_entry = arp.get(mac, {})
            rate_bps = client.get("data_rate_bps") or 0
            results.append(
                {
                    "mac": mac,
                    "hostname": lease.get("hostname") or lease.get("vci") or None,
                    "ip": client.get("ip") or lease.get("ip") or arp_entry.get("ip"),
                    "ssid": client.get("ssid"),
                    "signal_dbm": client.get("signal"),
                    "data_rate_mbps": round(rate_bps / 1_000_000, 1) if rate_bps else None,
                    "authenticated": client.get("authentication") == "pass",
                    "interface": lease.get("interface") or arp_entry.get("interface"),
                }
            )

        return {"target": fgt.name, "count": len(results), "clients": results}

    @mcp.tool
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
            leases = fetch_monitor(api, "api/v2/monitor/system/dhcp")

        results: list[dict[str, Any]] = []
        for lease in leases:
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

        return {"target": fgt.name, "count": len(results), "leases": results}

    @mcp.tool
    def get_arp_table(target: str | None = None, interface: str | None = None) -> dict[str, Any]:
        """Show the ARP table, which is the IP-to-MAC bindings the appliance sees.

        ARP catches devices that DHCP does not, meaning anything with a static
        address, so it is the fallback when a device is present on the network
        but holds no lease.

        Args:
            target: Which FortiGate to query. Optional when only one is configured.
            interface: Keep only entries learned on this interface.

        """
        fgt = registry.resolve(target)
        with connect(fgt) as api:
            entries = fetch_monitor(api, "api/v2/monitor/network/arp")

        results = [
            {
                "mac": normalize_mac(entry.get("mac", "")),
                "ip": entry.get("ip"),
                "interface": entry.get("interface"),
            }
            for entry in entries
            if not interface or entry.get("interface") == interface
        ]
        return {"target": fgt.name, "count": len(results), "entries": results}

    @mcp.tool
    def find_device(query: str, target: str | None = None) -> dict[str, Any]:
        """Identify a device on the network by MAC, IP, or hostname fragment.

        Searches the wireless client list, the DHCP lease table, and the ARP
        table together, then merges everything known about each matching device
        into one record. A device seen in several places produces one result
        rather than three partial ones.

        This is the tool for questions like "what is 192.168.1.47", "is Kevin's
        laptop on the network", or "which SSID is this MAC on".

        Args:
            query: A MAC address, an IP address, or part of a hostname. Matching
                is case-insensitive and substring-based, so a partial MAC or a
                bare hostname prefix works.
            target: Which FortiGate to query. Optional when only one is configured.

        """
        fgt = registry.resolve(target)
        with connect(fgt) as api:
            wifi = fetch_monitor(api, "api/v2/monitor/wifi/client")
            leases = fetch_monitor(api, "api/v2/monitor/system/dhcp")
            arp = fetch_monitor(api, "api/v2/monitor/network/arp")

        needle = query.strip().lower()
        merged: dict[str, dict[str, Any]] = {}

        def touch(mac: str) -> dict[str, Any]:
            return merged.setdefault(mac, {"mac": mac, "seen_in": []})

        for entry in leases:
            mac = normalize_mac(entry.get("mac", ""))
            name = entry.get("hostname") or entry.get("vci") or ""
            if not mac:
                continue
            if needle in mac or needle in (entry.get("ip") or "").lower() or needle in name.lower():
                record = touch(mac)
                record["seen_in"].append("dhcp")
                record["ip"] = entry.get("ip")
                record["hostname"] = name or None
                record["interface"] = entry.get("interface")
                record["lease_expires"] = entry.get("expire_time")

        for entry in arp:
            mac = normalize_mac(entry.get("mac", ""))
            if not mac:
                continue
            if needle in mac or needle in (entry.get("ip") or "").lower() or mac in merged:
                record = touch(mac)
                if "arp" not in record["seen_in"]:
                    record["seen_in"].append("arp")
                record.setdefault("ip", entry.get("ip"))
                record.setdefault("interface", entry.get("interface"))

        for entry in wifi:
            mac = normalize_mac(entry.get("mac", ""))
            if not mac:
                continue
            if needle in mac or needle in (entry.get("ip") or "").lower() or mac in merged:
                record = touch(mac)
                if "wifi" not in record["seen_in"]:
                    record["seen_in"].append("wifi")
                record.setdefault("ip", entry.get("ip"))
                record["ssid"] = entry.get("ssid")
                record["signal_dbm"] = entry.get("signal")
                record["wireless"] = True

        results = sorted(merged.values(), key=lambda item: item.get("ip") or item["mac"])
        return {
            "target": fgt.name,
            "query": query,
            "count": len(results),
            "devices": results,
        }
