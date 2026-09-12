"""Pure functions for reading FortiOS data shapes.

No I/O happens here, so every function is directly unit-testable against a
recorded response. Two jobs are done in this module.

The first is normalizing FortiOS's several ways of saying the same thing.
FortiOS is inconsistent across versions and across endpoints in ways that are
not documented and only surface against real hardware, so each quirk handled
below carries a note about where it was observed.

The second is summarizing. A raw FortiOS policy object carries eighty-plus
fields, the large majority of which are empty strings, unused IPv6 arrays, or
internal UUIDs. Handing all of that to a language model wastes its context on
noise and makes the signal harder to find. The ``summarize_*`` functions keep
the fields an operator would actually read and drop the rest.
"""

from __future__ import annotations

import ipaddress
from typing import Any


class FortiOSError(RuntimeError):
    """A FortiOS REST call returned a non-success status.

    FortiOS answers many user-fixable mistakes with HTTP 500 plus a body like
    ``{"status": "error", "error": -23, "cli_error": "..."}`` rather than a 4xx,
    and the underlying client library does not check status for us. Losing that
    body turns a diagnosable problem into a silent no-op, which is exactly how
    a create bug survived three releases of the sibling SSoT project.

    The status and error code are kept as attributes rather than only as text,
    so callers reporting a partial failure can describe it without parsing an
    error message back apart.
    """

    def __init__(self, message: str, *, http_status: int | None = None, error_code: Any = None) -> None:
        """Record the message alongside the FortiOS status and error code."""
        super().__init__(message)
        self.http_status = http_status
        self.error_code = error_code

    def summary(self) -> str:
        """Compact status suitable for putting in a tool response."""
        parts = []
        if self.http_status is not None:
            parts.append(f"http={self.http_status}")
        if self.error_code is not None:
            parts.append(f"error={self.error_code}")
        if self.http_status in {401, 403}:
            return "denied: " + " ".join(parts)
        return ("failed: " + " ".join(parts)) if parts else "failed"


def check_response(resp: Any, label: str) -> Any:
    """Raise :class:`FortiOSError` unless the response is HTTP 200.

    Returns the response unchanged on success so it can be wrapped inline at
    the call site.
    """
    status_code = getattr(resp, "status_code", None)
    if status_code == 200:
        return resp
    detail = ""
    error_code = None
    try:
        body = resp.json()
        error_code = body.get("error")
        detail = f" status={body.get('status')!r} error={error_code!r} cli_error={body.get('cli_error')!r}"
    except Exception:  # noqa: BLE001 - body may not be JSON at all
        detail = f" body={getattr(resp, 'text', '')[:200]!r}"
    raise FortiOSError(
        f"FortiOS rejected {label}: http={status_code}{detail}",
        http_status=status_code,
        error_code=error_code,
    )


def fortios_bool(value: Any, *, default: bool = False) -> bool:
    """Interpret a FortiOS boolean-ish field.

    FortiOS returns ``"enable"`` and ``"disable"`` strings where a JSON boolean
    would be natural, and it is not consistent about it: some endpoints use real
    booleans for the same concept. Passing these through ``bool()`` is a trap,
    because ``bool("disable")`` is ``True`` and every disabled thing silently
    reads as enabled. That exact mistake flipped every non-blackhole route to
    blackhole in the sibling project until it was caught against real hardware.

    >>> fortios_bool("enable")
    True
    >>> fortios_bool("disable")
    False
    >>> fortios_bool(True)
    True
    >>> fortios_bool(None)
    False
    """
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    return str(value).strip().lower() in {"enable", "enabled", "true", "yes", "on", "1", "up"}


def fortios_int(value: Any) -> int | None:
    """Read a FortiOS numeric field that may arrive as a string.

    FortiOS is not consistent about quoting numbers. An `isinstance(value, int)`
    check therefore discards real data: an interface whose `vlanid` arrives as
    `"200"` reads as having no VLAN tag at all, which is the same class of
    type-assumption failure that :func:`fortios_bool` exists to prevent, one
    field over.

    >>> fortios_int(100)
    100
    >>> fortios_int("200")
    200
    >>> fortios_int("")
    >>> fortios_int(None)
    """
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return None


def member_names(value: Any) -> list[str]:
    """Extract names from a FortiOS member list, whichever shape it arrives in.

    Relational fields such as ``srcaddr``, ``service``, and ``dstaddr`` normally
    arrive as ``[{"name": "X"}, ...]``. On FortiOS 7.0.x some of these same
    fields come back as a bare string holding one name, which was observed on a
    FortiWiFi-61E running 7.0.14 for the ``dstaddr`` field of a static route.
    Both shapes mean the same thing, so both are flattened here.

    >>> member_names([{"name": "WEB"}, {"name": "DB"}])
    ['WEB', 'DB']
    >>> member_names("WEB")
    ['WEB']
    >>> member_names(None)
    []
    """
    if not value:
        return []
    if isinstance(value, str):
        return [value] if value.strip() else []
    if isinstance(value, dict):
        name = value.get("name")
        return [name] if name else []
    names: list[str] = []
    for entry in value:
        if isinstance(entry, dict):
            name = entry.get("name")
            if name:
                names.append(name)
        elif isinstance(entry, str) and entry.strip():
            names.append(entry)
    return names


def subnet_to_cidr(subnet: str) -> str | None:
    """Convert FortiOS dotted-mask notation to CIDR, collapsing to the network.

    FortiOS writes IPv4 networks as one space-separated string rather than CIDR.
    This is the right conversion for ``firewall.address`` records, where the
    value genuinely is a network.

    >>> subnet_to_cidr("10.0.0.0 255.255.255.0")
    '10.0.0.0/24'
    >>> subnet_to_cidr("0.0.0.0 0.0.0.0")
    '0.0.0.0/0'
    >>> subnet_to_cidr("nonsense")
    """
    parts = (subnet or "").strip().split()
    if len(parts) != 2:
        return None
    try:
        return str(ipaddress.IPv4Network(f"{parts[0]}/{parts[1]}", strict=False))
    except ValueError:
        return None


def interface_ip_to_cidr(ip_field: str) -> str | None:
    """Convert a FortiOS interface ``ip`` field to host CIDR, keeping the host.

    This differs from :func:`subnet_to_cidr` in a way that matters. The same
    dotted-mask format means "this network" in ``firewall.address.subnet`` but
    "this interface's own address within that network" in ``system.interface.ip``.
    Collapsing the latter to its network address loses the host and produces
    phantom addresses, which is what happened on the first device sync of the
    sibling project.

    >>> interface_ip_to_cidr("203.0.113.10 255.255.255.0")
    '203.0.113.10/24'
    >>> interface_ip_to_cidr("0.0.0.0 0.0.0.0")
    """
    parts = (ip_field or "").strip().split()
    if len(parts) != 2:
        return None
    host, mask = parts
    if host == "0.0.0.0":
        return None
    try:
        ipaddress.IPv4Address(host)
        prefix_len = sum(bin(int(octet)).count("1") for octet in mask.split("."))
    except (ValueError, TypeError):
        return None
    return f"{host}/{prefix_len}"


# IANA protocol numbers that show up in FortiOS ``protocol: IP`` services.
# Protocol 0 deserves a note: IANA reserves it for HOPOPT, but FortiOS uses
# "protocol IP with no protocol-number" to mean "any IP protocol", which is how
# its built-in ALL service is defined. Reading it as "any" rather than HOPOPT is
# what an operator means.
IP_PROTOCOL_NAMES: dict[int, str] = {
    0: "any",
    1: "ICMP",
    2: "IGMP",
    4: "IPv4",
    6: "TCP",
    8: "EGP",
    17: "UDP",
    41: "IPv6",
    47: "GRE",
    50: "ESP",
    51: "AH",
    58: "IPv6-ICMP",
    88: "EIGRP",
    89: "OSPF",
    103: "PIM",
    112: "VRRP",
    115: "L2TP",
    132: "SCTP",
}

# Interface name prefixes FortiOS generates for its own bookkeeping. None of
# these represent an interface an operator configured, so they are hidden by
# default. wqtn.* is the quarantine interface auto-created alongside every VAP,
# vap.* is a VAP-tagged switch port, ssl.* is the SSL-VPN tunnel root, and
# naf.* is a name-affinity artifact seen on FortiOS 7.4 and later.
INTERNAL_INTERFACE_PREFIXES: tuple[str, ...] = ("wqtn.", "vap.", "ssl.", "naf.")


def is_internal_interface(name: str) -> bool:
    """Report whether an interface name is FortiOS bookkeeping rather than config.

    Filtering has to happen by name rather than by ``type``, because a
    quarantine interface and an operator's VLAN are both ``type: vlan`` and are
    otherwise indistinguishable.

    >>> is_internal_interface("wqtn.10.guest")
    True
    >>> is_internal_interface("vlan10")
    False
    """
    return any(name.startswith(prefix) for prefix in INTERNAL_INTERFACE_PREFIXES)


def summarize_address(raw: dict) -> dict[str, Any]:
    """Reduce a ``firewall/address`` object to name, type, and readable value.

    Each FortiOS address type keeps its value in a differently named field, so
    the discriminator is resolved here and the caller gets one ``value`` string
    regardless of type.
    """
    ftype = raw.get("type", "ipmask")
    name = raw.get("name", "")
    value: str | None = None

    if ftype in {"ipmask", "interface-subnet"}:
        value = subnet_to_cidr(raw.get("subnet", ""))
    elif ftype == "fqdn":
        value = raw.get("fqdn")
    elif ftype == "iprange":
        start, end = raw.get("start-ip"), raw.get("end-ip")
        value = f"{start}-{end}" if start and end else None
    elif ftype == "geography":
        value = raw.get("country")
    elif ftype == "mac":
        macs = [m.get("macaddr", "") for m in raw.get("macaddr", []) or [] if isinstance(m, dict)]
        value = ",".join(m for m in macs if m) or None
    elif ftype == "dynamic":
        value = raw.get("sub-type") or "external-connector"
    elif ftype == "wildcard":
        # A non-contiguous mask, which is exactly the kind of object an
        # operator asks about because it is hard to reason about. Reporting it
        # as having no value would hide the most surprising thing on the box.
        value = raw.get("wildcard")

    summary: dict[str, Any] = {"name": name, "type": ftype, "value": value}
    if value is None:
        # An unhandled type must be loud rather than blank, or a future FortiOS
        # address kind silently becomes invisible to every search.
        summary["unparsed_type"] = ftype
    if raw.get("comment"):
        summary["comment"] = raw["comment"]
    if raw.get("associated-interface"):
        summary["interface"] = raw["associated-interface"]
    return summary


def summarize_service(raw: dict) -> dict[str, Any]:
    """Reduce a ``firewall.service/custom`` object to name, protocol, and ports.

    FortiOS scatters the port range across ``tcp-portrange``, ``udp-portrange``,
    and ``sctp-portrange`` and only populates the one matching the protocol,
    while the ``protocol`` field itself may say ``TCP/UDP/SCTP`` meaning "any of
    the populated ones". Multi-port values are space-separated, as in Kerberos
    being ``88 464``.
    """
    name = raw.get("name", "")
    proto = raw.get("protocol", "")
    summary: dict[str, Any] = {"name": name}

    if proto in {"TCP/UDP/SCTP", "TCP", "UDP", "SCTP"}:
        ports: dict[str, str] = {}
        for key, label in (("tcp-portrange", "tcp"), ("udp-portrange", "udp"), ("sctp-portrange", "sctp")):
            raw_ports = str(raw.get(key) or "").strip()
            if raw_ports:
                # Strip the ":src-range" qualifier FortiOS appends on services
                # that also constrain the source port, such as RLOGIN's
                # "513:512-1023". Nothing downstream models source ports.
                ports[label] = ",".join(p.split(":", 1)[0] for p in raw_ports.split())
        summary["protocol"] = "/".join(label.upper() for label in ports) if ports else "TCP"
        summary["ports"] = ports
    elif proto in {"ICMP", "ICMP6"}:
        summary["protocol"] = "ICMP" if proto == "ICMP" else "IPv6-ICMP"
        if raw.get("icmptype") is not None:
            summary["icmp_type"] = raw["icmptype"]
    elif proto == "IP":
        number = raw.get("protocol-number")
        number = 0 if number is None else int(number)
        summary["protocol"] = IP_PROTOCOL_NAMES.get(number, f"ip-proto-{number}")
        summary["protocol_number"] = number
    elif proto == "ALL":
        # The pseudo-protocol on proxy services such as the built-in webproxy.
        summary["protocol"] = "any"
    else:
        summary["protocol"] = proto or "unknown"

    if raw.get("comment"):
        summary["comment"] = raw["comment"]
    if raw.get("category"):
        summary["category"] = raw["category"]
    return summary


def summarize_policy(raw: dict) -> dict[str, Any]:
    """Reduce a ``firewall/policy`` object to the fields an operator reads.

    A raw policy carries eighty-plus fields. What survives here is the rule as
    a human would state it: what it matches, which way traffic flows, whether
    it allows or denies, and whether it is on.
    """
    summary: dict[str, Any] = {
        "id": raw.get("policyid"),
        "name": raw.get("name") or f"policy-{raw.get('policyid')}",
        "enabled": fortios_bool(raw.get("status"), default=True),
        "action": raw.get("action", "deny"),
        "from": member_names(raw.get("srcintf")),
        "to": member_names(raw.get("dstintf")),
        "source": member_names(raw.get("srcaddr")),
        "destination": member_names(raw.get("dstaddr")),
        "service": member_names(raw.get("service")),
    }
    if fortios_bool(raw.get("nat")):
        summary["nat"] = True
    if raw.get("schedule") and raw["schedule"] != "always":
        summary["schedule"] = raw["schedule"]
    logtraffic = raw.get("logtraffic")
    if logtraffic and logtraffic != "disable":
        summary["log"] = logtraffic
    if raw.get("comments"):
        summary["comment"] = raw["comments"]
    return summary


def summarize_interface(raw: dict) -> dict[str, Any]:
    """Reduce a ``system/interface`` object to its operator-visible shape."""
    name = raw.get("name", "")
    summary: dict[str, Any] = {
        "name": name,
        "type": raw.get("type", "physical"),
        "status": "up" if fortios_bool(raw.get("status"), default=True) else "down",
        "vdom": raw.get("vdom", "root"),
    }
    address = interface_ip_to_cidr(raw.get("ip", ""))
    if address:
        summary["ip"] = address

    secondaries = [
        cidr
        for entry in (raw.get("secondaryip") or [])
        if isinstance(entry, dict) and (cidr := interface_ip_to_cidr(entry.get("ip", "")))
    ]
    if secondaries:
        summary["secondary_ips"] = secondaries

    # An interface that gets its address by DHCP or PPPoE genuinely holds no
    # address in the configuration, so reporting only the absence of "ip" would
    # answer "what is my WAN address" with "it has none". Say how it is
    # addressed instead, and point at the runtime view.
    mode = raw.get("mode")
    if mode and mode != "static":
        summary["addressing"] = mode
        if address is None:
            summary["note"] = f"address assigned by {mode}; see get_routing_table for the runtime value"

    # A VLAN sub-interface names its parent in "interface" and its tag in
    # "vlanid". FortiOS reports vlanid 0 on interfaces that carry no tag, and
    # sometimes quotes the number, hence fortios_int rather than isinstance.
    vlan_id = fortios_int(raw.get("vlanid"))
    if vlan_id is not None and vlan_id > 0:
        summary["vlan_id"] = vlan_id
    if raw.get("interface"):
        summary["parent"] = raw["interface"]
    if raw.get("description"):
        summary["description"] = raw["description"]
    if raw.get("allowaccess"):
        summary["management_access"] = raw["allowaccess"]
    if raw.get("mtu"):
        summary["mtu"] = raw["mtu"]
    return summary


def route_destination(raw: dict) -> str | None:
    """Resolve a ``router/static`` destination to CIDR, or None when it is named.

    A route states its destination one of two ways. Usually ``dst`` holds a
    dotted-mask literal. When the operator points the route at a named address
    object instead, the real destination lives in ``dstaddr`` and FortiOS sets
    ``dst`` to the all-zeros sentinel. Reading ``dst`` first in that case turns
    every named-destination route into a bogus default route, so ``dstaddr``
    has to win whenever it is populated.

    Returns None when the destination is a named object, since resolving the
    name requires a second REST call that belongs in the caller.
    """
    if member_names(raw.get("dstaddr")):
        return None
    dst = str(raw.get("dst") or "").strip()
    return subnet_to_cidr(dst) if dst else None


def summarize_route(raw: dict) -> dict[str, Any]:
    """Reduce a ``router/static`` entry to its operator-visible shape."""
    blackhole = fortios_bool(raw.get("blackhole"))
    named = member_names(raw.get("dstaddr"))
    summary: dict[str, Any] = {
        "seq_num": raw.get("seq-num"),
        "destination": route_destination(raw),
        "distance": raw.get("distance"),
        "priority": raw.get("priority"),
        "enabled": fortios_bool(raw.get("status"), default=True),
    }
    if named:
        summary["destination_address_object"] = named[0] if len(named) == 1 else named
    if blackhole:
        summary["blackhole"] = True
    else:
        gateway = str(raw.get("gateway") or "").strip()
        if gateway and gateway != "0.0.0.0":
            summary["gateway"] = gateway
        if raw.get("device"):
            summary["interface"] = raw["device"]
    if raw.get("comment"):
        summary["comment"] = raw["comment"]
    return summary


def resolve_route_destinations(
    summaries: list[dict[str, Any]],
    address_rows: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Fill in named route destinations from the address table, in place.

    Shared deliberately. When each caller resolved separately, two tools
    reported different destinations for the same route in the same conversation:
    one had done the lookup and the other had not. The output contract of
    :func:`summarize_route` should not depend on which caller post-processed it.

    Every summary gains a ``destination_resolution`` field so the three states
    stay distinguishable: a literal ``dst``, a named object we resolved, and a
    named object we could not.
    """
    by_name = {row.get("name", ""): row for row in address_rows}
    for summary in summaries:
        named = summary.get("destination_address_object")
        if not named:
            summary["destination_resolution"] = "literal"
            continue
        if isinstance(named, list):
            summary["destination_resolution"] = "named_unresolved"
            continue
        referenced = by_name.get(named)
        if referenced and referenced.get("type", "ipmask") in {"ipmask", "interface-subnet"}:
            resolved = subnet_to_cidr(referenced.get("subnet", ""))
            if resolved:
                summary["destination"] = resolved
                summary["destination_resolution"] = "named_resolved"
                continue
        summary["destination_resolution"] = "named_unresolved"
    return summaries


def normalize_mac(value: str) -> str:
    """Lowercase a MAC address for comparison.

    FortiOS is not consistent about MAC casing between the wifi, DHCP, and ARP
    endpoints, so joining records across them requires normalizing first.

    >>> normalize_mac("AA:BB:CC:DD:EE:01")
    'aa:bb:cc:dd:ee:01'
    """
    return (value or "").strip().lower()
