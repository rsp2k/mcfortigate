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
import re
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


#: Policy fields this module reads directly. Listed so the backstop below can
#: tell "handled" from "never heard of it".
_POLICY_HANDLED = frozenset(
    {
        "policyid", "name", "status", "action", "srcintf", "dstintf",
        "srcaddr", "dstaddr", "service", "nat", "schedule", "logtraffic",
        "comments", "srcaddr-negate", "dstaddr-negate", "service-negate",
        "internet-service", "internet-service-name", "internet-service-group",
        "internet-service-custom", "internet-service-custom-group",
        "internet-service-negate", "internet-service-src",
        "internet-service-src-name", "internet-service-src-group",
        "internet-service-src-custom", "internet-service-src-custom-group",
        "internet-service-src-negate", "srcaddr6", "dstaddr6", "groups",
        "users", "fsso-groups",
    }
)

#: Fields deliberately dropped, each verified not to change what a rule matches
#: or what it does with a match. Everything here appears at a non-default value
#: on a stock FortiOS 7.0.14 policy, so without this list the backstop would
#: fire on every rule and be ignored within a day.
#:
#: The bar for adding a name here is knowing it cannot alter the rule's meaning.
#: When unsure, leave it out and let it surface in `unsummarized`: a noisy
#: backstop wastes attention, a quiet one loses rules.
_POLICY_IGNORED = frozenset(
    {
        # Identity and bookkeeping.
        "uuid", "uuid-idx", "q_origin_key", "global-label", "label",
        # Hardware offload and session handling.
        "anti-replay", "auto-asic-offload", "np-acceleration",
        "delay-tcp-npu-session", "firewall-session-dirty", "session-ttl",
        "tcp-mss-receiver", "tcp-mss-sender", "tcp-session-without-syn",
        "timeout-send-rst", "dsri", "fec",
        # QoS and marking. Affects treatment, never whether traffic matches.
        "tos", "tos-mask", "tos-negate", "diffserv-forward", "diffserv-reverse",
        "diffservcode-forward", "diffservcode-rev", "vlan-cos-fwd",
        "vlan-cos-rev", "traffic-shaper", "traffic-shaper-reverse",
        "per-ip-shaper", "dynamic-shaping",
        # Inspection profiles. Change what happens to matched traffic, not what
        # matches; surfacing every one of them would drown the summary.
        "inspection-mode", "profile-type", "profile-group",
        "profile-protocol-options", "ssl-ssh-profile", "av-profile",
        "webfilter-profile", "dnsfilter-profile", "emailfilter-profile",
        "dlp-sensor", "file-filter-profile", "ips-sensor", "application-list",
        "voip-profile", "sctp-filter-profile", "icap-profile", "waf-profile",
        "ssh-filter-profile", "cifs-profile", "videofilter-profile",
        "utm-status", "custom-log-fields", "replacemsg-override-group",
        "decrypted-traffic-mirror", "capture-packet", "block-notification",
        # Logging detail beyond the summarized `logtraffic`.
        "logtraffic-start",
        # WAN optimization, caching, and proxy plumbing.
        "wanopt", "wanopt-detection", "wanopt-passive-opt", "wanopt-peer",
        "wanopt-profile", "webcache", "webcache-https", "wccp",
        "webproxy-forward-server", "webproxy-profile", "http-policy-redirect",
        "ssh-policy-redirect",
        # NAT detail. `nat` itself is summarized; these qualify an active NAT.
        "natip", "natinbound", "natoutbound", "fixedport", "inbound",
        "outbound", "nat46", "nat64", "ippool", "poolname", "poolname6",
        # Geo and reputation matching at their defaults.
        "geoip-match", "geoip-anycast", "reputation-direction",
        "reputation-minimum",
        # Authentication presentation, not scope. Scope is `groups` / `users`.
        "auth-cert", "auth-path", "auth-redirect-addr", "disclaimer",
        "captive-portal-exempt", "email-collect", "redirect-url",
        "identity-based-route", "ntlm", "ntlm-enabled-browsers", "ntlm-guest",
        "fsso-agent-for-ntlm", "radius-mac-auth-bypass", "permit-any-host",
        "permit-stun-host", "rtp-nat", "rtp-addr", "send-deny-packet",
        "match-vip", "match-vip-only", "schedule-timeout", "vpntunnel",
        "passive-wan-health-measurement", "vlan-filter", "src-vendor-mac",
        "sgt", "sgt-check", "ztna-status", "ztna-ems-tag", "ztna-geo-tag",
    }
)

#: Values that mean "this field is at its default and says nothing".
_POLICY_EMPTY = ("", [], {}, None, "disable", "0.0.0.0 0.0.0.0", 0)


def _is_default(value: Any) -> bool:
    """Report whether a policy field carries no information.

    Compared by identity-and-equality against a small sentinel set rather than
    by truthiness, because `0` and `""` are meaningful defaults here while a
    field holding `False` would not be.
    """
    return any(value == empty and type(value) is type(empty) for empty in _POLICY_EMPTY)


def _internet_services(raw: dict, prefix: str) -> list[str]:
    """Collect Internet Service names across the four fields that hold them."""
    names: list[str] = []
    for suffix in ("name", "group", "custom", "custom-group"):
        names.extend(member_names(raw.get(f"{prefix}-{suffix}")))
    return names


def summarize_policy(raw: dict) -> dict[str, Any]:
    """Reduce a ``firewall/policy`` object to the fields an operator reads.

    A raw policy carries 147 fields on FortiOS 7.0.14. What survives here is the
    rule as a human would state it: what it matches, which way traffic flows,
    whether it allows or denies, and whether it is on.

    Two classes of field are handled specially because dropping them would not
    merely shorten the answer, it would reverse it.

    Negation. `srcaddr-negate` and its siblings make a policy match everything
    *except* what is listed, so a summary that reports the list alone states the
    opposite of the rule. These appear as `source_negated` and friends, and
    again in prose in `match_note`, since a flag beside a list is easy to skim
    past and a sentence is not.

    Internet Service. With `internet-service` enabled, FortiOS ignores `dstaddr`
    entirely and matches against its Internet Service database instead. The real
    match appears as `destination_internet_service`, and `match_note` says that
    the address is inert, because `destination: ["all"]` left unqualified reads
    as a rule that reaches everything.

    Anything else carrying a non-default value that this function neither reads
    nor explicitly ignores lands in `unsummarized`. That is the backstop for the
    field nobody knew to look for, including the ones a future firmware adds.
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

    notes: list[str] = []

    # Negation, the field class that inverts meaning.
    for field_name, key, label in (
        ("srcaddr-negate", "source_negated", "source"),
        ("dstaddr-negate", "destination_negated", "destination"),
        ("service-negate", "service_negated", "service"),
    ):
        if fortios_bool(raw.get(field_name)):
            summary[key] = True
            notes.append(f"This rule matches every {label} EXCEPT the ones listed in '{label}'.")

    # Internet Service, the field class that replaces the address match.
    if fortios_bool(raw.get("internet-service")):
        services = _internet_services(raw, "internet-service")
        summary["destination_internet_service"] = services
        if fortios_bool(raw.get("internet-service-negate")):
            summary["destination_internet_service_negated"] = True
        notes.append(
            "Destination matching uses the Internet Service database, so the "
            "'destination' address list is ignored by the appliance."
        )
    if fortios_bool(raw.get("internet-service-src")):
        summary["source_internet_service"] = _internet_services(raw, "internet-service-src")
        if fortios_bool(raw.get("internet-service-src-negate")):
            summary["source_internet_service_negated"] = True
        notes.append(
            "Source matching uses the Internet Service database, so the "
            "'source' address list is ignored by the appliance."
        )

    # Scope that narrows a rule below what its address lists suggest.
    for field_name, key in (
        ("srcaddr6", "source_v6"),
        ("dstaddr6", "destination_v6"),
        ("groups", "identity_groups"),
        ("users", "identity_users"),
        ("fsso-groups", "identity_fsso_groups"),
    ):
        if members := member_names(raw.get(field_name)):
            summary[key] = members

    if fortios_bool(raw.get("nat")):
        summary["nat"] = True
    if raw.get("schedule") and raw["schedule"] != "always":
        summary["schedule"] = raw["schedule"]
    logtraffic = raw.get("logtraffic")
    if logtraffic and logtraffic != "disable":
        summary["log"] = logtraffic
    if raw.get("comments"):
        summary["comment"] = raw["comments"]

    if notes:
        summary["match_note"] = " ".join(notes)

    unsummarized = {
        key: value
        for key, value in raw.items()
        if key not in _POLICY_HANDLED and key not in _POLICY_IGNORED and not _is_default(value)
    }
    if unsummarized:
        summary["unsummarized"] = unsummarized

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

    # Written as a loop rather than a comprehension with a walrus in its
    # condition. That form tests the converted value for truthiness, so it would
    # drop a legitimate address the moment the converter returned anything
    # falsy, which is the family of mistake `bool("disable")` belongs to. The
    # test here is on whether the conversion succeeded, not on what it produced.
    #
    # The second half matters as much: an entry this code cannot read used to
    # disappear without trace, so an interface carrying an unparseable secondary
    # address looked exactly like one carrying none.
    secondaries: list[str] = []
    unreadable = 0
    for entry in raw.get("secondaryip") or []:
        if not isinstance(entry, dict):
            unreadable += 1
            continue
        cidr = interface_ip_to_cidr(entry.get("ip", ""))
        if cidr is None:
            unreadable += 1
            continue
        secondaries.append(cidr)
    if secondaries:
        summary["secondary_ips"] = secondaries
    if unreadable:
        summary["secondary_ips_unreadable"] = unreadable

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


def describe_usage_row(row: dict[str, Any], looked_up_as: str) -> dict[str, Any]:
    """Make one `currently_using` row from the usage endpoint readable.

    The appliance names the referencing table as a `path` and `name` pair, which
    reads better rejoined, and identifies the referencing object by its primary
    key. The `attribute` says which field of that object holds the reference,
    which is what distinguishes a policy using an address as its source from one
    using it as its destination.

    `reference_count` is deliberately not carried through. Hardware sets it to
    zero on rows that are genuine references, so a reader who trusted it would
    conclude the opposite of what the row means.

    >>> describe_usage_row({"path": "firewall", "name": "policy", "mkey": "1",
    ...                     "attribute": "srcaddr", "reference_count": 0}, "address")
    {'table': 'firewall.policy', 'object': '1', 'looked_up_as': 'address', 'attribute': 'srcaddr'}
    """
    path = str(row.get("path") or "").strip()
    name = str(row.get("name") or "").strip()
    table = ".".join(part for part in (path, name) if part)
    described: dict[str, Any] = {
        "table": table or "unknown",
        "object": row.get("mkey"),
        "looked_up_as": looked_up_as,
    }
    if row.get("attribute"):
        described["attribute"] = row["attribute"]
    return described


#: The three ways a 48-bit MAC gets written. Colon and dash forms come from
#: Unix and Windows tooling respectively, the four-digit dotted form from Cisco,
#: and the bare form from anything that stripped the punctuation. Matching is
#: anchored so that a value which is not a whole MAC cannot be reshaped.
_MAC_WHOLE = re.compile(
    r"^(?:[0-9a-f]{2}(?:[:-][0-9a-f]{2}){5}|[0-9a-f]{4}(?:\.[0-9a-f]{4}){2}|[0-9a-f]{12})$"
)

#: A whole MAC or a leading, trailing, or middle run of one, as an operator
#: would paste it. The group sizes are what keeps an IPv4 address out: dotted
#: groups must be four hex digits, so `192.168.1.47` cannot qualify, while
#: colon and dash groups must be one or two, so `fe80::1` cannot either.
_MAC_PART = re.compile(
    r"^(?:[0-9a-f]{1,2}(?:[:-][0-9a-f]{1,2})+|[0-9a-f]{4}(?:\.[0-9a-f]{4})+|[0-9a-f]{12})$"
)

_MAC_SEPARATORS = str.maketrans("", "", ":-.")


def normalize_mac(value: str) -> str:
    """Canonicalize a MAC address to lowercase colon-separated form.

    `find_device` and `list_wifi_clients` join the wifi, DHCP, and ARP tables on
    this value, and a join key normalized on only one axis is a join that can
    silently match nothing. Lowercasing alone leaves the key carrying whatever
    punctuation its source happened to use, so `AA-BB-CC-DD-EE-FF` from one
    endpoint and `aa:bb:cc:dd:ee:ff` from another describe one device and index
    as two, with the tool reporting the device as unknown and nothing in the
    output hinting why.

    Measured on FWF61E / 7.0.14, every endpoint reachable with populated rows
    used the colon form, so this is insurance rather than a fix for an observed
    disagreement. It costs nothing and removes a whole failure mode.

    Anything that is not a whole MAC comes back lowercased and otherwise
    untouched, because inventing structure for a hostname or a truncated field
    would be worse than leaving it alone.

    >>> normalize_mac("AA:BB:CC:DD:EE:01")
    'aa:bb:cc:dd:ee:01'
    >>> normalize_mac("AA-BB-CC-DD-EE-01")
    'aa:bb:cc:dd:ee:01'
    >>> normalize_mac("aabb.ccdd.ee01")
    'aa:bb:cc:dd:ee:01'
    >>> normalize_mac("guest-laptop")
    'guest-laptop'
    """
    text = (value or "").strip().lower()
    if not _MAC_WHOLE.match(text):
        return text
    digits = text.translate(_MAC_SEPARATORS)
    return ":".join(digits[index : index + 2] for index in range(0, 12, 2))


def mac_fragment_digits(value: str) -> str | None:
    """Reduce a MAC or part of one to bare hex digits, or None if it is not one.

    The query side of the same join. An operator reads a MAC off whatever is in
    front of them and pastes it, so the punctuation in the question rarely
    matches the punctuation in the table. Comparing digits ignores that.

    Returning None for anything that is not MAC-shaped is the load-bearing part.
    An IPv4 address is made entirely of hex digits and dots, so a looser test
    would let a query for `192.168.1.47` match an unrelated device by its MAC,
    which is a confidently wrong answer rather than a missing one.

    >>> mac_fragment_digits("20-47-47-7D-DB-7B")
    '2047477ddb7b'
    >>> mac_fragment_digits("7d:db:7b")
    '7ddb7b'
    >>> mac_fragment_digits("192.168.1.47")
    """
    text = (value or "").strip().lower()
    if not _MAC_PART.match(text):
        return None
    digits = text.translate(_MAC_SEPARATORS)
    # Two digits is one octet, which would match most of the table. Below four
    # the answer is noise rather than a lookup.
    return digits if len(digits) >= 4 else None
