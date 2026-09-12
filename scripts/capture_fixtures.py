#!/usr/bin/env python3
"""Record sanitized FortiOS payloads from a live appliance into `tests/fixtures/`.

Why this exists. Hand-written response shapes encode what we believed FortiOS
returns, and on this project that belief has been wrong repeatedly: an uptime
field that exists in no endpoint, a `results` that is an object where a list was
assumed, a `reference_count` that reads zero on genuine references, a policy
carrying 147 fields. Every one of those passed a green test suite. Fixtures
captured from hardware make the tests assert against what the appliance sends.

Re-runnable on purpose. Point it at a newer firmware and the fixtures refresh in
place, so the day a shape changes is the day the suite says so rather than the
day an operator does. The output is deterministic: the same appliance produces
byte-identical files, because every placeholder is allocated from the payloads
themselves in a fixed order rather than randomly.

Usage:

    uv run python scripts/capture_fixtures.py
    uv run python scripts/capture_fixtures.py --target edge --show-mapping

Credentials come from the `.env` beside `pyproject.toml`, read with the same
helper `validate_hardware.py` uses so the two scripts cannot disagree about what
that file means. Nothing here writes to the appliance. Every call is a GET.

What is sanitized, and why
--------------------------

These files are committed, and the package may be published to PyPI, where an
sdist is permanent and mirrored. A leak cannot be recalled, so the rule is to
fail closed: anything that could identify this site is replaced even when it
looks harmless.

**IPv4 addresses.** Every address outside the documentation and special-purpose
ranges is renumbered. The lab uses RFC 1918 space and one real public
allocation, and both identify the site. Renumbering is done per *network*, not
per address, so that two records about the same subnet stay joined: an interface
address, the connected route for it, and an ARP entry inside it all land in the
same replacement network with their host parts intact. Without that the
cross-endpoint tests would be joining coincidences.

RFC 5737 (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`) supplies the
first three replacement networks and is preferred. It offers only three, and
this appliance carries more distinct networks than that, so the overflow comes
from `198.18.0.0/15`, the RFC 2544 benchmarking range, and networks larger than
a /24 come from `100.64.0.0/10`, RFC 6598 shared address space. Both are
IANA special-purpose assignments that belong to no organization and are never
routed on the public internet. Networks shorter than /24 are allocated from a
separate arena so that a /16 replacement cannot swallow a /24 replacement and
invent a containment relationship the real data did not have.

Addresses that carry meaning rather than identity are kept verbatim:
`0.0.0.0`, the all-ones broadcast, dotted netmasks, loopback, and anything
already inside a documentation range. A FortiOS record is full of `0.0.0.0`
sentinels whose whole significance is being that exact value.

Note that several renumbered networks are FortiOS factory defaults rather than
operator configuration, such as the switch-controller and extender-controller
reserved networks and the SSL-VPN tunnel pool. They identify nothing. They are
renumbered anyway, so that the audit grep over `tests/fixtures/` stays a clean
binary signal instead of a list of exceptions a reader has to re-verify.

**MAC addresses** become the RFC 7042 documentation range `00:00:5E:00:53:xx`.
The separator and the hex case of the original are preserved, because FortiOS is
not consistent about either between the wifi, DHCP, and ARP endpoints and
`normalize_mac` exists to absorb that. A fixture that tidied the casing would
hide the bug it was captured to catch. The all-zero and broadcast MACs are kept,
being sentinels rather than devices.

**The serial number** keeps its model prefix and loses everything that
identifies the unit, so `FWF61E...` stays recognizably a FortiWiFi-61E serial.
It appears in the envelope of every cmdb response, which is itself a tested
behaviour, so it has to stay present rather than be stripped.

**UUIDs** are zero-filled and numbered. They are not secret, but they correlate
against appliance logs and a support case.

**Anything credential-shaped is removed outright** rather than placeholdered,
since a placeholder in a password field is still a password field somebody may
later fill in by hand. A key whose value is empty is kept, because an empty
string is not a credential and its presence is part of the response shape. The
read-only token used for capture sees empty strings for all of these, but a
firmware that returned an encrypted blob must not be able to ship one here.

**Hostnames and FQDNs fail closed.** The appliance's own hostname is kept: it is
the factory default derived from the model. The stock FortiGuard address objects
(`gmail.com`, `login.microsoft.com`, and the rest) are kept, because they ship on
every appliance and say nothing about this one. Every other FQDN, DHCP lease
hostname, or vendor class identifier becomes a numbered placeholder, since those
name people's laptops and phones.

**The config revision hash** is replaced. It fingerprints one appliance's exact
configuration state.

**The resource-usage history is trimmed** to three samples per period and rebased
onto a fixed origin. It is otherwise 100 KB of wall-clock-stamped time series
establishing one fact the tool actually reads, which is that a metric is a list
of objects with a `current` key. The rebase also keeps re-captures from churning
the file on every run. This is the only place a payload is shortened rather than
rewritten, and it is called out in the manifest.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass, field
from datetime import date
from ipaddress import IPv4Address, IPv4Network
from pathlib import Path
from typing import Any
from urllib.parse import urlencode

# The .env reader lives in the sibling script. Importing it rather than copying
# it keeps one set of quoting rules for one file.
sys.path.insert(0, str(Path(__file__).resolve().parent))

from validate_hardware import load_dotenv  # noqa: E402

from mcfortigate import client  # noqa: E402
from mcfortigate.config import ConfigError, TargetRegistry  # noqa: E402

#: Every cmdb table this server reads. Captured as the whole envelope, because
#: the serial, firmware version, and build number are siblings of `results`
#: rather than inside it, and tools depend on that placement.
CMDB_ENDPOINTS: tuple[str, ...] = (
    client.ADDRESSES,
    client.ADDRESS_GROUPS,
    client.SERVICES,
    client.SERVICE_GROUPS,
    client.POLICIES,
    client.VIPS,
    client.INTERFACES,
    client.STATIC_ROUTES,
    client.SYSTEM_GLOBAL,
)

#: Monitor endpoints, which report observed state rather than configuration.
MONITOR_ENDPOINTS: tuple[str, ...] = (
    client.MON_SYSTEM_STATUS,
    client.MON_RESOURCE_USAGE,
    client.MON_WIFI_CLIENTS,
    client.MON_DHCP_LEASES,
    client.MON_ARP,
    client.MON_ROUTING_TABLE,
)

#: A name no appliance has, used to capture what the usage endpoint answers when
#: asked about an object that does not exist. It answers HTTP 200 with an empty
#: list, identically to a real object nothing references, which is the reason
#: `find_references` needs a separate existence check to reach a verdict.
ABSENT_OBJECT = "__mcfortigate_absent__"

#: Object-usage probes, each capturing one behaviour of
#: `monitor/system/object/usage` that a verdict depends on. The label becomes
#: part of the fixture filename.
USAGE_PROBES: tuple[tuple[str, str, str, str], ...] = (
    # Referenced twice by one policy, at srcaddr and at dstaddr. This is the
    # pair of counts that disagree on purpose.
    ("address_all", "firewall", "address", "all"),
    # Referenced once, and by a group rather than a policy.
    ("address_group_member", "firewall", "address", "gmail.com"),
    # Exists and is referenced by nothing.
    ("address_unreferenced", "firewall", "address", "none"),
    # The mismatched-table trap: an interface name asked of the address table
    # answers 200 and an empty list, exactly as an unreferenced object does.
    ("address_table_asked_about_an_interface", "firewall", "address", "wan1"),
    # The same key asked of the table it really lives in.
    ("interface_wan1", "system", "interface", "wan1"),
    # The container chain, which is what `find_references` walks past the direct
    # referrer. Without these the expansion path has no fixture behind it: the
    # objects above happen to have no expandable container, so the walk queries
    # nothing and its tests pass without exercising it.
    #
    # `internal1` is a switch port and gives the real three-level chain this
    # appliance has: internal1 -> virtual-switch:internal -> interface:lan ->
    # policy:1. Note `internal` must be asked as an *interface*; asked as a
    # virtual-switch it answers 200 and an empty list, which would end the walk
    # at depth one while still reporting success.
    ("interface_internal_switch_member", "system", "interface", "internal1"),
    ("interface_internal_as_interface", "system", "interface", "internal"),
    ("interface_lan_container", "system", "interface", "lan"),
    # The group that `gmail.com` sits in, so the address-side walk has a
    # container to open rather than only a membership row to report.
    ("addrgrp_g_suite_container", "firewall", "addrgrp", "G Suite"),
)

#: The absent-object probe is issued against every kind, because with no kind
#: resolved `find_references` sweeps all of them.
ABSENT_PROBES: tuple[tuple[str, str, str, str], ...] = tuple(
    (f"absent_{label}", q_path, q_name, ABSENT_OBJECT)
    for _kind, label, _table, q_path, q_name in client.OBJECT_KINDS
)

# --- sanitization -----------------------------------------------------------

#: Replacement networks for /24-and-longer, best first. RFC 5737 is the
#: documentation range and is preferred; RFC 2544 benchmarking space supplies
#: the overflow, since RFC 5737 holds only three /24s.
PREFERRED_24: tuple[IPv4Network, ...] = (
    IPv4Network("192.0.2.0/24"),
    IPv4Network("198.51.100.0/24"),
    IPv4Network("203.0.113.0/24"),
)
OVERFLOW_24 = IPv4Network("198.18.0.0/15")

#: Replacement space for networks shorter than /24, kept separate so a /16
#: replacement cannot contain a /24 replacement. RFC 6598 shared address space.
LARGE_ARENA = IPv4Network("100.64.0.0/10")

#: Address space left exactly as captured. Every one of these carries meaning as
#: a literal value rather than identifying anything.
KEPT_NETWORKS: tuple[IPv4Network, ...] = (
    IPv4Network("0.0.0.0/32"),
    IPv4Network("127.0.0.0/8"),
    IPv4Network("224.0.0.0/4"),
    IPv4Network("255.255.255.255/32"),
    *PREFERRED_24,
    OVERFLOW_24,
    LARGE_ARENA,
)

#: FortiGuard address objects that ship on every FortiGate. Keeping them keeps
#: the fixtures recognizable as a stock configuration; everything else that
#: looks like a hostname is replaced.
STOCK_FQDNS: frozenset[str] = frozenset(
    {
        "gmail.com",
        "*.google.com",
        "*.dropbox.com",
        "login.microsoft.com",
        "login.microsoftonline.com",
        "login.windows.net",
    }
)

#: Substrings that make a key credential-shaped. A key matching any of these
#: loses its value entirely when it has one.
CREDENTIAL_MARKERS: tuple[str, ...] = (
    "password",
    "passwd",
    "passphrase",
    "secret",
    "psk",
    "private-key",
    "privatekey",
    "auth-key",
    "wifi-key",
    "api-key",
    "apikey",
    "token",
)

#: Keys that contain a credential marker as a substring but hold no credential.
#: `q_origin_key` is an object's own name and `mkey` is a primary key, both of
#: which several tests read.
CREDENTIAL_EXEMPT: frozenset[str] = frozenset({"q_origin_key", "mkey", "wifi-keyindex", "keyindex"})

#: Placeholder for the configuration revision hash.
REVISION_PLACEHOLDER = "0" * 32

#: Samples kept per resource-usage history period, and the epoch they are
#: rebased onto so a re-capture does not churn the file.
HISTORY_SAMPLES = 3
HISTORY_ORIGIN_MS = 1_700_000_000_000

#: Current readings pinned to fixed values, because their captured value is
#: whatever the appliance happened to be doing that second.
#:
#: `cpu` is pinned to zero deliberately. A test asserts that a zero reading
#: survives `get_system_status`, guarding the difference between filtering the
#: optional fields on `is not None` and on truthiness — the latter drops a
#: genuine zero as though the appliance never answered. That guard needs a zero
#: to guard. The first capture got one by luck, because the lab was idle; a
#: re-capture during this session's own load got 3, which would have left the
#: test passing while protecting nothing, since a truthy 3 cannot detect a
#: truthiness bug. Pinning it makes the subject permanent rather than lucky.
#:
#: The others are pinned only so a re-capture produces an identical file.
PINNED_CURRENT = {"cpu": 0, "mem": 37, "session": 16, "setuprate": 0, "disk": 3}

_IPV4 = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
_MAC = re.compile(r"(?<![0-9A-Fa-f])[0-9A-Fa-f]{2}([:-])(?:[0-9A-Fa-f]{2}\1){4}[0-9A-Fa-f]{2}(?![0-9A-Fa-f])")
_UUID = re.compile(r"(?<![0-9A-Fa-f])[0-9A-Fa-f]{8}(?:-[0-9A-Fa-f]{4}){3}-[0-9A-Fa-f]{12}(?![0-9A-Fa-f])")
_PAIR = re.compile(r"^(\d{1,3}(?:\.\d{1,3}){3})\s+(\d{1,3}(?:\.\d{1,3}){3})$")
_CIDR = re.compile(r"^(\d{1,3}(?:\.\d{1,3}){3})/(\d{1,2})$")

#: MAC addresses that are sentinels rather than devices.
KEPT_MACS: frozenset[str] = frozenset({"00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff"})


def _prefix_from_mask(mask: str) -> int | None:
    """Read a dotted netmask as a prefix length, or None when it is not one.

    A non-contiguous value is rejected rather than guessed at, so that a
    wildcard mask is renumbered as an address instead of being mistaken for a
    network boundary.
    """
    try:
        octets = [int(part) for part in mask.split(".")]
    except ValueError:
        return None
    if len(octets) != 4 or any(octet < 0 or octet > 255 for octet in octets):
        return None
    bits = int(IPv4Address(mask))
    inverted = ~bits & 0xFFFFFFFF
    if inverted & (inverted + 1):
        return None
    return 32 - inverted.bit_length()


def _is_kept(address: IPv4Address) -> bool:
    """Report whether an address is left exactly as the appliance sent it."""
    return any(address in network for network in KEPT_NETWORKS)


@dataclass
class Mapping:
    """Every placeholder assigned during one capture, for auditing."""

    networks: dict[str, str] = field(default_factory=dict)
    macs: dict[str, str] = field(default_factory=dict)
    uuids: dict[str, str] = field(default_factory=dict)
    hostnames: dict[str, str] = field(default_factory=dict)
    serial: tuple[str, str] | None = None


class Sanitizer:
    """Rewrites captured payloads, consistently across all of them.

    Two passes. `scan` walks every payload and works out which networks need a
    replacement and which replacement blocks are already occupied by values the
    appliance itself sent. `allocate` then hands out blocks largest first, so a
    /16 never has to squeeze into space a /24 already took. Only then does
    `apply` rewrite, which is what makes the output deterministic: the mapping
    does not depend on which endpoint happened to be read first.
    """

    def __init__(self, serial: str | None, appliance_hostname: str | None) -> None:
        """Record the identity values that steer keep-or-replace decisions."""
        self.serial = serial
        self.appliance_hostname = appliance_hostname
        self.mapping = Mapping()
        if serial:
            # Keep the model prefix so the placeholder still reads as a serial
            # for this hardware, and zero the unit-identifying remainder.
            self.mapping.serial = (serial, serial[:6] + "0" * max(0, len(serial) - 6))
        self._requests: dict[tuple[int, int], None] = {}
        self._occupied: set[IPv4Network] = set()
        self._blocks: dict[tuple[int, int], IPv4Network] = {}

    # -- pass one ----------------------------------------------------------

    def scan(self, value: Any) -> None:
        """Collect the networks needing replacement and the blocks already in use."""
        if isinstance(value, dict):
            for item in value.values():
                self.scan(item)
        elif isinstance(value, list):
            for item in value:
                self.scan(item)
        elif isinstance(value, str):
            self._scan_string(value)

    def _scan_string(self, text: str) -> None:
        pair = _PAIR.match(text.strip())
        cidr = _CIDR.match(text.strip())
        if pair and (prefix := _prefix_from_mask(pair.group(2))) is not None:
            self._request(pair.group(1), prefix)
            return
        if cidr:
            self._request(cidr.group(1), int(cidr.group(2)))
            return
        for literal in _IPV4.findall(text):
            self._request(literal, 32)

    def _request(self, literal: str, prefix: int) -> None:
        """Note that one address needs a replacement, or that one block is taken."""
        try:
            address = IPv4Address(literal)
        except ValueError:
            return
        if _is_kept(address):
            # A documentation address the appliance already uses occupies its
            # own block, so nothing else may be allocated onto it.
            self._occupied.add(IPv4Network((int(address) & 0xFFFFFF00, 24)))
            return
        self._requests.setdefault(self._key(address, prefix), None)

    @staticmethod
    def _key(address: IPv4Address, prefix: int) -> tuple[int, int]:
        """Group addresses by the network they must stay together within.

        Anything /24 or longer is keyed on its enclosing /24, so a host address,
        the subnet it sits in, and the connected route for it all resolve to one
        replacement block with their host parts preserved.
        """
        if prefix >= 24:
            return (int(address) & 0xFFFFFF00, 24)
        return (int(address) & ((0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF), prefix)

    # -- pass two ----------------------------------------------------------

    def allocate(self) -> None:
        """Hand out a replacement block for every network seen, largest first."""
        small = [key for key in self._requests if key[1] >= 24]
        large = sorted((key for key in self._requests if key[1] < 24), key=lambda key: key[1])

        pool = iter([*PREFERRED_24, *OVERFLOW_24.subnets(new_prefix=24)])
        for key in small:
            self._blocks[key] = self._take(pool)

        cursor = int(LARGE_ARENA.network_address)
        for key in large:
            size = 1 << (32 - key[1])
            cursor = (cursor + size - 1) & ~(size - 1)
            block = IPv4Network((cursor, key[1]))
            if block.subnet_of(LARGE_ARENA) is False:  # pragma: no cover - arena is /10
                raise RuntimeError("ran out of replacement space for networks shorter than /24")
            self._blocks[key] = block
            cursor += size

        for (base, prefix), block in self._blocks.items():
            self.mapping.networks[f"{IPv4Address(base)}/{prefix}"] = str(block)

    def _take(self, pool: Any) -> IPv4Network:
        """Pull the next unoccupied /24 out of the replacement pool."""
        for block in pool:
            if block not in self._occupied:
                self._occupied.add(block)
                return block
        raise RuntimeError("ran out of replacement /24 blocks")

    # -- pass three --------------------------------------------------------

    def apply(self, value: Any, *, key: str | None = None) -> Any:
        """Return a rewritten copy of one payload."""
        if isinstance(value, dict):
            rewritten: dict[str, Any] = {}
            for name, item in value.items():
                if self._is_credential(name) and item not in ("", None, [], {}):
                    continue
                if name == "revision" and isinstance(item, str):
                    rewritten[name] = REVISION_PLACEHOLDER
                    continue
                rewritten[name] = self.apply(item, key=name)
            return rewritten
        if isinstance(value, list):
            return [self.apply(item, key=key) for item in value]
        if isinstance(value, str):
            return self._rewrite(value, key)
        return value

    @staticmethod
    def _is_credential(name: str) -> bool:
        lowered = name.lower()
        if lowered in CREDENTIAL_EXEMPT:
            return False
        return any(marker in lowered for marker in CREDENTIAL_MARKERS)

    def _rewrite(self, text: str, key: str | None) -> str:
        if self.mapping.serial and text == self.mapping.serial[0]:
            return self.mapping.serial[1]
        if key == "fqdn" and text and text not in STOCK_FQDNS:
            return self._hostname(text, "host")
        if key in {"hostname", "vci"} and text and text != self.appliance_hostname:
            return self._hostname(text, "device")
        rewritten = _UUID.sub(lambda match: self._uuid(match.group(0)), text)
        rewritten = _MAC.sub(lambda match: self._mac(match.group(0), match.group(1)), rewritten)
        return self._rewrite_addresses(rewritten)

    def _rewrite_addresses(self, text: str) -> str:
        pair = _PAIR.match(text.strip())
        cidr = _CIDR.match(text.strip())
        if pair and (prefix := _prefix_from_mask(pair.group(2))) is not None:
            return f"{self._address(pair.group(1), prefix)} {pair.group(2)}"
        if cidr:
            return f"{self._address(cidr.group(1), int(cidr.group(2)))}/{cidr.group(2)}"
        return _IPV4.sub(lambda match: self._address(match.group(0), 32), text)

    def _address(self, literal: str, prefix: int) -> str:
        try:
            address = IPv4Address(literal)
        except ValueError:
            return literal
        if _is_kept(address):
            return literal
        key = self._key(address, prefix)
        block = self._blocks.get(key)
        if block is None:
            # Returning the original here would ship a live address, so this
            # fails the capture instead. It means the rewrite pass saw a literal
            # the scan pass did not, which is a bug in this script.
            raise RuntimeError(f"no replacement allocated for a network seen during rewrite ({prefix=})")
        offset = int(address) - key[0]
        return str(IPv4Address(int(block.network_address) + offset))

    def _mac(self, literal: str, separator: str) -> str:
        canonical = literal.lower().replace("-", ":")
        if canonical in KEPT_MACS:
            return literal
        if canonical not in self.mapping.macs:
            index = len(self.mapping.macs)
            if index > 0xFF:
                raise RuntimeError("more MAC addresses than the RFC 7042 documentation range holds")
            self.mapping.macs[canonical] = f"00:00:5e:00:53:{index:02x}"
        replacement = self.mapping.macs[canonical].replace(":", separator)
        # Case and separator are part of the shape: FortiOS differs between the
        # wifi, DHCP, and ARP endpoints, and `normalize_mac` exists for that.
        return replacement.upper() if literal.upper() == literal else replacement

    def _uuid(self, literal: str) -> str:
        if literal not in self.mapping.uuids:
            self.mapping.uuids[literal] = f"00000000-0000-0000-0000-{len(self.mapping.uuids) + 1:012d}"
        return self.mapping.uuids[literal]

    def _hostname(self, literal: str, kind: str) -> str:
        if literal not in self.mapping.hostnames:
            self.mapping.hostnames[literal] = f"{kind}{len(self.mapping.hostnames) + 1:02d}.example"
        return self.mapping.hostnames[literal]


def shrink_resource_history(payload: Any) -> Any:
    """Trim the resource-usage time series, keeping the shape the tool reads.

    `get_system_status` reads `results[metric][0]["current"]` and nothing else,
    while the full payload is 100 KB of wall-clock-stamped samples that change on
    every capture. Three samples per period preserve that a period holds a list
    of `[timestamp, value]` pairs, and rebasing onto a fixed origin keeps the
    relative spacing while making a re-capture produce an identical file.

    The `current` readings named in `PINNED_CURRENT` are also fixed. See that
    constant for why `cpu` in particular must stay zero.
    """
    results = payload.get("results")
    if not isinstance(results, dict):
        return payload
    for metric, series in results.items():
        if not isinstance(series, list):
            continue
        if metric in PINNED_CURRENT and series and isinstance(series[0], dict):
            series[0]["current"] = PINNED_CURRENT[metric]
        for sample in series:
            history = sample.get("historical") if isinstance(sample, dict) else None
            if not isinstance(history, dict):
                continue
            for period, window in history.items():
                if isinstance(window, dict):
                    history[period] = _rebase(window)
    return payload


def _rebase(window: dict[str, Any]) -> dict[str, Any]:
    """Keep the first few samples of one history period, on a fixed timeline."""
    values = window.get("values")
    if not isinstance(values, list) or not values:
        return window
    kept = [pair for pair in values[:HISTORY_SAMPLES] if isinstance(pair, list) and len(pair) == 2]
    if not kept:
        return window
    origin = kept[0][0]
    shifted = [[HISTORY_ORIGIN_MS - (origin - stamp), value] for stamp, value in kept]
    stamps = [pair[0] for pair in shifted]
    return {**window, "values": shifted, "start": min(stamps), "end": max(stamps)}


def fixture_name(path: str, label: str | None = None) -> str:
    """Derive a fixture filename from the endpoint it was read from.

    Mechanical rather than hand-chosen so a reader can go from a fixture back to
    the constant in `client.py` without consulting a table, and so a renamed
    endpoint produces a visibly new file instead of silently overwriting one.

    >>> fixture_name("api/v2/cmdb/firewall.service/custom")
    'cmdb_firewall_service_custom'
    >>> fixture_name("api/v2/monitor/system/object/usage", "address_all")
    'monitor_system_object_usage__address_all'
    """
    stem = path.removeprefix("api/v2/").replace("/", "_").replace(".", "_")
    return f"{stem}__{label}" if label else stem


def capture(target_name: str | None) -> tuple[dict[str, Any], dict[str, Any], Sanitizer]:
    """Read every endpoint, then sanitize the lot together.

    Everything is read before anything is rewritten, because the replacement
    mapping has to be decided across all payloads at once. Deciding it endpoint
    by endpoint would make the output depend on read order.
    """
    registry = TargetRegistry()
    fgt = registry.resolve(target_name)
    print(f"reading {fgt.name} at {fgt.url}  (auth={fgt.auth_mode}, vdom={fgt.vdom})")

    raw: dict[str, Any] = {}
    manifest: dict[str, Any] = {}

    with client.connect(fgt) as api:
        for path in CMDB_ENDPOINTS + MONITOR_ENDPOINTS:
            response = api.fortigate.get(path)
            if response.status_code != 200:
                raise SystemExit(f"{path} answered http={response.status_code}; refusing to write a partial set")
            name = fixture_name(path)
            raw[name] = response.json()
            manifest[name] = {"endpoint": path}
            print(f"  {name:44} {_rowcount(raw[name])}")

        for label, q_path, q_name, mkey in USAGE_PROBES + ABSENT_PROBES:
            query = {"q_path": q_path, "q_name": q_name, "mkey": mkey}
            response = api.fortigate.get(f"{client.MON_OBJECT_USAGE}?{urlencode(query)}")
            if response.status_code != 200:
                raise SystemExit(f"object usage {label} answered http={response.status_code}")
            name = fixture_name(client.MON_OBJECT_USAGE, label)
            raw[name] = response.json()
            manifest[name] = {"endpoint": client.MON_OBJECT_USAGE, "query": query}
            print(f"  {name:44} {_usage_summary(raw[name])}")

    identity = raw[fixture_name(client.SYSTEM_GLOBAL)]
    hostname = (identity.get("results") or {}).get("hostname")
    sanitizer = Sanitizer(identity.get("serial"), hostname)
    for payload in raw.values():
        sanitizer.scan(payload)
    sanitizer.allocate()

    usage_name = fixture_name(client.MON_RESOURCE_USAGE)
    raw[usage_name] = shrink_resource_history(raw[usage_name])
    manifest[usage_name]["trimmed"] = (
        f"history reduced to {HISTORY_SAMPLES} samples per period and rebased onto a fixed origin"
    )

    clean = {name: sanitizer.apply(payload) for name, payload in raw.items()}
    return clean, manifest, sanitizer


def _rowcount(payload: dict[str, Any]) -> str:
    """Describe a payload by its row count, never by its contents."""
    results = payload.get("results")
    if isinstance(results, list):
        return f"{len(results)} rows"
    if isinstance(results, dict):
        return f"object, {len(results)} keys"
    return "no results"


def _usage_summary(payload: dict[str, Any]) -> str:
    """Describe an object-usage answer by its two counts."""
    results = payload.get("results")
    body = results[0] if isinstance(results, list) and results else results if isinstance(results, dict) else {}
    return f"can_use={len(body.get('can_use') or [])} currently_using={len(body.get('currently_using') or [])}"


def write(clean: dict[str, Any], manifest: dict[str, Any], identity: dict[str, Any], out: Path) -> None:
    """Write the fixtures and the manifest that names what each one is."""
    out.mkdir(parents=True, exist_ok=True)
    for name, payload in clean.items():
        (out / f"{name}.json").write_text(json.dumps(payload, indent=1) + "\n")
    (out / "manifest.json").write_text(
        json.dumps({"captured": date.today().isoformat(), **identity, "fixtures": manifest}, indent=1) + "\n"
    )


def main() -> None:
    """Capture, sanitize, and write the fixture set."""
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--target", help="Which configured FortiGate to capture from")
    parser.add_argument(
        "--out",
        type=Path,
        default=Path(__file__).resolve().parent.parent / "tests" / "fixtures",
        help="Directory to write fixtures into",
    )
    parser.add_argument(
        "--show-mapping",
        action="store_true",
        help="Print the real-to-placeholder mapping. Prints live addresses, so keep it off a shared terminal.",
    )
    args = parser.parse_args()

    load_dotenv(Path(__file__).resolve().parent.parent / ".env")
    try:
        clean, manifest, sanitizer = capture(args.target)
    except ConfigError as exc:
        raise SystemExit(f"configuration error: {exc}") from None

    status = clean[fixture_name(client.MON_SYSTEM_STATUS)].get("results") or {}
    envelope = clean[fixture_name(client.SYSTEM_GLOBAL)]
    identity = {
        "appliance": {
            "model": status.get("model"),
            "version": envelope.get("version"),
            "build": envelope.get("build"),
        }
    }
    write(clean, manifest, identity, args.out)

    print(f"\nwrote {len(clean)} fixtures plus a manifest to {args.out}")
    print(
        f"replaced {len(sanitizer.mapping.networks)} networks, {len(sanitizer.mapping.macs)} MACs, "
        f"{len(sanitizer.mapping.uuids)} UUIDs, {len(sanitizer.mapping.hostnames)} hostnames, "
        f"and the serial"
    )
    if args.show_mapping:
        for title, table in (
            ("networks", sanitizer.mapping.networks),
            ("macs", sanitizer.mapping.macs),
            ("hostnames", sanitizer.mapping.hostnames),
        ):
            print(f"\n{title}:")
            for real, placeholder in table.items():
                print(f"  {real:24} -> {placeholder}")
        if sanitizer.mapping.serial:
            print(f"\nserial:\n  {sanitizer.mapping.serial[0]} -> {sanitizer.mapping.serial[1]}")
    print(
        "\nNow run the audit grep before committing:\n"
        "  grep -rnE '192\\.168\\.|10\\.[0-9]+\\.[0-9]+\\.[0-9]+|172\\.(1[6-9]|2[0-9]|3[01])\\.' tests/fixtures/"
    )


if __name__ == "__main__":
    main()
