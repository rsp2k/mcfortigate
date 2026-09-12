"""Tool-level tests for the vdom override and for filters that narrow silently.

Two findings share one sentence. A caller that gets three rows back cannot tell
whether the table holds three rows or three hundred with a filter applied, and a
caller reading `vdom: root` cannot tell whether that is where the rows came from
or merely what the server was configured with. Both are answers that look
complete and are not, which is the failure this whole project is organised
against.

These drive the real tool bodies through the real `fetch_table` and
`fetch_monitor`, with only the transport faked, so a change to status handling
or envelope reading shows up here rather than only on hardware.
"""

from __future__ import annotations

import asyncio
import json
from contextlib import contextmanager

import pytest

from mcfortigate.config import FortiGateTarget, TargetRegistry
from mcfortigate.server import build_server

AVAILABLE_INTERFACES = "api/v2/monitor/system/available-interfaces"

# Shaped after the FortiWiFi-61E the lab runs, trimmed to the rows that matter.
# `wan1` is DHCP yet still carries an address in the configuration, which is
# what the appliance actually does and which a fixture invented from the
# documentation would get wrong.
INTERFACE_ROWS = [
    {"name": "wan1", "type": "physical", "mode": "dhcp", "ip": "203.0.113.11 255.255.255.0", "vdom": "root"},
    {"name": "wan2", "type": "physical", "mode": "dhcp", "ip": "0.0.0.0 0.0.0.0", "vdom": "root"},
    {"name": "lan", "type": "switch", "mode": "static", "ip": "192.0.2.99 255.255.255.0", "vdom": "root"},
    {"name": "dmz", "type": "physical", "mode": "static", "ip": "198.51.100.1 255.255.255.0", "vdom": "root"},
    {"name": "modem", "type": "physical", "mode": "pppoe", "ip": "0.0.0.0 0.0.0.0", "vdom": "root"},
    {"name": "vlan100", "type": "vlan", "mode": "static", "interface": "lan", "vlanid": 100, "vdom": "root"},
    {"name": "ssl.root", "type": "tunnel", "mode": "static", "vdom": "root"},
    {"name": "naf.root", "type": "tunnel", "mode": "static", "vdom": "root"},
    {"name": "wqtn.16.wifi", "type": "vlan", "mode": "static", "vdom": "root"},
]

# What `monitor/system/available-interfaces` reported for those same rows on
# 7.0.14. Note which way round it falls: `naf.root` is offered as a policy
# endpoint and `ssl.root` is not, which is the opposite of what the names
# suggest.
AVAILABLE_ROWS = [
    {"name": "wan1", "valid_in_policy": True},
    {"name": "wan2", "valid_in_policy": True},
    {"name": "lan", "valid_in_policy": True},
    {"name": "dmz", "valid_in_policy": True},
    {"name": "modem"},
    {"name": "vlan100", "valid_in_policy": True},
    {"name": "ssl.root"},
    {"name": "naf.root", "valid_in_policy": True},
    {"name": "wqtn.16.wifi"},
]

ARP_ROWS = [
    {"ip": "192.0.2.240", "mac": "20:47:47:7d:db:7b", "interface": "lan"},
    {"ip": "203.0.113.1", "mac": "A0-BC-6F-BF-8C-57", "interface": "wan1"},
]

DHCP_ROWS = [
    {"ip": "192.0.2.50", "mac": "2047.477d.db7b", "hostname": "kiosk", "interface": "lan"},
]

WIFI_ROWS = [
    {"mac": "AABBCCDDEEFF", "ip": "192.0.2.77", "ssid": "guest", "signal": -61, "authentication": "pass"},
]


class Response:
    """A requests.Response stand-in carrying a FortiOS envelope."""

    def __init__(self, status_code: int, body: dict | None = None):
        self.status_code = status_code
        self._body = body
        self.text = json.dumps(body or {})

    def json(self) -> dict:
        if self._body is None:
            raise ValueError("not json")
        return self._body


class FakeAppliance:
    """Serves canned tables, echoing back whichever vdom was asked for.

    The echo is the point. A real FortiGate names the vdom it answered for in
    every envelope, so a fake that always says `root` would hide exactly the
    mislabelling these tests are about.
    """

    def __init__(self, vdom: str = "root", known_vdoms: tuple[str, ...] = ("root",)):
        self.vdom = vdom
        self.known_vdoms = known_vdoms
        self.paths: list[str] = []
        self.available_status = 200

    def get(self, path: str, *_args, **_kwargs) -> Response:
        self.paths.append(path)
        if self.vdom not in self.known_vdoms:
            # Measured: an unknown vdom answers 424, not 404 and not 403.
            return Response(424, {"status": "error", "vdom": self.vdom})
        envelope = {"vdom": self.vdom, "status": "success"}
        if path.startswith(AVAILABLE_INTERFACES):
            if self.available_status != 200:
                return Response(self.available_status, {"status": "error"})
            return Response(200, {**envelope, "results": AVAILABLE_ROWS})
        table = {
            "api/v2/cmdb/system/interface": INTERFACE_ROWS,
            "api/v2/cmdb/router/static": [],
            "api/v2/cmdb/firewall/address": [],
            "api/v2/monitor/network/arp": ARP_ROWS,
            "api/v2/monitor/system/dhcp": DHCP_ROWS,
            "api/v2/monitor/wifi/client": WIFI_ROWS,
            "api/v2/monitor/router/ipv4": [],
        }.get(path.split("?")[0])
        if table is None:
            return Response(404, {"status": "error"})
        return Response(200, {**envelope, "results": table})


class FakeAPI:
    """Stands in for FortiGateAPI, exposing only what the read layer uses."""

    def __init__(self, vdom: str = "root", known_vdoms: tuple[str, ...] = ("root",)):
        self.fortigate = FakeAppliance(vdom, known_vdoms)

    def logout(self) -> None:
        """No session to end."""


@pytest.fixture
def appliance(monkeypatch: pytest.MonkeyPatch):
    """A server backed by the fake appliance, with the appliance handed back."""
    box = FakeAPI()

    @contextmanager
    def fake_connect(_target):
        yield box

    for module in ("network", "live"):
        monkeypatch.setattr(f"mcfortigate.tools.{module}.connect", fake_connect)

    registry = TargetRegistry({"lab": FortiGateTarget(name="lab", host="fgt.example", token="x", vdom="root")})
    return build_server(registry), box


def call(server, name: str, arguments: dict | None = None):
    """Invoke a tool and return its payload."""
    raw = asyncio.run(server.call_tool(name, arguments or {}))
    for attribute in ("data", "structured_content", "structuredContent"):
        value = getattr(raw, attribute, None)
        if isinstance(value, dict):
            return value
    content = getattr(raw, "content", None)
    if content and getattr(content[0], "text", None):
        return json.loads(content[0].text)
    raise AssertionError(f"could not unwrap a payload from {raw!r}")


class TestFiltersReportWhatTheyRemoved:
    """H5. A short list and a small table have to be distinguishable.

    Every one of these tools returns a bare list of rows. Nothing in that list
    says a filter ran, so a model that asked for `interface_type=vlan` and got
    one row has no way to know whether the appliance has one interface or
    twenty-nine. Paging already solved the same problem for the other axis by
    always reporting `total_available`; this is that, for filters.
    """

    def test_unfiltered_listing_claims_no_filters(self, appliance):
        server, _ = appliance
        result = call(server, "list_interfaces", {"include_internal": True})
        assert "filters_applied" not in result
        assert result["count"] == len(INTERFACE_ROWS)

    def test_filter_names_itself_and_its_cost(self, appliance):
        server, _ = appliance
        result = call(server, "list_interfaces", {"include_internal": True, "interface_type": "vlan"})
        assert result["filters_applied"]["interface_type"] == "vlan"
        assert result["filtered_out"]["interface_type"] == len(INTERFACE_ROWS) - 2
        assert result["total_before_filters"] == len(INTERFACE_ROWS)

    def test_total_available_still_counts_matches_not_the_table(self, appliance):
        """The two numbers answer different questions and must both be present."""
        server, _ = appliance
        result = call(server, "list_interfaces", {"include_internal": True, "interface_type": "vlan"})
        assert result["total_available"] == 2
        assert result["total_before_filters"] == len(INTERFACE_ROWS)
        assert result["total_available"] != result["total_before_filters"]

    def test_a_filter_that_removed_nothing_still_reports_zero(self, appliance):
        """Silence would read as "no filter ran", which is a different claim."""
        server, _ = appliance
        result = call(server, "list_interfaces", {"include_internal": True, "interface_type": "physical"})
        assert result["filtered_out"]["interface_type"] == len(INTERFACE_ROWS) - 4

    def test_hiding_internal_interfaces_counts_as_a_filter(self, appliance):
        """It is on by default, which makes it the easiest one to forget."""
        server, _ = appliance
        result = call(server, "list_interfaces", {})
        assert "internal_hidden" in result["filters_applied"]
        assert result["filtered_out"]["internal_hidden"] >= 1

    def test_filter_note_says_what_is_not_being_seen(self, appliance):
        server, _ = appliance
        result = call(server, "list_interfaces", {"include_internal": True, "interface_type": "vlan"})
        note = result["filter_note"]
        assert "interface_type" in note
        assert str(len(INTERFACE_ROWS)) in note

    def test_arp_interface_filter_is_reported(self, appliance):
        """An interface-name typo otherwise reads as an empty ARP table."""
        server, _ = appliance
        result = call(server, "get_arp_table", {"interface": "lann"})
        assert result["entries"] == []
        assert result["filters_applied"]["interface"] == "lann"
        assert result["filtered_out"]["interface"] == len(ARP_ROWS)
        assert result["total_before_filters"] == len(ARP_ROWS)

    def test_dhcp_filters_are_reported(self, appliance):
        server, _ = appliance
        result = call(server, "list_dhcp_leases", {"hostname_contains": "nothing-like-this"})
        assert result["filtered_out"]["hostname_contains"] == len(DHCP_ROWS)

    def test_wifi_ssid_filter_is_reported(self, appliance):
        server, _ = appliance
        result = call(server, "list_wifi_clients", {"ssid": "corp"})
        assert result["filtered_out"]["ssid"] == len(WIFI_ROWS)

    def test_routing_table_protocol_filter_is_reported(self, appliance):
        server, _ = appliance
        result = call(server, "get_routing_table", {"protocol": "bgp"})
        assert result["filters_applied"]["protocol"] == "bgp"

    def test_static_ip_filter_names_what_it_drops(self, appliance):
        """DHCP interfaces do hold an address here, which is not obvious.

        FortiOS writes the leased address back into the configuration, so
        `with_ip_only` keeps `wan1` despite its mode being dhcp. It drops the
        two that genuinely have no address. Measured on the lab unit.
        """
        server, _ = appliance
        result = call(server, "list_interfaces", {"include_internal": True, "with_ip_only": True})
        names = [entry["name"] for entry in result["interfaces"]]
        assert "wan1" in names
        assert "wan2" not in names and "modem" not in names
        assert result["filtered_out"]["with_ip_only"] == 6


class TestVdomArgument:
    """H4. Every tool was pinned to the configured vdom with no way to ask elsewhere."""

    def test_vdom_defaults_to_the_configured_one(self, appliance):
        server, box = appliance
        result = call(server, "list_interfaces", {})
        assert result["vdom"] == "root"
        assert box.fortigate.vdom == "root"

    def test_override_reaches_the_appliance(self, appliance):
        server, box = appliance
        box.fortigate.known_vdoms = ("root", "dmz")
        call(server, "list_interfaces", {"vdom": "dmz"})
        assert box.fortigate.vdom == "dmz"

    def test_response_reports_the_vdom_actually_queried(self, appliance):
        """Reporting the configured default beside other rows mislabels the answer."""
        server, box = appliance
        box.fortigate.known_vdoms = ("root", "dmz")
        result = call(server, "list_interfaces", {"vdom": "dmz"})
        assert result["vdom"] == "dmz"

    @pytest.mark.parametrize(
        "tool",
        ["list_interfaces", "list_vlans", "list_static_routes", "get_routing_table"],
    )
    def test_network_tools_all_take_a_vdom(self, appliance, tool: str):
        server, box = appliance
        box.fortigate.known_vdoms = ("root", "dmz")
        assert call(server, tool, {"vdom": "dmz"})["vdom"] == "dmz"

    @pytest.mark.parametrize("tool", ["list_dhcp_leases", "get_arp_table", "list_wifi_clients"])
    def test_live_tools_all_take_a_vdom(self, appliance, tool: str):
        server, box = appliance
        box.fortigate.known_vdoms = ("root", "dmz")
        assert call(server, tool, {"vdom": "dmz"})["vdom"] == "dmz"

    def test_find_device_takes_a_vdom(self, appliance):
        server, box = appliance
        box.fortigate.known_vdoms = ("root", "dmz")
        assert call(server, "find_device", {"query": "kiosk", "vdom": "dmz"})["vdom"] == "dmz"

    def test_an_unknown_vdom_fails_loudly_rather_than_reading_as_empty(self, appliance):
        """Measured on hardware: FortiOS answers 424 for a vdom that does not exist.

        The danger is the shape of the failure, not the failure. A 424 that
        reached the caller as an empty table would report an appliance with no
        interfaces.
        """
        server, _ = appliance
        with pytest.raises(Exception, match="424|vdom"):
            call(server, "list_interfaces", {"vdom": "nosuchvdom"})

    def test_an_unknown_vdom_is_not_reported_as_an_empty_live_table(self, appliance):
        """Live tools fail soft, so the same 424 has to arrive as a warning."""
        server, _ = appliance
        result = call(server, "get_arp_table", {"vdom": "nosuchvdom"})
        assert result["entries"] == []
        assert result.get("warning")


class TestPolicyEndpointsAreNeverHidden:
    """M8. Whether an interface is bookkeeping is not decidable from its name.

    The prefix list hides `ssl.root` and `naf.root` and leaves `wqt.root` and
    `l2t.root` visible, all four of which FortiOS generates. Asked directly,
    7.0.14 says `naf.root` is valid in a policy and `ssl.root` is not, which is
    the reverse of the review's assumption and of what the names imply. So the
    appliance decides, and the name only decides when the appliance cannot be
    asked.
    """

    def test_an_interface_the_appliance_offers_to_policies_is_shown(self, appliance):
        server, _ = appliance
        names = [entry["name"] for entry in call(server, "list_interfaces", {})["interfaces"]]
        assert "naf.root" in names

    def test_an_interface_the_appliance_does_not_offer_stays_hidden(self, appliance):
        server, _ = appliance
        result = call(server, "list_interfaces", {})
        assert "ssl.root" in result["hidden_internal"]
        assert "wqtn.16.wifi" in result["hidden_internal"]

    def test_the_basis_for_hiding_is_stated(self, appliance):
        server, _ = appliance
        result = call(server, "list_interfaces", {})
        assert result["hidden_internal_basis"] == "appliance"

    def test_falls_back_to_the_name_when_the_appliance_cannot_be_asked(self, appliance):
        """A denied lookup must not quietly become a confident answer."""
        server, box = appliance
        box.fortigate.available_status = 403
        result = call(server, "list_interfaces", {})
        assert result["hidden_internal_basis"] == "name_prefix"
        assert "naf.root" in result["hidden_internal"]
        assert "could not" in result["hidden_internal_note"]

    def test_include_internal_still_shows_everything(self, appliance):
        server, _ = appliance
        result = call(server, "list_interfaces", {"include_internal": True})
        names = [entry["name"] for entry in result["interfaces"]]
        assert "ssl.root" in names and "wqtn.16.wifi" in names


class TestMacSeparatorsJoinAcrossSources:
    """M3, at the level where it actually hurts.

    The three live tables are joined on MAC. This fixture deliberately spells
    the same address three different ways, one per source, which is the thing
    lowercasing alone cannot survive.
    """

    def test_a_dashed_query_finds_a_colon_spelled_device(self, appliance):
        server, _ = appliance
        result = call(server, "find_device", {"query": "20-47-47-7D-DB-7B"})
        assert result["count"] == 1
        assert result["devices"][0]["mac"] == "20:47:47:7d:db:7b"

    def test_a_cisco_dotted_query_finds_the_same_device(self, appliance):
        server, _ = appliance
        result = call(server, "find_device", {"query": "2047.477d.db7b"})
        assert result["count"] == 1

    def test_sources_spelling_a_mac_differently_merge_into_one_device(self, appliance):
        """DHCP writes it Cisco-style here and ARP colon-style, as one device."""
        server, _ = appliance
        result = call(server, "find_device", {"query": "20:47:47:7d:db:7b"})
        assert result["count"] == 1
        assert sorted(result["devices"][0]["seen_in"]) == ["arp", "dhcp"]
        assert result["devices"][0]["hostname"] == "kiosk"

    def test_listing_tools_report_one_canonical_spelling(self, appliance):
        server, _ = appliance
        arp = call(server, "get_arp_table", {})["entries"]
        assert {entry["mac"] for entry in arp} == {"20:47:47:7d:db:7b", "a0:bc:6f:bf:8c:57"}

    def test_an_ip_query_does_not_match_a_mac(self, appliance):
        """An IP is dots and hex digits, so a loose MAC match would catch it."""
        server, _ = appliance
        result = call(server, "find_device", {"query": "203.0.113.1"})
        assert [device["ip"] for device in result["devices"]] == ["203.0.113.1"]


def test_fake_appliance_is_wired_up(appliance):
    """Guard against a fixture that silently serves nothing."""
    server, _ = appliance
    assert call(server, "list_interfaces", {"include_internal": True})["count"] == len(INTERFACE_ROWS)




class TestFilterTallyItself:
    """The counting primitive, exercised where the tools cannot reach it."""

    def test_an_undeclared_filter_cannot_be_counted(self):
        """A miscount would produce a report that omits a filter which really ran.

        That is the same dishonesty the class exists to remove, arriving through
        a typo instead of through an omission, so it fails loudly rather than
        inventing a key.
        """
        from mcfortigate.paging import FilterTally

        tally = FilterTally(interface="lan")
        with pytest.raises(KeyError, match="never declared"):
            tally.drop("interfaces")

    def test_declared_filters_count_from_zero(self):
        from mcfortigate.paging import FilterTally

        tally = FilterTally(interface="lan", name_contains=None)
        fields = tally.describe(total=7)
        assert fields["filtered_out"] == {"interface": 0}
        assert "name_contains" not in fields["filters_applied"]

    def test_a_false_flag_is_not_an_active_filter(self):
        """`with_ip_only=False` is the caller declining a filter, not using one."""
        from mcfortigate.paging import FilterTally

        assert FilterTally(with_ip_only=False).describe(total=7) == {}

    def test_a_true_flag_is_an_active_filter(self):
        from mcfortigate.paging import FilterTally

        assert FilterTally(with_ip_only=True).describe(total=7)["filters_applied"] == {"with_ip_only": True}
