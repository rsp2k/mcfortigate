"""Tests for the FortiOS reading layer.

Several of these encode quirks that were discovered against real hardware
rather than read in documentation. Those carry a note about what breaks when
the behavior regresses, because the failure mode is usually silent.
"""

from __future__ import annotations

import pytest

from mcfortigate.fortios import (
    FortiOSError,
    check_response,
    fortios_bool,
    interface_ip_to_cidr,
    is_internal_interface,
    mac_fragment_digits,
    member_names,
    normalize_mac,
    route_destination,
    subnet_to_cidr,
    summarize_address,
    summarize_interface,
    summarize_policy,
    summarize_route,
    summarize_service,
)


class FakeResponse:
    """Stand-in for a requests.Response."""

    def __init__(self, status_code: int, body: dict | None = None, text: str = ""):
        self.status_code = status_code
        self._body = body
        self.text = text

    def json(self) -> dict:
        if self._body is None:
            raise ValueError("not json")
        return self._body


class TestCheckResponse:
    def test_passes_through_on_200(self):
        resp = FakeResponse(200)
        assert check_response(resp, "test") is resp

    def test_raises_with_fortios_error_code(self):
        resp = FakeResponse(500, {"status": "error", "error": -23, "cli_error": "in use"})
        with pytest.raises(FortiOSError) as exc:
            check_response(resp, "address.delete")
        message = str(exc.value)
        assert "address.delete" in message
        assert "-23" in message
        assert "in use" in message

    def test_falls_back_to_text_when_body_is_not_json(self):
        resp = FakeResponse(502, None, text="<html>bad gateway</html>")
        with pytest.raises(FortiOSError, match="bad gateway"):
            check_response(resp, "anything")


class TestFortiosBool:
    """FortiOS says enable/disable where JSON would say true/false.

    Passing these through bool() reads every disabled thing as enabled, since
    bool("disable") is True. That mistake flipped every non-blackhole route to
    blackhole in the sibling project before it was caught on real hardware.
    """

    def test_enable_and_disable_strings(self):
        assert fortios_bool("enable") is True
        assert fortios_bool("disable") is False

    def test_disable_is_not_truthy(self):
        assert fortios_bool("disable") is not True

    def test_real_booleans_pass_through(self):
        assert fortios_bool(True) is True
        assert fortios_bool(False) is False

    def test_missing_uses_default(self):
        assert fortios_bool(None) is False
        assert fortios_bool(None, default=True) is True

    def test_other_truthy_spellings(self):
        for value in ("up", "yes", "on", "1", "true", "ENABLE"):
            assert fortios_bool(value) is True


class TestMemberNames:
    """Relational fields arrive as a list of dicts, or on 7.0.x as a bare string."""

    def test_list_of_dicts(self):
        assert member_names([{"name": "WEB"}, {"name": "DB"}]) == ["WEB", "DB"]

    def test_bare_string_shape(self):
        assert member_names("WEB") == ["WEB"]

    def test_single_dict(self):
        assert member_names({"name": "WEB"}) == ["WEB"]

    def test_empty_inputs(self):
        assert member_names(None) == []
        assert member_names([]) == []
        assert member_names("") == []

    def test_skips_malformed_entries(self):
        assert member_names([{"name": "GOOD"}, {"nope": "BAD"}, {}]) == ["GOOD"]


class TestAddressConversion:
    """The same dotted-mask format means different things in different fields."""

    def test_subnet_collapses_to_network(self):
        assert subnet_to_cidr("10.0.0.0 255.255.255.0") == "10.0.0.0/24"

    def test_subnet_handles_default_route(self):
        assert subnet_to_cidr("0.0.0.0 0.0.0.0") == "0.0.0.0/0"

    def test_subnet_returns_none_on_garbage(self):
        assert subnet_to_cidr("nonsense") is None
        assert subnet_to_cidr("") is None

    def test_interface_ip_keeps_the_host(self):
        """Collapsing an interface address to its network invents a phantom IP."""
        assert interface_ip_to_cidr("203.0.113.10 255.255.255.0") == "203.0.113.10/24"

    def test_interface_ip_differs_from_subnet_for_same_input(self):
        raw = "203.0.113.10 255.255.255.0"
        assert interface_ip_to_cidr(raw) != subnet_to_cidr(raw)

    def test_unassigned_interface_reads_as_none(self):
        assert interface_ip_to_cidr("0.0.0.0 0.0.0.0") is None


class TestInternalInterfaces:
    def test_quarantine_and_vap_prefixes(self):
        assert is_internal_interface("wqtn.10.guest") is True
        assert is_internal_interface("vap.10.corp") is True
        assert is_internal_interface("ssl.root") is True

    def test_operator_vlan_is_not_internal(self):
        assert is_internal_interface("vlan10") is False
        assert is_internal_interface("internal3.100") is False
        assert is_internal_interface("wan1") is False


class TestSummarizeAddress:
    def test_ipmask(self):
        summary = summarize_address({"name": "WEB", "type": "ipmask", "subnet": "10.0.10.0 255.255.255.0"})
        assert summary == {"name": "WEB", "type": "ipmask", "value": "10.0.10.0/24"}

    def test_fqdn(self):
        summary = summarize_address({"name": "vendor", "type": "fqdn", "fqdn": "example.com"})
        assert summary["value"] == "example.com"

    def test_iprange(self):
        summary = summarize_address({"name": "POOL", "type": "iprange", "start-ip": "10.0.0.5", "end-ip": "10.0.0.10"})
        assert summary["value"] == "10.0.0.5-10.0.0.10"

    def test_mac_type_is_readable(self):
        summary = summarize_address({"name": "cam", "type": "mac", "macaddr": [{"macaddr": "aa:bb:cc:dd:ee:01"}]})
        assert summary["value"] == "aa:bb:cc:dd:ee:01"

    def test_type_defaults_to_ipmask_when_absent(self):
        summary = summarize_address({"name": "X", "subnet": "10.1.0.0 255.255.0.0"})
        assert summary["type"] == "ipmask"
        assert summary["value"] == "10.1.0.0/16"


class TestSummarizeService:
    def test_tcp_ports(self):
        summary = summarize_service({"name": "HTTPS", "protocol": "TCP/UDP/SCTP", "tcp-portrange": "443"})
        assert summary["ports"] == {"tcp": "443"}

    def test_multi_port_is_space_separated_upstream(self):
        summary = summarize_service({"name": "KERBEROS", "protocol": "TCP/UDP/SCTP", "tcp-portrange": "88 464"})
        assert summary["ports"]["tcp"] == "88,464"

    def test_source_port_qualifier_is_dropped(self):
        """RLOGIN is written 513:512-1023, meaning dst 513 from src 512-1023."""
        summary = summarize_service({"name": "RLOGIN", "protocol": "TCP/UDP/SCTP", "tcp-portrange": "513:512-1023"})
        assert summary["ports"]["tcp"] == "513"

    def test_protocol_ip_with_number(self):
        summary = summarize_service({"name": "OSPF", "protocol": "IP", "protocol-number": 89})
        assert summary["protocol"] == "OSPF"

    def test_protocol_ip_without_number_means_any(self):
        """The built-in ALL service is protocol IP with no number, meaning any."""
        summary = summarize_service({"name": "ALL", "protocol": "IP"})
        assert summary["protocol"] == "any"

    def test_pseudo_protocol_all(self):
        summary = summarize_service({"name": "webproxy", "protocol": "ALL"})
        assert summary["protocol"] == "any"

    def test_icmp6_is_reported_by_its_iana_name(self):
        summary = summarize_service({"name": "PING6", "protocol": "ICMP6"})
        assert summary["protocol"] == "IPv6-ICMP"


class TestSummarizePolicy:
    def test_drops_the_noise_fields(self):
        raw = {
            "policyid": 3,
            "name": "Allow web",
            "status": "enable",
            "action": "accept",
            "srcintf": [{"name": "lan"}],
            "dstintf": [{"name": "wan1"}],
            "srcaddr": [{"name": "INTERNAL"}],
            "dstaddr": [{"name": "all"}],
            "service": [{"name": "HTTPS"}],
            "srcaddr6": [],
            "uuid": "abc-123",
            "comments": "",
            "schedule": "always",
            "logtraffic": "disable",
        }
        summary = summarize_policy(raw)
        assert summary["id"] == 3
        assert summary["source"] == ["INTERNAL"]
        assert summary["enabled"] is True
        # Noise and defaults are not carried through.
        assert "uuid" not in summary
        assert "srcaddr6" not in summary
        assert "schedule" not in summary
        assert "log" not in summary
        assert "comment" not in summary

    def test_disabled_policy_reads_as_disabled(self):
        assert summarize_policy({"policyid": 1, "status": "disable"})["enabled"] is False

    def test_unnamed_policy_gets_a_stable_label(self):
        assert summarize_policy({"policyid": 7})["name"] == "policy-7"

    def test_non_default_schedule_and_log_are_kept(self):
        summary = summarize_policy({"policyid": 1, "schedule": "business-hours", "logtraffic": "all"})
        assert summary["schedule"] == "business-hours"
        assert summary["log"] == "all"


class TestSummarizeInterface:
    def test_vlan_subinterface(self):
        summary = summarize_interface(
            {
                "name": "vlan100",
                "type": "vlan",
                "status": "up",
                "vdom": "root",
                "interface": "wan1",
                "vlanid": 100,
                "ip": "198.51.100.1 255.255.255.0",
            }
        )
        assert summary["vlan_id"] == 100
        assert summary["parent"] == "wan1"
        assert summary["ip"] == "198.51.100.1/24"

    def test_vlanid_zero_means_untagged(self):
        summary = summarize_interface({"name": "wan1", "type": "physical", "vlanid": 0})
        assert "vlan_id" not in summary

    def test_unaddressed_interface_omits_ip(self):
        summary = summarize_interface({"name": "wan1", "type": "physical", "ip": "0.0.0.0 0.0.0.0"})
        assert "ip" not in summary

    def test_secondary_addresses_are_listed(self):
        summary = summarize_interface(
            {
                "name": "lan",
                "ip": "10.0.0.1 255.255.255.0",
                "secondaryip": [{"ip": "10.0.1.1 255.255.255.0"}],
            }
        )
        assert summary["secondary_ips"] == ["10.0.1.1/24"]


class TestRouteDestination:
    """dst is a placeholder whenever dstaddr is populated.

    Reading dst first turns every named-destination route into a bogus default
    route, because FortiOS writes the all-zeros sentinel into dst in that case.
    """

    def test_literal_destination(self):
        assert route_destination({"dst": "10.20.0.0 255.255.0.0"}) == "10.20.0.0/16"

    def test_genuine_default_route(self):
        assert route_destination({"dst": "0.0.0.0 0.0.0.0"}) == "0.0.0.0/0"

    def test_named_destination_defers_resolution(self):
        assert route_destination({"dstaddr": [{"name": "DC_NETS"}]}) is None

    def test_named_destination_wins_over_placeholder_dst(self):
        raw = {"dst": "0.0.0.0 0.0.0.0", "dstaddr": "DC_NETS"}
        assert route_destination(raw) is None

    def test_summarized_route_keeps_the_object_name(self):
        summary = summarize_route({"seq-num": 9, "dst": "0.0.0.0 0.0.0.0", "dstaddr": "DC_NETS"})
        assert summary["destination_address_object"] == "DC_NETS"
        assert summary["destination"] is None


class TestSummarizeRoute:
    def test_gateway_route(self):
        summary = summarize_route(
            {
                "seq-num": 1,
                "dst": "203.0.113.0 255.255.255.0",
                "gateway": "192.168.1.1",
                "device": "wan2",
                "distance": 10,
                "blackhole": "disable",
            }
        )
        assert summary["destination"] == "203.0.113.0/24"
        assert summary["gateway"] == "192.168.1.1"
        assert summary["interface"] == "wan2"
        assert "blackhole" not in summary

    def test_blackhole_route_has_no_next_hop(self):
        summary = summarize_route(
            {"seq-num": 5, "dst": "192.0.2.0 255.255.255.0", "gateway": "0.0.0.0", "blackhole": "enable"}
        )
        assert summary["blackhole"] is True
        assert "gateway" not in summary

    def test_disable_string_does_not_read_as_blackhole(self):
        """The regression this file exists to prevent."""
        summary = summarize_route(
            {"seq-num": 1, "dst": "0.0.0.0 0.0.0.0", "gateway": "192.168.1.1", "blackhole": "disable"}
        )
        assert "blackhole" not in summary
        assert summary["gateway"] == "192.168.1.1"

    def test_unset_gateway_is_omitted(self):
        summary = summarize_route({"seq-num": 2, "dst": "10.0.0.0 255.0.0.0", "gateway": "0.0.0.0"})
        assert "gateway" not in summary


class TestNormalizeMac:
    def test_lowercases(self):
        assert normalize_mac("AA:BB:CC:DD:EE:01") == "aa:bb:cc:dd:ee:01"

    def test_handles_empty(self):
        assert normalize_mac("") == ""
        assert normalize_mac(None) == ""


class TestProtocolNamingIsConsistent:
    """Protocol names read uppercase regardless of which branch produced them.

    Port-based services build their protocol label from the populated port
    fields, which are lowercase keys, while ICMP and IP-protocol services read
    theirs from a table. Without normalizing, one service reports "tcp/udp" and
    the next reports "ICMP" in the same list.
    """

    def test_port_based_services_are_uppercase(self):
        summary = summarize_service(
            {"name": "DNS", "protocol": "TCP/UDP/SCTP", "tcp-portrange": "53", "udp-portrange": "53"}
        )
        assert summary["protocol"] == "TCP/UDP"

    def test_single_protocol_is_uppercase(self):
        summary = summarize_service({"name": "HTTP", "protocol": "TCP/UDP/SCTP", "tcp-portrange": "80"})
        assert summary["protocol"] == "TCP"

    def test_port_keys_stay_lowercase_for_lookup(self):
        summary = summarize_service({"name": "HTTP", "protocol": "TCP/UDP/SCTP", "tcp-portrange": "80"})
        assert summary["ports"] == {"tcp": "80"}


class TestMacSeparatorNormalization:
    """M3. Separators differ between vendors and sometimes between endpoints.

    `find_device` joins the wifi, DHCP, and ARP tables on MAC and matches an
    operator's query against them. Lowercasing alone leaves the join keyed on
    whatever punctuation each source happened to use, so one source spelling a
    MAC `aa-bb-cc-dd-ee-ff` while another spells it `aa:bb:cc:dd:ee:ff` means
    the join matches nothing and the device is reported as unknown. Silently.
    """

    def test_dash_separated_becomes_colon_separated(self):
        assert normalize_mac("AA-BB-CC-DD-EE-FF") == "aa:bb:cc:dd:ee:ff"

    def test_cisco_dotted_becomes_colon_separated(self):
        assert normalize_mac("AABB.CCDD.EEFF") == "aa:bb:cc:dd:ee:ff"

    def test_bare_hex_becomes_colon_separated(self):
        assert normalize_mac("aabbccddeeff") == "aa:bb:cc:dd:ee:ff"

    def test_already_canonical_is_unchanged(self):
        assert normalize_mac("20:47:47:7d:db:7b") == "20:47:47:7d:db:7b"

    def test_every_spelling_of_one_address_collapses_to_one_key(self):
        """The property the join actually depends on."""
        spellings = ["AA:BB:CC:DD:EE:FF", "aa-bb-cc-dd-ee-ff", "AABB.CCDD.EEFF", "aabbccddeeff"]
        assert len({normalize_mac(spelling) for spelling in spellings}) == 1

    def test_non_mac_text_is_not_reshaped(self):
        """Nothing may be invented from a value that is not a MAC.

        A hostname or a truncated field reaching this function must come back
        recognizable, not rearranged into something that looks like hardware.
        """
        assert normalize_mac("guest-laptop") == "guest-laptop"
        assert normalize_mac("unknown") == "unknown"
        assert normalize_mac("192.168.1.47") == "192.168.1.47"

    def test_empty_and_none_stay_empty(self):
        assert normalize_mac("") == ""
        assert normalize_mac(None) == ""


class TestMacFragmentDigits:
    """Separator-insensitive matching for a partial MAC typed by an operator.

    The query side of the same join. Someone reading a MAC off a Cisco switch
    types `2047.477d.db7b`; someone reading it off a Windows box types
    `20-47-47-7D-DB-7B`. Both must find the ARP row that FortiOS spells
    `20:47:47:7d:db:7b`.
    """

    @pytest.mark.parametrize(
        ("query", "digits"),
        [
            ("20-47-47-7d-db-7b", "2047477ddb7b"),
            ("2047.477d.db7b", "2047477ddb7b"),
            ("20:47:47:7d:db:7b", "2047477ddb7b"),
            ("2047477DDB7B", "2047477ddb7b"),
            ("7d-db-7b", "7ddb7b"),
            ("AA:BB", "aabb"),
        ],
    )
    def test_mac_shaped_input_yields_digits(self, query: str, digits: str):
        assert mac_fragment_digits(query) == digits

    @pytest.mark.parametrize(
        "query",
        [
            "192.168.1.47",  # an IP is all hex digits and dots, and must not pass
            "10.0.0.1",
            "fe80::1",
            "guest-laptop",
            "",
            "a",  # too few digits to distinguish anything
            "a:b",
        ],
    )
    def test_non_mac_input_is_rejected(self, query: str):
        """An IPv4 address is the dangerous case: dots and hex digits only.

        Letting one through would let a query for an IP match an unrelated
        device by its MAC, which is a confidently wrong answer rather than a
        missing one.
        """
        assert mac_fragment_digits(query) is None


class TestSecondaryIpsAreNotSilentlyDropped:
    """M9. The walrus in the old comprehension doubled as the filter test.

    `[cidr for entry in rows if (cidr := convert(entry))]` keeps a row only
    when the converted value is truthy, which is the same family of mistake as
    `bool("disable")`: the test is on the value rather than on whether the
    conversion succeeded. It also threw away unconvertible rows without trace,
    so an interface carrying a secondary address this code cannot parse looked
    identical to one carrying none.
    """

    def test_parsable_secondaries_are_listed(self):
        summary = summarize_interface(
            {"name": "lan", "ip": "10.0.0.1 255.255.255.0", "secondaryip": [{"ip": "10.0.1.1 255.255.255.0"}]}
        )
        assert summary["secondary_ips"] == ["10.0.1.1/24"]
        assert "secondary_ips_unreadable" not in summary

    def test_unparsable_secondary_is_reported_rather_than_dropped(self):
        summary = summarize_interface(
            {
                "name": "lan",
                "ip": "10.0.0.1 255.255.255.0",
                "secondaryip": [{"ip": "10.0.1.1 255.255.255.0"}, {"ip": "not-an-address"}],
            }
        )
        assert summary["secondary_ips"] == ["10.0.1.1/24"]
        assert summary["secondary_ips_unreadable"] == 1

    def test_an_interface_whose_only_secondary_is_unreadable_still_says_so(self):
        """The case the old code made invisible."""
        summary = summarize_interface({"name": "lan", "secondaryip": [{"ip": "garbage"}]})
        assert "secondary_ips" not in summary
        assert summary["secondary_ips_unreadable"] == 1

    def test_no_secondaries_reports_nothing(self):
        """Absent beats zero. A count of zero invites a reader to wonder."""
        summary = summarize_interface({"name": "lan", "ip": "10.0.0.1 255.255.255.0"})
        assert "secondary_ips" not in summary
        assert "secondary_ips_unreadable" not in summary


class TestInterfaceCidrNeverReturnsAFalsyString:
    """The contract the old walrus-as-filter silently depended on.

    `[cidr for entry in rows if (cidr := convert(entry))]` is correct only while
    `convert` never returns a value that is both legitimate and falsy. Nothing
    stated that, nothing enforced it, and the comprehension would have started
    dropping real addresses the day it stopped being true. The loop that
    replaced it tests `is not None` instead, so it no longer matters; this pins
    the contract anyway, because the next person to reach for a walrus here
    deserves to find out from a test rather than from a missing interface.
    """

    @pytest.mark.parametrize(
        "field",
        [
            "203.0.113.10 255.255.255.0",
            "10.0.0.1 255.255.255.255",
            "10.0.0.1 0.0.0.0",
            "192.0.2.1 255.255.0.0",
        ],
    )
    def test_a_successful_conversion_is_always_truthy(self, field: str):
        result = interface_ip_to_cidr(field)
        assert result is not None
        assert result, "a falsy success value would be dropped by any truthiness filter"

    @pytest.mark.parametrize("field", ["", "garbage", "0.0.0.0 0.0.0.0", "10.0.0.1", "a b"])
    def test_a_failed_conversion_is_none_not_empty_string(self, field: str):
        """Failure must be None so callers can tell it from a legitimate value."""
        assert interface_ip_to_cidr(field) is None
