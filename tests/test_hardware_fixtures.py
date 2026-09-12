"""Every tool driven through payloads a real FortiWiFi-61E actually sent.

The rest of the suite proves the reading layer handles shapes we wrote down.
This file proves it handles the shapes the appliance sends, which on this
project has repeatedly been a different thing: an uptime field present in no
endpoint, a `results` that is an object where a list was assumed, a
`reference_count` reading zero on genuine references, a policy carrying 147
fields. Each of those passed a green suite first.

The payloads under `tests/fixtures/` were captured by
`scripts/capture_fixtures.py` from FortiOS 7.0.14 and sanitized. Nothing in them
was typed by hand, so an assertion here that passes is an assertion about the
appliance rather than about our imagination of it. When a future firmware
changes a shape, re-run the capture and the failures point at what moved.

One gap worth naming rather than hiding. The lab appliance had no associated
wireless clients and no DHCP leases at capture time, so the wifi and DHCP
fixtures are genuinely empty tables. The three-way MAC join in `find_device` is
therefore exercised against ARP alone, and the MAC casing difference between
those three endpoints, which `normalize_mac` exists for, is not covered by real
data yet. Re-capture with a client associated to close that.
"""

from __future__ import annotations

import pytest
from conftest import Response, fixture_payload

from mcfortigate.client import ADDRESSES, INTERFACES, MON_OBJECT_USAGE, POLICIES
from mcfortigate.fortios import summarize_policy

DENIED = Response({"status": "error", "error": -37, "http_status": 403}, status_code=403)


class TestApplianceIdentity:
    """What `get_system_status` may claim about a 7.0.14 FortiWiFi-61E."""

    def test_identity_comes_from_the_response_envelope(self, hardware_tool):
        """Serial, version, and build are siblings of `results`, not inside it.

        The fixture keeps the whole envelope for exactly this reason. A helper
        that unwrapped to `results` would report no serial at all, and the API
        would look like it does not carry one.
        """
        status = hardware_tool("get_system_status")
        assert status["serial"].startswith("FWF61E")
        assert status["version"] == "v7.0.14"
        assert status["build"] == 601

    def test_model_and_hostname_survive(self, hardware_tool):
        status = hardware_tool("get_system_status")
        assert status["model"] == "FortiWiFi"
        assert status["model_number"] == "61E"
        assert status["hostname"] == "FortiWiFi-61E"

    def test_this_firmware_reports_no_uptime(self, hardware_tool):
        """Captured from hardware: 7.0.14 carries uptime in no monitor endpoint.

        The docstring promised uptime for weeks while the field was structurally
        null on every call. An omitted key says the appliance did not answer; a
        null would say the appliance has no uptime.
        """
        assert "uptime_seconds" not in hardware_tool("get_system_status")

    def test_an_idle_cpu_reading_of_zero_survives(self, hardware_tool):
        """The lab appliance is idle, so its real `cpu` reading is 0.

        Filtering the optional fields on truthiness rather than `is not None`
        drops this one measurement and passes everything else in this class.
        """
        assert hardware_tool("get_system_status")["cpu_percent"] == 0

    def test_the_resource_series_is_a_list_of_objects(self, hardware_tool):
        """`monitor/system/resource/usage` nests each metric one level deeper.

        The current reading is `results[metric][0]["current"]`, not
        `results[metric]`. Reading it one level too shallow yields a list and
        silently reports no load.
        """
        status = hardware_tool("get_system_status")
        assert isinstance(status["memory_percent"], int)
        assert isinstance(status["sessions"], int)


class TestAddressObjectsAsStored:
    """The fifteen address objects on a stock appliance, as FortiOS stores them."""

    def test_every_real_address_type_is_understood(self, hardware_tool):
        """`unparsed_type` is the backstop for an address kind we cannot read.

        Five types appear on this appliance: ipmask, interface-subnet, iprange,
        fqdn, and dynamic. If any of them stopped being handled the object would
        go blank rather than error, and this is what notices.
        """
        addresses = hardware_tool("list_address_objects")["addresses"]
        unparsed = [entry["name"] for entry in addresses if "unparsed_type" in entry]
        assert not unparsed, f"address types nobody handles: {unparsed}"

    def test_a_dotted_mask_means_a_network_here(self, hardware_tool):
        """`firewall.address.subnet` holds a network even when host bits are set.

        The captured `lan` object stores the interface's own address with a /24
        mask. As an address object it means the network, so it collapses. The
        same string on `system.interface.ip` means the host and must not, which
        is the pair of behaviours the next test pins.
        """
        by_name = {entry["name"]: entry for entry in hardware_tool("list_address_objects")["addresses"]}
        assert by_name["lan"]["value"] == "198.18.2.0/24"

    def test_the_same_string_keeps_its_host_on_an_interface(self, hardware_tool):
        """The other half of the pair, from the same captured octets.

        Collapsing an interface address to its network invents an IP that does
        not exist, which is how the sibling project's first device sync went
        wrong. These two assertions read the same value out of two tables.
        """
        by_name = {entry["name"]: entry for entry in hardware_tool("list_interfaces")["interfaces"]}
        assert by_name["lan"]["ip"] == "198.18.2.99/24"

    def test_the_all_object_is_a_default_route_style_wildcard(self, hardware_tool):
        by_name = {entry["name"]: entry for entry in hardware_tool("list_address_objects")["addresses"]}
        assert by_name["all"]["value"] == "0.0.0.0/0"
        assert by_name["none"]["value"] == "0.0.0.0/32"

    def test_an_ip_range_reports_both_ends(self, hardware_tool):
        by_name = {entry["name"]: entry for entry in hardware_tool("list_address_objects")["addresses"]}
        assert by_name["SSLVPN_TUNNEL_ADDR1"]["value"] == "198.18.0.200-198.18.0.210"

    def test_a_dynamic_address_reports_its_connector(self, hardware_tool):
        """A FortiClient EMS address has no IP at all, only a sub-type."""
        by_name = {entry["name"]: entry for entry in hardware_tool("list_address_objects")["addresses"]}
        assert by_name["FCTEMS_ALL_FORTICLOUD_SERVERS"]["value"] == "ems-tag"


class TestServicesAsStored:
    """The 87 built-in services, covering all four protocol spellings."""

    @pytest.mark.parametrize(
        ("name", "expected"),
        [
            # "protocol IP with no protocol-number" is how FortiOS spells "any IP
            # protocol". Reading 0 as its IANA meaning would report HOPOPT.
            ("ALL", {"protocol": "any", "protocol_number": 0}),
            ("GRE", {"protocol": "GRE", "protocol_number": 47}),
        ],
    )
    def test_ip_protocol_services(self, hardware_tool, name: str, expected: dict):
        by_name = {entry["name"]: entry for entry in hardware_tool("list_services")["services"]}
        assert {key: by_name[name][key] for key in expected} == expected

    def test_a_multi_port_service_keeps_every_port(self, hardware_tool):
        """Kerberos is `88 464`, space separated, on both TCP and UDP."""
        by_name = {entry["name"]: entry for entry in hardware_tool("list_services")["services"]}
        assert by_name["KERBEROS"]["ports"] == {"tcp": "88,464", "udp": "88,464"}
        assert by_name["KERBEROS"]["protocol"] == "TCP/UDP"

    def test_a_source_port_qualifier_is_dropped(self, hardware_tool):
        """RLOGIN is stored as `513:512-1023`, destination port then source range.

        Nothing downstream models source ports, and carrying the qualifier
        through would read as a destination port of 513 through 1023.
        """
        by_name = {entry["name"]: entry for entry in hardware_tool("list_services")["services"]}
        assert by_name["RLOGIN"]["ports"] == {"tcp": "513"}

    def test_icmp_keeps_its_type(self, hardware_tool):
        by_name = {entry["name"]: entry for entry in hardware_tool("list_services")["services"]}
        assert by_name["PING"]["protocol"] == "ICMP"
        assert by_name["PING"]["icmp_type"] == 8


class TestThePolicyAsFortiOSSendsIt:
    """One real policy, 147 fields, and what survives summarizing."""

    def test_the_raw_policy_really_does_carry_147_fields(self):
        """The claim the whole summarization design rests on, measured."""
        raw = fixture_payload("cmdb_firewall_policy")["results"][0]
        assert len(raw) == 147

    def test_the_summary_is_a_fraction_of_that(self, hardware_tool):
        summary = hardware_tool("list_policies")["policies"][0]
        assert len(summary) < 20

    def test_the_backstop_stays_quiet_on_a_stock_policy(self, hardware_tool):
        """`unsummarized` names fields nobody has classified.

        This is the assertion the ignore list exists to make possible. Every
        entry on that list appears at a non-default value on this captured
        policy, so an under-populated list makes the backstop fire on an
        ordinary rule and get ignored within a day.
        """
        summary = hardware_tool("list_policies")["policies"][0]
        assert "unsummarized" not in summary, f"unclassified policy fields: {summary.get('unsummarized')}"

    def test_the_backstop_still_fires_on_something_new(self):
        """The other half: a quiet backstop and a deleted backstop look alike.

        A field a future firmware adds has to surface, so this injects one into
        the captured policy and requires it back out.
        """
        raw = fixture_payload("cmdb_firewall_policy")["results"][0]
        raw["some-new-7.6-field"] = "enable"
        assert summarize_policy(raw)["unsummarized"] == {"some-new-7.6-field": "enable"}

    def test_the_rule_reads_the_way_an_operator_would_state_it(self, hardware_tool):
        summary = hardware_tool("list_policies")["policies"][0]
        assert summary["from"] == ["lan"]
        assert summary["to"] == ["wan1"]
        assert summary["source"] == ["all"]
        assert summary["destination"] == ["all"]
        assert summary["service"] == ["ALL"]
        assert summary["action"] == "accept"
        assert summary["enabled"] is True
        assert summary["nat"] is True

    def test_an_unnamed_policy_is_identified_by_its_id(self, hardware_tool):
        """FortiOS leaves `name` empty on a rule created without one."""
        assert hardware_tool("list_policies")["policies"][0]["name"] == "policy-1"

    def test_the_always_schedule_is_not_reported(self, hardware_tool):
        """Every stock rule is `always`, so saying so is noise."""
        assert "schedule" not in hardware_tool("list_policies")["policies"][0]


class TestInterfacesAsStored:
    """29 interfaces, of which seven are FortiOS bookkeeping."""

    def test_generated_interfaces_are_hidden_and_named(self, hardware_tool):
        """Hiding something silently and hiding it visibly are different acts."""
        response = hardware_tool("list_interfaces")
        hidden = response["hidden_internal"]
        assert hidden == ["naf.root", "ssl.root", *[name for name in hidden if name.startswith("wqtn.")]]
        assert len(response["interfaces"]) + len(hidden) == 29

    def test_a_dhcp_interface_reports_both_its_address_and_how_it_got_one(self, hardware_tool):
        """wan1 holds a DHCP-assigned address in the configuration table.

        Reporting only `addressing: dhcp` would answer "what is my WAN address"
        with "it has none", and reporting only the address would hide that
        nothing pins it.
        """
        by_name = {entry["name"]: entry for entry in hardware_tool("list_interfaces")["interfaces"]}
        assert by_name["wan1"]["ip"] == "198.18.4.11/24"
        assert by_name["wan1"]["addressing"] == "dhcp"
        assert "note" not in by_name["wan1"]

    def test_an_unaddressed_dynamic_interface_points_at_the_runtime_view(self, hardware_tool):
        by_name = {entry["name"]: entry for entry in hardware_tool("list_interfaces")["interfaces"]}
        assert "ip" not in by_name["modem"]
        assert by_name["modem"]["addressing"] == "pppoe"
        assert "get_routing_table" in by_name["modem"]["note"]

    def test_a_vlan_names_its_tag_and_its_parent(self, hardware_tool):
        vlans = hardware_tool("list_vlans")["vlans"]
        assert len(vlans) == 1
        assert vlans[0]["vlan_id"] == 100
        assert vlans[0]["parent"] == "wan1"

    def test_quarantine_vlans_are_not_listed_as_vlans(self, hardware_tool):
        """Five wqtn. interfaces are type vlan and carry tag 4093.

        Filtering by `type` alone would list all six. They are indistinguishable
        from an operator's VLAN except by name, which is why the filter is by
        name.
        """
        raw = fixture_payload("cmdb_system_interface")["results"]
        quarantine = [row for row in raw if row["name"].startswith("wqtn.")]
        assert quarantine and all(row["type"] == "vlan" for row in quarantine)
        assert not [entry for entry in hardware_tool("list_vlans")["vlans"] if entry["name"].startswith("wqtn.")]


class TestStaticRoutesAsStored:
    """Two routes, one of which uses the shape that broke the sibling project."""

    def test_a_named_destination_wins_over_the_dst_placeholder(self, hardware_tool):
        """Route 9002 stores `dst: 0.0.0.0 0.0.0.0` and the real target in `dstaddr`.

        Reading `dst` first turns this into a default route pointing at wan2,
        which is a far more dangerous wrong answer than no answer.
        """
        raw = {row["seq-num"]: row for row in fixture_payload("cmdb_router_static")["results"]}
        assert raw[9002]["dst"] == "0.0.0.0 0.0.0.0"
        assert raw[9002]["dstaddr"] == "ssot_test_dstaddr"

        routes = {entry["seq_num"]: entry for entry in hardware_tool("list_static_routes")["routes"]}
        assert routes[9002]["destination_address_object"] == "ssot_test_dstaddr"
        assert routes[9002]["destination"] == "192.0.2.0/24"
        assert routes[9002]["destination_resolution"] == "named_resolved"

    def test_dstaddr_arrives_as_a_bare_string_on_this_firmware(self):
        """7.0.x sends a string where 7.2+ sends a list of objects.

        Both mean one name. A join written for only the 7.2 shape matches
        nothing here and reports the route as having no named destination.
        """
        raw = {row["seq-num"]: row for row in fixture_payload("cmdb_router_static")["results"]}
        assert isinstance(raw[9002]["dstaddr"], str)

    def test_a_literal_destination_is_left_alone(self, hardware_tool):
        routes = {entry["seq_num"]: entry for entry in hardware_tool("list_static_routes")["routes"]}
        assert routes[9001]["destination"] == "203.0.113.0/24"
        assert routes[9001]["destination_resolution"] == "literal"

    def test_blackhole_is_a_string_and_neither_route_is_one(self, hardware_tool):
        """`bool("disable")` is True, which flipped every route in the sibling project."""
        raw = fixture_payload("cmdb_router_static")["results"]
        assert {row["blackhole"] for row in raw} == {"disable"}
        assert not [entry for entry in hardware_tool("list_static_routes")["routes"] if entry.get("blackhole")]


class TestConfiguredRoutesAreNotActiveRoutes:
    """The distinction the two route tools exist to keep visible."""

    def test_the_active_table_holds_routes_the_configuration_does_not(self, hardware_tool):
        """wan1's default route came from DHCP, so it is in neither static route.

        `cmdb/router/static` is operator intent. Answering "what is my default
        gateway" from it reports wan2 on this appliance, while the appliance is
        actually forwarding through wan1.
        """
        configured = hardware_tool("list_static_routes")["routes"]
        assert not [entry for entry in configured if entry.get("destination") == "0.0.0.0/0"]

        active = hardware_tool("get_routing_table")["routes"]
        default = [entry for entry in active if entry["destination"] == "0.0.0.0/0"]
        assert len(default) == 1
        assert default[0]["interface"] == "wan1"

    def test_connected_routes_agree_with_the_interface_addresses(self, hardware_tool):
        """Renumbering the fixtures per network is what makes this joinable.

        If the sanitizer had replaced addresses one at a time, the connected
        route for lan and lan's own address would sit in unrelated subnets and
        this test would be checking nothing.
        """
        active = {entry["interface"]: entry for entry in hardware_tool("get_routing_table")["routes"]}
        interfaces = {entry["name"]: entry for entry in hardware_tool("list_interfaces")["interfaces"]}
        assert active["lan"]["destination"] == "198.18.2.0/24"
        assert interfaces["lan"]["ip"].startswith("198.18.2.")


class TestLiveStateAndTheDeviceJoin:
    """Monitor endpoints, where empty and refused mean opposite things."""

    def test_arp_entries_come_back_normalized(self, hardware_tool):
        entries = hardware_tool("get_arp_table")["entries"]
        assert len(entries) == 2
        assert {entry["interface"] for entry in entries} == {"lan", "wan1"}
        assert all(entry["mac"] == entry["mac"].lower() for entry in entries)

    def test_a_device_is_found_by_its_address(self, hardware_tool):
        """With no wireless clients and no leases, ARP is the only source.

        A device known only to ARP is the static-address case the fallback
        exists for, and it still resolves to one merged record.
        """
        found = hardware_tool("find_device", {"query": "198.18.4.1"})
        assert found["count"] == 1
        device = found["devices"][0]
        assert device["seen_in"] == ["arp"]
        assert device["interface"] == "wan1"
        assert "hostname" not in device

    def test_an_empty_table_that_answered_carries_no_warning(self, hardware_tool):
        """The appliance has no leases and said so, which is not a failure.

        Fail soft on absence, never on denial. A warning here would train a
        reader to ignore the one that matters.
        """
        leases = hardware_tool("list_dhcp_leases")
        assert leases["leases"] == []
        assert leases["source_status"] == "ok"
        assert "warning" not in leases

    def test_wifi_reports_every_source_it_consulted(self, hardware_tool):
        clients = hardware_tool("list_wifi_clients")
        assert clients["clients"] == []
        assert clients["sources_checked"] == {"wifi": "ok", "dhcp": "ok", "arp": "ok"}
        assert "warning" not in clients


class TestObjectUsageAgainstRealAnswers:
    """The endpoint `find_references` trusts, and the three traps in it."""

    def test_reference_count_is_zero_on_genuine_references(self):
        """Every row hardware returns carries `reference_count: 0`.

        Summing it reports an in-use object as unreferenced. The presence of a
        row is the signal; `describe_usage_row` drops the field on purpose.
        """
        rows = fixture_payload("monitor_system_object_usage__address_all")["results"]["currently_using"]
        assert len(rows) == 2
        assert {row["reference_count"] for row in rows} == {0}

    def test_the_results_object_is_not_a_list(self):
        """`monitor/system/object/usage` answers with a bare object.

        The library's helper coerces `results` with `list()`, which on an object
        yields its keys as strings. Our `_rows` handles both, and this is the
        payload that proves the endpoint really does send the awkward one.
        """
        assert isinstance(fixture_payload("monitor_system_object_usage__address_all")["results"], dict)

    def test_asking_the_wrong_table_answers_200_and_nothing(self):
        """The same key, two tables, two opposite answers, both HTTP 200.

        `wan1` asked of `firewall/address` reports no references. Asked of
        `system/interface` it reports two. A mismatched pair is therefore
        indistinguishable from a clean object, which is why the kind is resolved
        from the defining cmdb table first.
        """
        wrong = fixture_payload("monitor_system_object_usage__address_table_asked_about_an_interface")
        right = fixture_payload("monitor_system_object_usage__interface_wan1")
        assert wrong["results"]["currently_using"] == []
        assert len(right["results"]["currently_using"]) == 2

    def test_an_object_that_does_not_exist_looks_exactly_like_a_clean_one(self):
        """Both answer 200 with an empty list, hence the existence check."""
        absent = fixture_payload("monitor_system_object_usage__absent_addresses")
        clean = fixture_payload("monitor_system_object_usage__address_unreferenced")
        assert absent["results"]["currently_using"] == clean["results"]["currently_using"] == []

    def test_the_reference_capable_table_count_is_enormous(self):
        """74 tables for an address, 234 for an interface.

        The five-table scan that preceded this covered five of 234. The count is
        why the appliance is the authority and the scan is only detail.
        """
        address = fixture_payload("monitor_system_object_usage__address_all")["results"]
        interface = fixture_payload("monitor_system_object_usage__interface_wan1")["results"]
        assert len(address["can_use"]) == 74
        assert len(interface["can_use"]) == 234


class TestFindReferencesAgainstRealPayloads:
    """The verdicts, computed from what the appliance actually answered."""

    def test_a_referenced_address_is_not_safe_to_delete(self, hardware_tool):
        result = hardware_tool("find_references", {"object_name": "all"})
        assert result["verdict"] == "referenced"
        assert result["safe_to_delete"] is False
        assert result["resolved_as"] == ["address"]

    def test_the_two_counts_disagree_on_purpose(self, hardware_tool):
        """One policy using an address twice is two sites and one object.

        `total_references` counts where a change must be made; the detail list
        counts what an operator has to open. Collapsing them would hide that two
        fields need editing.
        """
        result = hardware_tool("find_references", {"object_name": "all"})
        assert result["total_references"] == 2
        assert [row["attribute"] for row in result["references"]] == ["srcaddr", "dstaddr"]
        assert len(result["policies"]) == 1
        assert result["policies"][0]["referenced_as"] == ["source", "destination"]

    def test_the_appliance_finds_a_reference_no_scan_would(self, hardware_tool):
        """wan1 is referenced by the VLAN parented to it, in `system.interface`.

        No amount of scanning policies, groups, VIPs, and routes reaches that.
        It is the concrete reason the usage endpoint replaced the scan.
        """
        result = hardware_tool("find_references", {"object_name": "wan1"})
        tables = {(row["table"], row["attribute"]) for row in result["references"]}
        assert ("system.interface", "name") in tables
        assert result["candidate_tables"] == 234

    def test_group_membership_is_reported_as_the_group(self, hardware_tool):
        result = hardware_tool("find_references", {"object_name": "gmail.com"})
        assert result["references"][0]["table"] == "firewall.addrgrp"
        assert result["groups"] == [{"name": "G Suite", "kind": "address_group"}]

    def test_a_genuinely_unreferenced_object_is_declared_safe(self, hardware_tool):
        """The one verdict that permits a delete, on an object hardware confirmed."""
        result = hardware_tool("find_references", {"object_name": "none"})
        assert result["verdict"] == "no_references"
        assert result["safe_to_delete"] is True

    def test_a_name_that_exists_nowhere_is_a_typo_rather_than_a_clean_object(self, hardware_tool):
        result = hardware_tool("find_references", {"object_name": "__mcfortigate_absent__"})
        assert result["verdict"] == "object_not_found"
        assert "safe_to_delete" not in result
        assert result["resolved_as"] == []


class TestDegradedReadsOnRealShapes:
    """One real table refused while the rest of the appliance answers normally.

    This is the likely first-contact outcome for a correctly least-privileged
    token, not an exotic case, and the fixtures let it be tested without
    pretending about what the other tables hold.
    """

    def test_the_authority_outranks_a_broken_scan(self, degraded_tool):
        """Losing the policy table must not weaken a verdict usage already gave.

        The reference is still reported, from the appliance's own answer, while
        the detail list that needed the policy table is honestly empty.
        """
        call = degraded_tool({POLICIES: DENIED})
        result = call("find_references", {"object_name": "all"})
        assert result["verdict"] == "referenced"
        assert result["safe_to_delete"] is False
        assert result["policies"] == []
        assert "403" in result["sources_checked"]["policies"]

    def test_losing_the_authority_downgrades_a_clean_verdict(self, degraded_tool):
        """With usage denied, finding nothing is a fact about four tables.

        This is the verdict that was unreachable until `scan_unreadable` was
        separated from `unreadable`, and eight passing tests did not notice.
        """
        call = degraded_tool({MON_OBJECT_USAGE: DENIED})
        result = call("find_references", {"object_name": "none"})
        assert result["verdict"] == "no_references_in_checked_scopes"
        assert "safe_to_delete" not in result
        assert "not consulted" in result["note"]

    def test_a_denied_table_is_never_rendered_as_an_empty_one(self, degraded_tool):
        """The listing tools raise rather than report an appliance with no addresses."""
        call = degraded_tool({ADDRESSES: DENIED})
        with pytest.raises(Exception, match="403"):
            call("list_address_objects")

    def test_search_keeps_going_and_says_what_it_missed(self, degraded_tool):
        """Search aggregates, so it degrades rather than failing.

        That makes a low match count legitimate output, and the obligation
        becomes labelling it rather than presenting it as a finished search.
        """
        call = degraded_tool({INTERFACES: DENIED})
        result = call("search_config", {"term": "198.18.2"})
        assert "interfaces" not in result["matches"]
        assert result["matches"]["addresses"][0]["name"] == "lan"
        assert "403" in result["sources_checked"]["interfaces"]
        assert "incomplete" in result["warning"]
