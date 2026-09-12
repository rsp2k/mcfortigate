"""What `find_references` may claim, and the two ways it can be confidently wrong.

The tool answers the question that precedes every firewall change. Getting it
wrong in the safe direction wastes an operator's afternoon; getting it wrong in
the other direction deletes an object that half the ruleset depends on.

Two distinct failure modes are covered here, both found against hardware rather
than reasoned about.

**Undercounting.** The original implementation scanned five cmdb tables. The
appliance reports, via `monitor/system/object/usage`, that seventy-four tables
can reference a firewall address on FortiOS 7.0.14. An object used only by a
web-proxy profile or a security-exempt list was therefore reported as having no
references at all, with `safe_to_delete: true`.

**Asking the wrong table.** The usage endpoint answers HTTP 200 with an empty
`currently_using` list when the object is absent from the table you named. A
typo, a wrong `q_path`, and a genuinely unreferenced object are three different
facts wearing one response. Querying `firewall/address` for the name `wan1`
returns zero references for an interface that has two.

The payloads below are the shapes hardware returned.
"""

from __future__ import annotations

import asyncio
import json
from contextlib import contextmanager
from types import SimpleNamespace
from urllib.parse import parse_qs, urlparse

import pytest

from mcfortigate.config import FortiGateTarget, TargetRegistry
from mcfortigate.expansion import MAX_EXPANSION_DEPTH
from mcfortigate.server import build_server


class Response:
    """The parts of a requests.Response the fetch helpers touch."""

    def __init__(self, body: dict, status_code: int = 200) -> None:
        self.status_code = status_code
        self._body = body
        self.text = json.dumps(body)

    def json(self) -> dict:
        return self._body


def table(rows: list[dict]) -> Response:
    """A cmdb table response."""
    return Response({"results": rows, "status": "success"})


def usage(rows: list[dict]) -> Response:
    """A `monitor/system/object/usage` response.

    `can_use` is the schema-level list of tables that could reference this kind
    of object and is not a statement about this object, so it is stubbed short.
    Every row of `currently_using` carries `reference_count: 0` on real
    hardware, including rows that are genuine references, which is reproduced
    here deliberately: summing that field reports zero for a referenced object.
    """
    return Response(
        {
            "results": {
                "can_use": [{"path": "firewall", "name": "addrgrp", "range": "vdom"}],
                "currently_using": rows,
                "q_types": [31],
            },
            "status": "success",
        }
    )


def reference(path: str, name: str, mkey: str, attribute: str = "srcaddr") -> dict:
    """One `currently_using` row, shaped as hardware returns it."""
    return {
        "path": path,
        "name": name,
        "reference_count": 0,
        "static": False,
        "table_type": "table",
        "mkey": mkey,
        "vdom": "root",
        "range": "vdom",
        "attribute": attribute,
    }


class FakeAppliance:
    """Routes each request path to a canned response by suffix match."""

    def __init__(self, routes: dict[str, Response], default: Response | None = None) -> None:
        self.routes = routes
        self.default = default
        self.requested: list[str] = []
        self.fortigate = SimpleNamespace(get=self._get, _session=None)

    def _get(self, path: str, *_args, **_kwargs) -> Response:
        self.requested.append(path)
        for suffix, response in self.routes.items():
            if suffix in path:
                return response
        if self.default is not None:
            return self.default
        raise AssertionError(f"unrouted path: {path}")

    def logout(self) -> None:
        pass


def references_for(
    object_name: str,
    routes: dict[str, Response],
    monkeypatch: pytest.MonkeyPatch,
    default: Response | None = None,
) -> tuple[dict, FakeAppliance]:
    """Call `find_references` against a fake appliance."""
    appliance = FakeAppliance(routes, default)

    @contextmanager
    def fake_connect(_target):
        yield appliance

    monkeypatch.setattr("mcfortigate.tools.firewall.connect", fake_connect)
    registry = TargetRegistry({"lab": FortiGateTarget(name="lab", host="fgt.example", token="x")})
    server = build_server(registry)
    raw = asyncio.run(server.call_tool("find_references", {"object_name": object_name}))
    return raw.structured_content, appliance


# An appliance whose five historically-scanned tables are all empty. Anything
# the tool concludes here comes from the usage endpoint alone.
EMPTY_TABLES = {
    "cmdb/firewall/address": table([]),
    "cmdb/firewall/policy": table([]),
    "cmdb/firewall/addrgrp": table([]),
    "cmdb/firewall.service/group": table([]),
    "cmdb/firewall/vip": table([]),
    "cmdb/router/static": table([]),
    "cmdb/firewall.service/custom": table([]),
    "cmdb/system/interface": table([]),
}


class TestReferencesOutsideTheScannedTables:
    """The undercount: a real reference living in one of the other 69 tables."""

    def test_a_web_proxy_reference_is_found(self, monkeypatch):
        """The case the five-table scan cannot see.

        Nothing in policies, groups, VIPs, or routes mentions this object. A
        web-proxy profile does. Before the usage endpoint was consulted this
        returned `no_references` with `safe_to_delete: true`.
        """
        routes = dict(EMPTY_TABLES)
        routes["cmdb/firewall/address"] = table([{"name": "PROXY_SRC", "subnet": "10.0.0.0 255.0.0.0"}])
        routes["monitor/system/object/usage"] = usage([reference("web-proxy", "profile", "default", "srcaddr")])

        result, _ = references_for("PROXY_SRC", routes, monkeypatch)
        assert result["verdict"] == "referenced"
        assert result.get("safe_to_delete") is not True

    def test_the_reference_is_described_not_just_counted(self, monkeypatch):
        """An operator needs to know where to go and remove it."""
        routes = dict(EMPTY_TABLES)
        routes["cmdb/firewall/address"] = table([{"name": "PROXY_SRC", "subnet": "10.0.0.0 255.0.0.0"}])
        routes["monitor/system/object/usage"] = usage([reference("web-proxy", "profile", "default", "srcaddr")])

        result, _ = references_for("PROXY_SRC", routes, monkeypatch)
        described = json.dumps(result)
        assert "web-proxy" in described and "profile" in described

    def test_reference_count_zero_is_not_treated_as_no_reference(self, monkeypatch):
        """Every hardware row carries `reference_count: 0`, references included.

        Summing that field instead of counting rows yields zero for an object
        the appliance just said is in use.
        """
        routes = dict(EMPTY_TABLES)
        routes["cmdb/firewall/address"] = table([{"name": "IN_USE", "subnet": "10.0.0.0 255.0.0.0"}])
        routes["monitor/system/object/usage"] = usage([reference("firewall", "policy", "7", "dstaddr")])

        result, _ = references_for("IN_USE", routes, monkeypatch)
        assert result["total_references"] > 0
        assert result["verdict"] == "referenced"


class TestObjectIdentity:
    """The wrong-table trap: an empty answer that is not about this object."""

    def test_a_name_that_exists_nowhere_is_not_safe_to_delete(self, monkeypatch):
        """A typo must not come back as a clean bill of health.

        Deleting a nonexistent object is harmless; believing you verified the
        object you meant to name is not.
        """
        routes = dict(EMPTY_TABLES)
        routes["cmdb/firewall/address"] = table([{"name": "REAL_NAME", "subnet": "10.0.0.0 255.0.0.0"}])
        routes["monitor/system/object/usage"] = usage([])

        result, _ = references_for("REEL_NAME", routes, monkeypatch)
        assert result["verdict"] == "object_not_found"
        assert "safe_to_delete" not in result

    def test_an_interface_is_looked_up_as_an_interface(self, monkeypatch):
        """The concrete wrong-table case, measured on hardware.

        `firewall/address` with `mkey=wan1` answers 200 and an empty list while
        `system/interface` with the same key reports two references. Asking only
        the address table reports an in-use interface as unreferenced.
        """
        routes = dict(EMPTY_TABLES)
        routes["cmdb/system/interface"] = table([{"name": "wan1", "ip": "0.0.0.0 0.0.0.0"}])

        # The appliance answers per q_name, exactly as hardware does: the
        # address table reports nothing for this key, the interface table
        # reports the truth. Asking only the first is the bug.
        class QueryAware(FakeAppliance):
            def _get(self, path: str, *_args, **_kwargs):
                self.requested.append(path)
                if "monitor/system/object/usage" in path:
                    if "q_name=interface" in path:
                        return usage([reference("firewall", "policy", "1", "srcintf")])
                    return usage([])
                for suffix, response in self.routes.items():
                    if suffix in path:
                        return response
                raise AssertionError(f"unrouted path: {path}")

        appliance = QueryAware(routes)

        @contextmanager
        def fake_connect(_target):
            yield appliance

        monkeypatch.setattr("mcfortigate.tools.firewall.connect", fake_connect)
        registry = TargetRegistry({"lab": FortiGateTarget(name="lab", host="fgt.example", token="x")})
        server = build_server(registry)
        result = asyncio.run(server.call_tool("find_references", {"object_name": "wan1"})).structured_content

        assert result["verdict"] == "referenced", (
            "an interface referenced by a policy was reported unreferenced, which means "
            "the usage endpoint was queried against the wrong table"
        )
        assert result.get("safe_to_delete") is not True


class TestTheTwoCountsDisagreeOnPurpose:
    """One object referenced twice by one policy, counted two ways.

    Measured on the lab: asking about `all` returns `total_references: 2`,
    because policy 1 uses it at both `srcaddr` and `dstaddr`, while `policies`
    holds a single entry annotated with both roles. Reading those side by side
    looks like a bug unless you know the authoritative list counts reference
    sites and the detail list counts objects.

    Pinned here because the obvious "fix" for the apparent discrepancy is to
    make one of them match the other, which would lose real information either
    way: collapsing sites hides that two fields must change, and expanding
    objects would list the same policy twice for an operator to open once.
    """

    def _both_roles(self, monkeypatch):
        routes = dict(EMPTY_TABLES)
        routes["cmdb/firewall/address"] = table([{"name": "ANY", "subnet": "0.0.0.0 0.0.0.0"}])
        routes["cmdb/firewall/policy"] = table(
            [
                {
                    "policyid": 1,
                    "name": "policy-1",
                    "status": "enable",
                    "action": "accept",
                    "srcaddr": [{"name": "ANY"}],
                    "dstaddr": [{"name": "ANY"}],
                    "service": [{"name": "ALL"}],
                    "srcintf": [{"name": "wan1"}],
                    "dstintf": [{"name": "lan"}],
                }
            ]
        )
        routes["monitor/system/object/usage"] = usage(
            [
                reference("firewall", "policy", "1", "srcaddr"),
                reference("firewall", "policy", "1", "dstaddr"),
            ]
        )
        return references_for("ANY", routes, monkeypatch)[0]

    def test_authoritative_list_counts_reference_sites(self, monkeypatch):
        """Two fields of one policy are two places that must change."""
        result = self._both_roles(monkeypatch)
        assert result["total_references"] == 2
        assert len(result["references"]) == 2
        assert {row["attribute"] for row in result["references"]} == {"srcaddr", "dstaddr"}

    def test_detail_list_counts_objects_and_names_both_roles(self, monkeypatch):
        """One policy is one thing to open, whatever number of fields it uses."""
        result = self._both_roles(monkeypatch)
        assert len(result["policies"]) == 1
        assert result["policies"][0]["referenced_as"] == ["source", "destination"]


class TestAuthorityOfTheVerdict:
    """`safe_to_delete: true` requires the authoritative source to have answered."""

    def test_clean_object_is_safe_when_usage_answered(self, monkeypatch):
        """The one case where a true is earned."""
        routes = dict(EMPTY_TABLES)
        routes["cmdb/firewall/address"] = table([{"name": "UNUSED", "subnet": "10.9.9.0 255.255.255.0"}])
        routes["monitor/system/object/usage"] = usage([])

        result, _ = references_for("UNUSED", routes, monkeypatch)
        assert result["verdict"] == "no_references"
        assert result["safe_to_delete"] is True

    def test_no_true_verdict_when_usage_is_denied(self, monkeypatch):
        """Without the authoritative source, a zero count covers five tables of 74.

        The five-table scan finding nothing is a fact about five tables. It was
        previously reported as `safe_to_delete: true`, which is a claim about
        the whole appliance.
        """
        routes = dict(EMPTY_TABLES)
        routes["cmdb/firewall/address"] = table([{"name": "UNUSED", "subnet": "10.9.9.0 255.255.255.0"}])
        routes["monitor/system/object/usage"] = Response({"status": "error"}, status_code=403)

        result, _ = references_for("UNUSED", routes, monkeypatch)
        assert result.get("safe_to_delete") is not True
        assert result["verdict"] != "no_references"

    def test_a_complete_scan_without_the_authority_says_so(self, monkeypatch):
        """The middle state, which was unreachable when first written.

        Every usage failure also lands in `sources_checked`, so a verdict that
        keyed on "anything unreadable" collapsed this case into `indeterminate`
        and left this branch dead. Sabotaging the safety rule changed no test
        result, which is how the dead branch was found.

        The distinction earns its place: here the four scanned tables were read
        in full and held nothing, which is worth more to an operator than a flat
        "could not determine", while still not licensing a delete.
        """
        routes = dict(EMPTY_TABLES)
        routes["cmdb/firewall/address"] = table([{"name": "UNUSED", "subnet": "10.9.9.0 255.255.255.0"}])
        routes["monitor/system/object/usage"] = Response({"status": "error"}, status_code=403)

        result, _ = references_for("UNUSED", routes, monkeypatch)
        assert result["verdict"] == "no_references_in_checked_scopes"
        assert "safe_to_delete" not in result

    def test_a_broken_scan_is_indeterminate(self, monkeypatch):
        """When the scan itself was incomplete, say the weaker thing."""
        routes = dict(EMPTY_TABLES)
        routes["cmdb/firewall/address"] = table([{"name": "UNUSED", "subnet": "10.9.9.0 255.255.255.0"}])
        routes["monitor/system/object/usage"] = Response({"status": "error"}, status_code=403)
        routes["cmdb/firewall/policy"] = Response({"status": "error"}, status_code=403)

        result, _ = references_for("UNUSED", routes, monkeypatch)
        assert result["verdict"] == "indeterminate"
        assert "safe_to_delete" not in result

    def test_denied_usage_is_named_in_the_response(self, monkeypatch):
        """Why the answer is weaker has to be visible, not inferred."""
        routes = dict(EMPTY_TABLES)
        routes["cmdb/firewall/address"] = table([{"name": "UNUSED", "subnet": "10.9.9.0 255.255.255.0"}])
        routes["monitor/system/object/usage"] = Response({"status": "error"}, status_code=403)

        result, _ = references_for("UNUSED", routes, monkeypatch)
        assert "object_usage" in result["sources_checked"]
        assert result["sources_checked"]["object_usage"] != "ok"


class ChainAppliance(FakeAppliance):
    """Answers the usage endpoint per object, the way hardware does.

    `FakeAppliance` returns one canned usage response for every query, which
    cannot represent a chain: the whole point of expansion is that asking about
    the group returns something different from asking about its member. This
    one dispatches on the `q_path` / `q_name` / `mkey` triple the tool actually
    sends, and records every triple so a test can assert what was *not* asked.
    """

    def __init__(self, routes, usage_map, default=None):
        super().__init__(routes, default)
        self.usage_map = usage_map
        self.usage_calls: list[tuple[str, str, str]] = []

    def _get(self, path: str, *_args, **_kwargs):
        self.requested.append(path)
        if "monitor/system/object/usage" in path:
            query = parse_qs(urlparse(path).query)
            key = (query["q_path"][0], query["q_name"][0], query["mkey"][0])
            self.usage_calls.append(key)
            answer = self.usage_map.get(key, [])
            return answer if isinstance(answer, Response) else usage(answer)
        for suffix, response in self.routes.items():
            if suffix in path:
                return response
        if self.default is not None:
            return self.default
        raise AssertionError(f"unrouted path: {path}")


def chain_references(
    object_name: str,
    routes: dict[str, Response],
    usage_map: dict[tuple[str, str, str], object],
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[dict, ChainAppliance]:
    """Call `find_references` against an appliance that answers per object."""
    appliance = ChainAppliance(routes, usage_map)

    @contextmanager
    def fake_connect(_target):
        yield appliance

    monkeypatch.setattr("mcfortigate.tools.firewall.connect", fake_connect)
    registry = TargetRegistry({"lab": FortiGateTarget(name="lab", host="fgt.example", token="x")})
    server = build_server(registry)
    raw = asyncio.run(server.call_tool("find_references", {"object_name": object_name}))
    return raw.structured_content, appliance


def transitive_tables(result: dict) -> set[tuple[str, str]]:
    """The (table, object) pairs reached only by expansion."""
    return {(row["table"], str(row["object"])) for row in result["transitive_references"]}


def direct_tables(result: dict) -> set[tuple[str, str]]:
    """The (table, object) pairs the appliance named directly."""
    return {(row["table"], str(row["object"])) for row in result["references"]}


class TestTransitiveExpansion:
    """The thing that breaks is the policy, not the group that hides it.

    `monitor/system/object/usage` reports the direct referrer only. Measured on
    the lab FortiWiFi-61E, 7.0.14: `internal1` is a port of the hardware switch
    `internal`, `internal` is a member of the software switch `lan`, and `lan`
    is policy 1's source interface. Asking the appliance about `internal1`
    returns exactly one row, `system.virtual-switch:internal`, and never
    mentions the policy. An operator told only that answer deletes the port and
    is surprised by which rule stops matching.
    """

    def test_a_policy_using_the_group_is_reported_for_the_member(self, monkeypatch):
        """The whole point: WEB01 is in WEB_SERVERS, and policy 12 uses WEB_SERVERS."""
        routes = dict(EMPTY_TABLES)
        routes["cmdb/firewall/address"] = table([{"name": "WEB01", "subnet": "192.0.2.10 255.255.255.255"}])
        routes["cmdb/firewall/addrgrp"] = table([{"name": "WEB_SERVERS", "member": [{"name": "WEB01"}]}])
        usage_map = {
            ("firewall", "address", "WEB01"): [reference("firewall", "addrgrp", "WEB_SERVERS", "member")],
            ("firewall", "addrgrp", "WEB_SERVERS"): [reference("firewall", "policy", "12", "srcaddr")],
        }

        result, _ = chain_references("WEB01", routes, usage_map, monkeypatch)
        assert result["verdict"] == "referenced"
        assert ("firewall.policy", "12") in transitive_tables(result), (
            "deleting WEB01 breaks policy 12, and the tool reported only the group"
        )

    def test_a_transitive_reference_is_never_shaped_like_a_direct_one(self, monkeypatch):
        """A reached-through reference that reads as direct is a worse lie than omitting it."""
        routes = dict(EMPTY_TABLES)
        routes["cmdb/firewall/address"] = table([{"name": "WEB01", "subnet": "192.0.2.10 255.255.255.255"}])
        routes["cmdb/firewall/addrgrp"] = table([{"name": "WEB_SERVERS", "member": [{"name": "WEB01"}]}])
        usage_map = {
            ("firewall", "address", "WEB01"): [reference("firewall", "addrgrp", "WEB_SERVERS", "member")],
            ("firewall", "addrgrp", "WEB_SERVERS"): [reference("firewall", "policy", "12", "srcaddr")],
        }

        result, _ = chain_references("WEB01", routes, usage_map, monkeypatch)
        assert direct_tables(result) == {("firewall.addrgrp", "WEB_SERVERS")}
        for row in result["references"]:
            assert row["depth"] == 0
            assert "via" not in row
        for row in result["transitive_references"]:
            assert row["depth"] >= 1
            assert row["via"] == ["WEB_SERVERS"]

    def test_the_measured_hardware_chain_reaches_the_policy(self, monkeypatch):
        """Reproduces the three-level chain the lab appliance actually has.

        `internal1` -> `system.virtual-switch:internal` -> `system.interface:lan`
        -> `firewall.policy:1[srcintf]`. The policy sits at depth two, which is
        why the cap is not one.
        """
        routes = dict(EMPTY_TABLES)
        routes["cmdb/system/interface"] = table(
            [{"name": "internal1"}, {"name": "internal"}, {"name": "lan"}],
        )
        usage_map = {
            ("system", "interface", "internal1"): [reference("system", "virtual-switch", "internal", "port")],
            ("system", "interface", "internal"): [reference("system", "interface", "lan", "member")],
            ("system", "interface", "lan"): [
                reference("system.dhcp", "server", "2", "id"),
                reference("firewall", "address", "lan", "name"),
                reference("firewall", "policy", "1", "srcintf"),
            ],
        }

        result, appliance = chain_references("internal1", routes, usage_map, monkeypatch)
        reached = {(row["table"], str(row["object"]), row["depth"]) for row in result["transitive_references"]}
        assert ("firewall.policy", "1", 2) in reached
        assert [row["via"] for row in result["transitive_references"] if row["object"] == "1"] == [
            ["internal", "lan"]
        ]

    def test_a_switch_port_is_re_queried_as_an_interface_not_a_virtual_switch(self, monkeypatch):
        """The measured trap: `system.virtual-switch` is the wrong table to ask next.

        Hardware, 7.0.14: `q_path=system&q_name=virtual-switch&mkey=internal`
        answers 200 with an empty list, while `q_name=interface` with the same
        key returns the membership that continues the chain. Deriving the next
        query from the referencing table's own name silently ends the walk.
        """
        routes = dict(EMPTY_TABLES)
        routes["cmdb/system/interface"] = table([{"name": "internal1"}, {"name": "internal"}])
        usage_map = {
            ("system", "interface", "internal1"): [reference("system", "virtual-switch", "internal", "port")],
            ("system", "interface", "internal"): [reference("firewall", "policy", "1", "srcintf")],
        }

        result, appliance = chain_references("internal1", routes, usage_map, monkeypatch)
        assert ("system", "virtual-switch", "internal") not in appliance.usage_calls
        assert ("system", "interface", "internal") in appliance.usage_calls
        assert ("firewall.policy", "1") in transitive_tables(result)

    def test_a_zone_stands_in_for_its_interfaces(self, monkeypatch):
        """Zones are the same shape as groups, one level up from the interface.

        Unverified against hardware: `cmdb/system/zone` exists on the lab's
        7.0.14 and answers 200, but the appliance has no zones configured, so
        this fixture is the documented shape rather than a recorded one.
        """
        routes = dict(EMPTY_TABLES)
        routes["cmdb/system/interface"] = table([{"name": "port5"}])
        usage_map = {
            ("system", "interface", "port5"): [reference("system", "zone", "TRUST", "interface")],
            ("system", "zone", "TRUST"): [reference("firewall", "policy", "3", "srcintf")],
        }

        result, _ = chain_references("port5", routes, usage_map, monkeypatch)
        assert ("firewall.policy", "3") in transitive_tables(result)
        assert [row["via"] for row in result["transitive_references"] if row["object"] == "3"] == [["TRUST"]]

    def test_a_vlan_naming_its_parent_is_not_a_container(self, monkeypatch):
        """The same table means two things depending on which field holds the reference.

        Measured on the lab: `wan1` is referenced by `system.interface` twice
        over across the appliance, once as `ssot_test_vlan1[name]`, which is a
        VLAN naming its parent, and once through `lan[member]`, which is a
        switch holding a port. Only the second stands in for the interface when
        a policy matches, so only the second is walked through. Keying the
        container table on its name alone conflates them and turns the walk
        into an unbounded dependency crawl.
        """
        routes = dict(EMPTY_TABLES)
        routes["cmdb/system/interface"] = table([{"name": "wan1"}, {"name": "ssot_test_vlan1"}])
        usage_map = {
            ("system", "interface", "wan1"): [reference("system", "interface", "ssot_test_vlan1", "name")],
            ("system", "interface", "ssot_test_vlan1"): [reference("firewall", "policy", "99", "srcintf")],
        }

        result, appliance = chain_references("wan1", routes, usage_map, monkeypatch)
        assert ("system", "interface", "ssot_test_vlan1") not in appliance.usage_calls
        assert result["transitive_references"] == []

    def test_nothing_to_expand_leaves_the_direct_answer_alone(self, monkeypatch):
        """An object referenced only by a policy has no container to walk through."""
        routes = dict(EMPTY_TABLES)
        routes["cmdb/firewall/address"] = table([{"name": "DIRECT", "subnet": "192.0.2.0 255.255.255.0"}])
        usage_map = {
            ("firewall", "address", "DIRECT"): [reference("firewall", "policy", "4", "dstaddr")],
        }

        result, _ = chain_references("DIRECT", routes, usage_map, monkeypatch)
        assert result["transitive_references"] == []
        assert result["expansion"]["status"] == "complete"
        assert direct_tables(result) == {("firewall.policy", "4")}


class TestExpansionTerminates:
    """FortiOS permits a group inside a group, so assume it permits a loop."""

    def test_a_cyclic_group_membership_terminates(self, monkeypatch):
        """LOOP_A is in LOOP_B and LOOP_B is in LOOP_A.

        Without a visited set this walks until the depth cap saves it, which
        looks like working code and reports a fabricated `depth_capped`. With
        one, each container is asked about exactly once and the answer is
        complete.
        """
        routes = dict(EMPTY_TABLES)
        routes["cmdb/firewall/addrgrp"] = table(
            [
                {"name": "LOOP_A", "member": [{"name": "LOOP_B"}]},
                {"name": "LOOP_B", "member": [{"name": "LOOP_A"}]},
            ]
        )
        usage_map = {
            ("firewall", "addrgrp", "LOOP_A"): [reference("firewall", "addrgrp", "LOOP_B", "member")],
            ("firewall", "addrgrp", "LOOP_B"): [reference("firewall", "addrgrp", "LOOP_A", "member")],
        }

        result, appliance = chain_references("LOOP_A", routes, usage_map, monkeypatch)
        assert appliance.usage_calls.count(("firewall", "addrgrp", "LOOP_B")) == 1
        assert appliance.usage_calls.count(("firewall", "addrgrp", "LOOP_A")) == 1
        assert result["expansion"]["status"] == "complete"
        assert result["verdict"] == "referenced"

    def test_a_self_referencing_group_is_asked_about_once(self, monkeypatch):
        """The degenerate loop, where the container is its own member."""
        routes = dict(EMPTY_TABLES)
        routes["cmdb/firewall/addrgrp"] = table([{"name": "SELF", "member": [{"name": "SELF"}]}])
        usage_map = {
            ("firewall", "addrgrp", "SELF"): [reference("firewall", "addrgrp", "SELF", "member")],
        }

        result, appliance = chain_references("SELF", routes, usage_map, monkeypatch)
        assert appliance.usage_calls.count(("firewall", "addrgrp", "SELF")) == 1
        assert result["expansion"]["status"] == "complete"


def _deep_chain(monkeypatch, links: int):
    """An object nested `links` groups deep, each group inside the next."""
    routes = dict(EMPTY_TABLES)
    routes["cmdb/firewall/address"] = table([{"name": "DEEP", "subnet": "192.0.2.1 255.255.255.255"}])
    usage_map: dict[tuple[str, str, str], object] = {
        ("firewall", "address", "DEEP"): [reference("firewall", "addrgrp", "G1", "member")],
    }
    for index in range(1, links):
        usage_map[("firewall", "addrgrp", f"G{index}")] = [
            reference("firewall", "addrgrp", f"G{index + 1}", "member")
        ]
    return chain_references("DEEP", routes, usage_map, monkeypatch)


class TestExpansionIsBounded:
    """Each level costs a REST call per container, so the walk has a ceiling."""

    def test_a_shallow_chain_completes(self, monkeypatch):
        """Two levels is inside the cap and must not be reported as truncated."""
        result, _ = _deep_chain(monkeypatch, links=3)
        assert result["expansion"]["status"] == "complete"
        assert "unexpanded" not in result["expansion"]

    def test_hitting_the_cap_is_reported_rather_than_hidden(self, monkeypatch):
        """A truncated walk that looks complete is the failure this tool exists to avoid."""
        result, _ = _deep_chain(monkeypatch, links=8)
        expansion = result["expansion"]
        assert expansion["status"] == "depth_capped"
        assert expansion["max_depth"] == MAX_EXPANSION_DEPTH
        assert expansion["unexpanded"], "the names we stopped at have to be nameable"
        assert "expansion" in result["note"].lower() or "deeper" in result["note"].lower()

    def test_the_cap_actually_stops_the_walk(self, monkeypatch):
        """Bounding the depth is the point; an unbounded walk would ask about all eight."""
        _, appliance = _deep_chain(monkeypatch, links=8)
        expanded = [call for call in appliance.usage_calls if call[1] == "addrgrp"]
        assert len(expanded) == MAX_EXPANSION_DEPTH

    def test_a_container_already_opened_is_not_reported_as_unopened(self, monkeypatch):
        """A loop landing on the frontier at the cap is not work left undone.

        `G3` is a member of both `G4` and, looping back, `G2`. When the walk
        stops, both sit on the frontier, but `G2` was opened two levels ago.
        Naming it as unexpanded invents missing work and overstates how much of
        the chain went unread, which pushes an operator to chase a container
        that has already been accounted for.
        """
        routes = dict(EMPTY_TABLES)
        routes["cmdb/firewall/address"] = table([{"name": "LOOPY", "subnet": "192.0.2.5 255.255.255.255"}])
        usage_map: dict[tuple[str, str, str], object] = {
            ("firewall", "address", "LOOPY"): [reference("firewall", "addrgrp", "G1", "member")],
            ("firewall", "addrgrp", "G1"): [reference("firewall", "addrgrp", "G2", "member")],
            ("firewall", "addrgrp", "G2"): [reference("firewall", "addrgrp", "G3", "member")],
            ("firewall", "addrgrp", "G3"): [
                reference("firewall", "addrgrp", "G4", "member"),
                reference("firewall", "addrgrp", "G2", "member"),
            ],
        }

        result, _ = chain_references("LOOPY", routes, usage_map, monkeypatch)
        assert result["expansion"]["status"] == "depth_capped"
        assert result["expansion"]["unexpanded"] == ["G4"]

    def test_a_capped_expansion_never_claims_safe_to_delete(self, monkeypatch):
        """The invariant, pinned even though it currently holds by construction.

        There is nothing to expand through unless the direct lookup already
        found a container, and a direct hit forces `referenced`, so truncation
        and `safe_to_delete: true` cannot coexist. That is worth an assertion
        rather than a guard: a guard no input can reach reports as covered
        while proving nothing, which is how a dead branch got into this very
        tool's verdict logic once already.
        """
        result, _ = _deep_chain(monkeypatch, links=8)
        assert result["expansion"]["status"] == "depth_capped"
        assert result.get("safe_to_delete") is not True
        assert result["verdict"] == "referenced"


class TestExpansionFailures:
    """A container we could not read is a hole in the blast radius."""

    def test_a_denied_expansion_lookup_is_named(self, monkeypatch):
        """The group answered; what the group is used by did not."""
        routes = dict(EMPTY_TABLES)
        routes["cmdb/firewall/address"] = table([{"name": "WEB01", "subnet": "192.0.2.10 255.255.255.255"}])
        routes["cmdb/firewall/addrgrp"] = table([{"name": "WEB_SERVERS", "member": [{"name": "WEB01"}]}])
        usage_map = {
            ("firewall", "address", "WEB01"): [reference("firewall", "addrgrp", "WEB_SERVERS", "member")],
            ("firewall", "addrgrp", "WEB_SERVERS"): Response({"status": "error"}, status_code=403),
        }

        result, _ = chain_references("WEB01", routes, usage_map, monkeypatch)
        assert result["expansion"]["status"] == "incomplete"
        assert "WEB_SERVERS" in result["sources_checked"]["object_usage_expansion"]
        assert result.get("safe_to_delete") is not True

    def test_an_incomplete_direct_lookup_makes_the_expansion_incomplete(self, monkeypatch):
        """Expanding from a lower bound produces a lower bound.

        The tool sweeps every candidate kind when it cannot identify the
        object. If one of those sweeps is denied, the containers it would have
        named are unknown, so the walk that follows cannot be called complete
        no matter how cleanly it ran.
        """
        routes = dict(EMPTY_TABLES)
        # Denying the address table leaves the kind unidentified, so every kind
        # is swept and the denied sweep makes the seed set partial.
        routes["cmdb/firewall/address"] = Response({"status": "error"}, status_code=403)
        usage_map: dict[tuple[str, str, str], object] = {
            ("firewall", "address", "MYSTERY"): Response({"status": "error"}, status_code=403),
            ("firewall", "addrgrp", "MYSTERY"): [reference("firewall", "policy", "9", "srcaddr")],
        }

        result, _ = chain_references("MYSTERY", routes, usage_map, monkeypatch)
        assert result["expansion"]["status"] == "incomplete"
