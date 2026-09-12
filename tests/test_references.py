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

import pytest

from mcfortigate.config import FortiGateTarget, TargetRegistry
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
