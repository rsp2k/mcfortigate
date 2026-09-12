"""What `get_system_status` may and may not claim about an appliance.

Every payload here was captured from a FortiWiFi-61E running FortiOS 7.0.14
rather than written from the documentation, because the thing these tests guard
against is exactly the gap between the two. The tool's docstring promised uptime
for weeks. Hardware then showed that `monitor/system/status`,
`monitor/system/resource/usage`, and `monitor/system/time` between them do not
carry an uptime figure on that firmware at all, so the field was structurally
null on every call and no test noticed, because no test had ever seen a real
response.

The rule these tests enforce: a field is present when the appliance reported it
and absent when it did not, and no reading is dropped merely for being zero.
"""

from __future__ import annotations

import asyncio
import json
from contextlib import contextmanager
from types import SimpleNamespace

import pytest

from mcfortigate.config import FortiGateTarget, TargetRegistry
from mcfortigate.server import build_server

# Captured from the lab appliance. `system/global` results are trimmed to the
# fields the tool reads; the envelope siblings are reproduced in full because
# their placement outside `results` is the whole point of reading the envelope.
SYSTEM_GLOBAL_BODY = {
    "http_method": "GET",
    "revision": "abc",
    "results": {"hostname": "FortiWiFi-61E", "alias": "FortiWiFi-61E", "timezone": "04"},
    "vdom": "root",
    "path": "system",
    "name": "global",
    "status": "success",
    "serial": "FWF61E0000000000",
    "version": "v7.0.14",
    "build": 601,
}

# Note what is not here: no `uptime`, under any spelling.
SYSTEM_STATUS_BODY = {
    "results": {
        "hostname": "FortiWiFi-61E",
        "log_disk_status": "available",
        "model": "FortiWiFi",
        "model_name": "FortiWiFi",
        "model_number": "61E",
    },
    "status": "success",
}

# The resource series shape: every metric is a list of samples, and the current
# reading is the `current` key of the first one. An idle appliance reports a
# genuine zero here, which is the case the `is not None` filter exists for.
RESOURCE_USAGE_BODY = {
    "results": {
        "cpu": [{"current": 0}],
        "mem": [{"current": 37}],
        "session": [{"current": 16}],
        "disk": [{"current": 3}],
    },
    "status": "success",
}


class Response:
    """The parts of a requests.Response that the fetch helpers touch."""

    def __init__(self, body: dict, status_code: int = 200) -> None:
        self.status_code = status_code
        self._body = body
        self.text = json.dumps(body)

    def json(self) -> dict:
        return self._body


class FakeAppliance:
    """Answers each path from a routing table, so an unrouted path is loud."""

    def __init__(self, routes: dict[str, Response]) -> None:
        self.routes = routes
        self.requested: list[str] = []
        self.fortigate = SimpleNamespace(get=self._get, _session=None)

    def _get(self, path: str, *_args, **_kwargs) -> Response:
        self.requested.append(path)
        for suffix, response in self.routes.items():
            if path.endswith(suffix):
                return response
        raise AssertionError(f"unrouted path: {path}")

    def logout(self) -> None:
        pass


def build(routes: dict[str, Response], monkeypatch: pytest.MonkeyPatch):
    """A server whose meta tools talk to the supplied fake appliance."""
    appliance = FakeAppliance(routes)

    @contextmanager
    def fake_connect(_target):
        yield appliance

    monkeypatch.setattr("mcfortigate.tools.meta.connect", fake_connect)
    registry = TargetRegistry({"lab": FortiGateTarget(name="lab", host="fgt.example", token="x")})
    return build_server(registry), appliance


def status_of(routes: dict[str, Response], monkeypatch: pytest.MonkeyPatch) -> dict:
    """Call `get_system_status` against a fake appliance and return its payload."""
    server, _ = build(routes, monkeypatch)
    raw = asyncio.run(server.call_tool("get_system_status", {}))
    return raw.structured_content


HEALTHY = {
    "cmdb/system/global": Response(SYSTEM_GLOBAL_BODY),
    "monitor/system/status": Response(SYSTEM_STATUS_BODY),
    "monitor/system/resource/usage": Response(RESOURCE_USAGE_BODY),
}


class TestAgainstRealFirmware:
    """The 7.0.14 shapes, byte for byte as hardware returned them."""

    def test_identity_comes_from_the_envelope(self, monkeypatch):
        """Serial, version, and build are siblings of `results`, not inside it."""
        result = status_of(HEALTHY, monkeypatch)
        assert result["serial"] == "FWF61E0000000000"
        assert result["version"] == "v7.0.14"
        assert result["build"] == 601

    def test_model_is_reported(self, monkeypatch):
        """The tool promised a model and for a while silently discarded one."""
        assert status_of(HEALTHY, monkeypatch)["model"] == "FortiWiFi"

    def test_a_zero_reading_survives(self, monkeypatch):
        """An idle CPU reads 0, and 0 is a measurement rather than a missing one.

        Filtering the optional fields on truthiness instead of `is not None`
        passes every other test in this file and drops this one value, which is
        why it gets a test of its own.
        """
        result = status_of(HEALTHY, monkeypatch)
        assert result["cpu_percent"] == 0, "a genuine zero reading was dropped as though absent"

    def test_uptime_is_omitted_rather_than_null(self, monkeypatch):
        """7.0.14 reports no uptime, so the key must not appear at all.

        A null here would read to a model as "the appliance has no uptime",
        which is a claim about the hardware rather than about our coverage.
        """
        assert "uptime_seconds" not in status_of(HEALTHY, monkeypatch)

    def test_uptime_is_reported_when_the_firmware_offers_it(self, monkeypatch):
        """The other half of the contract, and the half that nearly went missing.

        Deleting the uptime lookup outright left every other test in this file
        green, because they all run against a firmware that reports no uptime.
        Absence-only assertions cannot distinguish "the appliance did not say"
        from "we never asked", so one firmware that does say is required.
        """
        routes = dict(HEALTHY)
        routes["monitor/system/status"] = Response(
            {"results": dict(SYSTEM_STATUS_BODY["results"], uptime=98765), "status": "success"}
        )
        assert status_of(routes, monkeypatch)["uptime_seconds"] == 98765


class TestDegradedReads:
    """What the tool says when part of the appliance will not answer."""

    def test_denied_usage_still_yields_identity(self, monkeypatch):
        """Losing the load figures must not cost us the serial."""
        routes = dict(HEALTHY)
        routes["monitor/system/resource/usage"] = Response({"status": "error"}, status_code=403)
        result = status_of(routes, monkeypatch)
        assert result["serial"] == "FWF61E0000000000"
        assert "cpu_percent" not in result

    def test_denied_usage_is_named(self, monkeypatch):
        """An absent metric has two causes and the response has to say which.

        Without this the answer is identical whether the firmware lacks the
        endpoint or the token was refused it.
        """
        routes = dict(HEALTHY)
        routes["monitor/system/resource/usage"] = Response({"status": "error"}, status_code=403)
        assert "denied" in status_of(routes, monkeypatch)["load_status"]

    def test_unsupported_usage_is_not_flagged(self, monkeypatch):
        """A firmware that lacks the endpoint is a fact, not a fault.

        `usable` covers `unsupported` precisely so the tool degrades quietly
        when the platform genuinely has nothing to report.
        """
        routes = dict(HEALTHY)
        routes["monitor/system/resource/usage"] = Response({}, status_code=404)
        result = status_of(routes, monkeypatch)
        assert "load_status" not in result
        assert "cpu_percent" not in result

    def test_denied_monitor_status_still_yields_identity(self, monkeypatch):
        """The cmdb envelope alone carries enough to identify the appliance."""
        routes = dict(HEALTHY)
        routes["monitor/system/status"] = Response({"status": "error"}, status_code=403)
        result = status_of(routes, monkeypatch)
        assert result["serial"] == "FWF61E0000000000"
        assert result["hostname"] == "FortiWiFi-61E"  # falls back to cmdb
        assert "denied" in result["runtime_status"]
        assert result["model"] is None
