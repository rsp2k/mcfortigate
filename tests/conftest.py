"""Serving the hardware-captured fixtures to the tools.

`tests/fixtures/` holds payloads recorded from a FortiWiFi-61E on FortiOS
7.0.14 by `scripts/capture_fixtures.py`, sanitized but otherwise byte for byte
what the appliance sent. What this module adds is an appliance that answers from
them, so a tool body can be executed against a real response shape rather than
against one somebody wrote down.

The routing table is built from the fixtures' own manifest rather than from a
list kept here, so a renamed endpoint or a fixture captured under a new name
cannot quietly stop being served. An unrouted path raises instead of returning
an empty result, because a silently empty answer is the failure mode this whole
package exists to prevent.
"""

from __future__ import annotations

import asyncio
import json
from contextlib import contextmanager
from copy import deepcopy
from functools import cache
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from urllib.parse import parse_qs, urlsplit

import pytest

from mcfortigate.config import FortiGateTarget, TargetRegistry
from mcfortigate.server import build_server

FIXTURE_DIR = Path(__file__).parent / "fixtures"

#: Tool modules whose `connect` has to be redirected at the fixture appliance.
TOOL_MODULES = ("firewall", "network", "live", "meta")


@cache
def _read(name: str) -> dict[str, Any]:
    """Read one fixture file, cached because the suite reads them repeatedly."""
    path = FIXTURE_DIR / f"{name}.json"
    if not path.is_file():
        raise AssertionError(f"missing fixture {name!r}; re-run scripts/capture_fixtures.py")
    return json.loads(path.read_text())


def fixture_payload(name: str) -> dict[str, Any]:
    """Return a private copy of one captured payload."""
    return deepcopy(_read(name))


def manifest() -> dict[str, Any]:
    """Return the capture manifest: which fixture came from which endpoint."""
    return _read("manifest")


class Response:
    """The parts of a requests.Response the fetch helpers touch."""

    def __init__(self, body: dict[str, Any], status_code: int = 200) -> None:
        """Hold a body and the status the appliance answered with."""
        self.status_code = status_code
        self._body = body
        self.text = json.dumps(body)

    def json(self) -> dict[str, Any]:
        """Return the parsed body."""
        return self._body


class FixtureAppliance:
    """A FortiGate that answers every read out of the captured fixtures.

    `overrides` replaces the answer for one endpoint, which is how a test asks
    what a tool does when a single real table is refused while the rest of the
    appliance keeps answering its genuine shapes.
    """

    def __init__(self, overrides: dict[str, Response] | None = None) -> None:
        """Build the routing table from the manifest, then apply any overrides."""
        self.requested: list[str] = []
        self.overrides = overrides or {}
        self._by_endpoint: dict[str, str] = {}
        self._by_query: dict[tuple[str, str, str], str] = {}
        for name, entry in manifest()["fixtures"].items():
            query = entry.get("query")
            if query:
                self._by_query[(query["q_path"], query["q_name"], query["mkey"])] = name
            else:
                self._by_endpoint[entry["endpoint"]] = name
        self.fortigate = SimpleNamespace(get=self._get, _session=None)

    def _get(self, path: str, *_args: Any, **_kwargs: Any) -> Response:
        self.requested.append(path)
        endpoint, _, _ = path.partition("?")
        if endpoint in self.overrides:
            return self.overrides[endpoint]
        query = parse_qs(urlsplit(path).query)
        if query:
            key = (query.get("q_path", [""])[0], query.get("q_name", [""])[0], query.get("mkey", [""])[0])
            name = self._by_query.get(key)
            if name is None:
                raise AssertionError(
                    f"no captured object-usage answer for {key}; add it to USAGE_PROBES in "
                    "scripts/capture_fixtures.py and re-capture"
                )
            return Response(fixture_payload(name))
        name = self._by_endpoint.get(endpoint)
        if name is None:
            raise AssertionError(f"unrouted path {path!r}; no fixture was captured for it")
        return Response(fixture_payload(name))

    def logout(self) -> None:
        """Match the library's interface; nothing to tear down."""


def _server_for(appliance: FixtureAppliance, monkeypatch: pytest.MonkeyPatch):
    """Build a server whose every tool talks to the supplied appliance."""

    @contextmanager
    def fake_connect(_target):
        yield appliance

    for module in TOOL_MODULES:
        monkeypatch.setattr(f"mcfortigate.tools.{module}.connect", fake_connect)
    registry = TargetRegistry({"lab": FortiGateTarget(name="lab", host="fgt.example", token="x")})
    return build_server(registry)


@pytest.fixture
def hardware_appliance() -> FixtureAppliance:
    """An appliance answering from the captured FortiOS 7.0.14 payloads."""
    return FixtureAppliance()


@pytest.fixture
def hardware_server(hardware_appliance: FixtureAppliance, monkeypatch: pytest.MonkeyPatch):
    """A server backed by the captured payloads."""
    return _server_for(hardware_appliance, monkeypatch)


def _caller(server):
    """Return a function that calls one tool and unwraps whatever FastMCP returned.

    FastMCP has moved the payload between a bare attribute and a content-block
    wrapper across releases, so all the shapes are tried rather than pinning one.
    """

    def call(name: str, arguments: dict[str, Any] | None = None) -> Any:
        raw = asyncio.run(server.call_tool(name, arguments or {}))
        for attribute in ("data", "structured_content", "structuredContent"):
            value = getattr(raw, attribute, None)
            if isinstance(value, (dict, list)):
                return value
        content = getattr(raw, "content", None)
        if content and getattr(content[0], "text", None):
            return json.loads(content[0].text)
        return raw

    return call


@pytest.fixture
def hardware_tool(hardware_server):
    """Call a tool against the captured payloads and return its response."""
    return _caller(hardware_server)


@pytest.fixture
def degraded_tool(monkeypatch: pytest.MonkeyPatch):
    """Call a tool with one real endpoint replaced by a failure response."""

    def build(overrides: dict[str, Response]):
        return _caller(_server_for(FixtureAppliance(overrides), monkeypatch))

    return build
