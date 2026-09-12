"""The denial scenario: what happens when the token cannot see what it checks.

This is the most important test in the suite, and it was written before the fix
it describes, watched to fail, and only then made to pass.

The setup it models is not exotic, it is the recommended one. A FortiGate REST
API admin is bound to an access profile with per-group permissions and to a
trusted-host list. A token scoped to firewall objects returns 403 on
`router/static` and `system/interface`. A token used from an address outside its
trusted-host list returns 403 on everything. Both are likely first-contact
outcomes, and both are what doing security correctly looks like.

What makes that dangerous here is the client library. `Connector.get()` does
`if not response.ok: return []`, so every 401, 403, 404, and 500 arrives as an
empty list with no exception and no status. A tool that counts references then
counts zero of them and reports that the object is safe to delete.

The rule these tests enforce: an answer derived from a table we could not read
is never presented as a clean bill of health.
"""

from __future__ import annotations

import asyncio
import json
from types import SimpleNamespace

import pytest

from mcfortigate.config import FortiGateTarget, TargetRegistry
from mcfortigate.server import build_server


class DeniedResponse:
    """An HTTP 403 carrying a FortiOS error body."""

    status_code = 403
    text = '{"status":"error","error":-37}'

    def json(self) -> dict:
        return {"status": "error", "error": -37, "http_status": 403}


class _SwallowsEverything:
    """Stands in for a `Connector` whose every read was denied.

    Mirrors the library faithfully: attribute access chains to any depth and
    `.get()` returns an empty list, which is precisely what the real
    `Connector.get()` does when the appliance answers 403.
    """

    def __getattr__(self, _name: str) -> _SwallowsEverything:
        return _SwallowsEverything()

    def get(self, *_args, **_kwargs) -> list:
        return []


class DenyingAPI:
    """A FortiGate that answers 403 to everything.

    Exposes both access styles on purpose. Reads through `cmdb` come back empty
    exactly as the library returns them, while reads through `fortigate.get`
    expose the real status. A tool that takes the first path cannot tell denial
    from emptiness; one that takes the second can.
    """

    def __init__(self) -> None:
        self.cmdb = _SwallowsEverything()
        self.fortigate = SimpleNamespace(
            get=lambda *_args, **_kwargs: DeniedResponse(),
            get_results=lambda *_args, **_kwargs: [],
        )


@pytest.fixture
def denied_server(monkeypatch: pytest.MonkeyPatch):
    """A server whose every FortiGate read is refused."""
    from contextlib import contextmanager

    @contextmanager
    def fake_connect(_target):
        yield DenyingAPI()

    for module in ("firewall", "network", "live", "meta"):
        monkeypatch.setattr(f"mcfortigate.tools.{module}.connect", fake_connect, raising=False)

    registry = TargetRegistry({"lab": FortiGateTarget(name="lab", host="fgt.example", token="x")})
    return build_server(registry)


def call(server, name: str, arguments: dict | None = None):
    """Invoke a tool and return its payload, or the raised exception."""
    try:
        raw = asyncio.run(server.call_tool(name, arguments or {}))
    except Exception as exc:  # noqa: BLE001 - an exception is a valid outcome here
        return exc
    for attribute in ("data", "structured_content", "structuredContent"):
        value = getattr(raw, attribute, None)
        if isinstance(value, (dict, list)):
            return value
    content = getattr(raw, "content", None)
    if content and getattr(content[0], "text", None):
        try:
            return json.loads(content[0].text)
        except json.JSONDecodeError:
            return content[0].text
    return raw


class TestFindReferencesUnderDenial:
    """The verdict must never read as safe when the sources were unreadable."""

    def test_does_not_claim_safe_to_delete(self, denied_server):
        """The bug this whole file exists for.

        Before the fix this returned `safe_to_delete: true`, byte for byte
        identical to a genuine no-references answer, for an object that might be
        referenced by every policy on the appliance.
        """
        result = call(denied_server, "find_references", {"object_name": "WEB"})
        if isinstance(result, Exception):
            return  # failing loudly is an acceptable outcome
        assert result.get("safe_to_delete") is not True, (
            "find_references reported safe_to_delete=true while every source was denied"
        )

    def test_reports_an_indeterminate_verdict(self, denied_server):
        """A denied read has to be visible in the answer, not inferred from silence."""
        result = call(denied_server, "find_references", {"object_name": "WEB"})
        if isinstance(result, Exception):
            return
        assert result.get("verdict") == "indeterminate"

    def test_omits_the_boolean_entirely_when_undecidable(self, denied_server):
        """Absent beats false.

        A model reading `safe_to_delete: false` stops there. A model reading a
        missing key has to look at the neighbouring fields to answer at all,
        which is the behavior we want when the truth is unknown.
        """
        result = call(denied_server, "find_references", {"object_name": "WEB"})
        if isinstance(result, Exception):
            return
        assert "safe_to_delete" not in result

    def test_names_which_sources_failed(self, denied_server):
        """The operator needs to know which permission to widen."""
        result = call(denied_server, "find_references", {"object_name": "WEB"})
        if isinstance(result, Exception):
            return
        sources = result.get("sources_checked")
        assert isinstance(sources, dict) and sources
        assert not any(status == "ok" for status in sources.values())
        assert any("403" in str(status) for status in sources.values())


class TestListingToolsUnderDenial:
    """A denied listing must not render as an empty appliance."""

    @pytest.mark.parametrize(
        ("tool", "collection"),
        [
            ("list_address_objects", "addresses"),
            ("list_policies", "policies"),
            ("list_services", "services"),
            ("list_interfaces", "interfaces"),
            ("list_static_routes", "routes"),
        ],
    )
    def test_denial_is_not_reported_as_empty(self, denied_server, tool: str, collection: str):
        """Answering "there are none" to "I could not look" is the core defect."""
        result = call(denied_server, tool, {})
        if isinstance(result, Exception):
            return
        assert result.get(collection) != [] or result.get("error"), (
            f"{tool} reported an empty {collection} list while the read was denied"
        )


class TestSearchUnderDenial:
    """A search that could read nothing must not report nothing found.

    Unlike the listing tools, search aggregates several sources and so keeps
    going when one refuses. That makes a zero count legitimate output, and the
    obligation becomes labelling it: the response must say the search was
    incomplete rather than presenting zero as a finished answer.
    """

    def test_no_matches_is_not_presented_as_a_clean_search(self, denied_server):
        result = call(denied_server, "search_config", {"term": "lan"})
        if isinstance(result, Exception):
            return
        assert result.get("total_matches") != 0 or result.get("warning") or result.get("error"), (
            "search_config reported zero matches with no indication the search could not read anything"
        )

    def test_names_which_sources_failed(self, denied_server):
        result = call(denied_server, "search_config", {"term": "lan"})
        if isinstance(result, Exception):
            return
        sources = result.get("sources_checked")
        assert isinstance(sources, dict) and sources
        assert any("403" in str(status) for status in sources.values())
