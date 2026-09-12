"""Tests for the connection and read layer.

This module had no direct tests at all when the review ran, which was awkward
given that it is the boundary where the client library's defects have to be
contained. Everything below is a containment check.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from mcfortigate.client import fetch_envelope, fetch_monitor, fetch_table
from mcfortigate.fortios import FortiOSError


class Response:
    """A stand-in for a requests.Response."""

    def __init__(self, status_code: int, body=None, text: str = ""):
        self.status_code = status_code
        self._body = body
        self.text = text

    def json(self):
        if self._body is None:
            raise ValueError("not json")
        return self._body


def api_returning(response) -> SimpleNamespace:
    """A fake API whose raw get returns this response."""
    return SimpleNamespace(fortigate=SimpleNamespace(get=lambda *_a, **_k: response))


def api_raising(exc: Exception) -> SimpleNamespace:
    """A fake API whose raw get raises."""

    def _raise(*_args, **_kwargs):
        raise exc

    return SimpleNamespace(fortigate=SimpleNamespace(get=_raise))


class TestFetchTable:
    """Every cmdb read must raise on a bad status rather than return nothing.

    The library's own connector does `if not response.ok: return []`, which
    makes a denied read indistinguishable from an empty table. These tests
    guard the replacement.
    """

    def test_returns_rows_on_success(self):
        api = api_returning(Response(200, {"results": [{"name": "A"}, {"name": "B"}]}))
        assert fetch_table(api, "api/v2/cmdb/firewall/address") == [{"name": "A"}, {"name": "B"}]

    @pytest.mark.parametrize("status", [401, 403, 404, 424, 500])
    def test_raises_on_any_error_status(self, status: int):
        api = api_returning(Response(status, {"status": "error", "error": -37}))
        with pytest.raises(FortiOSError):
            fetch_table(api, "api/v2/cmdb/firewall/policy")

    def test_error_carries_status_and_code_for_reporting(self):
        """Callers summarizing a partial failure should not parse message text."""
        api = api_returning(Response(403, {"status": "error", "error": -37}))
        with pytest.raises(FortiOSError) as exc:
            fetch_table(api, "api/v2/cmdb/firewall/policy")
        assert exc.value.http_status == 403
        assert exc.value.error_code == -37
        assert "denied" in exc.value.summary()

    def test_genuinely_empty_table_is_still_empty(self):
        """The fix must not turn a real empty table into an error."""
        api = api_returning(Response(200, {"results": []}))
        assert fetch_table(api, "api/v2/cmdb/firewall/vip") == []

    def test_object_shaped_results_become_one_row(self):
        """Singular endpoints return an object where tables return a list.

        The library coerces with `list()`, which on an object yields its keys as
        strings and so silently discards the record.
        """
        api = api_returning(Response(200, {"results": {"hostname": "fgt"}}))
        assert fetch_table(api, "api/v2/cmdb/system/global") == [{"hostname": "fgt"}]

    def test_non_dict_rows_are_dropped(self):
        api = api_returning(Response(200, {"results": [{"name": "A"}, "junk", 7]}))
        assert fetch_table(api, "api/v2/cmdb/firewall/address") == [{"name": "A"}]


class TestFetchEnvelope:
    """Identity fields live beside `results`, not inside it."""

    def test_exposes_serial_and_version(self):
        api = api_returning(
            Response(200, {"serial": "FGT-TEST", "version": "v7.0.14", "build": 601, "results": {"hostname": "fgt"}})
        )
        envelope = fetch_envelope(api, "api/v2/cmdb/system/global")
        assert envelope["serial"] == "FGT-TEST"
        assert envelope["results"]["hostname"] == "fgt"

    def test_raises_on_error_status(self):
        api = api_returning(Response(403, {"status": "error", "error": -37}))
        with pytest.raises(FortiOSError):
            fetch_envelope(api, "api/v2/cmdb/system/global")


class TestFetchMonitor:
    """Absence and denial must stay distinguishable.

    A FortiGate with no radio has no wireless endpoint, and degrading around
    that is correct. A FortiGate that refused the read is a permissions problem.
    Returning a bare list for both makes the second invisible.
    """

    def test_ok_carries_rows(self):
        result = fetch_monitor(api_returning(Response(200, {"results": [{"mac": "aa"}]})), "api/v2/monitor/wifi/client")
        assert result.status == "ok"
        assert result.ok and result.usable
        assert result.rows == [{"mac": "aa"}]

    @pytest.mark.parametrize("status", [404, 405])
    def test_missing_endpoint_is_unsupported_and_usable(self, status: int):
        """Hardware that lacks a feature is a fact, not a failure."""
        result = fetch_monitor(api_returning(Response(status)), "api/v2/monitor/wifi/client")
        assert result.status == "unsupported"
        assert result.usable and not result.ok

    @pytest.mark.parametrize("status", [401, 403])
    def test_denied_is_not_usable(self, status: int):
        """The distinction the whole class exists for."""
        result = fetch_monitor(api_returning(Response(status)), "api/v2/monitor/system/dhcp")
        assert result.status == "denied"
        assert not result.usable
        assert "denied" in result.describe()

    def test_transport_failure_is_an_error(self):
        result = fetch_monitor(api_raising(ConnectionError("no route")), "api/v2/monitor/network/arp")
        assert result.status == "error"
        assert not result.usable

    def test_object_shaped_results_become_one_row(self):
        """monitor/system/status returns an object, which is why uptime was always null."""
        api = api_returning(Response(200, {"results": {"uptime": 12345}}))
        result = fetch_monitor(api, "api/v2/monitor/system/status")
        assert result.rows == [{"uptime": 12345}]

    def test_unparseable_body_is_an_error_not_an_empty_ok(self):
        result = fetch_monitor(api_returning(Response(200, None)), "api/v2/monitor/wifi/client")
        assert result.status == "error"


class RecordingSession:
    """A requests.Session stand-in that remembers whether it was closed."""

    def __init__(self) -> None:
        self.closed = 0
        self.close_raises: Exception | None = None

    def close(self) -> None:
        self.closed += 1
        if self.close_raises is not None:
            raise self.close_raises


class FakeFortiGate:
    """The library's FortiGate connector, faithful on the points that matter.

    Two behaviours are reproduced exactly because `connect` depends on them.
    `logout()` drops its reference to the session without closing it, so
    anything that reads `_session` after logout sees None and closes nothing.
    And the session is created lazily, so a constructed object owns no socket.
    """

    def __init__(self, vdom: str = "root") -> None:
        self._session: RecordingSession | None = None
        self.vdom = vdom
        self.logout_calls = 0
        self.logout_raises: Exception | None = None

    def logout(self) -> None:
        self.logout_calls += 1
        if self.logout_raises is not None:
            self._session = None
            raise self.logout_raises
        self._session = None


class FakeAPI:
    """Stands in for FortiGateAPI."""

    def __init__(self, vdom: str = "root") -> None:
        self.fortigate = FakeFortiGate(vdom)

    def logout(self) -> None:
        self.fortigate.logout()


@pytest.fixture
def token_target():
    from mcfortigate.config import FortiGateTarget

    return FortiGateTarget(name="lab", host="fgt.example", token="t", verify_ssl=False, timeout=5)


def patched_connect(monkeypatch, api: FakeAPI, session: RecordingSession):
    """Point `connect` at fakes for both the constructor and the token login."""
    monkeypatch.setattr("mcfortigate.client.FortiGateAPI", lambda **_kwargs: api)
    monkeypatch.setattr("mcfortigate.client._token_session", lambda _target: session)


class TestConnectTeardown:
    """M7. Every exit path must end with the socket closed and the answer intact.

    The two mistakes this guards are specific. Reading `_session` after
    `logout()` finds None, because the library nulls the attribute without
    closing it, so the session has to be captured first or it leaks on every
    call. And a logout that fails must not turn a completed read into an
    exception, because by then the caller already has its answer.
    """

    def test_session_is_closed_on_the_normal_path(self, monkeypatch, token_target):
        from mcfortigate.client import connect

        api, session = FakeAPI(), RecordingSession()
        patched_connect(monkeypatch, api, session)
        with connect(token_target) as opened:
            assert opened is api
        assert session.closed == 1
        assert api.fortigate.logout_calls == 1

    def test_session_is_closed_when_the_body_raises(self, monkeypatch, token_target):
        from mcfortigate.client import connect

        api, session = FakeAPI(), RecordingSession()
        patched_connect(monkeypatch, api, session)
        with pytest.raises(RuntimeError, match="tool blew up"), connect(token_target):
            raise RuntimeError("tool blew up")
        assert session.closed == 1

    def test_a_failing_logout_cannot_destroy_a_good_answer(self, monkeypatch, token_target):
        """The guard the review asked about, exercised rather than asserted."""
        from mcfortigate.client import connect

        api, session = FakeAPI(), RecordingSession()
        api.fortigate.logout_raises = ConnectionError("appliance went away")
        patched_connect(monkeypatch, api, session)
        answer = None
        with connect(token_target):
            answer = "the rows the caller already has"
        assert answer == "the rows the caller already has"

    def test_a_failing_logout_still_closes_the_session(self, monkeypatch, token_target):
        """Swallowing the logout error must not also swallow the cleanup."""
        from mcfortigate.client import connect

        api, session = FakeAPI(), RecordingSession()
        api.fortigate.logout_raises = ConnectionError("appliance went away")
        patched_connect(monkeypatch, api, session)
        with connect(token_target):
            pass
        assert session.closed == 1

    def test_a_failing_close_does_not_escape(self, monkeypatch, token_target):
        from mcfortigate.client import connect

        api, session = FakeAPI(), RecordingSession()
        session.close_raises = OSError("socket already gone")
        patched_connect(monkeypatch, api, session)
        with connect(token_target):
            pass
        assert session.closed == 1

    def test_repeated_calls_close_every_session(self, monkeypatch, token_target):
        """A leak shows up as accumulation, so count across calls rather than one."""
        from mcfortigate.client import connect

        sessions = []
        for _ in range(5):
            api, session = FakeAPI(), RecordingSession()
            sessions.append(session)
            patched_connect(monkeypatch, api, session)
            with connect(token_target):
                pass
        assert [session.closed for session in sessions] == [1] * 5

    def test_failed_authentication_leaves_no_open_session(self, monkeypatch, token_target):
        """`_token_session` raises before the context is entered, so it owns its own cleanup."""
        from mcfortigate.client import _token_session

        session = RecordingSession()
        monkeypatch.setattr("mcfortigate.client.requests.Session", lambda: session)

        class Denied:
            status_code = 403

        monkeypatch.setattr(session, "get", lambda *_a, **_k: Denied(), raising=False)
        with pytest.raises(FortiOSError, match="rejected the API token"):
            _token_session(token_target)
        assert session.closed == 1

    def test_an_unexpected_authentication_failure_still_closes(self, monkeypatch, token_target):
        """The enumerated exception list cannot be complete, so cleanup must not depend on it."""
        from mcfortigate.client import _token_session

        session = RecordingSession()
        monkeypatch.setattr("mcfortigate.client.requests.Session", lambda: session)

        def explode(*_args, **_kwargs):
            raise MemoryError("nothing to do with requests")

        monkeypatch.setattr(session, "get", explode, raising=False)
        with pytest.raises(MemoryError):
            _token_session(token_target)
        assert session.closed == 1


class TestVdomOverride:
    """H4. A tool pinned to one vdom cannot answer about another.

    The reported `vdom` has to name the one actually read. Reporting the
    configured default beside rows fetched from somewhere else is a join
    mislabelled at the top of the response, which is worse than refusing.
    """

    def test_resolve_falls_back_to_the_configured_vdom(self, token_target):
        from mcfortigate.client import resolve_vdom

        assert resolve_vdom(token_target) == "root"
        assert resolve_vdom(token_target, None) == "root"
        assert resolve_vdom(token_target, "") == "root"
        assert resolve_vdom(token_target, "   ") == "root"

    def test_resolve_prefers_the_override(self, token_target):
        from mcfortigate.client import resolve_vdom

        assert resolve_vdom(token_target, "dmz") == "dmz"
        assert resolve_vdom(token_target, "  dmz  ") == "dmz"

    def test_use_vdom_rescopes_the_session(self):
        from mcfortigate.client import use_vdom

        api = FakeAPI()
        use_vdom(api, "dmz")
        assert api.fortigate.vdom == "dmz"

    def test_use_vdom_leaves_the_default_alone(self):
        from mcfortigate.client import use_vdom

        api = FakeAPI()
        use_vdom(api, None)
        use_vdom(api, "")
        assert api.fortigate.vdom == "root"


class TestReadsAreAttributedToTheRightVdom:
    """The appliance names the vdom it answered for in every envelope.

    Measured on FWF61E / 7.0.14: every cmdb and monitor endpoint this server
    reads carries a top-level `vdom`. So the vdom a response claims does not
    have to be inferred from what was asked; it can be checked against what was
    answered, and a mismatch is a mislabelled answer rather than a missing one.
    """

    def api_with_vdom(self, requested: str, response) -> SimpleNamespace:
        return SimpleNamespace(fortigate=SimpleNamespace(vdom=requested, get=lambda *_a, **_k: response))

    def test_agreeing_envelope_passes(self):
        api = self.api_with_vdom("root", Response(200, {"vdom": "root", "results": [{"name": "A"}]}))
        assert fetch_table(api, "api/v2/cmdb/firewall/address") == [{"name": "A"}]

    def test_mismatched_envelope_raises(self):
        api = self.api_with_vdom("dmz", Response(200, {"vdom": "root", "results": [{"name": "A"}]}))
        with pytest.raises(FortiOSError, match="vdom"):
            fetch_table(api, "api/v2/cmdb/firewall/address")

    def test_envelope_without_a_vdom_is_not_second_guessed(self):
        """Absent beats false: an unstated vdom is no evidence of a mismatch."""
        api = self.api_with_vdom("dmz", Response(200, {"results": [{"name": "A"}]}))
        assert fetch_table(api, "api/v2/cmdb/firewall/address") == [{"name": "A"}]

    def test_monitor_mismatch_is_reported_rather_than_raised(self):
        """Live tools fail soft, so the mismatch has to arrive as a status."""
        api = self.api_with_vdom("dmz", Response(200, {"vdom": "root", "results": [{"mac": "aa"}]}))
        result = fetch_monitor(api, "api/v2/monitor/network/arp")
        assert result.status == "wrong_vdom"
        assert not result.usable
        assert result.rows == []

    def test_monitor_agreement_passes(self):
        api = self.api_with_vdom("root", Response(200, {"vdom": "root", "results": [{"mac": "aa"}]}))
        result = fetch_monitor(api, "api/v2/monitor/network/arp")
        assert result.status == "ok"
        assert result.vdom == "root"

    def test_error_messages_name_the_vdom_that_was_asked_for(self):
        """A 424 from a vdom typo is otherwise indistinguishable from any other 424."""
        api = self.api_with_vdom("nosuchvdom", Response(424, {"status": "error"}))
        with pytest.raises(FortiOSError, match="nosuchvdom"):
            fetch_table(api, "api/v2/cmdb/system/interface")
