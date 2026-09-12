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
