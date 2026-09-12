"""FortiGate connection handling.

Sessions are opened per tool call rather than pooled. With token auth, which
is the preferred mode, this costs nothing because the token travels on each
request and there is no login round-trip to amortize. With username and
password there is one login per call, which is an acceptable price for never
holding a stale session across an idle MCP server that may sit unused for
hours between questions.
"""

from __future__ import annotations

import warnings
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any

from fortigate_api import FortiGateAPI

from mcfortigate.config import FortiGateTarget
from mcfortigate.fortios import FortiOSError


@contextmanager
def connect(target: FortiGateTarget) -> Iterator[FortiGateAPI]:
    """Open a FortiGate session for the duration of the block.

    Suppresses urllib3's unverified-HTTPS warning when the target opts out of
    certificate verification, since a lab appliance with a self-signed cert is
    a deliberate configuration rather than something to warn about on every
    single call.
    """
    kwargs: dict[str, Any] = {
        "host": target.host,
        "scheme": target.scheme,
        "verify": target.verify_ssl,
        "timeout": target.timeout,
        "vdom": target.vdom,
    }
    if target.port:
        kwargs["port"] = target.port
    if target.token:
        kwargs["token"] = target.token
    else:
        kwargs["username"] = target.username
        kwargs["password"] = target.password

    api = FortiGateAPI(**kwargs)
    with warnings.catch_warnings():
        if not target.verify_ssl:
            warnings.filterwarnings("ignore", message="Unverified HTTPS request")
        try:
            yield api
        finally:
            try:
                api.logout()
            except Exception:  # noqa: BLE001 - logout failures must not mask a real error
                pass


def fetch_envelope(api: FortiGateAPI, url: str) -> dict[str, Any]:
    """GET a cmdb URL and return the full response envelope.

    The envelope matters. FortiOS puts the appliance serial, firmware version,
    and build number as top-level siblings of ``results``, not inside it, and
    the library's ``get_result`` helper discards everything except ``results``.
    Worse, that helper coerces ``results`` with ``dict()``, which raises on any
    endpoint whose results are a list. Reading the raw response sidesteps both
    problems, and is the only way to see the serial at all.
    """
    resp = api.fortigate.get(url)
    status_code = getattr(resp, "status_code", None)
    if status_code != 200:
        raise FortiOSError(f"FortiOS rejected GET {url}: http={status_code}")
    body = resp.json()
    if not isinstance(body, dict):
        raise FortiOSError(f"Unexpected response shape from {url}: {type(body).__name__}")
    return body


def fetch_monitor(api: FortiGateAPI, url: str) -> list[dict[str, Any]]:
    """GET a monitor endpoint, returning an empty list when it is unavailable.

    The monitor tree is where FortiOS exposes observed runtime state rather
    than configuration, and its endpoints vary by platform and firmware. A
    FortiGate with no wireless hardware has no ``monitor/wifi/client`` at all.
    Failing soft keeps one absent feature from taking down a tool that joins
    several sources.
    """
    try:
        data = api.fortigate.get_results(url)
    except Exception:  # noqa: BLE001 - per-endpoint fail-soft is the point
        return []
    if isinstance(data, list):
        return [item for item in data if isinstance(item, dict)]
    if isinstance(data, dict):
        return [data]
    return []
