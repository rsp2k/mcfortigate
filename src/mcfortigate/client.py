"""FortiGate connection handling and status-checked reads.

Two things here exist specifically to work around defects in `fortigate-api`
2.0.8, and both are load-bearing.

The first is that `Connector.get()` does `if not response.ok: return []`, so
every 401, 403, 404, and 500 reaches the caller as an empty list with no
exception and no status. Nothing in this package may use it, because a tool
that cannot tell "denied" from "none" will eventually tell an operator that a
referenced object is safe to delete. `fetch_table` is the replacement.

The second is that the library's token login calls `session.get()` with no
timeout, while the password branch beside it passes one. Token auth is the mode
we recommend, so the recommended path is the unbounded one. Measured against an
unroutable address, a single tool call took 134 seconds. `connect` performs that
login itself, with a deadline, and hands the library a ready session.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any
from urllib.parse import urlencode, urljoin

import requests
from fortigate_api import FortiGateAPI

from mcfortigate.config import FortiGateTarget
from mcfortigate.fortios import FortiOSError, check_response

# Canonical FortiOS cmdb paths. Spelled out rather than read from the library's
# private `_path` attributes so a reader can see exactly which endpoint each
# tool reads, and so a library refactor cannot silently retarget them.
ADDRESSES = "api/v2/cmdb/firewall/address"
ADDRESS_GROUPS = "api/v2/cmdb/firewall/addrgrp"
SERVICES = "api/v2/cmdb/firewall.service/custom"
SERVICE_GROUPS = "api/v2/cmdb/firewall.service/group"
POLICIES = "api/v2/cmdb/firewall/policy"
VIPS = "api/v2/cmdb/firewall/vip"
INTERFACES = "api/v2/cmdb/system/interface"
STATIC_ROUTES = "api/v2/cmdb/router/static"
SYSTEM_GLOBAL = "api/v2/cmdb/system/global"

# Monitor endpoints report observed state rather than configuration.
MON_SYSTEM_STATUS = "api/v2/monitor/system/status"
MON_RESOURCE_USAGE = "api/v2/monitor/system/resource/usage"
MON_WIFI_CLIENTS = "api/v2/monitor/wifi/client"
MON_DHCP_LEASES = "api/v2/monitor/system/dhcp"
MON_ARP = "api/v2/monitor/network/arp"
MON_ROUTING_TABLE = "api/v2/monitor/router/ipv4"
MON_OBJECT_USAGE = "api/v2/monitor/system/object/usage"
# What the web UI populates a policy's interface pickers from. Each row carries
# `valid_in_policy`, which is the appliance's own answer to "is this a real
# policy endpoint" and the only reliable one. See review finding M8.
MON_AVAILABLE_INTERFACES = "api/v2/monitor/system/available-interfaces"

#: The object kinds a name can be resolved against, each pairing the cmdb table
#: that defines the object with the `q_path` / `q_name` the usage endpoint wants
#: for it.
#:
#: The pairing has to be right. `monitor/system/object/usage` answers HTTP 200
#: with an empty `currently_using` list when the key is absent from the table it
#: was asked about, so a mismatched pair reports an in-use object as
#: unreferenced. Measured on 7.0.14: asking the address table about `wan1`
#: returns nothing, while asking the interface table about it returns two
#: references.
OBJECT_KINDS: tuple[tuple[str, str, str, str, str], ...] = (
    ("address", "addresses", ADDRESSES, "firewall", "address"),
    ("address group", "address_groups", ADDRESS_GROUPS, "firewall", "addrgrp"),
    ("service", "services", SERVICES, "firewall.service", "custom"),
    ("service group", "service_groups", SERVICE_GROUPS, "firewall.service", "group"),
    ("virtual IP", "vips", VIPS, "firewall", "vip"),
    ("interface", "interfaces", INTERFACES, "system", "interface"),
)


class MonitorResult:
    """A monitor read, carrying why it is empty when it is empty.

    An absent endpoint and a denied one both produce no rows, and they mean
    opposite things. A FortiGate with no radio genuinely has no wireless client
    list, and a tool joining several sources should carry on without it. A
    FortiGate that refused the read is a permissions problem the operator needs
    told about. Collapsing both to a bare list makes the second invisible.

    The rule: fail soft on absence, never on denial.
    """

    __slots__ = ("rows", "status", "detail", "vdom")

    def __init__(
        self,
        rows: list[dict[str, Any]],
        status: str,
        detail: str | None = None,
        vdom: str | None = None,
    ) -> None:
        """Record the rows alongside why there are however many there are."""
        self.rows = rows
        self.status = status
        self.detail = detail
        #: The vdom the appliance said it answered for, when it said. None is
        #: "it did not say", never "the default".
        self.vdom = vdom

    @property
    def ok(self) -> bool:
        """True when the endpoint answered."""
        return self.status == "ok"

    @property
    def usable(self) -> bool:
        """True when carrying on without these rows is honest.

        An endpoint the platform does not implement is a fact about the
        hardware. A denial or a transport failure is not, and callers should
        surface those rather than quietly degrading.
        """
        return self.status in {"ok", "unsupported"}

    def describe(self) -> str:
        """Short status suitable for putting in a tool response."""
        return self.status if self.detail is None else f"{self.status}: {self.detail}"


def _token_session(target: FortiGateTarget) -> requests.Session:
    """Authenticate a token session under our own deadline.

    The library would do this lazily inside the first request with no timeout at
    all. Doing it here means an appliance that drops packets rather than
    refusing them costs us `target.timeout` instead of blocking until the
    operating system gives up.
    """
    session = requests.Session()
    port = f":{target.port}" if target.port else ""
    base = f"{target.scheme}://{target.host}{port}"
    # The handover flag rather than a close on each failure branch. Enumerated
    # cleanup only covers the failures somebody thought of, and this function
    # is the one place holding an open socket that no context manager owns yet:
    # it is called before `connect` enters its own try block, so anything
    # escaping here escapes with the socket still open. MemoryError and a
    # KeyboardInterrupt landing mid-handshake are not in the except list below
    # and never will be.
    handed_over = False
    try:
        try:
            response = session.get(
                urljoin(base, "/" + MON_SYSTEM_STATUS),
                headers={"Authorization": f"Bearer {target.token}"},
                verify=target.verify_ssl,
                timeout=target.timeout,
            )
        except requests.exceptions.Timeout as exc:
            raise FortiOSError(
                f"{target.name} at {target.url} did not respond within {target.timeout}s. "
                "Check that the appliance is reachable and that any tunnel is still open."
            ) from exc
        except requests.exceptions.RequestException as exc:
            raise FortiOSError(f"Could not reach {target.name} at {target.url}: {type(exc).__name__}") from exc

        if response.status_code in {401, 403}:
            raise FortiOSError(
                f"{target.name} rejected the API token (http={response.status_code}). "
                "Check that the token is correct and that this host is in its trusted-host list."
            )
        if response.status_code != 200:
            raise FortiOSError(f"{target.name} returned http={response.status_code} during authentication")
        handed_over = True
        return session
    finally:
        if not handed_over:
            session.close()


def resolve_vdom(target: FortiGateTarget, vdom: str | None = None) -> str:
    """Work out which virtual domain a call will actually be scoped to.

    Tools report this rather than `target.vdom`. On a multi-VDOM appliance the
    two differ the moment a caller overrides, and a response that answers from
    one vdom while labelling itself with another is a mislabelled join at the
    top of the payload, which is harder to catch than a missing answer.

    A blank or whitespace override means "no override" rather than "the empty
    vdom", since that is what an LLM filling in an optional string argument
    tends to produce.
    """
    chosen = (vdom or "").strip()
    return chosen or target.vdom


def use_vdom(api: FortiGateAPI, vdom: str | None) -> None:
    """Scope every subsequent read on this session to a different vdom.

    The vdom is a per-request query parameter rather than a property of the
    session, which is why this is separate from :func:`connect` instead of an
    argument to it. Binding it at connect time would imply a session belongs to
    one vdom, and it does not.

    Passing nothing leaves the target's configured vdom in place.
    """
    chosen = (vdom or "").strip()
    if chosen:
        api.fortigate.vdom = chosen


@contextmanager
def connect(target: FortiGateTarget) -> Iterator[FortiGateAPI]:
    """Open a FortiGate session for the duration of the block.

    Sessions are per call rather than pooled. With token auth there is no login
    round-trip to amortize, and never holding a session across an idle server is
    worth more than saving one that costs nothing.

    With username and password the library performs a full login per call, which
    writes an admin login event to the appliance event log each time. A chatty
    model can produce a lot of those, which is one more reason to prefer a token.

    Reads are scoped to the target's configured vdom. Call :func:`use_vdom` on
    the yielded object to point them somewhere else; the vdom rides on each
    request rather than on the session, so it can change mid-block.
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

    # Pre-authenticate the token path ourselves so it is bounded. The library
    # only logs in when `_session` is unset, so handing it a live session skips
    # its own unbounded probe entirely. The password path already passes a
    # timeout, so it is left alone.
    if target.token:
        api.fortigate._session = _token_session(target)  # noqa: SLF001 - see module docstring

    try:
        yield api
    finally:
        session = getattr(api.fortigate, "_session", None)
        try:
            api.logout()
        except Exception:  # noqa: BLE001 - a logout failure must not destroy a good answer
            pass
        if session is not None:
            try:
                session.close()
            except Exception:  # noqa: BLE001 - socket teardown, nothing to salvage
                pass


def _rows(body: Any, url: str) -> list[dict[str, Any]]:
    """Normalize a FortiOS `results` payload into a list of records.

    FortiOS returns a list for table endpoints and a bare object for singular
    ones such as `system/global`. The library's helper coerces with `list()`,
    which on an object silently yields its keys as strings, so callers receive a
    list of meaningless strings or, after filtering, nothing at all. Both shapes
    are handled here and anything else is an error rather than an empty result.
    """
    if not isinstance(body, dict):
        raise FortiOSError(f"Unexpected response shape from {url}: {type(body).__name__}")
    results = body.get("results")
    if results is None:
        return []
    if isinstance(results, dict):
        return [results]
    if isinstance(results, list):
        return [row for row in results if isinstance(row, dict)]
    raise FortiOSError(f"Unexpected results shape from {url}: {type(results).__name__}")


def requested_vdom(api: FortiGateAPI) -> str | None:
    """Report which vdom this session is currently scoping reads to, if it says."""
    return getattr(getattr(api, "fortigate", None), "vdom", None)


def _label(api: FortiGateAPI, path: str) -> str:
    """Error label naming both the endpoint and the vdom it was asked of.

    Measured on 7.0.14: a vdom that does not exist answers HTTP 424, which is
    also what an endpoint with an unmet dependency answers. Without the vdom in
    the message the two are indistinguishable, and a typo in a vdom name reads
    as a broken endpoint.
    """
    vdom = requested_vdom(api)
    return f"GET {path}" if vdom is None else f"GET {path} (vdom={vdom!r})"


def _answered_vdom(body: Any) -> str | None:
    """Read back the vdom the appliance answered for, or None when it did not say."""
    return body.get("vdom") if isinstance(body, dict) else None


def _check_vdom(api: FortiGateAPI, body: Any, path: str) -> str | None:
    """Raise unless the vdom that answered is the vdom that was asked.

    Every cmdb and monitor endpoint this server reads names its vdom in the
    response envelope, verified across all seventeen paths on FWF61E / 7.0.14.
    So the vdom a tool reports need not be assumed from what was requested; it
    can be checked against what replied.

    The failure this prevents is a response labelled `vdom: dmz` carrying rows
    from `root`, which no reader can detect from the payload. Silence from the
    appliance is not treated as disagreement, because an unstated vdom is no
    evidence either way.
    """
    answered = _answered_vdom(body)
    asked = requested_vdom(api)
    if answered is not None and asked is not None and answered != asked:
        raise FortiOSError(
            f"{path} was requested for vdom {asked!r} but the appliance answered for {answered!r}. "
            "Refusing to attribute these rows to the wrong virtual domain."
        )
    return answered


def fetch_table(api: FortiGateAPI, path: str) -> list[dict[str, Any]]:
    """Read a cmdb table, raising on any status other than 200.

    Use this rather than `api.cmdb.*.get()` anywhere in this package. The
    library's connector turns every error status into an empty list, which makes
    a denied read indistinguishable from an empty table.

    The request still goes through the library's request builder, so it inherits
    vdom scoping, the bearer header, and the per-request timeout.
    """
    response = api.fortigate.get(path)
    check_response(response, _label(api, path))
    body = response.json()
    _check_vdom(api, body, path)
    return _rows(body, path)


def fetch_envelope(api: FortiGateAPI, path: str) -> dict[str, Any]:
    """Read a cmdb URL and return the whole response envelope.

    The envelope matters because FortiOS puts the appliance serial, firmware
    version, and build number as siblings of `results` rather than inside it.
    Helpers that unwrap straight to `results` discard them, which is why the
    serial appears to be missing from the API until you read the raw response.
    """
    response = api.fortigate.get(path)
    check_response(response, _label(api, path))
    body = response.json()
    if not isinstance(body, dict):
        raise FortiOSError(f"Unexpected response shape from {path}: {type(body).__name__}")
    _check_vdom(api, body, path)
    return body


def fetch_monitor(api: FortiGateAPI, path: str) -> MonitorResult:
    """Read a monitor endpoint, distinguishing absence from denial.

    Returns a :class:`MonitorResult` rather than a list so the caller can tell
    an unimplemented endpoint from a refused one. See that class for why the
    difference matters.
    """
    try:
        response = api.fortigate.get(path)
    except Exception as exc:  # noqa: BLE001 - transport failure is a reportable status
        return MonitorResult([], "error", f"{type(exc).__name__}")

    status_code = getattr(response, "status_code", None)
    if status_code in {404, 405}:
        return MonitorResult([], "unsupported", f"http={status_code}")
    if status_code in {401, 403}:
        return MonitorResult([], "denied", f"http={status_code}")
    if status_code != 200:
        return MonitorResult([], "error", f"http={status_code}")

    try:
        body = response.json()
        rows = _rows(body, path)
    except (FortiOSError, ValueError) as exc:
        return MonitorResult([], "error", str(exc)[:120])

    answered = _answered_vdom(body)
    asked = requested_vdom(api)
    if answered is not None and asked is not None and answered != asked:
        # Rows dropped on purpose. Handing back live state attributed to the
        # wrong virtual domain is worse than handing back none, because a live
        # tool's caller has no other way to notice.
        return MonitorResult([], "wrong_vdom", f"asked {asked!r}, answered {answered!r}", answered)
    return MonitorResult(rows, "ok", None, answered)


def fetch_object_usage(api: FortiGateAPI, q_path: str, q_name: str, mkey: str) -> MonitorResult:
    """Ask the appliance what references one object.

    This is what the web UI's reference counter calls, and it is authoritative
    in a way that scanning tables is not: it knows every table that can hold a
    reference, which on 7.0.14 is seventy-four of them for a firewall address.

    The single row it returns carries `can_use`, the tables that could reference
    an object of this kind, and `currently_using`, the ones that do.

    Two cautions. The caller must pass a `q_path` / `q_name` that matches the
    table the object actually lives in, because a mismatch is answered with an
    empty list rather than an error. And every `currently_using` row carries
    `reference_count: 0` on real hardware, genuine references included, so the
    presence of a row is the signal and the count is not.

    Names are URL-encoded here because object names legitimately contain
    spaces, as with the stock `G Suite` address group.
    """
    query = urlencode({"q_path": q_path, "q_name": q_name, "mkey": mkey})
    return fetch_monitor(api, f"{MON_OBJECT_USAGE}?{query}")
