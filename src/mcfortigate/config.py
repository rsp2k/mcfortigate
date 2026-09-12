"""Target resolution from environment variables.

A "target" is one FortiGate appliance. Two config styles are supported and
they can coexist:

**Single target** (the common case). Set ``FORTIGATE_HOST`` plus credentials
and the server registers one target. Its name comes from ``FORTIGATE_NAME``
if set, otherwise from the host itself, so tools can omit the ``target``
argument entirely::

    FORTIGATE_HOST=fgt-edge1.example.com
    FORTIGATE_TOKEN=abc123
    FORTIGATE_VERIFY_SSL=false

**Multiple targets.** Set ``FORTIGATE_TARGETS`` to a JSON object mapping a
short alias to that appliance's connection details. Aliases are what the LLM
passes as the ``target`` argument, so keep them short and memorable::

    FORTIGATE_TARGETS='{
      "edge":   {"host": "fgt-edge1.example.com", "token": "abc"},
      "branch": {"host": "fgt-br2.example.com",   "token": "def", "verify_ssl": false}
    }'

Credentials never appear in tool arguments or responses. They are read from
the environment at startup and held in the target registry. Two auth modes
match FortiOS REST conventions: an API token (FortiOS 5.6+, preferred), or a
username and password pair as the legacy fallback.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from urllib.parse import urlparse


class ConfigError(RuntimeError):
    """Raised when the environment doesn't describe a usable FortiGate target."""


@dataclass(frozen=True)
class FortiGateTarget:
    """Connection details for one FortiGate appliance.

    The ``token`` / ``username`` / ``password`` fields are excluded from
    ``repr`` so a stray log line or traceback can't leak them. ``describe()``
    is the safe representation to hand back to an LLM.
    """

    name: str
    host: str
    scheme: str = "https"
    port: int | None = None
    vdom: str = "root"
    verify_ssl: bool = True
    timeout: int = 30
    token: str | None = field(default=None, repr=False)
    username: str | None = field(default=None, repr=False)
    password: str | None = field(default=None, repr=False)

    def __post_init__(self) -> None:
        """Validate that at least one usable auth mode is present."""
        if not self.token and not (self.username and self.password):
            raise ConfigError(
                f"Target {self.name!r} has no usable credentials. Set either a "
                f"token, or both a username and a password."
            )

    @property
    def auth_mode(self) -> str:
        """Which FortiOS auth style this target will use."""
        return "token" if self.token else "username+password"

    @property
    def url(self) -> str:
        """Human-readable base URL, for display only."""
        port_part = f":{self.port}" if self.port else ""
        return f"{self.scheme}://{self.host}{port_part}"

    def describe(self) -> dict[str, object]:
        """Credential-free summary safe to return from a tool."""
        return {
            "name": self.name,
            "url": self.url,
            "vdom": self.vdom,
            "auth_mode": self.auth_mode,
            "verify_ssl": self.verify_ssl,
            "timeout": self.timeout,
        }


def parse_host_url(raw_url: str) -> tuple[str, int | None, str]:
    """Split a host string into ``(host, port, scheme)``.

    fortigate-api wants these as three separate constructor arguments rather
    than one URL, and operators write the host every possible way, so this
    normalizes all of them. A bare hostname is assumed to be https, which is
    the only sane default for a firewall management interface.

    >>> parse_host_url("https://fgt-edge1.example.com")
    ('fgt-edge1.example.com', None, 'https')
    >>> parse_host_url("https://fgt:8443/")
    ('fgt', 8443, 'https')
    >>> parse_host_url("fortigate.example.com")
    ('fortigate.example.com', None, 'https')
    >>> parse_host_url("http://fgt.lab:8080")
    ('fgt.lab', 8080, 'http')
    """
    raw = raw_url.strip().rstrip("/")
    if not raw:
        raise ConfigError("Empty host value")
    # urlparse treats a schemeless string as a path, not a host, so give it one.
    if "://" not in raw:
        raw = "https://" + raw

    parsed = urlparse(raw)
    if not parsed.hostname:
        raise ConfigError(f"Could not extract a hostname from {raw_url!r}")
    return parsed.hostname, parsed.port, parsed.scheme or "https"


def _as_int(value: object, default: int, name: str) -> int:
    """Coerce a setting to an int, failing with a message that names the setting.

    The bare `int()` this replaces raised `invalid literal for int() with base
    10: '30s'` from inside a startup path, which says nothing about which
    variable was wrong or where to change it. Settings arrive from a `.env`
    file, so units-in-the-value (`30s`) and stray quotes are the normal kinds of
    mistake rather than exotic ones.
    """
    if value is None or value == "":
        return default
    if isinstance(value, bool):
        raise ConfigError(f"{name} must be a number, not a true/false value")
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        raise ConfigError(
            f"{name} must be a whole number of seconds or a port number, but is {value!r}. "
            "Write it as digits only, with no units and no quotes."
        ) from None


def _as_bool(value: object, default: bool) -> bool:
    """Coerce the usual truthy spellings operators write in a .env file."""
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


def _target_from_mapping(name: str, raw: dict) -> FortiGateTarget:
    """Build a target from one entry of the ``FORTIGATE_TARGETS`` JSON object."""
    host_value = raw.get("host") or raw.get("url")
    if not host_value:
        raise ConfigError(f"Target {name!r} is missing a 'host' key")
    host, url_port, scheme = parse_host_url(str(host_value))

    # An explicit "port" key wins over one embedded in the host URL.
    port = raw.get("port", url_port)
    return FortiGateTarget(
        name=name,
        host=host,
        scheme=scheme,
        port=_as_int(port, 0, f"port for target {name!r}") or None,
        vdom=str(raw.get("vdom", "root")),
        verify_ssl=_as_bool(raw.get("verify_ssl"), True),
        timeout=_as_int(raw.get("timeout"), 30, f"timeout for target {name!r}"),
        token=raw.get("token"),
        username=raw.get("username"),
        password=raw.get("password"),
    )


def load_targets(env: dict[str, str] | None = None) -> dict[str, FortiGateTarget]:
    """Read every configured target out of the environment.

    Returns a mapping of alias to target. An empty mapping is a valid result
    and is not an error here, because the server should still start and report
    the misconfiguration through its tools rather than crashing at import time
    where the operator would only see it in a log they may not be watching.
    """
    env = dict(os.environ if env is None else env)
    targets: dict[str, FortiGateTarget] = {}

    raw_multi = env.get("FORTIGATE_TARGETS", "").strip()
    if raw_multi:
        try:
            parsed = json.loads(raw_multi)
        except json.JSONDecodeError as exc:
            raise ConfigError(f"FORTIGATE_TARGETS is not valid JSON: {exc}") from exc
        if not isinstance(parsed, dict):
            raise ConfigError("FORTIGATE_TARGETS must be a JSON object keyed by target alias")
        for alias, spec in parsed.items():
            if not isinstance(spec, dict):
                raise ConfigError(f"FORTIGATE_TARGETS entry {alias!r} must be a JSON object")
            targets[alias] = _target_from_mapping(alias, spec)

    single_host = env.get("FORTIGATE_HOST", "").strip()
    if single_host:
        host, url_port, scheme = parse_host_url(single_host)
        env_port = env.get("FORTIGATE_PORT", "").strip()
        name = env.get("FORTIGATE_NAME", "").strip() or host
        targets[name] = FortiGateTarget(
            name=name,
            host=host,
            scheme=scheme,
            port=_as_int(env_port, 0, "FORTIGATE_PORT") or url_port,
            vdom=env.get("FORTIGATE_VDOM", "root").strip() or "root",
            verify_ssl=_as_bool(env.get("FORTIGATE_VERIFY_SSL"), True),
            timeout=_as_int(env.get("FORTIGATE_TIMEOUT"), 30, "FORTIGATE_TIMEOUT"),
            token=env.get("FORTIGATE_TOKEN") or None,
            username=env.get("FORTIGATE_USERNAME") or None,
            password=env.get("FORTIGATE_PASSWORD") or None,
        )

    return targets


class TargetRegistry:
    """Holds the configured targets and resolves the ``target`` tool argument.

    Resolution is deliberately forgiving in the single-target case, since most
    installs have exactly one FortiGate and making the LLM name it every time
    is friction with no payoff. When several are configured, an omitted target
    is an error whose message lists the valid aliases, so the model can correct
    itself on the next call instead of guessing.
    """

    def __init__(self, targets: dict[str, FortiGateTarget] | None = None) -> None:
        """Build a registry, reading the environment when targets are not supplied."""
        self._targets = targets if targets is not None else load_targets()

    def __len__(self) -> int:
        """Return the number of configured targets."""
        return len(self._targets)

    @property
    def names(self) -> list[str]:
        """Configured target aliases, sorted for stable output."""
        return sorted(self._targets)

    def all(self) -> list[FortiGateTarget]:
        """Every configured target, sorted by alias."""
        return [self._targets[name] for name in self.names]

    def resolve(self, target: str | None = None) -> FortiGateTarget:
        """Return the requested target, or the only one when unambiguous."""
        if not self._targets:
            raise ConfigError(
                "No FortiGate targets are configured. Set FORTIGATE_HOST and "
                "FORTIGATE_TOKEN for a single appliance, or FORTIGATE_TARGETS "
                "with a JSON object for several."
            )
        if target:
            try:
                return self._targets[target]
            except KeyError:
                raise ConfigError(f"Unknown target {target!r}. Configured targets: {', '.join(self.names)}") from None
        if len(self._targets) == 1:
            return next(iter(self._targets.values()))
        raise ConfigError(
            f"Several FortiGates are configured, so 'target' is required. Choose one of: {', '.join(self.names)}"
        )
