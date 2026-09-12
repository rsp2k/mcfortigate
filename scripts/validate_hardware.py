#!/usr/bin/env python3
"""Exercise every tool against a real FortiGate and report what came back.

Unit tests prove the reading layer handles the response shapes we recorded.
They cannot prove those are the shapes a given appliance actually sends, which
is a distinction the sibling project learned expensively: four separate bugs
shipped past a green test suite and only appeared against hardware.

This script closes that gap. It calls every tool through the MCP layer rather
than importing the functions directly, so schema validation and serialization
are exercised too, and reports three things per tool: whether it succeeded, how
long it took, and a shape summary of what came back.

It also applies suspicion heuristics. A real firewall with zero interfaces is
not a passing result, it is a silent failure wearing a success costume, and
this script says so.

Usage:

    uv run python scripts/validate_hardware.py

    # Against a named target when several are configured
    uv run python scripts/validate_hardware.py --target edge

Credentials come from a `.env` file beside `pyproject.toml` when one exists,
and from the environment otherwise. Anything already exported wins, so a
one-off target can be given inline without editing the file.

Nothing here writes to the appliance. Every call is a read.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from mcfortigate.config import ConfigError, TargetRegistry
from mcfortigate.server import build_server


def load_dotenv(path: Path) -> int:
    """Read `KEY=value` lines into the environment, without adding a dependency.

    Deliberately small. It handles the forms an operator actually writes in a
    .env file, which is comments, blank lines, optional `export`, and quoted
    values, and it does not attempt interpolation. Existing environment
    variables are left alone so an inline override beats the file.
    """
    if not path.is_file():
        return 0
    loaded = 0
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        line = line.removeprefix("export ").lstrip()
        key, separator, value = line.partition("=")
        if not separator:
            continue
        key = key.strip()
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        if key and key not in os.environ:
            os.environ[key] = value
            loaded += 1
    return loaded

# Tools that need an argument beyond `target`, with a value chosen to be
# harmless and to exercise the code path rather than to match anything. A
# search for a string no appliance contains still proves the search ran.
TOOL_ARGUMENTS: dict[str, dict[str, Any]] = {
    "search_config": {"term": "lan"},
    "find_device": {"query": "aa:"},
    "find_references": {"object_name": "all"},
}

# Tools where an empty result on a live appliance means something is wrong
# rather than that the table is genuinely empty. Every FortiGate has
# interfaces, addresses, services, and policies. Several legitimately have no
# VLANs, no VIPs, no wireless clients, and no static routes.
EXPECT_NONEMPTY: dict[str, str] = {
    "list_interfaces": "interfaces",
    "list_address_objects": "addresses",
    "list_services": "services",
    "list_policies": "policies",
    "get_routing_table": "routes",
}


@dataclass
class Result:
    """What one tool call produced."""

    name: str
    ok: bool
    seconds: float
    payload: Any = None
    error: str | None = None
    warnings: list[str] = field(default_factory=list)


def _unwrap(raw: Any) -> Any:
    """Pull the JSON payload out of whatever shape call_tool returned.

    FastMCP has moved this between releases, returning bare data in some
    versions and a content-block wrapper in others. Handling both keeps this
    script working across an upgrade instead of failing in a way that looks
    like a FortiGate problem.
    """
    for attribute in ("data", "structured_content", "structuredContent"):
        value = getattr(raw, attribute, None)
        if isinstance(value, (dict, list)):
            return value

    content = getattr(raw, "content", None)
    if content:
        first = content[0]
        text = getattr(first, "text", None)
        if text:
            try:
                return json.loads(text)
            except json.JSONDecodeError:
                return text
    if isinstance(raw, (dict, list)):
        return raw
    return repr(raw)


def _shape(payload: Any, depth: int = 0) -> str:
    """Describe a payload's structure without dumping its contents.

    A firewall's configuration is exactly the kind of thing not to print in
    full to a terminal that may be logged or shared, so this reports counts and
    key names rather than values.
    """
    if isinstance(payload, dict):
        parts = []
        for key, value in payload.items():
            if isinstance(value, list):
                parts.append(f"{key}[{len(value)}]")
            elif isinstance(value, dict):
                parts.append(f"{key}{{{len(value)}}}" if depth else f"{key}={_shape(value, depth + 1)}")
            elif value is None:
                parts.append(f"{key}=null")
            else:
                parts.append(key)
        return "{" + ", ".join(parts) + "}"
    if isinstance(payload, list):
        return f"[{len(payload)} items]"
    return type(payload).__name__


def _inspect(name: str, payload: Any) -> list[str]:
    """Apply suspicion heuristics to one tool's result."""
    warnings: list[str] = []
    if not isinstance(payload, dict):
        return [f"expected an object, got {type(payload).__name__}"]

    collection_key = EXPECT_NONEMPTY.get(name)
    if collection_key:
        items = payload.get(collection_key)
        if isinstance(items, list) and not items:
            warnings.append(
                f"'{collection_key}' is empty, which no real appliance should be. "
                "Check credentials, VDOM scope, and the read-only profile's permissions."
            )

    # A count field that disagrees with the list it describes means a filter
    # and its counter drifted apart.
    count = payload.get("count")
    if isinstance(count, int):
        lists = [value for value in payload.values() if isinstance(value, list)]
        if lists and count != len(lists[0]):
            warnings.append(f"count={count} disagrees with the returned list length {len(lists[0])}")

    # Every summarized record should have shed the FortiOS noise fields. Seeing
    # one means a summarizer was bypassed somewhere.
    raw_markers = {"uuid", "q_origin_key", "srcaddr6", "dstaddr6", "obj-type"}
    for value in payload.values():
        if isinstance(value, list):
            for item in value[:5]:
                if isinstance(item, dict) and (leaked := raw_markers & set(item)):
                    warnings.append(f"raw FortiOS fields leaked through: {sorted(leaked)}")
                    break
    return warnings


async def run(target: str | None, verbose: bool) -> int:
    """Call every tool and print a report. Returns a process exit code."""
    env_file = Path(__file__).resolve().parent.parent / ".env"
    loaded = load_dotenv(env_file)
    if verbose and loaded:
        print(f"loaded {loaded} setting(s) from {env_file}")

    try:
        registry = TargetRegistry()
    except ConfigError as exc:
        print(f"configuration error: {exc}", file=sys.stderr)
        return 2

    if not len(registry):
        print(
            f"No targets configured. Set FORTIGATE_HOST and FORTIGATE_TOKEN in the environment, "
            f"or put them in {env_file}.",
            file=sys.stderr,
        )
        return 2

    try:
        resolved = registry.resolve(target)
    except ConfigError as exc:
        print(f"{exc}", file=sys.stderr)
        return 2

    server = build_server(registry)
    tools = sorted(await server.list_tools(), key=lambda tool: tool.name)

    print(f"\nValidating {len(tools)} tools against {resolved.name} at {resolved.url}")
    print(f"auth={resolved.auth_mode}  vdom={resolved.vdom}  verify_ssl={resolved.verify_ssl}")
    print("=" * 78)

    results: list[Result] = []
    for tool in tools:
        arguments: dict[str, Any] = dict(TOOL_ARGUMENTS.get(tool.name, {}))
        # list_targets enumerates configuration and takes no target.
        if "target" in tool.parameters.get("properties", {}) and target:
            arguments["target"] = target

        started = time.perf_counter()
        try:
            raw = await server.call_tool(tool.name, arguments)
            payload = _unwrap(raw)
            elapsed = time.perf_counter() - started
            results.append(
                Result(tool.name, True, elapsed, payload=payload, warnings=_inspect(tool.name, payload))
            )
        except Exception as exc:  # noqa: BLE001 - a failing tool is a result, not a crash
            elapsed = time.perf_counter() - started
            results.append(Result(tool.name, False, elapsed, error=f"{type(exc).__name__}: {exc}"))

    for result in results:
        mark = "ok  " if result.ok else "FAIL"
        print(f"\n[{mark}] {result.name}  ({result.seconds:.2f}s)")
        if result.error:
            print(f"       {result.error}")
            continue
        print(f"       {_shape(result.payload)}")
        for warning in result.warnings:
            print(f"       warning: {warning}")
        if verbose:
            rendered = json.dumps(result.payload, indent=2, default=str)
            for line in rendered.splitlines()[:40]:
                print(f"       | {line}")

    failed = [r for r in results if not r.ok]
    warned = [r for r in results if r.ok and r.warnings]
    slowest = max(results, key=lambda r: r.seconds)

    print("\n" + "=" * 78)
    print(f"{len(results) - len(failed)}/{len(results)} tools succeeded")
    if warned:
        print(f"{len(warned)} returned something suspicious: {', '.join(r.name for r in warned)}")
    if failed:
        print(f"{len(failed)} failed: {', '.join(r.name for r in failed)}")
    print(f"slowest: {slowest.name} at {slowest.seconds:.2f}s")

    if failed:
        return 1
    return 3 if warned else 0


def main() -> None:
    """Parse arguments and run the validation."""
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--target", help="Which configured FortiGate to validate against")
    parser.add_argument("--verbose", action="store_true", help="Print the first 40 lines of each payload")
    args = parser.parse_args()
    raise SystemExit(asyncio.run(run(args.target, args.verbose)))


if __name__ == "__main__":
    main()
