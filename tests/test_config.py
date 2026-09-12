"""Tests for target configuration and resolution."""

from __future__ import annotations

import pytest

from mcfortigate.config import (
    ConfigError,
    FortiGateTarget,
    TargetRegistry,
    load_targets,
    parse_host_url,
)


class TestParseHostUrl:
    def test_https_url(self):
        assert parse_host_url("https://fgt.example.com") == ("fgt.example.com", None, "https")

    def test_url_with_port_and_trailing_slash(self):
        assert parse_host_url("https://fgt:8443/") == ("fgt", 8443, "https")

    def test_bare_hostname_assumes_https(self):
        assert parse_host_url("fgt.example.com") == ("fgt.example.com", None, "https")

    def test_explicit_http(self):
        assert parse_host_url("http://fgt.lab:8080") == ("fgt.lab", 8080, "http")

    def test_bare_ip(self):
        assert parse_host_url("192.0.2.10") == ("192.0.2.10", None, "https")

    def test_empty_is_rejected(self):
        with pytest.raises(ConfigError):
            parse_host_url("   ")


class TestFortiGateTarget:
    def test_token_auth(self):
        target = FortiGateTarget(name="edge", host="fgt.example.com", token="secret")
        assert target.auth_mode == "token"

    def test_username_password_auth(self):
        target = FortiGateTarget(name="edge", host="fgt.example.com", username="ro", password="pw")
        assert target.auth_mode == "username+password"

    def test_no_credentials_is_rejected(self):
        with pytest.raises(ConfigError, match="no usable credentials"):
            FortiGateTarget(name="edge", host="fgt.example.com")

    def test_username_without_password_is_rejected(self):
        with pytest.raises(ConfigError):
            FortiGateTarget(name="edge", host="fgt.example.com", username="ro")

    def test_url_includes_port_when_set(self):
        target = FortiGateTarget(name="e", host="fgt", port=8443, token="x")
        assert target.url == "https://fgt:8443"

    def test_url_omits_default_port(self):
        assert FortiGateTarget(name="e", host="fgt", token="x").url == "https://fgt"

    def test_describe_never_leaks_credentials(self):
        target = FortiGateTarget(name="edge", host="fgt", token="super-secret", password="also-secret")
        described = repr(target.describe())
        assert "super-secret" not in described
        assert "also-secret" not in described

    def test_repr_never_leaks_credentials(self):
        target = FortiGateTarget(name="edge", host="fgt", token="super-secret")
        assert "super-secret" not in repr(target)


class TestLoadTargets:
    def test_single_target_from_host_and_token(self):
        targets = load_targets({"FORTIGATE_HOST": "fgt.example.com", "FORTIGATE_TOKEN": "abc"})
        assert list(targets) == ["fgt.example.com"]
        assert targets["fgt.example.com"].token == "abc"

    def test_explicit_name_overrides_host_as_alias(self):
        targets = load_targets(
            {"FORTIGATE_HOST": "fgt.example.com", "FORTIGATE_TOKEN": "abc", "FORTIGATE_NAME": "edge"}
        )
        assert list(targets) == ["edge"]

    def test_verify_ssl_accepts_the_usual_spellings(self):
        for raw, expected in (("false", False), ("FALSE", False), ("0", False), ("no", False), ("true", True)):
            targets = load_targets({"FORTIGATE_HOST": "fgt", "FORTIGATE_TOKEN": "abc", "FORTIGATE_VERIFY_SSL": raw})
            assert targets["fgt"].verify_ssl is expected

    def test_verify_ssl_defaults_to_on(self):
        targets = load_targets({"FORTIGATE_HOST": "fgt", "FORTIGATE_TOKEN": "abc"})
        assert targets["fgt"].verify_ssl is True

    def test_port_in_url_is_picked_up(self):
        targets = load_targets({"FORTIGATE_HOST": "https://fgt:8443", "FORTIGATE_TOKEN": "abc"})
        assert targets["fgt"].port == 8443

    def test_explicit_port_env_wins_over_url(self):
        targets = load_targets(
            {"FORTIGATE_HOST": "https://fgt:8443", "FORTIGATE_TOKEN": "abc", "FORTIGATE_PORT": "9443"}
        )
        assert targets["fgt"].port == 9443

    def test_multi_target_json(self):
        targets = load_targets(
            {
                "FORTIGATE_TARGETS": (
                    '{"edge": {"host": "fgt-edge.example.com", "token": "a"},'
                    ' "branch": {"host": "fgt-br.example.com", "token": "b", "verify_ssl": false}}'
                )
            }
        )
        assert sorted(targets) == ["branch", "edge"]
        assert targets["branch"].verify_ssl is False

    def test_both_styles_can_coexist(self):
        targets = load_targets(
            {
                "FORTIGATE_TARGETS": '{"edge": {"host": "fgt-edge.example.com", "token": "a"}}',
                "FORTIGATE_HOST": "fgt-lab.example.com",
                "FORTIGATE_TOKEN": "b",
                "FORTIGATE_NAME": "lab",
            }
        )
        assert sorted(targets) == ["edge", "lab"]

    def test_malformed_json_is_rejected_clearly(self):
        with pytest.raises(ConfigError, match="not valid JSON"):
            load_targets({"FORTIGATE_TARGETS": "{nope"})

    def test_json_array_is_rejected(self):
        with pytest.raises(ConfigError, match="JSON object"):
            load_targets({"FORTIGATE_TARGETS": '["edge"]'})

    def test_entry_without_host_is_rejected(self):
        with pytest.raises(ConfigError, match="missing a 'host' key"):
            load_targets({"FORTIGATE_TARGETS": '{"edge": {"token": "a"}}'})

    def test_empty_environment_yields_no_targets(self):
        assert load_targets({}) == {}


class TestTargetRegistry:
    @staticmethod
    def _registry(**targets: FortiGateTarget) -> TargetRegistry:
        return TargetRegistry(dict(targets))

    def test_sole_target_resolves_without_being_named(self):
        registry = self._registry(edge=FortiGateTarget(name="edge", host="fgt", token="x"))
        assert registry.resolve().name == "edge"

    def test_named_target_resolves(self):
        registry = self._registry(
            edge=FortiGateTarget(name="edge", host="a", token="x"),
            branch=FortiGateTarget(name="branch", host="b", token="y"),
        )
        assert registry.resolve("branch").name == "branch"

    def test_ambiguous_resolution_lists_the_choices(self):
        registry = self._registry(
            edge=FortiGateTarget(name="edge", host="a", token="x"),
            branch=FortiGateTarget(name="branch", host="b", token="y"),
        )
        with pytest.raises(ConfigError) as exc:
            registry.resolve()
        message = str(exc.value)
        assert "branch" in message and "edge" in message

    def test_unknown_target_lists_the_choices(self):
        registry = self._registry(edge=FortiGateTarget(name="edge", host="a", token="x"))
        with pytest.raises(ConfigError) as exc:
            registry.resolve("nope")
        assert "edge" in str(exc.value)

    def test_empty_registry_explains_how_to_configure(self):
        registry = TargetRegistry({})
        with pytest.raises(ConfigError, match="FORTIGATE_HOST"):
            registry.resolve()

    def test_names_are_sorted(self):
        registry = self._registry(
            zed=FortiGateTarget(name="zed", host="a", token="x"),
            alpha=FortiGateTarget(name="alpha", host="b", token="y"),
        )
        assert registry.names == ["alpha", "zed"]


class TestNumericSettingsFailReadably:
    """A bad number in .env must name the setting, not just the literal.

    The bare `int()` these replace raised "invalid literal for int() with base
    10: '30s'" from inside startup, which tells an operator nothing about which
    variable to change. Units in the value are the normal mistake, since these
    are seconds and people write seconds as `30s`.
    """

    def test_timeout_with_units_names_the_variable(self):
        with pytest.raises(ConfigError) as caught:
            load_targets({"FORTIGATE_HOST": "fgt.example", "FORTIGATE_TOKEN": "x", "FORTIGATE_TIMEOUT": "30s"})
        assert "FORTIGATE_TIMEOUT" in str(caught.value)
        assert "30s" in str(caught.value)

    def test_port_with_junk_names_the_variable(self):
        with pytest.raises(ConfigError) as caught:
            load_targets({"FORTIGATE_HOST": "fgt.example", "FORTIGATE_TOKEN": "x", "FORTIGATE_PORT": "https"})
        assert "FORTIGATE_PORT" in str(caught.value)

    def test_a_per_target_bad_number_names_that_target(self):
        """With several appliances, which one failed is the useful half."""
        with pytest.raises(ConfigError) as caught:
            load_targets({"FORTIGATE_TARGETS": '{"branch": {"host": "b.example", "token": "x", "timeout": "abc"}}'})
        assert "branch" in str(caught.value)

    def test_empty_value_falls_back_to_the_default(self):
        """`FORTIGATE_TIMEOUT=` with nothing after it is not an error."""
        targets = load_targets({"FORTIGATE_HOST": "fgt.example", "FORTIGATE_TOKEN": "x", "FORTIGATE_TIMEOUT": ""})
        assert next(iter(targets.values())).timeout == 30

    def test_a_good_value_still_works(self):
        targets = load_targets({"FORTIGATE_HOST": "fgt.example", "FORTIGATE_TOKEN": "x", "FORTIGATE_TIMEOUT": " 45 "})
        assert next(iter(targets.values())).timeout == 45
