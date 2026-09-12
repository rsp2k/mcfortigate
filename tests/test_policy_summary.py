"""What a policy summary must not leave out, and what it must never invert.

A FortiOS 7.0.14 policy carries 147 fields. Reducing that to something a model
can reason about means dropping most of them, and the question is which drops
are safe. Most are: `wanopt-passive-opt` does not change who may talk to whom.
Two classes are not.

**Negation inverts the rule.** With `srcaddr-negate: enable` the policy matches
every source *except* the ones listed. A summary reporting `source: ["LAN"]`
then states the exact opposite of what the appliance enforces, and states it
with the same confidence as a correct answer.

**Internet Service replaces the address.** With `internet-service: enable`
FortiOS ignores `dstaddr` outright and takes the destination from the Internet
Service database instead. Reading `dstaddr` and reporting `destination: all`
describes a rule that does not exist.

Both are silent: the fields sit at their defaults on most policies, so a
summary that ignores them is correct until the day it is catastrophically not.

Field names and values below are from a live FortiWiFi-61E.
"""

from __future__ import annotations

from mcfortigate.fortios import summarize_policy

# A policy as hardware returns it, trimmed to the keys that carry meaning.
# Every value here is a real FortiOS default for this firmware.
BASE = {
    "policyid": 1,
    "name": "policy-1",
    "status": "enable",
    "action": "accept",
    "srcintf": [{"name": "lan"}],
    "dstintf": [{"name": "wan1"}],
    "srcaddr": [{"name": "LAN"}],
    "dstaddr": [{"name": "all"}],
    "service": [{"name": "ALL"}],
    "schedule": "always",
    "srcaddr-negate": "disable",
    "dstaddr-negate": "disable",
    "service-negate": "disable",
    "internet-service": "disable",
    "internet-service-src": "disable",
    "srcaddr6": [],
    "dstaddr6": [],
    "groups": [],
    "users": [],
}


def policy(**overrides) -> dict:
    """A base policy with specific fields overridden."""
    return {**BASE, **overrides}


class TestNegationIsNeverSilent:
    """A negated match must be impossible to read as a positive one."""

    def test_source_negation_is_reported(self):
        """Without this the summary says the opposite of the rule."""
        summary = summarize_policy(policy(**{"srcaddr-negate": "enable"}))
        assert summary.get("source_negated") is True

    def test_destination_negation_is_reported(self):
        summary = summarize_policy(policy(**{"dstaddr-negate": "enable"}))
        assert summary.get("destination_negated") is True

    def test_service_negation_is_reported(self):
        summary = summarize_policy(policy(**{"service-negate": "enable"}))
        assert summary.get("service_negated") is True

    def test_negation_is_absent_rather_than_false(self):
        """The house rule: an absent key, not a false one.

        Most policies negate nothing, and carrying three false booleans on
        every rule trains a reader to skip them, which is exactly when the
        true one arrives.
        """
        summary = summarize_policy(policy())
        assert "source_negated" not in summary
        assert "destination_negated" not in summary
        assert "service_negated" not in summary

    def test_negation_is_spelled_out_in_words(self):
        """A flag beside a list can be skimmed past. A sentence cannot.

        The consumer here is a language model reading a dict, with no rendering
        to make the flag visually prominent, so the inversion is also stated in
        prose.
        """
        summary = summarize_policy(policy(**{"srcaddr-negate": "enable"}))
        note = summary.get("match_note", "").lower()
        assert "except" in note or "not" in note
        assert "source" in note

    def test_the_string_disable_does_not_read_as_negated(self):
        """`bool("disable")` is True, the bug that flipped every route once."""
        summary = summarize_policy(policy(**{"srcaddr-negate": "disable"}))
        assert "source_negated" not in summary


class TestInternetServiceReplacesTheDestination:
    """When enabled, `dstaddr` is not what the rule matches."""

    def test_internet_service_destination_is_reported(self):
        summary = summarize_policy(
            policy(
                **{
                    "internet-service": "enable",
                    "internet-service-name": [{"name": "Microsoft-Office365"}],
                }
            )
        )
        assert "Microsoft-Office365" in summary.get("destination_internet_service", [])

    def test_the_ignored_address_is_flagged_not_reported_as_the_match(self):
        """`dstaddr: all` is live-looking but inert here, so say so.

        Leaving `destination: ["all"]` unqualified beside the real match invites
        the conclusion that this rule reaches everything.
        """
        summary = summarize_policy(
            policy(
                **{
                    "internet-service": "enable",
                    "internet-service-name": [{"name": "Microsoft-Office365"}],
                }
            )
        )
        note = summary.get("match_note", "").lower()
        assert "internet service" in note
        # The point is that the note says the address list does not apply, not
        # that it uses any particular spelling of the field name.
        assert "ignored" in note
        assert "destination" in note

    def test_source_internet_service_is_reported(self):
        summary = summarize_policy(
            policy(
                **{
                    "internet-service-src": "enable",
                    "internet-service-src-name": [{"name": "Github"}],
                }
            )
        )
        assert "Github" in summary.get("source_internet_service", [])

    def test_disabled_internet_service_adds_nothing(self):
        summary = summarize_policy(policy())
        assert "destination_internet_service" not in summary
        assert "match_note" not in summary


class TestScopeThatNarrowsTheRule:
    """Fields that make a policy apply to fewer people than it appears to."""

    def test_identity_groups_are_reported(self):
        """`source: all` plus a user group is not `source: all`."""
        summary = summarize_policy(policy(groups=[{"name": "Contractors"}]))
        assert "Contractors" in summary.get("identity_groups", [])

    def test_users_are_reported(self):
        summary = summarize_policy(policy(users=[{"name": "jdoe"}]))
        assert "jdoe" in summary.get("identity_users", [])

    def test_ipv6_members_are_reported(self):
        """A v4-only summary of a dual-stack rule understates its reach."""
        summary = summarize_policy(policy(srcaddr6=[{"name": "LAN6"}], dstaddr6=[{"name": "any6"}]))
        assert "LAN6" in summary.get("source_v6", [])
        assert "any6" in summary.get("destination_v6", [])

    def test_empty_scope_fields_are_omitted(self):
        summary = summarize_policy(policy())
        for key in ("identity_groups", "identity_users", "source_v6", "destination_v6"):
            assert key not in summary


class TestTheUnsummarizedBackstop:
    """What protects against the next firmware's new field.

    Everything above is a field someone knew to look for. The backstop covers
    the ones nobody did: a key carrying a non-default value that this code has
    never heard of is named rather than dropped, so a rule whose meaning turns
    on it is visible instead of silently misreported.
    """

    def test_an_unknown_non_default_field_is_surfaced(self):
        summary = summarize_policy(policy(**{"some-future-match-field": "enable"}))
        assert "some-future-match-field" in summary.get("unsummarized", {})

    def test_a_real_policy_produces_no_backstop_noise(self):
        """The backstop is worthless if it fires on every policy.

        These are the non-default values a stock FortiOS 7.0.14 policy carries
        and none of them change what the rule matches, so all are allowlisted.
        A backstop that cries wolf on every call gets ignored, which is the
        same as not having one.
        """
        summary = summarize_policy(
            policy(
                **{
                    "reputation-direction": "destination",
                    "firewall-session-dirty": "check-all",
                    "tos": "0x00",
                    "tos-mask": "0x00",
                    "geoip-match": "physical-location",
                    "inspection-mode": "flow",
                    "profile-type": "single",
                    "profile-protocol-options": "default",
                    "ssl-ssh-profile": "no-inspection",
                    "wanopt-detection": "active",
                    "wanopt-passive-opt": "default",
                    "session-ttl": "0",
                    "vlan-cos-fwd": 255,
                    "vlan-cos-rev": 255,
                    "natip": "0.0.0.0 0.0.0.0",
                    "diffservcode-forward": "000000",
                    "diffservcode-rev": "000000",
                    "anti-replay": "enable",
                    "auto-asic-offload": "enable",
                    "np-acceleration": "enable",
                    "outbound": "enable",
                    "uuid": "00000000-0000-0000-0000-000000000000",
                    "q_origin_key": 1,
                }
            )
        )
        assert "unsummarized" not in summary, (
            f"backstop fired on stock fields: {sorted(summary.get('unsummarized', {}))}"
        )

    def test_empty_unknown_fields_do_not_fire(self):
        """An unknown field at its empty default says nothing."""
        summary = summarize_policy(policy(**{"some-future-field": "", "another": []}))
        assert "unsummarized" not in summary
