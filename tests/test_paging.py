"""What a bounded response must tell the caller.

The hazard is a silently short answer. An unbounded response that a client
truncates on the way to the model is indistinguishable, to the model, from a
complete one, so "which hosts are on this subnet" gets answered confidently
from whatever fraction survived. Bounding here is the cheap part; saying so in
the payload is the part that matters.
"""

from __future__ import annotations

import pytest

from mcfortigate.paging import DEFAULT_LIMIT, MAX_LIMIT, paginate


class TestCompleteResults:
    """A result that is all of them must be recognizable as all of them."""

    def test_short_list_is_not_marked_truncated(self):
        _, fields = paginate([1, 2, 3])
        assert "truncated" not in fields
        assert "next_offset" not in fields

    def test_total_available_matches_count_when_complete(self):
        """The reader's positive signal that nothing is missing."""
        window, fields = paginate(list(range(7)))
        assert fields["count"] == fields["total_available"] == len(window) == 7

    def test_empty_table_is_complete_not_truncated(self):
        window, fields = paginate([])
        assert window == []
        assert fields == {"count": 0, "total_available": 0}


class TestTruncatedResults:
    """A partial result must carry how to get the rest."""

    def test_window_is_bounded(self):
        window, _ = paginate(list(range(500)), limit=10)
        assert window == list(range(10))

    def test_truncation_is_declared(self):
        _, fields = paginate(list(range(500)), limit=10)
        assert fields["truncated"] is True
        assert fields["total_available"] == 500

    def test_next_offset_resumes_exactly(self):
        """Off-by-one here silently drops or duplicates a row."""
        first, fields = paginate(list(range(25)), limit=10)
        second, _ = paginate(list(range(25)), limit=10, offset=fields["next_offset"])
        assert first + second == list(range(20))

    def test_paging_note_warns_against_reading_it_as_whole(self):
        """The flag is for code, the sentence is for the model reading the dict."""
        _, fields = paginate(list(range(500)), limit=10)
        note = fields["paging_note"].lower()
        assert "offset=10" in note
        assert "whole" in note or "rest" in note

    def test_exact_fit_is_not_truncated(self):
        """The boundary case: a window that ends exactly at the end."""
        _, fields = paginate(list(range(10)), limit=10)
        assert "truncated" not in fields
        assert "next_offset" not in fields


class TestDefaultsAndLimits:
    """The default is the whole point, since most callers pass nothing."""

    def test_default_limit_applies_when_unspecified(self):
        window, fields = paginate(list(range(DEFAULT_LIMIT + 50)))
        assert len(window) == DEFAULT_LIMIT
        assert fields["truncated"] is True

    def test_maximum_limit_is_enforced(self):
        """A caller asking for everything is exactly the case this guards."""
        window, fields = paginate(list(range(MAX_LIMIT + 500)), limit=100_000)
        assert len(window) == MAX_LIMIT
        assert "maximum" in fields["paging_note"]


class TestOutOfRangeArgumentsAreCorrectedNotRejected:
    """A model's bad guess should cost a row, not end the task."""

    @pytest.mark.parametrize("bad_offset", [-1, -500])
    def test_negative_offset_reads_as_zero(self, bad_offset):
        window, fields = paginate(list(range(5)), limit=2, offset=bad_offset)
        assert window == [0, 1]
        assert "negative" in fields["paging_note"]

    @pytest.mark.parametrize("bad_limit", [0, -10])
    def test_non_positive_limit_falls_back_to_default(self, bad_limit):
        window, fields = paginate(list(range(5)), limit=bad_limit)
        assert window == list(range(5))
        assert "default" in fields["paging_note"]

    def test_offset_past_the_end_explains_itself(self):
        """An empty window with 4000 total looks like a bug until it is explained."""
        window, fields = paginate(list(range(12)), offset=5000)
        assert window == []
        assert fields["total_available"] == 12
        assert "past the end" in fields["paging_note"]

    def test_offset_past_the_end_is_not_marked_truncated(self):
        """There is nothing further on, so offering a next_offset would loop."""
        _, fields = paginate(list(range(12)), offset=5000)
        assert "truncated" not in fields
        assert "next_offset" not in fields
