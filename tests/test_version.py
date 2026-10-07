"""Package version metadata."""

from __future__ import annotations

import asn_filter
from asn_filter import get_version


def test_version_is_semver_like() -> None:
    assert isinstance(asn_filter.__version__, str)
    parts = asn_filter.__version__.split(".")
    assert len(parts) >= 2
    assert all(part.isdigit() for part in parts[:2])


def test_get_version_matches_dunder() -> None:
    assert get_version() == asn_filter.__version__
