from __future__ import annotations

import pytest

from app.version_review import (
    parse_version_observations,
    review_descriptions,
    validate_review_entries,
)


def test_version_review_preserves_ambiguous_and_unidentified_versions():
    entries = parse_version_observations(
        """
21/tcp open ftp vsftpd 2.0.8 or later
53/tcp open domain Unbound
80/tcp open http Apache httpd 2.4.58
"""
    )

    assert [entry["port"] for entry in entries] == [21, 53, 80]
    assert entries[0]["product"] == "vsftpd"
    assert entries[0]["version"] == "2.0.8 or later"
    assert entries[0]["confidence"] == "ambiguous"
    assert entries[0]["reviewable"] is False
    assert entries[1]["version"] == "Version not identified"
    assert entries[1]["reviewable"] is False
    assert entries[2]["product"] == "Apache"
    assert entries[2]["version"] == "httpd 2.4.58"


def test_version_review_rejects_unknown_or_unreviewed_entries():
    entries = parse_version_observations("22/tcp open ssh OpenSSH 9.6")
    with pytest.raises(ValueError, match="unknown software entry"):
        validate_review_entries(entries, ["not-real"], [])
    with pytest.raises(ValueError, match="Review every entry"):
        validate_review_entries(entries, [], [])


def test_version_review_descriptions_are_two_client_ready_lines():
    entries = parse_version_observations("21/tcp open ftp vsftpd 2.0.8")
    found = review_descriptions("outdated", entries, [])
    negative = review_descriptions("none_outdated", entries, [])
    assert len(found) == len(negative) == 2
    assert all(line and "Nmap" not in line and "21.0.2.8" not in line for line in found + negative)
