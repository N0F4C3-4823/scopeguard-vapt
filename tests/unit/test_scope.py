import pytest

from app.scope import ScopeError, parse_scope


def test_scope_normalizes_and_deduplicates_targets():
    targets = parse_scope(["192.0.2.10", "192.0.2.10", "Example.ORG", "2001:db8::1"], [], 256)
    assert [target.value for target in targets] == ["192.0.2.10", "example.org", "2001:db8::1"]


def test_scope_bounds_cidr_and_applies_exclusions():
    targets = parse_scope(["192.0.2.0/30", "fixture://mixed"], ["fixture://mixed"], 4)
    assert targets[0].kind == "cidr"
    assert targets[0].host_count == 4
    with pytest.raises(ScopeError, match="maximum"):
        parse_scope(["192.0.2.0/24"], [], 16)


def test_scope_rejects_invalid_and_empty_effective_scope():
    with pytest.raises(ScopeError):
        parse_scope(["not a host"], [], 256)
    with pytest.raises(ScopeError, match="All targets"):
        parse_scope(["192.0.2.10"], ["192.0.2.10"], 256)
