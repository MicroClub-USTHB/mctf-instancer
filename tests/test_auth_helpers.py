"""Unit tests for CTFd member-normalization helpers.

CTFd returns team members in several shapes across versions (bare list,
`{members: [...]}`, nested `{user: {...}}`, numeric ids, etc.). These helpers
flatten all of them to `[{'id', 'name'}]`; the tests pin that behavior since
it feeds team display and, indirectly, team scoping.
"""
from app.auth import CTFdAuth


def test_extract_rows_from_bare_list():
    rows = CTFdAuth._extract_member_rows([{"id": 1, "name": "a"}])
    assert rows == [{"id": 1, "name": "a"}]


def test_extract_rows_from_wrapped_keys():
    assert CTFdAuth._extract_member_rows({"members": [{"id": 1}]}) == [{"id": 1}]
    assert CTFdAuth._extract_member_rows({"data": {"users": [{"id": 2}]}}) == [{"id": 2}]


def test_extract_rows_from_unknown_shape_is_empty():
    assert CTFdAuth._extract_member_rows(42) == []
    assert CTFdAuth._extract_member_rows({"nope": "x"}) == []


def test_normalize_nested_user_objects():
    raw = [{"user": {"id": 7, "username": "alice"}}]
    out = CTFdAuth._normalize_team_members(raw)
    assert out == [{"id": "7", "name": "alice"}]


def test_normalize_prefers_name_over_username():
    raw = [{"id": 3, "name": "Real Name", "username": "handle"}]
    out = CTFdAuth._normalize_team_members(raw)
    assert out == [{"id": "3", "name": "Real Name"}]


def test_normalize_dedupes_identical_members():
    raw = [{"id": 1, "name": "a"}, {"id": 1, "name": "a"}]
    out = CTFdAuth._normalize_team_members(raw)
    assert out == [{"id": "1", "name": "a"}]


def test_normalize_scalar_members():
    # A list of plain names or ids should still normalize to id/name pairs.
    out = CTFdAuth._normalize_team_members(["bob", 5])
    assert {"id": "bob", "name": "bob"} in out
    assert {"id": "5", "name": "5"} in out


def test_normalize_empty_inputs():
    assert CTFdAuth._normalize_team_members(None) == []
    assert CTFdAuth._normalize_team_members([]) == []
