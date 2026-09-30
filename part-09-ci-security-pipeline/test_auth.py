"""
test_auth.py
Unit tests for require_permission() in part-02-fastapi-api/auth.py.

These tests call the inner permission_checker function directly with a
fake token payload, bypassing FastAPI's dependency injection and the
network-dependent verify_token step entirely. That is deliberate: this
suite tests the permission logic in isolation, fast and without any
Auth0 credentials, so it can run in CI on every push.

To run locally:
    cd part-02-fastapi-api
    pip install pytest
    pytest ../part-09-ci-security-pipeline/test_auth.py
"""

import asyncio
import sys
from pathlib import Path

import pytest
from fastapi import HTTPException

# part-02's auth.py is imported directly; this test file expects to be
# run with part-02-fastapi-api on the Python path (see the CI workflow
# and the "To run locally" instructions above).
sys.path.insert(0, str(Path(__file__).parent.parent / "part-02-fastapi-api"))
from auth import require_permission  # noqa: E402


def run(coro):
    return asyncio.run(coro)


def test_allows_when_permission_present_in_permissions_claim():
    checker = require_permission("read:protected")
    payload = {"permissions": ["read:protected"], "scope": ""}
    result = run(checker(payload))
    assert result == payload


def test_allows_when_permission_present_in_scope_claim():
    checker = require_permission("read:protected")
    payload = {"permissions": [], "scope": "read:protected openid"}
    result = run(checker(payload))
    assert result == payload


def test_denies_when_permission_missing_from_both_claims():
    checker = require_permission("read:sensitive")
    payload = {"permissions": ["read:protected"], "scope": "openid"}
    with pytest.raises(HTTPException) as exc_info:
        run(checker(payload))
    assert exc_info.value.status_code == 403


def test_denies_when_token_payload_is_empty():
    checker = require_permission("read:protected")
    payload = {}
    with pytest.raises(HTTPException) as exc_info:
        run(checker(payload))
    assert exc_info.value.status_code == 403


def test_does_not_grant_a_different_permission():
    """A token permitted for one scope must not pass a check for another --
    this is the exact bug class permission systems most often ship by
    accident, so it gets its own explicit test."""
    checker = require_permission("read:sensitive")
    payload = {"permissions": ["read:protected", "write:protected"], "scope": ""}
    with pytest.raises(HTTPException) as exc_info:
        run(checker(payload))
    assert exc_info.value.status_code == 403