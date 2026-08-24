"""T6 — per-user audit logging.

Neither source repo tested audit.py at all. It is the answer to "who queried
what", which is the whole point of the Okta retrofit, so it gets tests here.

The middleware itself is plain async and does not import anything SDK-2.0-only
until it runs, so these tests are part of the shared suite and run on both legs
of the matrix.
"""

from __future__ import annotations

import logging
from types import SimpleNamespace

import pytest
from conftest import SECRET, make_settings
from mcp.server.auth.middleware.auth_context import auth_context_var
from mcp.server.auth.middleware.bearer_auth import AuthenticatedUser
from test_group_gate import as_caller, user_token

from fga_mcp_auth import SERVICE_CLIENT_ID, FGAAccessToken
from fga_mcp_auth.audit import AuditMiddleware


def ctx(method: str = "tools/call", tool: str | None = "get_bill"):
    params = {"name": tool} if tool is not None else None
    return SimpleNamespace(method=method, params=params)


async def ok(_ctx):
    return {"ok": True}


async def boom(_ctx):
    raise ValueError("upstream exploded")


@pytest.fixture
def middleware():
    return AuditMiddleware(make_settings())


class TestIdentity:
    async def test_identified_user_on_a_tool_call(self, middleware, caplog):
        with caplog.at_level(logging.INFO), as_caller(user_token("Everyone")):
            assert await middleware(ctx(), ok) == {"ok": True}
        record = _last(caplog, "tool call")
        assert record.user == "staff@example.org"
        assert record.tool == "get_bill"
        assert record.event_category == "mcp.call"

    async def test_service_token_is_named_as_such(self, middleware, caplog):
        with caplog.at_level(logging.INFO), as_caller(user_token(client_id=SERVICE_CLIENT_ID)):
            await middleware(ctx(), ok)
        assert _last(caplog, "tool call").user == "service-token"

    async def test_anonymous_when_no_token_is_bound(self, middleware, caplog):
        with caplog.at_level(logging.INFO), as_caller(None):
            await middleware(ctx(), ok)
        assert _last(caplog, "tool call").user == "anonymous"

    async def test_falls_back_to_decoding_a_bare_access_token(self, caplog):
        """A plain SDK AccessToken (no identity attributes) still gets a name,
        by decoding the JWT the same way the token was minted."""
        from mcp.server.auth.provider import AccessToken

        from fga_mcp_auth import tokens

        settings = make_settings()
        jwt_token = tokens.mint(
            secret=SECRET,
            issuer=settings.issuer,
            audience=settings.audience,
            kind="access",
            client_id="claude-client",
            scopes=[],
            user={"sub": "00u9", "email": "other@example.org"},
            ttl=60,
        )
        bare = AccessToken(token=jwt_token, client_id="claude-client", scopes=[], expires_at=None)
        with caplog.at_level(logging.INFO), as_caller(bare):
            await AuditMiddleware(settings)(ctx(), ok)
        record = _last(caplog, "tool call")
        assert record.user == "other@example.org"
        assert record.okta_sub == "00u9"

    async def test_unknown_when_the_token_cannot_be_decoded(self, middleware, caplog):
        from mcp.server.auth.provider import AccessToken

        bare = AccessToken(token="garbage", client_id="claude-client", scopes=[], expires_at=None)
        with caplog.at_level(logging.INFO), as_caller(bare):
            await middleware(ctx(), ok)
        assert _last(caplog, "tool call").user == "unknown"

    def test_identify_never_raises(self, middleware):
        """Auditing must not be able to break a call. A token object whose
        attributes blow up is the cheapest way to prove the guard holds."""

        class Hostile:
            client_id = "claude-client"
            scopes: list[str] = []

            @property
            def token(self):
                raise RuntimeError("boom")

        reset = auth_context_var.set(AuthenticatedUser(Hostile()))
        try:
            assert middleware._identify()["user"] == "unknown"
        finally:
            auth_context_var.reset(reset)


class TestRecordShape:
    async def test_record_carries_the_server_slug(self, middleware, caplog):
        """One MCP_SERVER_SLUG does both jobs: the token `aud` and this field, so
        a shared log drain can tell the seven servers apart."""
        with caplog.at_level(logging.INFO), as_caller(user_token()):
            await middleware(ctx(), ok)
        assert _last(caplog, "tool call").server == "fga-quorum"

    async def test_tools_list_is_not_info_logged(self, middleware, caplog):
        """tools/list runs constantly; logging it would drown the drain."""
        with caplog.at_level(logging.INFO), as_caller(user_token()):
            await middleware(ctx(method="tools/list", tool=None), ok)
        assert not [r for r in caplog.records if r.getMessage() == "tool call"]

    async def test_duration_is_recorded(self, middleware, caplog):
        with caplog.at_level(logging.INFO), as_caller(user_token()):
            await middleware(ctx(), ok)
        assert _last(caplog, "tool call").duration_ms >= 0


class TestFailurePath:
    async def test_failure_is_audited_and_re_raised(self, middleware, caplog):
        """Registered outermost so a tool that raises still produces an audit
        line rather than vanishing — and the exception must still propagate."""
        with (
            caplog.at_level(logging.WARNING),
            as_caller(user_token()),
            pytest.raises(ValueError, match="upstream exploded"),
        ):
            await middleware(ctx(), boom)
        record = _last(caplog, "mcp call failed")
        assert record.error == "ValueError"
        assert record.tool == "get_bill"
        assert record.event_category == "mcp.call.error"

    async def test_non_tool_failures_are_audited_too(self, middleware, caplog):
        with (
            caplog.at_level(logging.WARNING),
            as_caller(user_token()),
            pytest.raises(ValueError),
        ):
            await middleware(ctx(method="resources/list", tool=None), boom)
        assert _last(caplog, "mcp call failed").mcp_method == "resources/list"


class TestResultPassthrough:
    async def test_the_handler_result_is_returned_unchanged(self, middleware):
        sentinel = {"content": [{"type": "text", "text": "hi"}]}

        async def handler(_ctx):
            return sentinel

        with as_caller(user_token()):
            assert await middleware(ctx(), handler) is sentinel

    async def test_context_is_passed_through_untouched(self, middleware):
        seen = {}

        async def handler(received):
            seen["ctx"] = received
            return None

        given = ctx()
        with as_caller(user_token()):
            await middleware(given, handler)
        assert seen["ctx"] is given


def _last(caplog, message: str):
    matches = [r for r in caplog.records if r.getMessage() == message]
    assert matches, f"no {message!r} record in {[r.getMessage() for r in caplog.records]}"
    return matches[-1]


def _unused() -> FGAAccessToken:  # pragma: no cover - keeps the import honest
    return user_token()
