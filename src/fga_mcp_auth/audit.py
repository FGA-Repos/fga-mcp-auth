"""Per-user audit logging (MCP SDK 2.0 only).

The fleet security audit flagged that the MCP servers have no per-user identity —
a shared password meant every call was anonymous. Now that Okta establishes who is
calling, log it: which person invoked which tool, on which server, and whether it
failed.

Emitted as structured JSON for the BetterStack drain, so "who queried what" is
answerable without shipping a separate audit store.

SDK 1.x has no equivalent middleware tier, so 1.x consumers keep
token-issuance-level logging until they move to 2.0. That is not a regression —
they never had per-call audit.
"""

from __future__ import annotations

import logging
import time
from typing import Any

import jwt

from .constants import SERVICE_CLIENT_ID
from .settings import Settings

logger = logging.getLogger(__name__)


class AuditMiddleware:
    """Logs every inbound MCP request with the authenticated user attached.

    Registered outermost so it observes handler failures too — a tool that raises
    still produces an audit line rather than vanishing.
    """

    def __init__(self, settings: Settings):
        self._settings = settings
        self._secret = settings.secret_value() or ""
        self._server = settings.audience

    def _identify(self) -> dict[str, Any]:
        """Best-effort caller identity. Never raises — auditing must not break calls."""
        try:
            from mcp.server.auth.middleware.auth_context import get_access_token

            token = get_access_token()
        except Exception:
            return {"user": "unknown"}

        if token is None:
            return {"user": "anonymous"}
        if token.client_id == SERVICE_CLIENT_ID:
            return {"user": "service-token", "client_id": token.client_id}

        # Fast path: FGAAccessToken already carries the identity claims, so the
        # common case never re-decodes the JWT.
        email = getattr(token, "email", "") or ""
        sub = getattr(token, "sub", "") or ""
        if email or sub:
            return {"user": email or sub, "okta_sub": sub, "client_id": token.client_id}

        # Fallback: decode the token ourselves. Deliberately lax
        # (verify_aud/verify_iss off) — this is identity extraction for a log
        # line, not authorization. The token already passed real verification in
        # load_access_token or it would not be in the auth context at all.
        try:
            claims = jwt.decode(
                token.token,
                self._secret,
                algorithms=["HS256"],
                options={"verify_aud": False, "verify_iss": False},
            )
        except Exception:
            return {"user": "unknown", "client_id": token.client_id}
        return {
            "user": claims.get("email") or claims.get("sub") or "unknown",
            "okta_sub": claims.get("sub"),
            "client_id": token.client_id,
        }

    async def __call__(self, ctx, call_next):
        method = getattr(ctx, "method", None)
        tool = None
        params = getattr(ctx, "params", None)
        if method == "tools/call" and isinstance(params, dict):
            tool = params.get("name")

        who = self._identify()
        started = time.perf_counter()
        try:
            result = await call_next(ctx)
        except Exception as exc:
            logger.warning(
                "mcp call failed",
                extra={
                    **who,
                    "server": self._server,
                    "mcp_method": method,
                    "tool": tool,
                    "error": type(exc).__name__,
                    "duration_ms": round((time.perf_counter() - started) * 1000, 1),
                    "event_category": "mcp.call.error",
                },
            )
            raise
        # Only tool calls are worth an info line; tools/list runs constantly.
        if tool:
            logger.info(
                "tool call",
                extra={
                    **who,
                    "server": self._server,
                    "mcp_method": method,
                    "tool": tool,
                    "duration_ms": round((time.perf_counter() - started) * 1000, 1),
                    "event_category": "mcp.call",
                },
            )
        return result
