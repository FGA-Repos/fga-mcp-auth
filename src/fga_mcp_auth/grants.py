"""Token-endpoint grant handlers, and the seam a future grant slots into.

The SDK owns the `/token` route and calls provider protocol methods per grant
type, so there is no dispatch table in the request path today. This module
exists anyway: grant logic lives here as free functions over an explicit
`GrantContext` (no provider internals), and the provider methods are two-line
delegates.

That is the Enterprise Managed Auth door. When Anthropic's jwt-bearer grant
(`urn:ietf:params:oauth:grant-type:jwt-bearer`) becomes available, it lands as
`grants_jwt_bearer.py`, one GRANT_HANDLERS entry, and a mount that routes that
grant_type to it — with nothing in this file changing.

The mount is the part with a trap in it, so it is written down here rather than
rediscovered later. `mcp.custom_route("/token")` does NOT work: both SDK lines
append custom routes AFTER the SDK's own auth routes, and Starlette matches
first-route-wins, so the SDK's `/token` permanently shadows a custom one.
Verified on mcp 1.29.1 (`create_auth_routes` at fastmcp/server.py:881,
`routes.extend(self._custom_starlette_routes)` at :950) and on mcp 2.1.0
(mcpserver/server.py:1192 and :1259); pinned by
`test_a_custom_token_route_cannot_shadow_the_sdk_one` in both wiring suites, so
an upstream reordering shows up as a failing test rather than a stale comment.
Two mounts that do work, both outside this module:

  * ASGI middleware wrapped around the built app, peeking `grant_type` on
    POST /token and handling jwt-bearer itself; or
  * reordering `app.routes` after `streamable_http_app()` so ours precedes the
    SDK's.

Either way the SDK's handler also rejects a grant_type absent from the
registered client's `grant_types` (token.py:121), so a DCR client would have to
carry the jwt-bearer URN before the SDK path could ever be reached.

Deliberately NOT implemented now: it is waitlist-gated. Only the seam ships.

RFC 8707 `resource` is already carried through pending state and auth codes, so
no DCR assumption is baked into the token shape either.
"""

from __future__ import annotations

import logging
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from mcp.server.auth.provider import TokenError
from mcp.shared.auth import OAuthClientInformationFull, OAuthToken

from .constants import ACCESS_TTL, REFRESH_TTL
from .settings import Settings
from .tokens import InvalidTokenFormat, user_from_claims

logger = logging.getLogger(__name__)


@dataclass
class GrantContext:
    """Everything a grant handler needs, and nothing about who called it."""

    settings: Settings
    mint: Callable[..., str]
    now: Callable[[], int] = lambda: int(time.time())


async def authorization_code_grant(
    ctx: GrantContext,
    client: OAuthClientInformationFull,
    scopes: list[str],
    identity: dict[str, Any] | None,
) -> OAuthToken:
    """Auth code -> access + refresh.

    `identity` is the verified Okta identity recorded when the code was minted.
    None means the code exists but has no identity attached: fail closed.
    Defaulting to {} here would mint a fully-valid token for an anonymous
    session with full access, which is worse than an error. No path reaches it
    today; the failure mode is what matters.
    """
    if identity is None:
        logger.error("Auth code had no associated identity; refusing to issue a token")
        raise TokenError("invalid_grant", "Authorization code is not associated with a user.")

    logger.info(
        "Issued tokens",
        extra={
            "client_id": client.client_id,
            "user": identity.get("email", "?"),
            "server": ctx.settings.audience,
            "event_category": "auth.token.issued",
        },
    )
    return OAuthToken(
        access_token=ctx.mint("access", client.client_id, scopes, identity, ACCESS_TTL),
        token_type="Bearer",
        expires_in=ACCESS_TTL,
        refresh_token=ctx.mint("refresh", client.client_id, scopes, identity, REFRESH_TTL),
    )


async def refresh_token_grant(
    ctx: GrantContext,
    client: OAuthClientInformationFull,
    verify: Callable[[str], dict[str, Any] | None],
    refresh_token: str,
    scopes: list[str],
) -> OAuthToken:
    """Refresh -> a new pair, on the ORIGINAL horizon.

    Non-sliding on purpose: refresh re-mints from the token's own claims and
    never re-contacts Okta, so a sliding expiry would let a deactivated account
    renew itself forever. REFRESH_TTL is therefore literally the offboarding
    tail, and this function is what keeps it bounded.

    Both failure modes of `verify` are fatal here, for the same reason as in
    authorization_code_grant: no claims means no identity, and minting from an
    empty claim set would hand out a valid 1h access token for an anonymous
    session. Worse, its refresh partner would floor at 60s and verify cleanly
    on the next round trip, so the anonymous pair could be renewed every 60
    seconds forever — an expired refresh token laundered into a permanent
    session, and the end of the offboarding guarantee this docstring makes.
    """
    try:
        claims = verify(refresh_token)
    except InvalidTokenFormat as exc:
        # RFC-compliant: claude.ai renders invalid_grant as an inline Connect
        # card and retries the tool call, so a token-format change costs one
        # click rather than a 500 and a lost conversation.
        raise TokenError("invalid_grant", "Token format not recognized; re-authenticate.") from exc

    if claims is None:
        # Reachable: the SDK checks expiry against the snapshot taken by
        # load_refresh_token, and the token can cross its `exp` between that
        # check and this re-verification.
        logger.info(
            "Refresh token failed verification at exchange; refusing to re-mint",
            extra={
                "client_id": client.client_id,
                "server": ctx.settings.audience,
                "event_category": "auth.refresh.rejected",
            },
        )
        raise TokenError("invalid_grant", "Refresh token is not valid; re-authenticate.")

    user = user_from_claims(claims)
    remaining = max(60, int(claims.get("exp", 0)) - ctx.now())
    return OAuthToken(
        access_token=ctx.mint("access", client.client_id, scopes, user, ACCESS_TTL),
        token_type="Bearer",
        expires_in=ACCESS_TTL,
        refresh_token=ctx.mint("refresh", client.client_id, scopes, user, remaining),
    )


GRANT_HANDLERS: dict[str, Callable[..., Any]] = {
    "authorization_code": authorization_code_grant,
    "refresh_token": refresh_token_grant,
    # EMA v-next: "urn:ietf:params:oauth:grant-type:jwt-bearer": jwt_bearer.grant
}
