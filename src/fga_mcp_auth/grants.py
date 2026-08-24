"""Token-endpoint grant handlers, and the seam a future grant slots into.

The SDK owns the `/token` route and calls provider protocol methods per grant
type, so there is no dispatch table in the request path today. This module
exists anyway: grant logic lives here as free functions over an explicit
`GrantContext` (no provider internals), and the provider methods are two-line
delegates.

That is the Enterprise Managed Auth door. When Anthropic's jwt-bearer grant
(`urn:ietf:params:oauth:grant-type:jwt-bearer`) becomes available, it lands as
`grants_jwt_bearer.py`, one GRANT_HANDLERS entry, and a thin custom `/token`
pre-route that peeks `grant_type`, dispatches jwt-bearer itself, and falls
through to the SDK handler otherwise — with nothing in this file changing.
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
    """
    try:
        claims = verify(refresh_token) or {}
    except InvalidTokenFormat as exc:
        # RFC-compliant: claude.ai renders invalid_grant as an inline Connect
        # card and retries the tool call, so a token-format change costs one
        # click rather than a 500 and a lost conversation.
        raise TokenError("invalid_grant", "Token format not recognized; re-authenticate.") from exc

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
