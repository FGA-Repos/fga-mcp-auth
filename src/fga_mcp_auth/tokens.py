"""Our own token format: stateless HS256 JWTs that ARE the session.

There is no server-side store to check a token against — DO App Platform
redeploys on every push, and in-memory tokens logged every staff session out on
each deploy. So the signature, `iss`, `aud`, `typ` and `v` are the entire trust
boundary.

# shortcut: stateless tokens cannot be revoked before they expire, and stateless
# refresh rotation cannot detect replay of an old refresh token. Access TTL is
# kept short (1h) to bound the first; the second is accepted. Upgrade path if it
# matters: a jti denylist in Postgres, or rotate MCP_TOKEN_SECRET to invalidate
# every token at once.

Two claims exist here that neither source server had:

  `aud`  the canonical server slug. Seven FGA MCP servers share one Okta app and
         may be handed the same MCP_TOKEN_SECRET by an admin taking a shortcut.
         Before `aud`, the only boundary between them was `iss` — and `iss` falls
         back to http://localhost:<port> on every one of them if MCP_ALLOWED_HOST
         is unset. `aud` plus a boot-required MCP_SERVER_SLUG closes that.

  `v`    the token format version. An unrecognized version raises
         InvalidTokenFormat, which callers turn into a 401 or an RFC-compliant
         `invalid_grant` — never a 500. That makes a future claim-set change
         degrade to a one-click re-auth in claude.ai instead of an outage.

Both are in REQUIRED_CLAIMS, and that has a one-time deploy cost worth stating
plainly rather than discovering: fga-quorum-mcp and fga-ob3-mcp are LIVE and
mint neither claim, so the first deploy that takes this package rejects every
token they have already issued. Every connected staff member is asked to
reconnect, at once, when the deploy lands.

It degrades gracefully — a legacy access token is a 401 + WWW-Authenticate and
a legacy refresh is `invalid_grant`, both of which claude.ai renders as an
inline Connect card and retries, and the static MCP_BEARER_TOKEN path
(socialbot, scripts) is untouched — but it is NOT behavior-identical, so it is
Jacob's call to accept, not an implementation detail. TestLegacyTokenRejection
pins the shape of the failure, and it belongs in both retrofit PR bodies as a
deploy-timing note (off-peak, announced).

If a silent cutover is preferred instead, `MCP_ACCEPT_LEGACY_TOKENS=true` is the
transition build: `aud` and `v` drop out of the required set and a token missing
them is read as format v1, so live sessions survive the deploy and re-mint
themselves with both claims on their next refresh. Turn it off inside the 7-day
refresh window. While it is on, legacy tokens (only) are unaudienced, so the
cross-server barrier is down for them — modern tokens are still checked, and a
token bearing the WRONG `aud` is still rejected either way.
"""

from __future__ import annotations

import secrets
import time
from typing import Any

import jwt

from .constants import TOKEN_VERSION

REQUIRED_CLAIMS = ["exp", "iat", "iss", "aud", "typ", "client_id", "v"]
# The same set minus the two claims this package added, for the transition
# window (MCP_ACCEPT_LEGACY_TOKENS). Everything that was ever a trust boundary
# on the live servers — signature, `iss`, `typ`, `exp` — is still required.
LEGACY_REQUIRED_CLAIMS = [c for c in REQUIRED_CLAIMS if c not in ("aud", "v")]


class InvalidTokenFormat(Exception):
    """Signed by us, but in a token format this build does not recognize."""


def user_from_claims(claims: dict[str, Any]) -> dict[str, Any]:
    """The identity we carry forward, from either an Okta id_token or one of our
    own refresh tokens. One place, so a new claim can't be added to only half."""
    return {
        "sub": claims.get("sub", ""),
        "email": claims.get("email", ""),
        "name": claims.get("name", ""),
        "groups": claims.get("groups", []),
    }


def mint(
    *,
    secret: str,
    issuer: str,
    audience: str,
    kind: str,
    client_id: str,
    scopes: list[str],
    user: dict[str, Any],
    ttl: int,
    now: int | None = None,
) -> str:
    issued = int(time.time()) if now is None else now
    return jwt.encode(
        {
            "iss": issuer,
            "aud": audience,
            "v": TOKEN_VERSION,
            "sub": user.get("sub", ""),
            "email": user.get("email", ""),
            "name": user.get("name", ""),
            "groups": user.get("groups", []),
            "client_id": client_id,
            "scope": " ".join(scopes),
            "typ": kind,
            "iat": issued,
            "exp": issued + ttl,
            "jti": secrets.token_urlsafe(12),
        },
        secret,
        algorithm="HS256",
    )


def verify(
    token: str,
    *,
    secret: str,
    issuer: str,
    audience: str,
    kind: str,
    accept_legacy: bool = False,
) -> dict[str, Any] | None:
    """Return the claims, or None if the token is not a valid `kind` token here.

    Raises InvalidTokenFormat (rather than returning None) when the signature is
    OURS but the format version is not one this build understands — that
    distinction is what lets the token endpoint answer `invalid_grant` and
    prompt a re-auth instead of failing opaquely.

    `accept_legacy` is the retrofit transition window: a pre-package token with
    no `aud` and no `v` verifies as format v1 instead of being rejected. It never
    loosens anything else, and a token that DOES carry `aud` is still held to it.
    """
    try:
        claims = jwt.decode(
            token,
            secret,
            algorithms=["HS256"],
            issuer=issuer,
            audience=audience,
            options={
                "require": LEGACY_REQUIRED_CLAIMS if accept_legacy else REQUIRED_CLAIMS,
                # Turning the library's check off does NOT skip the check: an
                # `aud` that is present is compared below. It only stops PyJWT
                # from rejecting a token that has no `aud` at all.
                "verify_aud": not accept_legacy,
            },
        )
    except jwt.MissingRequiredClaimError as exc:
        if getattr(exc, "claim", None) == "v":
            raise InvalidTokenFormat("token carries no format version") from exc
        return None
    except jwt.InvalidTokenError:
        return None

    if accept_legacy and "aud" in claims and not _audience_matches(claims["aud"], audience):
        return None
    # A legacy token predates the `v` claim, so absent means v1 — the format
    # those servers were already minting. A `v` that is present still has to be
    # one we know, transition or not.
    version = claims.get("v", TOKEN_VERSION if accept_legacy else None)
    if version != TOKEN_VERSION:
        raise InvalidTokenFormat(f"unrecognized token format version {claims.get('v')!r}")
    if claims.get("typ") != kind:
        return None
    return claims


def _audience_matches(claim: Any, audience: str) -> bool:
    """`aud` may be a string or a list (RFC 7519 §4.1.3)."""
    return audience in (claim if isinstance(claim, list) else [claim])


def scopes_from(claims: dict[str, Any]) -> list[str]:
    raw = claims.get("scope") or ""
    return raw.split() if raw else []
