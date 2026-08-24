"""The OAuth 2.1 authorization-server provider: Okta authenticates, we issue.

Flow:
1. Claude hits /.well-known/oauth-authorization-server (handled by the MCP SDK)
2. Claude registers via POST /register (DCR, handled by the SDK — redirect URIs
   are allowlist-checked HERE, see register_client)
3. Claude redirects the user to GET /authorize -> we stash the request and
   return the relative URL /login?state=...
4. GET /login 302s to Okta's authorize endpoint (PKCE S256 + nonce + state)
5. Okta sends the user back to GET /okta/callback; we exchange the code,
   validate the id_token against Okta's JWKS, then issue our auth code and
   redirect to Claude's callback
6. Claude exchanges the code at POST /token (handled by the SDK)
7. Claude calls /mcp with Bearer <access_token>

Only in-flight state lives in memory (pending logins, auth codes, the DCR
registry). Tokens are stateless, so a redeploy never logs anyone out.
"""

from __future__ import annotations

import base64
import hashlib
import logging
import secrets
import time
from collections import OrderedDict
from typing import Any
from urllib.parse import urlparse

from mcp.server.auth.provider import (
    AccessToken,
    AuthorizationCode,
    AuthorizationParams,
    OAuthAuthorizationServerProvider,
    RefreshToken,
    RegistrationError,
)
from mcp.shared.auth import OAuthClientInformationFull, OAuthToken
from starlette.requests import Request
from starlette.responses import HTMLResponse, Response

from . import routes, tokens
from .constants import (
    AUTH_CODE_TTL,
    MAX_CLIENTS,
    PENDING_TTL,
    SERVICE_CLIENT_ID,
    SERVICE_TOKEN_SEPARATOR,
)
from .grants import GrantContext, authorization_code_grant, refresh_token_grant
from .okta import OktaOIDC
from .redirects import is_allowed_redirect
from .settings import Settings
from .tokens import InvalidTokenFormat

logger = logging.getLogger(__name__)


class FGAAccessToken(AccessToken):
    """AccessToken plus the identity claims, so the gating helper and the audit
    middleware can read who is calling straight off the SDK's auth context
    instead of re-decoding the JWT."""

    sub: str = ""
    email: str = ""
    name: str = ""
    groups: list[str] = []


class FGARefreshToken(RefreshToken):
    sub: str = ""
    email: str = ""
    name: str = ""
    groups: list[str] = []


class FGAAuthProvider(OAuthAuthorizationServerProvider):
    """One provider for the whole fleet. Configure it, don't subclass it."""

    def __init__(self, settings: Settings):
        secret = settings.secret_value()
        # RFC 7518 §3.2: an HS256 key must be at least as long as the hash
        # output. A short secret here is brute-forceable into token forgery, so
        # refuse to start rather than warn.
        if not secret or len(secret.encode()) < 32:
            raise ValueError(
                "MCP_TOKEN_SECRET must be at least 32 bytes. Generate one with: "
                'python3 -c "import secrets; print(secrets.token_urlsafe(48))"'
            )
        self.settings = settings
        self._secret = secret
        self._issuer = settings.issuer
        self._audience = settings.audience
        self._service_token = settings.service_token_value()
        self._require_bound_service_token()
        # One-shot latch so the "a legacy token was actually used" warning below
        # cannot become one log line per MCP request.
        self._warned_legacy = False
        self._warn_legacy_window()

        okta_cfg = settings.okta
        self._okta = (
            OktaOIDC(okta_cfg, f"{self._issuer}/okta/callback") if okta_cfg.enabled else None
        )

        self._clients: OrderedDict[str, OAuthClientInformationFull] = OrderedDict()
        self._auth_codes: dict[str, AuthorizationCode] = {}
        # code -> verified Okta identity. A side map rather than an attribute on
        # AuthorizationCode, which is a pydantic model and may not carry extras.
        self._code_users: dict[str, dict] = {}
        # state_key -> pending OAuth context awaiting the Okta round-trip
        self._pending: dict[str, dict] = {}

        self._grants = GrantContext(settings=settings, mint=self._mint)

        if self._okta is None:
            logger.warning(
                "Okta is not configured — the server will refuse interactive logins. "
                "Set OKTA_ISSUER, OKTA_CLIENT_ID, OKTA_CLIENT_SECRET."
            )

    def _require_bound_service_token(self) -> None:
        """Check the static bearer names the server it belongs to.

        A user token cannot be replayed at a sibling server because `aud` says
        which one minted it. The service bearer has no claims to check — it is
        an opaque string compared byte-for-byte — so an admin who sets one
        MCP_BEARER_TOKEN across the seven DO apps gives every holder of the
        congress bearer (a socialbot config, a CI log, a script) unrestricted
        access to teamtailor's PII tools. A `<slug>.` prefix makes that
        configuration visible, and with MCP_REQUIRE_BOUND_BEARER=true it makes
        it impossible: the token teamtailor accepts cannot be a token congress
        also accepts.

        Enforcement is ON by default, so the fleet cannot drift into the shared
        bearer by inattention — the plan's "cross-server replay is impossible
        even with identical secrets" has to cover the path that grants MORE than
        a user token does, not just the JWT one.

        Opting OUT (MCP_REQUIRE_BOUND_BEARER=false) is a deployment fact rather
        than a mode: quorum and ob3 are live with unprefixed bearers that
        socialbot also holds, so requiring the prefix on their retrofit deploy
        would be a three-place credential rotation with a socialbot outage in
        the gap — precisely the regression the plan's T1 gate exists to prevent.
        Those two deploys set it false, re-issue the bearer, then drop the
        variable. Unbound still boots there; it just says so, loudly.

        One shape is always fatal, switch or no switch: a bearer that IS the
        prefix and nothing else. That is never a deliberate choice, it is a
        truncated env var, and it would otherwise be a guessable credential.
        """
        if not self._service_token:
            return

        prefix = f"{self._audience}{SERVICE_TOKEN_SEPARATOR}" if self._audience else None
        if prefix and self._service_token.startswith(prefix):
            if len(self._service_token) > len(prefix):
                return
            raise ValueError(
                f"MCP_BEARER_TOKEN is only the prefix '{prefix}' with no secret after it. "
                f"Use {prefix}<random>."
            )

        example = f"{self._audience or '<MCP_SERVER_SLUG>'}{SERVICE_TOKEN_SEPARATOR}"
        detail = (
            "MCP_BEARER_TOKEN is not bound to this server: it does not start with "
            f"'{example}'. The service bearer never expires and is unrestricted, so "
            "one value shared across servers replays at all of them. Re-issue it with: "
            f"python3 -c \"import secrets; print('{example}' + secrets.token_urlsafe(32))\""
        )
        if not self._audience:
            detail = (
                "MCP_BEARER_TOKEN is set but MCP_SERVER_SLUG is not, so the service "
                "bearer cannot be bound to a server at all. " + detail
            )
        if self.settings.require_bound_bearer:
            raise ValueError(
                detail + " (Binding is required by default; MCP_REQUIRE_BOUND_BEARER=false "
                "is the retrofit-only escape hatch.)"
            )
        logger.warning(
            "%s MCP_REQUIRE_BOUND_BEARER is off — remove that override once every caller "
            "holds the new value.",
            detail,
            extra={"event_category": "auth.config.warning"},
        )

    def _warn_legacy_window(self) -> None:
        """Say out loud that the transition window is open.

        MCP_ACCEPT_LEGACY_TOKENS is a deploy-window switch, not a mode: while it
        is on, a token with no `aud` is accepted, so the cross-server barrier is
        down for pre-package tokens. Left on, it silently stays down forever.
        Announcing it at boot — and again the first time one is actually used —
        is what makes "turn it off inside the refresh window" an observable step
        rather than a line in a PR body nobody re-reads.
        """
        if not self.settings.accept_legacy_tokens:
            return
        logger.warning(
            "MCP_ACCEPT_LEGACY_TOKENS is ON: tokens minted before this package (no 'aud', "
            "no 'v') are accepted as format v1, so the cross-server replay barrier is down "
            "for them. This is a retrofit deploy window only — turn it off within the "
            "7-day refresh TTL, by which point every live session has re-minted itself.",
            extra={"event_category": "auth.config.warning", "server": self._audience},
        )

    # --- our own token format ---------------------------------------------

    def _mint(
        self,
        kind: str,
        client_id: str,
        scopes: list[str],
        user: dict,
        ttl: int,
        now: int | None = None,
    ) -> str:
        """`now` pins `iat` so a caller can express an absolute horizon as a TTL
        without the clock moving underneath it (see refresh_token_grant)."""
        return tokens.mint(
            secret=self._secret,
            issuer=self._issuer,
            audience=self._audience,
            kind=kind,
            client_id=client_id,
            scopes=scopes,
            user=user,
            ttl=ttl,
            now=now,
        )

    def _verify(self, token: str, kind: str) -> dict | None:
        """May raise InvalidTokenFormat; callers decide 401 vs invalid_grant."""
        claims = tokens.verify(
            token,
            secret=self._secret,
            issuer=self._issuer,
            audience=self._audience,
            kind=kind,
            accept_legacy=self.settings.accept_legacy_tokens,
        )
        if claims is not None and "aud" not in claims and not self._warned_legacy:
            # Only reachable with accept_legacy on. Once per process: enough to
            # prove the window is still doing something, quiet enough to leave in.
            self._warned_legacy = True
            logger.warning(
                "Accepted a pre-package token with no 'aud' claim (MCP_ACCEPT_LEGACY_TOKENS). "
                "Sessions from before the retrofit are still live; the switch can come off "
                "once this stops appearing.",
                extra={"event_category": "auth.legacy.accepted", "server": self._audience},
            )
        return claims

    def _prune(self) -> None:
        now = time.time()
        for key, pending in list(self._pending.items()):
            if now - pending["created_at"] > PENDING_TTL:
                self._pending.pop(key, None)
        for code, auth_code in list(self._auth_codes.items()):
            if auth_code.expires_at and auth_code.expires_at < now:
                self._auth_codes.pop(code, None)
                self._code_users.pop(code, None)

    # --- OAuthAuthorizationServerProvider protocol -------------------------

    async def get_client(self, client_id: str) -> OAuthClientInformationFull | None:
        return self._clients.get(client_id)

    async def register_client(self, client_info: OAuthClientInformationFull) -> None:
        # DCR is open, so the redirect allowlist is enforced HERE rather than at
        # /authorize. Rejecting at authorize-time meant returning an error
        # redirect built on the untrusted URI itself, which made that endpoint an
        # open redirect: anyone could register a client pointing at their own
        # host, then send a staff member a link that 302'd them off our domain
        # mid-"sign in with Okta". Refusing the registration removes the
        # primitive. (Don't log full redirect URIs — DCR is unauthenticated and
        # an attacker could push junk URIs into our logs.)
        for uri in client_info.redirect_uris or []:
            if not is_allowed_redirect(str(uri)):
                logger.warning(
                    "Rejected client registration with redirect host %s",
                    urlparse(str(uri)).hostname or "(none)",
                    extra={"event_category": "auth.registration.rejected"},
                )
                raise RegistrationError(
                    "invalid_redirect_uri",
                    "redirect_uri must be https on claude.ai or claude.com, "
                    "or http/https on localhost.",
                )
        self._clients[client_info.client_id] = client_info
        while len(self._clients) > MAX_CLIENTS:
            evicted, _ = self._clients.popitem(last=False)
            logger.info("Evicted oldest OAuth client %s (registry at cap)", evicted)
        logger.info("Registered OAuth client %s", client_info.client_id)

    async def authorize(
        self, client: OAuthClientInformationFull, params: AuthorizationParams
    ) -> str:
        redirect_uri = str(params.redirect_uri)
        if not is_allowed_redirect(redirect_uri):
            # Defence in depth: register_client already refuses these. If one
            # somehow reaches here, bounce to an error page on OUR origin —
            # never back to the untrusted URI, which is what made this an open
            # redirect. The SDK 302s to whatever string we return, and its
            # AuthorizeError path would build the error redirect ON the
            # registered URI, so raising would hand the attacker the redirect.
            logger.warning(
                "Rejected authorize with disallowed redirect host %s",
                urlparse(redirect_uri).hostname or "(none)",
                extra={"event_category": "auth.redirect.rejected"},
            )
            return f"{self._issuer}/oauth/error?reason=redirect_not_allowed"

        # Stash the OAuth request (plus our half of the Okta PKCE exchange) and
        # return a RELATIVE URL to our login hop, which 302s on to Okta. Relative
        # means the string handed to the SDK's 302 cannot be pointed at a foreign
        # host no matter what the client registered, and an Okta discovery outage
        # becomes a clean retryable /login failure rather than an exception
        # thrown inside the SDK's /authorize handler.
        self._prune()
        state_key = secrets.token_urlsafe(32)
        self._pending[state_key] = {
            "client_id": client.client_id,
            "redirect_uri": redirect_uri,
            "redirect_uri_given": params.redirect_uri_provided_explicitly,
            "code_challenge": params.code_challenge,
            "scopes": params.scopes or [],
            # RFC 8707 pass-through. Kept so a resource-scoped future (EMA) does
            # not need the pending-state shape to change.
            "resource": getattr(params, "resource", None),
            "original_state": params.state,
            "okta_verifier": secrets.token_urlsafe(64),
            "okta_nonce": secrets.token_urlsafe(24),
            "created_at": time.time(),
        }
        return f"/login?state={state_key}"

    async def load_authorization_code(
        self, client: OAuthClientInformationFull, authorization_code: str
    ) -> AuthorizationCode | None:
        code = self._auth_codes.get(authorization_code)
        if not code or code.client_id != client.client_id:
            return None
        if code.expires_at and code.expires_at < time.time():
            self._auth_codes.pop(authorization_code, None)
            # Pop the identity too, or it is unreachable by _prune() (which
            # iterates _auth_codes) and leaks until the process restarts.
            self._code_users.pop(authorization_code, None)
            return None
        return code

    async def exchange_authorization_code(
        self, client: OAuthClientInformationFull, authorization_code: AuthorizationCode
    ) -> OAuthToken:
        # Consume the auth code (one-shot).
        self._auth_codes.pop(authorization_code.code, None)
        identity = self._code_users.pop(authorization_code.code, None)
        return await authorization_code_grant(
            self._grants, client, authorization_code.scopes, identity
        )

    async def load_access_token(self, token: str) -> AccessToken | None:
        # Service token: static MCP_BEARER_TOKEN, never expires, used by
        # socialbot, curl and deploy verification. Slug-bound when the bearer
        # carries the prefix (see _require_bound_service_token), so a sibling
        # server's bearer cannot match here. Checked BEFORE any JWT
        # verification. .encode() both
        # sides: compare_digest raises TypeError on a non-ASCII str, and headers
        # are latin-1 decoded, so `Bearer \xff` would 500 instead of 401 on an
        # unauthenticated path — and that 500 is itself a probe for whether a
        # service token is configured.
        if self._service_token and secrets.compare_digest(
            token.encode(), self._service_token.encode()
        ):
            return FGAAccessToken(
                token=token,
                client_id=SERVICE_CLIENT_ID,
                scopes=[],
                expires_at=None,
            )
        try:
            claims = self._verify(token, "access")
        except InvalidTokenFormat:
            # A token we signed, in a shape this build no longer understands.
            # 401 + WWW-Authenticate is the right answer; the client re-auths.
            logger.info("Rejected access token with an unrecognized format version")
            return None
        if not claims:
            return None
        return FGAAccessToken(
            token=token,
            client_id=claims["client_id"],
            scopes=tokens.scopes_from(claims),
            expires_at=int(claims["exp"]),
            sub=claims.get("sub", "") or "",
            email=claims.get("email", "") or "",
            name=claims.get("name", "") or "",
            groups=list(claims.get("groups") or []),
        )

    async def load_refresh_token(
        self, client: OAuthClientInformationFull, refresh_token: str
    ) -> RefreshToken | None:
        try:
            claims = self._verify(refresh_token, "refresh")
        except InvalidTokenFormat:
            return None
        if not claims or claims.get("client_id") != client.client_id:
            return None
        return FGARefreshToken(
            token=refresh_token,
            client_id=client.client_id,
            scopes=tokens.scopes_from(claims),
            expires_at=int(claims["exp"]),
            sub=claims.get("sub", "") or "",
            email=claims.get("email", "") or "",
            name=claims.get("name", "") or "",
            groups=list(claims.get("groups") or []),
        )

    async def exchange_refresh_token(
        self,
        client: OAuthClientInformationFull,
        refresh_token: RefreshToken,
        scopes: list[str],
    ) -> OAuthToken:
        return await refresh_token_grant(
            self._grants,
            client,
            lambda tok: self._verify(tok, "refresh"),
            refresh_token.token,
            scopes,
        )

    async def revoke_token(self, token: AccessToken | RefreshToken) -> None:
        # Stateless tokens: nothing to delete. The wiring advertises
        # RevocationOptions(enabled=False) so we never claim otherwise.
        logger.info("Revocation requested; stateless tokens expire on their own")

    # --- login-hop internals (used by routes.py) ---------------------------

    def take_pending(self, state_key: str) -> dict | Response:
        """Look up a pending login, or the 400 to return instead.

        Both /login and /okta/callback need the same two checks; keeping them in
        one place means a future guard here (rate limiting, say) can't land in
        only one of them. The pending dict is left in place — the callback still
        needs it, and /login is deliberately replayable without re-minting the
        PKCE secrets, because a browser refresh must not strand the in-flight
        Okta round-trip.
        """
        pending = self._pending.get(state_key)
        if not pending:
            return HTMLResponse(routes.error_html("This login link is invalid or expired."), 400)
        if time.time() - pending["created_at"] > PENDING_TTL:
            self._pending.pop(state_key, None)
            return HTMLResponse(
                routes.error_html("This login link expired. Try connecting again."), 400
            )
        return pending

    @staticmethod
    def pkce_challenge(verifier: str) -> str:
        digest = hashlib.sha256(verifier.encode()).digest()
        return base64.urlsafe_b64encode(digest).rstrip(b"=").decode()

    def issue_auth_code(self, pending: dict, claims: dict[str, Any]) -> str:
        our_code = secrets.token_urlsafe(32)
        self._auth_codes[our_code] = AuthorizationCode(
            code=our_code,
            client_id=pending["client_id"],
            redirect_uri=pending["redirect_uri"],
            redirect_uri_provided_explicitly=pending["redirect_uri_given"],
            code_challenge=pending["code_challenge"],
            scopes=pending["scopes"],
            expires_at=time.time() + AUTH_CODE_TTL,
            resource=pending.get("resource"),
        )
        self._code_users[our_code] = tokens.user_from_claims(claims)
        return our_code

    # --- route handlers (thin delegates; the bodies live in routes.py) ------

    async def handle_login_get(self, request: Request) -> Response:
        return await routes.handle_login_get(self, request)

    async def handle_okta_callback(self, request: Request) -> Response:
        return await routes.handle_okta_callback(self, request)

    def handle_oauth_error(self, request: Request) -> Response:
        return routes.handle_oauth_error(request)
