"""The login leg: Okta OIDC.

## Why Okta is the login and not the token issuer

Claude's connector UI speaks OAuth — there is no field for a static bearer
header — so the MCP server has to be an authorization server. The question is
only who authenticates the human.

The clean alternative (Okta as the authorization server, us as a pure resource
server validating Okta-issued tokens) needs Okta to mint tokens audienced to
this server, which needs a custom authorization server, which needs the API
Access Management SKU. FGA does not have it — verified 2026-07-29: both
`GET /api/v1/authorizationServers` and the *public*
`/oauth2/default/.well-known/openid-configuration` return 401. The same SKU
gates the spec's Enterprise Managed Auth extension.

So: Okta is the login. We run the OAuth dance with Claude, redirect the human to
Okta for OIDC, consume the `id_token` to learn who they are, and then issue our
own tokens. This needs only Okta's org authorization server, which every tenant
has, and costs nothing.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any

import httpx
import jwt

from .constants import OKTA_SCOPES
from .settings import OktaConfig
from .urls import append_params

logger = logging.getLogger(__name__)


class AuthzDenied(Exception):
    """Authenticated with Okta, but not permitted to use this server."""


class OktaOIDC:
    """Thin OIDC client for the login leg. Endpoints come from discovery."""

    def __init__(self, cfg: OktaConfig, redirect_uri: str):
        self.cfg = cfg
        self.redirect_uri = redirect_uri
        self._meta: dict[str, Any] | None = None
        self._jwks: jwt.PyJWKClient | None = None
        self._lock = asyncio.Lock()
        # One keep-alive client for the life of the process. There is no close()
        # hook: the provider is built by the wiring helper, which the app
        # lifespan never sees. Logins are rare and the process owns this until
        # exit, so that's the trade.
        self._http = httpx.AsyncClient(timeout=10)

    async def metadata(self) -> dict[str, Any]:
        # Fast path first: this is re-entered 2-3x per login (authorize_url,
        # exchange_and_verify, the issuer check in the callback).
        if self._meta is not None:
            return self._meta
        async with self._lock:
            if self._meta is None:
                resp = await self._http.get(self.cfg.discovery_url)
                resp.raise_for_status()
                self._meta = resp.json()
                # PyJWKClient caches keys and is sync; only construct it once.
                self._jwks = jwt.PyJWKClient(self._meta["jwks_uri"], cache_keys=True)
                logger.info(
                    "Okta OIDC discovery complete",
                    extra={"issuer": self._meta.get("issuer")},
                )
            return self._meta

    async def authorize_url(self, state: str, nonce: str, challenge: str) -> str:
        meta = await self.metadata()
        return append_params(
            meta["authorization_endpoint"],
            {
                "client_id": str(self.cfg.client_id),
                "response_type": "code",
                "scope": OKTA_SCOPES,
                "redirect_uri": self.redirect_uri,
                "state": state,
                "nonce": nonce,
                "code_challenge": challenge,
                "code_challenge_method": "S256",
            },
        )

    async def exchange_and_verify(self, code: str, verifier: str, nonce: str) -> dict[str, Any]:
        """Swap the Okta code for an id_token and validate it. Returns claims."""
        meta = await self.metadata()
        resp = await self._http.post(
            meta["token_endpoint"],
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": self.redirect_uri,
                "code_verifier": verifier,
            },
            auth=(str(self.cfg.client_id), str(self.cfg.client_secret)),
            headers={"Accept": "application/json"},
        )
        if resp.status_code != 200:
            logger.warning("Okta token exchange failed: %s %s", resp.status_code, resp.text[:200])
            raise AuthzDenied("Okta rejected the authorization code.")

        id_token = resp.json().get("id_token")
        if not id_token:
            raise AuthzDenied("Okta returned no id_token.")

        assert self._jwks is not None
        signing_key = await asyncio.to_thread(self._jwks.get_signing_key_from_jwt, id_token)
        claims = jwt.decode(
            id_token,
            signing_key.key,
            algorithms=["RS256"],
            audience=str(self.cfg.client_id),
            issuer=meta["issuer"],
            options={"require": ["exp", "iat", "sub", "aud", "iss"]},
        )
        if claims.get("nonce") != nonce:
            raise AuthzDenied("id_token nonce mismatch.")
        return claims

    def check_authorized(self, claims: dict[str, Any]) -> None:
        """Server-wide login gate. Fails closed — a missing claim denies.

        OKTA_ALLOWED_GROUPS is empty in production today = any authenticated FGA
        user, because the shared Okta app has NO groups claim configured.
        Setting an allowlist before adding that claim to the app would deny every
        login by design. OKTA_ALLOWED_EMAIL_DOMAINS is a second, independent
        gate, also empty (inert) by default.
        """
        self._check_groups(claims)
        self._check_email_domain(claims)

    def _check_groups(self, claims: dict[str, Any]) -> None:
        allowed = self.cfg.allowed_groups
        if not allowed:
            return
        groups = claims.get("groups")
        if not isinstance(groups, list):
            # Do NOT treat an absent claim as "no restriction": that would turn a
            # misconfigured Okta app into an open door.
            raise AuthzDenied(
                "This server requires Okta group membership, but the id_token carried "
                "no 'groups' claim. Add a groups claim to the Okta OIDC app."
            )
        if not allowed.intersection(groups):
            raise AuthzDenied("Your Okta account is not in a group permitted to use this server.")

    def _check_email_domain(self, claims: dict[str, Any]) -> None:
        allowed = self.cfg.allowed_email_domains
        if not allowed:
            return
        email = claims.get("email")
        if not isinstance(email, str) or "@" not in email:
            raise AuthzDenied(
                "This server restricts sign-in by email domain, but the id_token "
                "carried no usable 'email' claim."
            )
        if email.rsplit("@", 1)[1].lower() not in allowed:
            raise AuthzDenied("Your email domain is not permitted to use this server.")
