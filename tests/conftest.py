"""Shared fixtures. Everything is offline: Okta discovery metadata is primed on
the OktaOIDC instance, the JWKS is a fake that hands back a locally generated RSA
public key, and the Okta token endpoint is stubbed with respx. No network, ever.

Ported from fga-quorum-mcp's tests/test_oauth.py (the 118-test suite that gates
the live Okta deployment), re-homed to package imports.
"""

from __future__ import annotations

import time
from types import SimpleNamespace
from urllib.parse import parse_qs, urlparse

import httpx
import jwt
import pytest
import respx
from mcp.server.auth.provider import AuthorizationParams
from mcp.shared.auth import OAuthClientInformationFull

from fga_mcp_auth import FGAAuthProvider, Settings
from fga_mcp_auth._compat import sdk_major

SDK_MAJOR = sdk_major()

SECRET = "test-secret-at-least-32-bytes-long-for-hs256"
OTHER_SECRET = "attacker-secret-also-at-least-32-bytes-long"
HOST = "fga-example-mcp.ondigitalocean.app"
BASE = f"https://{HOST}"
SLUG = "fga-quorum"
OTHER_SLUG = "fga-ob3"
SERVICE_TOKEN = "static-service-token-for-verify-deployed"

OKTA_ISSUER = "https://example.okta.com"
OKTA_CLIENT_ID = "0oaEXAMPLECLIENTID000"
OKTA_CLIENT_SECRET = "okta-client-secret"
OKTA_META = {
    "issuer": OKTA_ISSUER,
    "authorization_endpoint": f"{OKTA_ISSUER}/oauth2/v1/authorize",
    "token_endpoint": f"{OKTA_ISSUER}/oauth2/v1/token",
    "jwks_uri": f"{OKTA_ISSUER}/oauth2/v1/keys",
}

CLAUDE_REDIRECT = "https://claude.ai/api/mcp/auth_callback"
PHISH_REDIRECT = "https://phish.example/cb"
HOSTILE = "phish.example"

USER = {"sub": "00u1", "email": "staff@example.org", "name": "Test User", "groups": ["Everyone"]}

# The env vars an HTTP deployment cannot boot without.
REQUIRED_ENV = {
    "MCP_ALLOWED_HOST": HOST,
    "MCP_SERVER_SLUG": SLUG,
    "MCP_TOKEN_SECRET": SECRET,
    "OKTA_ISSUER": OKTA_ISSUER,
    "OKTA_CLIENT_ID": OKTA_CLIENT_ID,
    "OKTA_CLIENT_SECRET": OKTA_CLIENT_SECRET,
}

# Every env var the package reads, so a test can start from a clean slate.
ALL_ENV = [
    *REQUIRED_ENV,
    "MCP_BEARER_TOKEN",
    "OKTA_ALLOWED_GROUPS",
    "OKTA_ALLOWED_EMAIL_DOMAINS",
    "MCP_TOOL_GATING",
    "MCP_PORT",
]


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    """The package reads the process environment; a stray real value would make
    these tests pass or fail for the wrong reason."""
    for name in ALL_ENV:
        monkeypatch.delenv(name, raising=False)


# --------------------------------------------------------------------------- #
# RSA signing material for fake Okta id_tokens (generated once per session)
# --------------------------------------------------------------------------- #
_KEYS: tuple[object, object] | None = None


def rsa_keys():
    """(private, public). 2048-bit, generated lazily so import stays cheap."""
    global _KEYS
    if _KEYS is None:
        from cryptography.hazmat.primitives.asymmetric import rsa

        priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        _KEYS = (priv, priv.public_key())
    return _KEYS


class FakeJWKS:
    """Stands in for jwt.PyJWKClient — always returns the one key we signed with."""

    def __init__(self, key):
        self._key = key

    def get_signing_key_from_jwt(self, token):  # noqa: ARG002 - signature parity
        return SimpleNamespace(key=self._key)


def make_id_token(*, nonce: str, key=None, **overrides) -> str:
    now = int(time.time())
    claims = {
        "iss": OKTA_ISSUER,
        "aud": OKTA_CLIENT_ID,
        "sub": USER["sub"],
        "email": USER["email"],
        "name": USER["name"],
        "nonce": nonce,
        "iat": now,
        "exp": now + 300,
    }
    claims.update(overrides)
    claims = {k: v for k, v in claims.items() if v is not None}
    priv, _ = rsa_keys()
    return jwt.encode(claims, key or priv, algorithm="RS256")


# --------------------------------------------------------------------------- #
# Settings / provider / client helpers
# --------------------------------------------------------------------------- #
def make_settings(
    *,
    allowed_groups: frozenset[str] = frozenset(),
    allowed_email_domains: frozenset[str] = frozenset(),
    service_token: str | None = SERVICE_TOKEN,
    secret: str | None = SECRET,
    host: str | None = HOST,
    slug: str | None = SLUG,
    okta: bool = True,
    tool_gating: bool = False,
) -> Settings:
    return Settings(
        allowed_host=host,
        server_slug=slug,
        token_secret=secret,
        bearer_token=service_token,
        okta_issuer=OKTA_ISSUER if okta else None,
        okta_client_id=OKTA_CLIENT_ID if okta else None,
        okta_client_secret=OKTA_CLIENT_SECRET if okta else None,
        allowed_groups=allowed_groups,
        allowed_email_domains=allowed_email_domains,
        tool_gating_enabled=tool_gating,
    )


def make_provider(**kwargs) -> FGAAuthProvider:
    settings = kwargs.pop("settings", None) or make_settings(**kwargs)
    provider = FGAAuthProvider(settings)
    if provider._okta is not None:
        # Prime discovery + JWKS so nothing reaches the network.
        provider._okta._meta = dict(OKTA_META)
        provider._okta._jwks = FakeJWKS(rsa_keys()[1])
    return provider


def make_client(
    *redirect_uris: str, client_id: str = "claude-client"
) -> OAuthClientInformationFull:
    return OAuthClientInformationFull(
        client_id=client_id,
        redirect_uris=list(redirect_uris or (CLAUDE_REDIRECT,)),
        grant_types=["authorization_code", "refresh_token"],
    )


def fake_request(**query_params) -> SimpleNamespace:
    """Minimal stand-in for a Starlette Request — handlers only read query_params."""
    return SimpleNamespace(query_params=query_params)


def mint_raw(secret: str, *, audience: str = SLUG, issuer: str = BASE, **claims) -> str:
    """Sign an arbitrary claim set. Models an attacker who has somehow obtained
    the HMAC key, to check what the OTHER checks still catch."""
    now = int(time.time())
    base = {
        "iss": issuer,
        "aud": audience,
        "v": 1,
        "sub": "00u1",
        "email": "staff@example.org",
        "name": "Test User",
        "groups": [],
        "client_id": "claude-client",
        "scope": "",
        "typ": "access",
        "iat": now,
        "exp": now + 3600,
    }
    base.update(claims)
    base = {k: v for k, v in base.items() if v is not None}
    return jwt.encode(base, secret, algorithm="HS256")


def decode(token: str, *, secret: str = SECRET, audience: str = SLUG, issuer: str = BASE) -> dict:
    return jwt.decode(token, secret, algorithms=["HS256"], issuer=issuer, audience=audience)


async def start_login(
    provider: FGAAuthProvider,
    *,
    redirect_uri: str = CLAUDE_REDIRECT,
    state: str | None = "claude-state",
) -> tuple[OAuthClientInformationFull, str]:
    """register -> /authorize. Returns (client, our pending state key)."""
    client = make_client(redirect_uri)
    await provider.register_client(client)
    target = await provider.authorize(
        client,
        AuthorizationParams(
            state=state,
            scopes=[],
            code_challenge="c" * 43,
            redirect_uri=redirect_uri,
            redirect_uri_provided_explicitly=True,
        ),
    )
    assert target.startswith("/login?"), target
    return client, parse_qs(urlparse(target).query)["state"][0]


async def run_callback(
    provider: FGAAuthProvider,
    state: str,
    *,
    id_token: str | None = "__default__",
    token_status: int = 200,
    token_body: dict | None = None,
    **extra_query,
):
    """Drive handle_okta_callback with the Okta token endpoint stubbed."""
    if id_token == "__default__":
        id_token = make_id_token(nonce=provider._pending[state]["okta_nonce"])
    body = token_body if token_body is not None else {"id_token": id_token}
    with respx.mock:
        route = respx.post(OKTA_META["token_endpoint"]).mock(
            return_value=httpx.Response(token_status, json=body)
        )
        resp = await provider.handle_okta_callback(
            fake_request(state=state, code="okta-code", **extra_query)
        )
    return resp, route


async def complete_login(provider: FGAAuthProvider):
    """Full happy path -> (client, OAuthToken)."""
    client, state = await start_login(provider)
    resp, _ = await run_callback(provider, state)
    code = parse_qs(urlparse(resp.headers["location"]).query)["code"][0]
    auth_code = await provider.load_authorization_code(client, code)
    return client, await provider.exchange_authorization_code(client, auth_code)


@pytest.fixture
def provider():
    return make_provider()
