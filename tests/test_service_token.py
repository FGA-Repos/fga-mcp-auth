"""T1 — the static MCP_BEARER_TOKEN service path.

socialbot, curl and deploy-verification scripts authenticate with this in
production. A silent break here takes down socialbot's tool calls, so this file
is a regression gate, not a nice-to-have. Consumers add their own wiring-level
round-trip on top.
"""

from __future__ import annotations

from conftest import SERVICE_TOKEN, make_client, make_provider

from fga_mcp_auth import SERVICE_CLIENT_ID


class TestServiceToken:
    async def test_service_token_works_and_never_expires(self, provider):
        loaded = await provider.load_access_token(SERVICE_TOKEN)
        assert loaded is not None
        assert loaded.expires_at is None
        assert loaded.client_id == SERVICE_CLIENT_ID

    async def test_wrong_bearer_rejected(self, provider):
        assert await provider.load_access_token(SERVICE_TOKEN + "x") is None
        assert await provider.load_access_token("totally-wrong") is None

    async def test_empty_token_rejected(self, provider):
        assert await provider.load_access_token("") is None

    async def test_no_service_token_configured_accepts_nothing(self):
        bare = make_provider(service_token=None)
        assert await bare.load_access_token(SERVICE_TOKEN) is None
        assert await bare.load_access_token("") is None

    async def test_service_token_is_not_a_refresh_token(self, provider):
        assert await provider.load_refresh_token(make_client(), SERVICE_TOKEN) is None

    async def test_non_ascii_bearer_does_not_explode(self, provider):
        """compare_digest on str raises TypeError for non-ASCII — that would be a
        500 where a 401 belongs, and a probe for whether a service token is set."""
        assert await provider.load_access_token("tökén-with-ünicode") is None


class TestServiceTokenRobustness:
    async def test_service_token_works_without_okta_configured(self):
        """Okta being unreachable must not cost us deploy verification."""
        provider = make_provider(okta=False)
        tok = await provider.load_access_token(SERVICE_TOKEN)
        assert tok is not None and tok.expires_at is None

    async def test_no_service_token_configured_means_no_bypass(self):
        provider = make_provider(service_token=None)
        assert await provider.load_access_token("") is None
        assert await provider.load_access_token("None") is None

    async def test_non_ascii_bearer_returns_401_not_500(self):
        provider = make_provider()
        assert await provider.load_access_token("\xff\xfe-not-a-token") is None

    async def test_service_token_prefix_and_extension_rejected(self):
        provider = make_provider()
        assert await provider.load_access_token(SERVICE_TOKEN[:-1]) is None
        assert await provider.load_access_token(SERVICE_TOKEN + "x") is None
        assert await provider.load_access_token(SERVICE_TOKEN.upper()) is None

    async def test_service_token_is_checked_before_jwt_verification(self):
        """Ordering matters: the service token is opaque, not a JWT, so if JWT
        verification ran first it would raise or log on every service call."""
        provider = make_provider(secret="z" * 40)
        assert await provider.load_access_token(SERVICE_TOKEN) is not None
