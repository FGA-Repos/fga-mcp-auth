"""T1 — the static MCP_BEARER_TOKEN service path.

socialbot, curl and deploy-verification scripts authenticate with this in
production. A silent break here takes down socialbot's tool calls, so this file
is a regression gate, not a nice-to-have. Consumers add their own wiring-level
round-trip on top.
"""

from __future__ import annotations

import pytest
from conftest import (
    OTHER_SLUG,
    SERVICE_TOKEN,
    SLUG,
    make_client,
    make_provider,
    service_token_for,
)

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


class TestServiceTokenIsAudienceBound:
    """T3's service-path twin.

    `aud` stops a user token minted for one server from being replayed at
    another. The service bearer has no claims to check — it is an opaque string
    compared byte-for-byte — and it grants MORE than a user token does
    (SERVICE_CLIENT_ID is unrestricted at the group gate and never expires). So
    its binding is structural: `<MCP_SERVER_SLUG>.<random>` or no boot, which
    makes one bearer shared across the seven DO apps a configuration that cannot
    exist rather than one the README merely warns about.
    """

    def test_unprefixed_bearer_refuses_to_boot(self):
        with pytest.raises(ValueError, match="MCP_SERVER_SLUG"):
            make_provider(service_token="one-bearer-set-on-every-do-app")

    def test_another_servers_bearer_refuses_to_boot_here(self):
        with pytest.raises(ValueError, match="MCP_SERVER_SLUG"):
            make_provider(slug=SLUG, service_token=service_token_for(OTHER_SLUG))

    def test_prefix_with_no_secret_after_it_refuses_to_boot(self):
        with pytest.raises(ValueError, match="no secret after it"):
            make_provider(service_token=f"{SLUG}.")

    def test_bearer_without_a_server_slug_refuses_to_boot(self):
        """Nothing to bind to. Boot-required MCP_SERVER_SLUG makes this
        unreachable in production; it must still not degrade to unbound."""
        with pytest.raises(ValueError, match="MCP_SERVER_SLUG"):
            make_provider(slug=None, service_token="unbindable-bearer")

    def test_correctly_bound_bearer_boots(self):
        assert make_provider(service_token=service_token_for(SLUG)) is not None

    async def test_teamtailors_bearer_does_not_open_congress(self):
        """The scenario in full: same MCP_TOKEN_SECRET, same issuer fallback,
        two servers. The bearer that opens the PII server must not open the
        other one — nor the reverse, which is how a leaked congress bearer used
        to reach teamtailor's candidate tools."""
        teamtailor = make_provider(slug="fga-teamtailor", host=None)
        congress = make_provider(slug="fga-congress", host=None)
        assert teamtailor.settings.issuer == congress.settings.issuer

        pii_bearer = service_token_for("fga-teamtailor")
        assert await teamtailor.load_access_token(pii_bearer) is not None
        assert await congress.load_access_token(pii_bearer) is None
        assert await teamtailor.load_access_token(service_token_for("fga-congress")) is None
