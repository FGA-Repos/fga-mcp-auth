"""Our own token format: forgery, type confusion, statelessness, audience
binding (A1) and format versioning (A2).

Our tokens ARE the session — there is no server-side store to check them
against, so signature + `iss` + `aud` + `typ` + `v` are the entire trust
boundary.
"""

from __future__ import annotations

import time

import jwt
import pytest
from conftest import (
    BASE,
    OTHER_SECRET,
    OTHER_SLUG,
    SECRET,
    SLUG,
    USER,
    decode,
    make_client,
    make_provider,
    mint_raw,
)

from fga_mcp_auth import ACCESS_TTL, REFRESH_TTL, TOKEN_VERSION, InvalidTokenFormat
from fga_mcp_auth.grants import TokenError, refresh_token_grant


class TestTokenMinting:
    async def test_access_token_roundtrip_carries_identity(self, provider):
        token = provider._mint("access", "client-a", ["read"], USER, 60)
        loaded = await provider.load_access_token(token)
        assert loaded is not None
        assert loaded.client_id == "client-a"
        assert loaded.scopes == ["read"]
        claims = decode(token)
        assert claims["email"] == "staff@example.org"
        assert claims["sub"] == "00u1"
        assert claims["typ"] == "access"

    async def test_loaded_token_exposes_identity_claims(self, provider):
        """FGAAccessToken carries sub/email/groups so the gate and the audit
        middleware never have to re-decode the JWT."""
        token = provider._mint("access", "client-a", [], USER, 60)
        loaded = await provider.load_access_token(token)
        assert loaded.email == USER["email"]
        assert loaded.sub == USER["sub"]
        assert loaded.groups == USER["groups"]

    async def test_refresh_token_is_not_accepted_as_access_token(self, provider):
        """Type confusion: a 7-day token must not act as a 1-hour one."""
        refresh = provider._mint("refresh", "client-a", [], USER, 60)
        assert await provider.load_access_token(refresh) is None

    async def test_access_token_is_not_accepted_as_refresh_token(self, provider):
        """The other direction of the same hole — an access token must not renew."""
        client = make_client()
        access = provider._mint("access", client.client_id, [], USER, 60)
        assert await provider.load_refresh_token(client, access) is None

    async def test_expired_token_rejected(self, provider):
        assert await provider.load_access_token(mint_raw(SECRET, exp=int(time.time()) - 5)) is None

    async def test_token_signed_with_another_secret_rejected(self, provider):
        assert await provider.load_access_token(mint_raw(OTHER_SECRET)) is None

    async def test_tampered_signature_rejected(self, provider):
        token = provider._mint("access", "client-a", [], USER, 60)
        head, payload, sig = token.split(".")
        flipped = "A" if sig[0] != "A" else "B"
        assert await provider.load_access_token(f"{head}.{payload}.{flipped}{sig[1:]}") is None

    async def test_tampered_payload_rejected(self, provider):
        """Swap in a different identity but keep the original signature."""
        token = provider._mint("access", "client-a", [], USER, 60)
        head, _, sig = token.split(".")
        evil = mint_raw(SECRET, email="attacker@evil.example")
        assert await provider.load_access_token(f"{head}.{evil.split('.')[1]}.{sig}") is None

    async def test_alg_none_token_rejected(self, provider):
        """The classic: unsigned token claiming to be valid. verify pins HS256."""
        unsigned = jwt.encode(
            {
                "iss": BASE,
                "aud": SLUG,
                "v": TOKEN_VERSION,
                "typ": "access",
                "client_id": "c",
                "iat": int(time.time()),
                "exp": int(time.time()) + 60,
            },
            key="",
            algorithm="none",
        )
        assert await provider.load_access_token(unsigned) is None

    async def test_wrong_issuer_rejected(self, provider):
        assert (
            await provider.load_access_token(mint_raw(SECRET, iss="https://evil.example")) is None
        )

    async def test_token_without_typ_claim_rejected(self, provider):
        """`typ` is required, so a pre-retrofit-shaped token cannot slip through."""
        assert await provider.load_access_token(mint_raw(SECRET, typ=None)) is None

    async def test_garbage_string_rejected(self, provider):
        assert await provider.load_access_token("not-a-jwt-at-all") is None

    async def test_refresh_token_bound_to_its_client(self, provider):
        refresh = provider._mint("refresh", "client-a", [], USER, 60)
        assert await provider.load_refresh_token(make_client(client_id="client-b"), refresh) is None
        assert (
            await provider.load_refresh_token(make_client(client_id="client-a"), refresh)
        ) is not None

    async def test_signed_token_without_client_id_is_401_not_500(self, provider):
        """fga-quorum-mcp pinned the opposite: verify required only exp/iss/typ,
        then load_access_token did claims["client_id"] unguarded -> KeyError ->
        500. Not reachable without the HMAC key, so this is defence in depth —
        but a malformed-but-signed token must be a clean 401."""
        assert await provider.load_access_token(mint_raw(SECRET, client_id=None)) is None

    async def test_scope_cannot_be_escalated_across_a_refresh_exchange(self, provider):
        """exchange_refresh_token takes `scopes` from the request. The SDK narrows
        them; confirm what lands in the new token."""
        client = make_client()
        refresh = provider._mint("refresh", client.client_id, ["read"], USER, 600)
        rt = await provider.load_refresh_token(client, refresh)
        out = await provider.exchange_refresh_token(client, rt, ["read"])
        assert decode(out.access_token)["scope"] == "read"


class TestStatelessness:
    """The point of the design: a redeploy must not log staff out."""

    async def test_token_from_one_instance_verifies_in_a_fresh_instance(self):
        minted = make_provider()._mint("access", "client-a", ["read"], USER, 300)
        after_redeploy = make_provider()  # same config, brand-new process state
        loaded = await after_redeploy.load_access_token(minted)
        assert loaded is not None
        assert loaded.client_id == "client-a"

    async def test_fresh_instance_with_a_different_secret_rejects(self):
        minted = make_provider()._mint("access", "client-a", [], USER, 300)
        assert await make_provider(secret=OTHER_SECRET).load_access_token(minted) is None

    async def test_fresh_instance_at_a_different_issuer_rejects(self):
        other = make_provider(host="fga-other-mcp.ondigitalocean.app", slug=OTHER_SLUG)
        minted = other._mint("access", "client-a", [], USER, 300)
        assert await make_provider().load_access_token(minted) is None


class TestCrossServerReplay:
    """Seven FGA MCP servers share one Okta app and may be handed the SAME
    MCP_TOKEN_SECRET. Before A1 the only boundary was `iss`, derived from
    MCP_ALLOWED_HOST — and that collapses to http://localhost:8080 on every one
    of them when MCP_ALLOWED_HOST is unset."""

    async def test_other_servers_token_rejected_even_with_shared_secret(self):
        provider = make_provider()
        ob3_token = mint_raw(
            SECRET, issuer="https://fga-other-mcp.ondigitalocean.app", audience=OTHER_SLUG
        )
        assert await provider.load_access_token(ob3_token) is None

    async def test_issuerless_token_rejected(self):
        assert await make_provider().load_access_token(mint_raw(SECRET, iss=None)) is None

    async def test_audienceless_token_rejected(self):
        assert await make_provider().load_access_token(mint_raw(SECRET, aud=None)) is None

    async def test_wrong_audience_rejected(self):
        provider = make_provider()
        assert await provider.load_access_token(mint_raw(SECRET, audience=OTHER_SLUG)) is None

    async def test_same_secret_same_issuer_different_slug_rejected(self):
        """T3, the positive half. This is the exact configuration that used to
        collapse: MCP_ALLOWED_HOST unset on two servers gives them an identical
        issuer, and an admin reusing one secret across the seven DO apps is a
        very plausible convenience move. `aud` is what stops it now, and
        MCP_SERVER_SLUG is boot-required so it can never be empty in production."""
        fallback_host = None  # -> http://localhost:8080 on both
        server_a = make_provider(host=fallback_host, slug="fga-quorum")
        server_b = make_provider(host=fallback_host, slug="fga-teamtailor")
        assert server_a.settings.issuer == server_b.settings.issuer == "http://localhost:8080"
        stolen = server_a._mint("access", "c", [], USER, 3600)
        assert await server_b.load_access_token(stolen) is None
        # ...and still works on the server it was minted for.
        assert await server_a.load_access_token(stolen) is not None


class TestTokenFormatVersion:
    """A2/T5. An unrecognized format must degrade to a re-auth, never a 500."""

    def test_minted_tokens_carry_the_version_claim(self, provider):
        token = provider._mint("access", "c", [], USER, 60)
        assert decode(token)["v"] == TOKEN_VERSION

    async def test_unknown_version_access_token_is_401_not_500(self, provider):
        """load_access_token swallows InvalidTokenFormat -> None -> SDK 401 +
        WWW-Authenticate, which is what makes claude.ai re-connect."""
        assert await provider.load_access_token(mint_raw(SECRET, v=999)) is None

    async def test_missing_v_claim_rejected(self, provider):
        assert await provider.load_access_token(mint_raw(SECRET, v=None)) is None

    async def test_unknown_version_refresh_load_is_none(self, provider):
        client = make_client()
        token = mint_raw(SECRET, typ="refresh", v=999, client_id=client.client_id)
        assert await provider.load_refresh_token(client, token) is None

    async def test_unknown_version_refresh_exchange_is_invalid_grant(self, provider):
        """The grant path is the one that must not 500: RFC-compliant
        invalid_grant makes claude.ai show an inline Connect card and retry the
        tool call, so a package upgrade that changes token shape costs one click
        instead of a lost conversation."""
        client = make_client()
        good = provider._mint("refresh", client.client_id, [], USER, 600)
        rt = await provider.load_refresh_token(client, good)
        rt.token = mint_raw(SECRET, typ="refresh", v=999, client_id=client.client_id)
        with pytest.raises(TokenError) as exc:
            await provider.exchange_refresh_token(client, rt, [])
        assert exc.value.error == "invalid_grant"

    def test_verify_raises_invalid_token_format_for_unknown_version(self, provider):
        with pytest.raises(InvalidTokenFormat):
            provider._verify(mint_raw(SECRET, v=999), "access")


class TestRefreshFailsClosed:
    """A refresh that cannot be verified must be `invalid_grant`, never a token.

    The regression this pins: `verify(refresh_token) or {}` minted a fully-valid
    1h access token for sub=""/email="" whenever verification failed, plus a
    refresh partner whose TTL floored at 60s. That partner then verified
    cleanly, floored at 60s again, and so on — an expired or forged refresh
    token laundered into an anonymous session renewable every 60 seconds
    forever, which is the exact opposite of the bounded offboarding tail
    REFRESH_TTL is supposed to guarantee.
    """

    async def test_grant_refuses_to_mint_when_verification_returns_none(self, provider):
        with pytest.raises(TokenError) as exc:
            await refresh_token_grant(provider._grants, make_client(), lambda _t: None, "tok", [])
        assert exc.value.error == "invalid_grant"

    async def test_refresh_expiring_between_the_sdk_check_and_ours_is_invalid_grant(self, provider):
        """Reachable in production: the SDK checks `expires_at` from the snapshot
        load_refresh_token returned, and the token can cross `exp` before
        exchange re-decodes it."""
        client = make_client()
        rt = await provider.load_refresh_token(
            client, provider._mint("refresh", client.client_id, [], USER, 600)
        )
        rt.token = mint_raw(
            SECRET, typ="refresh", client_id=client.client_id, exp=int(time.time()) - 1
        )
        with pytest.raises(TokenError) as exc:
            await provider.exchange_refresh_token(client, rt, [])
        assert exc.value.error == "invalid_grant"

    async def test_refresh_signed_with_another_secret_is_invalid_grant(self, provider):
        client = make_client()
        rt = await provider.load_refresh_token(
            client, provider._mint("refresh", client.client_id, [], USER, 600)
        )
        rt.token = mint_raw(OTHER_SECRET, typ="refresh", client_id=client.client_id)
        with pytest.raises(TokenError) as exc:
            await provider.exchange_refresh_token(client, rt, [])
        assert exc.value.error == "invalid_grant"

    async def test_an_unverifiable_refresh_cannot_be_renewed_in_a_loop(self, provider):
        """The full attack, stated as a test: every round must raise, so there
        is never a 60-second token to come back with."""
        client = make_client()
        rt = await provider.load_refresh_token(
            client, provider._mint("refresh", client.client_id, [], USER, 600)
        )
        rt.token = mint_raw(SECRET, typ="refresh", client_id=client.client_id, v=None)
        for _ in range(3):
            with pytest.raises(TokenError):
                await provider.exchange_refresh_token(client, rt, [])


class TestLegacyTokenRejection:
    """Deploy-time consequence of A1/A2, pinned rather than discovered.

    fga-quorum-mcp and fga-ob3-mcp are LIVE and mint neither `aud` nor `v`, both
    of which are in REQUIRED_CLAIMS. So the first deploy of the retrofit rejects
    every token they have already issued: one forced reconnect for every
    connected staff member, at deploy time. That is NOT behavior-identical, it
    is in both retrofit PR bodies, and it is Jacob's call to accept.

    What these tests hold is the shape of the failure — 401 on access,
    `invalid_grant` on refresh, so claude.ai shows an inline Connect card and
    retries the tool call. A 500, or (before the fail-closed fix above) an
    anonymous session, would make the same deploy an incident.
    """

    @staticmethod
    def legacy(**claims) -> str:
        """A pre-retrofit token: our signature, our issuer, no `aud`, no `v`."""
        return mint_raw(SECRET, aud=None, v=None, **claims)

    async def test_legacy_access_token_is_a_clean_401(self, provider):
        assert await provider.load_access_token(self.legacy()) is None

    async def test_legacy_refresh_token_does_not_load(self, provider):
        client = make_client()
        legacy = self.legacy(typ="refresh", client_id=client.client_id)
        assert await provider.load_refresh_token(client, legacy) is None

    async def test_legacy_refresh_exchange_is_invalid_grant_not_a_500(self, provider):
        client = make_client()
        rt = await provider.load_refresh_token(
            client, provider._mint("refresh", client.client_id, [], USER, 600)
        )
        rt.token = self.legacy(typ="refresh", client_id=client.client_id)
        with pytest.raises(TokenError) as exc:
            await provider.exchange_refresh_token(client, rt, [])
        assert exc.value.error == "invalid_grant"

    def test_the_rejection_is_the_missing_claims_not_the_signature(self):
        """Otherwise this suite would pass for the wrong reason: the legacy token
        really is one we would have signed and issued."""
        claims = jwt.decode(self.legacy(), SECRET, algorithms=["HS256"], issuer=BASE, audience=None)
        assert "aud" not in claims and "v" not in claims
        assert claims["iss"] == BASE and claims["typ"] == "access"


class TestOffboardingWindow:
    def test_refresh_ttl_is_exactly_seven_days(self):
        """Refresh re-mints from claims and never re-contacts Okta, so this
        constant IS how long a deactivated Okta account keeps working."""
        assert REFRESH_TTL == 7 * 24 * 3600

    def test_seven_days_is_the_documented_worst_case(self):
        assert REFRESH_TTL == 604800

    def test_access_ttl_stays_short(self):
        assert ACCESS_TTL <= 3600

    async def test_minted_refresh_token_expires_in_seven_days(self, provider):
        from conftest import complete_login

        _client, tokens = await complete_login(provider)
        claims = decode(tokens.refresh_token)
        assert claims["exp"] - claims["iat"] == 7 * 24 * 3600

    async def test_refresh_does_not_slide_expiry(self, provider):
        """Otherwise a deactivated account renews itself forever."""
        client = make_client()
        refresh = provider._mint("refresh", client.client_id, [], USER, 120)
        loaded = await provider.load_refresh_token(client, refresh)
        assert loaded is not None
        issued = await provider.exchange_refresh_token(client, loaded, [])
        assert decode(issued.refresh_token)["exp"] <= decode(refresh)["exp"] + 1

    async def test_refresh_preserves_identity(self, provider):
        client = make_client()
        refresh = provider._mint("refresh", client.client_id, ["read"], USER, 600)
        loaded = await provider.load_refresh_token(client, refresh)
        issued = await provider.exchange_refresh_token(client, loaded, ["read"])
        claims = decode(issued.access_token)
        assert claims["email"] == USER["email"] and claims["sub"] == USER["sub"]

    async def test_refreshed_token_keeps_the_audience(self):
        """A refresh must not launder a token into an unaudienced one."""
        provider = make_provider()
        client = make_client()
        refresh = provider._mint("refresh", client.client_id, [], USER, 600)
        rt = await provider.load_refresh_token(client, refresh)
        out = await provider.exchange_refresh_token(client, rt, [])
        assert decode(out.access_token)["aud"] == SLUG


class TestOffboardingTailEndToEnd:
    async def test_repeated_refresh_never_extends_past_the_original_expiry(self):
        provider = make_provider()
        client = make_client()
        token = provider._mint("refresh", client.client_id, [], USER, REFRESH_TTL)
        horizon = decode(token)["exp"]
        for _ in range(5):
            rt = await provider.load_refresh_token(client, token)
            assert rt is not None
            token = (await provider.exchange_refresh_token(client, rt, [])).refresh_token
            assert decode(token)["exp"] <= horizon, (
                "refresh slid the expiry outward — offboarding tail is unbounded"
            )

    async def test_deactivated_user_is_never_rechecked_against_okta(self):
        """Stated plainly as a test, and deliberately pinned: refresh re-mints
        from the token's own claims. Nothing here consults Okta, so a deactivated
        account keeps working for the remaining life of its refresh token. An
        Okta user-status check at refresh is package v1.1 — it needs an SSWS
        token in seven deploys plus a failure policy, and v1.0.0 is
        behavior-identical to what is live."""
        provider = make_provider()
        client = make_client()
        refresh = provider._mint(
            "refresh", client.client_id, [], {"sub": "00u1", "email": "gone@example.org"}, 600
        )
        rt = await provider.load_refresh_token(client, refresh)
        out = await provider.exchange_refresh_token(client, rt, [])
        assert decode(out.access_token)["email"] == "gone@example.org"
