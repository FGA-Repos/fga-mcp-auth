"""v1.1 — the refresh-time Okta user-status check.

The property under test is the offboarding tail: with OKTA_ADMIN_TOKEN set, a
deactivated Okta account must lose its stateless session at its next refresh
instead of riding out the 7-day REFRESH_TTL. The failure policy is the other half
and matters just as much — an Okta admin-API hiccup must NOT lock every staff
member out of every MCP server, so unavailability allows and warns.

Everything is offline: both endpoints the package calls
(`GET /api/v1/users/{login}` and the once-per-process `GET /api/v1/users/me`
admin-token canary) are stubbed with respx, and any unstubbed request raises
rather than reaching a real tenant.
"""

from __future__ import annotations

import logging

import httpx
import pytest
import respx
from conftest import (
    OKTA_ADMIN_TOKEN,
    OKTA_ISSUER,
    SERVICE_TOKEN,
    USER,
    decode,
    make_client,
    make_provider,
    make_settings,
    okta_me_url,
    okta_user_url,
)

from fga_mcp_auth import Settings
from fga_mcp_auth.constants import USER_STATUS_CACHE_TTL
from fga_mcp_auth.grants import TokenError, authorization_code_grant
from fga_mcp_auth.user_status import OktaUserStatus, admin_base

# Statuses an offboarded or blocked account can be in. LOCKED_OUT is in here on
# purpose: it is temporary and self-service, but it is still a state the person
# cannot log in from, and a session that outlives login is the thing this check
# exists to remove.
DENIED_STATUSES = ["SUSPENDED", "DEPROVISIONED", "LOCKED_OUT", "PROVISIONED", "STAGED"]


def checking_provider(**kwargs):
    """A provider with the status check ON."""
    return make_provider(okta_admin_token=OKTA_ADMIN_TOKEN, **kwargs)


def canary_route(status_code: int = 200, *, side_effect=None):
    """Stub the one-time OKTA_ADMIN_TOKEN canary (`GET /api/v1/users/me`).

    It fires on the first lookup a checker makes, so every test that reaches Okta
    needs it stubbed whether or not the canary is what it is about — `users_route`
    does that for you. respx dedupes by pattern and the LAST mock wins, so a test
    that wants a specific canary response calls this AFTER `users_route`.
    """
    route = respx.get(okta_me_url())
    if side_effect is not None:
        return route.mock(side_effect=side_effect)
    return route.mock(return_value=httpx.Response(status_code, json={"id": "00uadminwhomintedit"}))


def users_route(status_code: int = 200, *, status: str | None = "ACTIVE", side_effect=None):
    """Stub the Okta Users API — and the canary, which is not what most of these
    tests are about. Call inside a `with respx.mock:` block."""
    canary_route()
    route = respx.get(okta_user_url(USER["email"]))
    if side_effect is not None:
        return route.mock(side_effect=side_effect)
    body = {"id": USER["sub"], "status": status} if status is not None else {}
    return route.mock(return_value=httpx.Response(status_code, json=body))


async def refresh(provider, client=None, *, ttl: int = 600):
    """One full refresh exchange, the way the SDK drives it."""
    client = client or make_client()
    token = provider._mint("refresh", client.client_id, [], USER, ttl)
    rt = await provider.load_refresh_token(client, token)
    assert rt is not None
    return await provider.exchange_refresh_token(client, rt, [])


class TestDisabledByDefault:
    """v1.0.0 behavior is what you get by not setting OKTA_ADMIN_TOKEN."""

    def test_the_setting_is_unset_by_default(self):
        assert Settings().okta_admin_token is None
        assert make_settings().okta_admin_token_value() is None

    def test_the_env_var_populates_it(self, monkeypatch):
        monkeypatch.setenv("OKTA_ADMIN_TOKEN", "00ssws-from-the-environment")
        assert Settings().okta_admin_token_value() == "00ssws-from-the-environment"

    def test_no_checker_is_built(self, provider):
        assert provider._user_status is None
        assert provider._grants.user_status is None

    def test_boot_says_the_check_is_disabled(self, caplog):
        with caplog.at_level(logging.INFO):
            make_provider()
        assert "refresh-time Okta user-status check DISABLED (OKTA_ADMIN_TOKEN not set)" in (
            caplog.text
        )

    async def test_refresh_never_calls_okta(self, provider):
        """No route is registered, so respx raises if anything is attempted."""
        with respx.mock:
            out = await refresh(provider)
            assert respx.calls.call_count == 0
        assert out.access_token

    def test_boot_says_the_check_is_configured_when_the_token_is_set(self, caplog):
        """CONFIGURED, not ENABLED: at boot all we know is that an env var is
        set. Okta has the last word — see TestAdminTokenCanary."""
        with caplog.at_level(logging.INFO):
            provider = checking_provider()
        assert "refresh-time Okta user-status check CONFIGURED" in caplog.text
        assert "ENABLED" not in caplog.text
        assert provider._user_status is not None

    def test_the_boot_log_never_prints_the_admin_token(self, caplog):
        with caplog.at_level(logging.INFO):
            checking_provider()
        assert OKTA_ADMIN_TOKEN not in caplog.text

    def test_an_admin_token_with_no_issuer_disables_the_check(self, caplog):
        """Unreachable in an HTTP deployment (OKTA_ISSUER is boot-required), so it
        warns instead of refusing to construct a local provider."""
        with caplog.at_level(logging.WARNING):
            provider = checking_provider(okta=False)
        assert provider._user_status is None
        assert "OKTA_ISSUER is not" in caplog.text


class TestActiveUsersPass:
    async def test_an_active_account_refreshes(self):
        provider = checking_provider()
        with respx.mock:
            route = users_route(status="ACTIVE")
            out = await refresh(provider)
        assert route.call_count == 1
        assert decode(out.refresh_token)["email"] == USER["email"]

    async def test_password_expired_refreshes(self):
        """The account is live; Okta will force the change at the next
        interactive login. Killing the session over it would be a password policy
        enforced as an outage."""
        provider = checking_provider()
        with respx.mock:
            users_route(status="PASSWORD_EXPIRED")
            out = await refresh(provider)
        assert out.access_token

    async def test_the_request_carries_the_ssws_header_and_the_encoded_email(self):
        provider = checking_provider()
        with respx.mock:
            route = users_route()
            await refresh(provider)
        request = route.calls[0].request
        assert request.headers["authorization"] == f"SSWS {OKTA_ADMIN_TOKEN}"
        assert str(request.url) == okta_user_url(USER["email"])
        assert "%40" in str(request.url)  # the "@" is a path segment, not a host


class TestInactiveUsersAreRefused:
    """The whole point: the offboarding tail becomes <=1h, not 7 days."""

    @pytest.mark.parametrize("status", DENIED_STATUSES)
    async def test_a_non_login_status_is_invalid_grant(self, status):
        provider = checking_provider()
        with respx.mock:
            users_route(status=status)
            with pytest.raises(TokenError) as exc:
                await refresh(provider)
        assert exc.value.error == "invalid_grant"

    async def test_an_unknown_status_denies(self):
        """Fail closed on a status Okta invents later: this gate IS the
        offboarding bound, so an unrecognized string must not widen it."""
        provider = checking_provider()
        with respx.mock:
            users_route(status="SOMETHING_OKTA_ADDED_IN_2027")
            with pytest.raises(TokenError) as exc:
                await refresh(provider)
        assert exc.value.error == "invalid_grant"

    async def test_a_missing_status_field_denies(self):
        provider = checking_provider()
        with respx.mock:
            users_route(status=None)
            with pytest.raises(TokenError) as exc:
                await refresh(provider)
        assert exc.value.error == "invalid_grant"

    async def test_a_404_denies(self):
        """Deprovisioned accounts are eventually deleted outright. Someone Okta
        has never heard of cannot log in, so their token cannot renew."""
        provider = checking_provider()
        with respx.mock:
            users_route(404, status=None)
            with pytest.raises(TokenError) as exc:
                await refresh(provider)
        assert exc.value.error == "invalid_grant"

    async def test_the_refusal_is_shaped_like_an_unverifiable_refresh_token(self):
        """`invalid_grant` with the verification-failure sentence — the "is not
        valid" one, NOT the expired-token sentence, which names its reason.
        claude.ai renders invalid_grant as an inline Connect card, so the user is
        sent to Okta and refused there by the system that knows why, and the
        response never answers "is this account deactivated?" for whoever is
        holding the token."""
        provider = checking_provider()
        with respx.mock:
            users_route(status="DEPROVISIONED")
            with pytest.raises(TokenError) as exc:
                await refresh(provider)
        assert exc.value.error == "invalid_grant"
        assert exc.value.error_description == "Refresh token is not valid; re-authenticate."
        assert "expired" not in exc.value.error_description

    async def test_the_denial_is_logged_with_the_email_and_the_status(self, caplog):
        provider = checking_provider()
        with caplog.at_level(logging.INFO), respx.mock:
            users_route(status="SUSPENDED")
            with pytest.raises(TokenError):
                await refresh(provider)
        record = next(
            r
            for r in caplog.records
            if getattr(r, "event_category", "") == "auth.refresh.user_inactive"
        )
        assert record.user == USER["email"]
        assert record.okta_status == "SUSPENDED"

    async def test_a_denied_refresh_cannot_be_retried_into_a_session(self):
        """The loop shape the v1.0.0 fail-closed tests pin, with a deactivated
        account instead of an unverifiable token."""
        provider = checking_provider()
        client = make_client()
        with respx.mock:
            users_route(status="DEPROVISIONED")
            for _ in range(3):
                with pytest.raises(TokenError):
                    await refresh(provider, client)


class TestUnavailableOktaFailsOpen:
    """An admin-API hiccup must not lock all staff out of every MCP server.

    This check runs on the refresh of every session on seven servers, so denying
    on error converts a few minutes of Okta trouble into a fleet-wide outage
    caused by the safety feature. The <=7d REFRESH_TTL horizon is still there as
    the backstop, which is what makes failing open affordable.
    """

    @pytest.mark.parametrize(
        "side_effect",
        [httpx.ConnectError("no route to host"), httpx.ReadTimeout("okta is slow")],
        ids=["transport-error", "timeout"],
    )
    async def test_transport_failures_allow_the_refresh(self, side_effect):
        provider = checking_provider()
        with respx.mock:
            users_route(side_effect=side_effect)
            out = await refresh(provider)
        assert out.access_token

    @pytest.mark.parametrize("code", [429, 500, 502, 401, 403])
    async def test_error_responses_allow_the_refresh(self, code):
        """401/403 included: a revoked or under-scoped SSWS token is our
        misconfiguration, and it would otherwise deny every refresh at once."""
        provider = checking_provider()
        with respx.mock:
            users_route(code, status=None)
            out = await refresh(provider)
        assert out.access_token

    async def test_it_warns_loudly(self, caplog):
        provider = checking_provider()
        with caplog.at_level(logging.WARNING), respx.mock:
            users_route(503, status=None)
            await refresh(provider)
        record = next(
            r
            for r in caplog.records
            if getattr(r, "event_category", "") == "auth.refresh.status_check_unavailable"
        )
        assert record.levelno == logging.WARNING
        assert record.user == USER["email"]

    async def test_an_unreadable_body_allows_the_refresh(self):
        provider = checking_provider()
        with respx.mock:
            canary_route()
            respx.get(okta_user_url(USER["email"])).mock(
                return_value=httpx.Response(200, content=b"<html>maintenance</html>")
            )
            out = await refresh(provider)
        assert out.access_token

    @pytest.mark.parametrize(
        "body", [["maintenance"], "down", 42], ids=["json-list", "json-string", "json-number"]
    )
    async def test_a_json_body_that_is_not_an_object_allows_and_warns(self, body, caplog):
        """A 200 whose body parses but is not an object — a proxy, a WAF
        interstitial, an error envelope. `.get()` on it used to raise
        AttributeError out of check(), whose contract is that it never raises, and
        an escaping exception here is a 500 on the token endpoint of every server
        at once. It is as unreadable as torn JSON, so it takes the same path."""
        provider = checking_provider()
        with caplog.at_level(logging.WARNING), respx.mock:
            canary_route()
            respx.get(okta_user_url(USER["email"])).mock(
                return_value=httpx.Response(200, json=body)
            )
            out = await refresh(provider)
        assert out.access_token
        record = next(
            r
            for r in caplog.records
            if getattr(r, "event_category", "") == "auth.refresh.status_check_unavailable"
        )
        assert record.user == USER["email"]

    async def test_a_non_object_body_is_not_cached_as_an_allow(self):
        """Fail-open, not fail-open-for-five-minutes: the next refresh has to ask
        again, or one bad gateway response buys a deactivated account a window."""
        provider = checking_provider()
        client = make_client()
        with respx.mock:
            canary_route()
            route = respx.get(okta_user_url(USER["email"])).mock(
                return_value=httpx.Response(200, json=["maintenance"])
            )
            await refresh(provider, client)
            await refresh(provider, client)
        assert route.call_count == 2

    async def test_a_token_with_no_email_claim_allows_and_warns(self, caplog):
        """Nothing to ask Okta about. Same reasoning as a 5xx: our gap, not the
        user's, and denying would break any session whose token predates an email
        claim."""
        provider = checking_provider()
        client = make_client()
        anon = provider._mint("refresh", client.client_id, [], {"sub": "00u1"}, 600)
        rt = await provider.load_refresh_token(client, anon)
        with caplog.at_level(logging.WARNING), respx.mock:
            out = await provider.exchange_refresh_token(client, rt, [])
            assert respx.calls.call_count == 0
        assert out.access_token
        assert "auth.refresh.status_check_unavailable" in [
            getattr(r, "event_category", "") for r in caplog.records
        ]

    async def test_the_horizon_is_still_hard_when_the_check_is_unavailable(self):
        """Fail-open must not become fail-forever: the re-minted token keeps the
        ORIGINAL exp, so REFRESH_TTL still bounds the tail underneath."""
        provider = checking_provider()
        client = make_client()
        original = provider._mint("refresh", client.client_id, [], USER, 600)
        rt = await provider.load_refresh_token(client, original)
        with respx.mock:
            users_route(side_effect=httpx.ConnectError("down"))
            out = await provider.exchange_refresh_token(client, rt, [])
        assert decode(out.refresh_token)["exp"] == decode(original)["exp"]


class TestAdminTokenCanary:
    """Setting OKTA_ADMIN_TOKEN turns the check on; Okta accepting it is what
    makes it work, and those are not the same fact.

    Because the check fails open, a revoked, rotated, mistyped or under-scoped
    SSWS token is invisible: every lookup 401s, every 401 allows the refresh with
    a WARNING that looks like an Okta hiccup, and the offboarding tail is quietly
    back to 7 days while the config says otherwise. So the first lookup of the
    process asks Okta about the token itself and says, once, which of the three
    states the check is really in.
    """

    async def test_a_good_token_earns_the_enabled_line(self, caplog):
        provider = checking_provider()
        with caplog.at_level(logging.INFO), respx.mock:
            users_route(status="ACTIVE")
            await refresh(provider)
        assert "refresh-time Okta user-status check ENABLED" in caplog.text
        assert "admin token accepted by Okta" in caplog.text

    async def test_the_canary_carries_the_ssws_header(self):
        provider = checking_provider()
        with respx.mock:
            users_route(status="ACTIVE")
            canary = canary_route()
            await refresh(provider)
        assert canary.call_count == 1
        assert canary.calls[0].request.headers["authorization"] == f"SSWS {OKTA_ADMIN_TOKEN}"

    async def test_it_runs_once_per_process_not_once_per_refresh(self):
        """It is a boot check that happens to be lazy, not a per-refresh cost."""
        provider = checking_provider()
        client = make_client()
        with respx.mock:
            users_route(status="ACTIVE")
            canary = canary_route()
            await refresh(provider, client)
            provider._user_status._allowed_until.clear()  # force real lookups
            await refresh(provider, client)
            provider._user_status._allowed_until.clear()
            await refresh(provider, client)
        assert canary.call_count == 1

    async def test_it_runs_once_even_when_okta_is_down(self):
        """The latch is set before the request, so a failed canary is not retried
        on every refresh for the life of the process."""
        provider = checking_provider()
        client = make_client()
        with respx.mock:
            users_route(status="ACTIVE")
            canary = canary_route(side_effect=httpx.ConnectError("down"))
            await refresh(provider, client)
            provider._user_status._allowed_until.clear()
            await refresh(provider, client)
        assert canary.call_count == 1

    @pytest.mark.parametrize("code", [401, 403])
    async def test_a_rejected_token_is_an_error_saying_the_check_is_off(self, code, caplog):
        provider = checking_provider()
        with caplog.at_level(logging.INFO), respx.mock:
            users_route(status="ACTIVE")
            canary_route(code)
            await refresh(provider)
        record = next(
            r for r in caplog.records if getattr(r, "event_category", "") == "auth.config.error"
        )
        assert record.levelno == logging.ERROR
        assert "EFFECTIVELY OFF" in record.getMessage()
        assert "REFRESH_TTL" in record.getMessage()
        assert "ENABLED" not in caplog.text

    async def test_a_rejected_token_still_never_denies_a_refresh(self):
        """The canary reports; it does not decide. Turning a bad admin token into
        a fleet-wide lockout is exactly what fail-open exists to prevent."""
        provider = checking_provider()
        with respx.mock:
            users_route(401, status=None)
            canary_route(401)
            out = await refresh(provider)
        assert out.access_token

    async def test_a_network_error_is_only_a_warning(self, caplog):
        """Indeterminate, not bad: the token may be fine and Okta unreachable."""
        provider = checking_provider()
        with caplog.at_level(logging.INFO), respx.mock:
            users_route(status="ACTIVE")
            canary_route(side_effect=httpx.ConnectError("no route to host"))
            out = await refresh(provider)
        record = next(
            r for r in caplog.records if getattr(r, "event_category", "") == "auth.config.warning"
        )
        assert record.levelno == logging.WARNING
        assert "configured but unproven" in record.getMessage()
        assert "ENABLED" not in caplog.text
        assert out.access_token

    @pytest.mark.parametrize("code", [429, 500, 503])
    async def test_an_unexpected_status_is_only_a_warning(self, code, caplog):
        provider = checking_provider()
        with caplog.at_level(logging.INFO), respx.mock:
            users_route(status="ACTIVE")
            canary_route(code)
            await refresh(provider)
        record = next(
            r for r in caplog.records if getattr(r, "event_category", "") == "auth.config.warning"
        )
        assert record.levelno == logging.WARNING
        assert "ENABLED" not in caplog.text

    async def test_it_never_prints_the_admin_token(self, caplog):
        provider = checking_provider()
        with caplog.at_level(logging.INFO), respx.mock:
            users_route(status="ACTIVE")
            canary_route(401)
            await refresh(provider)
        assert OKTA_ADMIN_TOKEN not in caplog.text

    async def test_a_token_with_no_email_claim_does_not_trigger_it(self):
        """Nothing is going to be looked up, so nothing needs proving yet."""
        provider = checking_provider()
        client = make_client()
        anon = provider._mint("refresh", client.client_id, [], {"sub": "00u1"}, 600)
        rt = await provider.load_refresh_token(client, anon)
        with respx.mock:
            await provider.exchange_refresh_token(client, rt, [])
            assert respx.calls.call_count == 0

    async def test_the_log_line_names_the_server(self, caplog):
        """A fleet-wide "this check is off" alarm has to say which of the seven."""
        provider = checking_provider()
        with caplog.at_level(logging.INFO), respx.mock:
            users_route(status="ACTIVE")
            canary_route(403)
            await refresh(provider)
        record = next(
            r for r in caplog.records if getattr(r, "event_category", "") == "auth.config.error"
        )
        assert record.server == provider._audience


class TestCache:
    """300s per email, ALLOW results only."""

    async def test_a_second_refresh_inside_the_ttl_makes_no_call(self):
        provider = checking_provider()
        client = make_client()
        with respx.mock:
            route = users_route(status="ACTIVE")
            await refresh(provider, client)
            await refresh(provider, client)
            await refresh(provider, client)
        assert route.call_count == 1

    async def test_an_expired_cache_entry_re_checks(self):
        provider = checking_provider()
        client = make_client()
        with respx.mock:
            route = users_route(status="ACTIVE")
            await refresh(provider, client)
            provider._user_status._ttl = 0  # every entry is now already stale
            provider._user_status._allowed_until[USER["email"]] = 0.0
            await refresh(provider, client)
        assert route.call_count == 2

    async def test_a_deny_is_never_cached(self):
        """A deactivation has to bite on the next refresh, and re-activating
        someone in Okta has to work immediately rather than after a window."""
        provider = checking_provider()
        client = make_client()
        with respx.mock:
            route = users_route(status="SUSPENDED")
            for _ in range(3):
                with pytest.raises(TokenError):
                    await refresh(provider, client)
        assert route.call_count == 3
        assert provider._user_status._allowed_until == {}

    async def test_an_unavailable_result_is_never_cached(self):
        """Otherwise one Okta blip would buy a deactivated account 5 more
        minutes on every server it touched during the blip."""
        provider = checking_provider()
        client = make_client()
        with respx.mock:
            route = users_route(side_effect=httpx.ConnectError("down"))
            await refresh(provider, client)
            await refresh(provider, client)
        assert route.call_count == 2

    async def test_expired_entries_are_pruned(self):
        checker = OktaUserStatus(issuer=OKTA_ISSUER, admin_token=OKTA_ADMIN_TOKEN)
        checker._allowed_until["someone@example.org"] = 0.0
        with respx.mock:
            users_route(status="ACTIVE")
            await checker.check(USER["email"])
        assert list(checker._allowed_until) == [USER["email"]]

    def test_the_ttl_default_is_the_shared_constant(self):
        checker = OktaUserStatus(issuer=OKTA_ISSUER, admin_token=OKTA_ADMIN_TOKEN)
        assert checker._ttl == USER_STATUS_CACHE_TTL


class TestScope:
    async def test_the_service_token_is_unaffected(self):
        """MCP_BEARER_TOKEN never refreshes, so it never reaches this check.
        No route is registered: any request at all would raise."""
        provider = checking_provider()
        with respx.mock:
            loaded = await provider.load_access_token(SERVICE_TOKEN)
            assert respx.calls.call_count == 0
        assert loaded is not None

    async def test_the_authorization_code_grant_does_not_check(self):
        """Login went through Okta seconds ago, so the code grant asking again
        would be a second round-trip for an answer it already has."""
        provider = checking_provider()
        with respx.mock:
            out = await authorization_code_grant(provider._grants, make_client(), [], USER)
            assert respx.calls.call_count == 0
        assert out.access_token

    async def test_access_tokens_are_not_checked_per_request(self):
        """The check is at the refresh grant only. Doing it in load_access_token
        would be an Okta admin-API call on every MCP request."""
        provider = checking_provider()
        token = provider._mint("access", "client-a", [], USER, 60)
        with respx.mock:
            assert await provider.load_access_token(token) is not None
            assert respx.calls.call_count == 0


class TestAdminBase:
    def test_the_org_host_is_used_even_for_a_custom_authorization_server(self):
        """OKTA_ISSUER may be a custom AS, but /api/v1/users is at the org root —
        and licensing API Access Management later is supposed to be a change to
        OKTA_ISSUER and nothing else."""
        assert admin_base("https://example.okta.com/oauth2/default") == "https://example.okta.com"

    def test_a_plain_org_issuer_is_unchanged(self):
        assert admin_base("https://example.okta.com") == "https://example.okta.com"

    def test_a_trailing_slash_does_not_double_up(self):
        checker = OktaUserStatus(issuer="https://example.okta.com/", admin_token="t")
        assert checker._base == "https://example.okta.com"
