"""The /login hop and /okta/callback: the whole Okta round-trip, offline.

JWKS is faked and the Okta token endpoint is stubbed with respx, so id_token
validation is exercised for real against a locally generated RSA key while
nothing reaches the network.

This file also pins the reconciliation verdicts that the two source servers
disagreed on: the /login hop shape (D4), the non-reflected Okta error (D3), the
capped-and-FIFO client registry (D1) and the `_code_users` cleanup (D8, which
fga-ob3-mcp's code would fail).
"""

from __future__ import annotations

import base64
import hashlib
import logging
import time
from urllib.parse import parse_qs, urlparse

import pytest
from conftest import (
    BASE,
    CLAUDE_REDIRECT,
    OKTA_CLIENT_ID,
    OKTA_ISSUER,
    OKTA_META,
    SECRET,
    SERVICE_TOKEN,
    USER,
    decode,
    fake_request,
    make_client,
    make_id_token,
    make_provider,
    run_callback,
    start_login,
)
from mcp.server.auth.provider import AuthorizationCode, TokenError

from fga_mcp_auth import ACCESS_TTL, AUTH_CODE_TTL, MAX_CLIENTS


class TestLoginHop:
    """D4. authorize() returns a RELATIVE /login URL and a dedicated route does
    the Okta redirect, so no external HTTP happens inside the SDK's /authorize
    handler and the 302 target can never be foreign."""

    async def test_login_redirects_to_okta_with_pkce_and_nonce(self, provider):
        _, state = await start_login(provider)
        resp = await provider.handle_login_get(fake_request(state=state))
        assert resp.status_code == 302
        url = urlparse(resp.headers["location"])
        assert f"{url.scheme}://{url.netloc}{url.path}" == OKTA_META["authorization_endpoint"]
        q = {k: v[0] for k, v in parse_qs(url.query).items()}
        assert q["client_id"] == OKTA_CLIENT_ID
        assert q["response_type"] == "code"
        assert q["redirect_uri"] == f"{BASE}/okta/callback"
        assert q["state"] == state
        assert q["code_challenge_method"] == "S256"
        pending = provider._pending[state]
        assert q["nonce"] == pending["okta_nonce"]
        expected = base64.urlsafe_b64encode(
            hashlib.sha256(pending["okta_verifier"].encode()).digest()
        ).rstrip(b"=")
        assert q["code_challenge"] == expected.decode()

    async def test_login_is_replayable_without_reminting_secrets(self, provider):
        """Refreshing /login must reuse the stashed verifier/nonce, not rotate
        them — rotating would strand the in-flight Okta round-trip."""
        _, state = await start_login(provider)
        first = provider._pending[state]["okta_verifier"]
        await provider.handle_login_get(fake_request(state=state))
        await provider.handle_login_get(fake_request(state=state))
        assert provider._pending[state]["okta_verifier"] == first

    async def test_unknown_state_rejected(self, provider):
        assert (await provider.handle_login_get(fake_request(state="made-up"))).status_code == 400

    async def test_missing_state_rejected(self, provider):
        assert (await provider.handle_login_get(fake_request())).status_code == 400

    async def test_expired_pending_login_rejected(self, provider):
        _, state = await start_login(provider)
        provider._pending[state]["created_at"] = time.time() - 10_000
        resp = await provider.handle_login_get(fake_request(state=state))
        assert resp.status_code == 400
        assert state not in provider._pending

    async def test_login_without_okta_configured_is_503_not_a_password_form(self):
        """The shared-password form is gone. With Okta unset there is no fallback
        login path at all — and in production require_http_complete() means this
        state cannot be reached."""
        no_okta = make_provider(okta=False)
        _, state = await start_login(no_okta)
        resp = await no_okta.handle_login_get(fake_request(state=state))
        assert resp.status_code == 503
        assert "password" not in resp.body.decode().lower()


class TestOktaCallbackHappyPath:
    async def test_full_flow_issues_a_code_then_tokens(self, provider):
        client, state = await start_login(provider)
        verifier = provider._pending[state]["okta_verifier"]  # captured before it's consumed
        resp, route = await run_callback(provider, state)

        assert resp.status_code == 302
        location = resp.headers["location"]
        assert location.startswith(CLAUDE_REDIRECT)
        q = parse_qs(urlparse(location).query)
        assert q["state"] == ["claude-state"]  # the client's own state is echoed
        code = q["code"][0]
        assert state not in provider._pending  # pending state consumed

        auth_code = await provider.load_authorization_code(client, code)
        assert auth_code is not None
        tokens = await provider.exchange_authorization_code(client, auth_code)

        loaded = await provider.load_access_token(tokens.access_token)
        assert loaded is not None and loaded.client_id == client.client_id
        claims = decode(tokens.access_token)
        assert claims["email"] == USER["email"]
        assert claims["sub"] == USER["sub"]
        assert tokens.expires_in == ACCESS_TTL

        # PKCE verifier + client_secret_basic went to Okta
        sent = dict(x.split("=", 1) for x in route.calls[0].request.content.decode().split("&"))
        assert sent["code_verifier"] == verifier
        assert sent["code"] == "okta-code"
        assert sent["grant_type"] == "authorization_code"
        assert route.calls[0].request.headers["authorization"].startswith("Basic ")

    async def test_auth_code_is_single_use(self, provider):
        client, state = await start_login(provider)
        resp, _ = await run_callback(provider, state)
        code = parse_qs(urlparse(resp.headers["location"]).query)["code"][0]
        auth_code = await provider.load_authorization_code(client, code)
        await provider.exchange_authorization_code(client, auth_code)
        # replay
        assert await provider.load_authorization_code(client, code) is None
        with pytest.raises(TokenError):
            await provider.exchange_authorization_code(client, auth_code)

    async def test_auth_code_bound_to_the_client_that_started_the_flow(self, provider):
        _, state = await start_login(provider)
        resp, _ = await run_callback(provider, state)
        code = parse_qs(urlparse(resp.headers["location"]).query)["code"][0]
        other = make_client(client_id="someone-else")
        assert await provider.load_authorization_code(other, code) is None

    async def test_expired_auth_code_rejected_and_identity_cleaned_up(self, provider):
        """D8. fga-ob3-mcp popped only _auth_codes here, so the orphaned
        _code_users entry became unreachable by _prune() (which iterates
        _auth_codes) and leaked until the process restarted."""
        client, state = await start_login(provider)
        resp, _ = await run_callback(provider, state)
        code = parse_qs(urlparse(resp.headers["location"]).query)["code"][0]
        provider._auth_codes[code].expires_at = time.time() - 1
        assert await provider.load_authorization_code(client, code) is None
        assert code not in provider._code_users

    def test_auth_code_ttl_is_short(self):
        assert AUTH_CODE_TTL <= 600

    async def test_flow_without_client_state_omits_it(self, provider):
        _, state = await start_login(provider, state=None)
        resp, _ = await run_callback(provider, state)
        assert "state=" not in urlparse(resp.headers["location"]).query

    async def test_rfc8707_resource_rides_through_to_the_auth_code(self, provider):
        """The EMA door: `resource` is carried in pending state and onto the
        minted code, so a resource-scoped future needs no shape change here."""
        client, state = await start_login(provider)
        provider._pending[state]["resource"] = f"{BASE}/mcp"
        resp, _ = await run_callback(provider, state)
        code = parse_qs(urlparse(resp.headers["location"]).query)["code"][0]
        assert str((await provider.load_authorization_code(client, code)).resource) == f"{BASE}/mcp"


class TestOktaCallbackRejections:
    """Every rejection must (a) not 302 back to the client and (b) mint no code."""

    def _assert_rejected(self, provider, resp):
        assert resp.status_code >= 400
        assert resp.status_code != 302
        assert "location" not in {k.lower() for k in resp.headers}
        assert provider._auth_codes == {}
        assert provider._code_users == {}

    async def test_wrong_nonce_rejected(self, provider):
        """Blocks id_token injection/replay from another login attempt."""
        _, state = await start_login(provider)
        resp, _ = await run_callback(
            provider, state, id_token=make_id_token(nonce="a-different-login")
        )
        assert resp.status_code == 403
        self._assert_rejected(provider, resp)

    async def test_wrong_audience_rejected(self, provider):
        """An id_token minted for a different Okta app must not work here."""
        _, state = await start_login(provider)
        token = make_id_token(nonce=provider._pending[state]["okta_nonce"], aud="0oaSOMEOTHERAPP")
        resp, _ = await run_callback(provider, state, id_token=token)
        self._assert_rejected(provider, resp)

    async def test_wrong_issuer_in_id_token_rejected(self, provider):
        _, state = await start_login(provider)
        token = make_id_token(
            nonce=provider._pending[state]["okta_nonce"], iss="https://evil.okta.com"
        )
        resp, _ = await run_callback(provider, state, id_token=token)
        self._assert_rejected(provider, resp)

    async def test_expired_id_token_rejected(self, provider):
        _, state = await start_login(provider)
        now = int(time.time())
        token = make_id_token(
            nonce=provider._pending[state]["okta_nonce"], iat=now - 3600, exp=now - 60
        )
        resp, _ = await run_callback(provider, state, id_token=token)
        self._assert_rejected(provider, resp)

    async def test_id_token_signed_by_an_unknown_key_rejected(self, provider):
        """Signature check is real, not decorative."""
        from cryptography.hazmat.primitives.asymmetric import rsa

        rogue = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        _, state = await start_login(provider)
        token = make_id_token(nonce=provider._pending[state]["okta_nonce"], key=rogue)
        resp, _ = await run_callback(provider, state, id_token=token)
        self._assert_rejected(provider, resp)

    @pytest.mark.parametrize("missing", ["sub", "exp", "iat", "aud", "iss"])
    async def test_id_token_missing_a_required_claim_rejected(self, provider, missing):
        _, state = await start_login(provider)
        token = make_id_token(nonce=provider._pending[state]["okta_nonce"], **{missing: None})
        resp, _ = await run_callback(provider, state, id_token=token)
        self._assert_rejected(provider, resp)

    async def test_okta_rejecting_the_code_is_a_403(self, provider):
        _, state = await start_login(provider)
        resp, _ = await run_callback(
            provider, state, token_status=400, token_body={"error": "invalid_grant"}
        )
        assert resp.status_code == 403
        self._assert_rejected(provider, resp)

    async def test_token_response_without_id_token_rejected(self, provider):
        _, state = await start_login(provider)
        resp, _ = await run_callback(
            provider, state, token_body={"access_token": "opaque-okta-token"}
        )
        assert resp.status_code == 403
        self._assert_rejected(provider, resp)

    async def test_issuer_mismatch_on_the_callback_rejected(self, provider):
        """RFC 9207: when the AS echoes `iss` it must match the one we trust —
        mix-up defence, and it fires BEFORE the code is spent."""
        _, state = await start_login(provider)
        resp, route = await run_callback(provider, state, iss="https://evil.okta.com")
        assert resp.status_code == 400
        assert not route.called
        self._assert_rejected(provider, resp)

    async def test_matching_issuer_on_the_callback_is_fine(self, provider):
        _, state = await start_login(provider)
        resp, _ = await run_callback(provider, state, iss=OKTA_ISSUER)
        assert resp.status_code == 302

    async def test_unknown_state_rejected(self, provider):
        resp = await provider.handle_okta_callback(
            fake_request(state="forged-state", code="okta-code")
        )
        assert resp.status_code == 400
        self._assert_rejected(provider, resp)

    async def test_expired_pending_state_rejected(self, provider):
        _, state = await start_login(provider)
        provider._pending[state]["created_at"] = time.time() - 10_000
        resp = await provider.handle_okta_callback(fake_request(state=state, code="c"))
        assert resp.status_code == 400
        assert state not in provider._pending
        self._assert_rejected(provider, resp)

    async def test_okta_error_param_logged_not_reflected(self, provider, caplog):
        """D3. Okta's error text is attacker-influenceable, so it goes to the log
        rather than onto a page on our own origin during a login flow."""
        _, state = await start_login(provider)
        with caplog.at_level(logging.WARNING):
            resp = await provider.handle_okta_callback(
                fake_request(state=state, error="access_denied")
            )
        assert resp.status_code == 400
        assert "access_denied" not in resp.body.decode()
        assert "access_denied" in caplog.text
        self._assert_rejected(provider, resp)

    async def test_missing_code_rejected(self, provider):
        _, state = await start_login(provider)
        resp = await provider.handle_okta_callback(fake_request(state=state))
        assert resp.status_code == 400
        self._assert_rejected(provider, resp)


class TestAuthCodeIdentityFailsClosed:
    async def test_code_without_identity_is_refused(self, provider):
        """Defaulting to an empty identity would mint a fully-valid token for an
        anonymous session instead of raising."""
        code = AuthorizationCode(
            code="orphan",
            client_id="claude-client",
            redirect_uri=CLAUDE_REDIRECT,
            redirect_uri_provided_explicitly=True,
            code_challenge="x" * 43,
            scopes=[],
            expires_at=time.time() + 60,
        )
        provider._auth_codes["orphan"] = code  # present, but no _code_users entry
        with pytest.raises(TokenError):
            await provider.exchange_authorization_code(make_client(), code)


class TestCallbackErrorReflection:
    """D3, adversarially. Escaping stops XSS but not phishing — attacker-chosen
    prose on our own origin, mid-login, is the whole primitive ("Session expired,
    call 1-800-...")."""

    async def test_okta_error_param_is_not_reflected_into_our_page(self, caplog):
        provider = make_provider()
        _client, state = await start_login(provider)
        with caplog.at_level(logging.WARNING):
            resp = await provider.handle_okta_callback(
                fake_request(state=state, error="CALL 1-800-EVIL NOW")
            )
        body = resp.body.decode()
        assert resp.status_code == 400
        assert "CALL 1-800-EVIL NOW" not in body
        # ...but it is still recoverable for debugging.
        assert "CALL 1-800-EVIL NOW" in caplog.text

    async def test_markup_in_error_param_never_reaches_the_page(self):
        """Belt and braces: even escaped markup should be absent, not merely inert."""
        provider = make_provider()
        _client, state = await start_login(provider)
        resp = await provider.handle_okta_callback(
            fake_request(state=state, error="<script>alert(1)</script>")
        )
        body = resp.body.decode()
        assert "<script>" not in body
        assert "&lt;script&gt;" not in body
        assert "alert(1)" not in body


class TestPendingStateHygiene:
    async def test_state_key_is_high_entropy_and_unique(self):
        provider = make_provider()
        keys = set()
        for _ in range(25):
            _client, state = await start_login(provider)
            keys.add(state)
        assert len(keys) == 25
        assert all(len(k) >= 40 for k in keys)

    async def test_pkce_verifier_and_nonce_are_unique_per_request(self):
        provider = make_provider()
        verifiers, nonces = set(), set()
        for _ in range(25):
            _client, state = await start_login(provider)
            verifiers.add(provider._pending[state]["okta_verifier"])
            nonces.add(provider._pending[state]["okta_nonce"])
        assert len(verifiers) == 25 and len(nonces) == 25

    async def test_callback_state_is_single_use(self):
        """Replaying a consumed state must not mint a second auth code."""
        provider = make_provider()
        _client, state = await start_login(provider)
        resp, _ = await run_callback(provider, state)
        assert resp.status_code == 302
        assert state not in provider._pending
        replay = await provider.handle_okta_callback(fake_request(state=state, code="okta-code"))
        assert replay.status_code == 400

    async def test_client_registry_is_capped_and_evicts_oldest_first(self):
        """D1. Availability: DCR is unauthenticated, so `_clients` is an open
        write primitive — on a basic-xxs box, unbounded growth is a slow memory
        exhaustion path. `_prune()` deliberately doesn't touch it (registrations
        are long-lived, unlike `_pending`/`_auth_codes`), so the bound is the
        MAX_CLIENTS FIFO cap in register_client instead. fga-ob3-mcp used a
        plain unbounded dict."""
        provider = make_provider()
        for i in range(MAX_CLIENTS + 25):
            await provider.register_client(make_client(CLAUDE_REDIRECT, client_id=f"c{i}"))

        assert len(provider._clients) == MAX_CLIENTS
        assert "c0" not in provider._clients
        assert "c24" not in provider._clients
        assert "c25" in provider._clients
        assert f"c{MAX_CLIENTS + 24}" in provider._clients

    async def test_authorize_does_not_evict_registered_clients(self):
        """The short-lived maps get pruned on authorize(); registrations must not,
        or an idle connector would lose its client mid-session."""
        provider = make_provider()
        for i in range(10):
            await provider.register_client(make_client(CLAUDE_REDIRECT, client_id=f"c{i}"))
        await start_login(provider)
        assert len(provider._clients) == 11

    async def test_rejected_registration_is_logged_by_host_not_full_uri(self, caplog):
        """D2. DCR is unauthenticated, so an attacker could otherwise push junk
        of their choosing into our log drain."""
        from mcp.server.auth.provider import RegistrationError

        provider = make_provider()
        noisy = "https://phish.example/cb?junk=" + "A" * 200
        with caplog.at_level(logging.WARNING), pytest.raises(RegistrationError):
            await provider.register_client(make_client(noisy, client_id="probe"))
        assert "phish.example" in caplog.text
        assert "A" * 200 not in caplog.text


class TestSecretsNeverLeak:
    def test_weak_secret_error_does_not_echo_the_secret(self):
        from conftest import make_settings

        from fga_mcp_auth import FGAAuthProvider

        with pytest.raises(ValueError) as exc:
            FGAAuthProvider(make_settings(secret="short-secret"))
        assert "short-secret" not in str(exc.value)

    async def test_error_pages_never_contain_the_signing_or_client_secret(self):
        provider = make_provider()
        _client, state = await start_login(provider)
        resp = await provider.handle_okta_callback(fake_request(state=state, error="access_denied"))
        body = resp.body.decode()
        for secret in (SECRET, SERVICE_TOKEN, "okta-client-secret"):
            assert secret not in body

    async def test_auth_code_redirect_carries_only_code_and_state(self):
        """The 302 back to Claude must not smuggle identity or Okta material."""
        provider = make_provider()
        _client, state = await start_login(provider)
        resp, _ = await run_callback(provider, state)
        qs = parse_qs(urlparse(resp.headers["location"]).query)
        assert set(qs) == {"code", "state"}
        assert "okta-code" not in resp.headers["location"]
