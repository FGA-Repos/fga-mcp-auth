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
    HOSTILE,
    OKTA_CLIENT_ID,
    OKTA_ISSUER,
    OKTA_META,
    PHISH_REDIRECT,
    SECRET,
    SERVICE_TOKEN,
    USER,
    decode,
    fake_request,
    make_client,
    make_id_token,
    make_provider,
    redirect_params,
    run_callback,
    start_login,
)
from mcp.server.auth.provider import (
    AuthorizationCode,
    AuthorizationParams,
    RegistrationError,
    TokenError,
)

from fga_mcp_auth import ACCESS_TTL, AUTH_CODE_TTL, MAX_CLIENTS
from fga_mcp_auth.constants import REDIRECT_ERRORS


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
    """Every rejection must mint no code, and must reach the OAuth client.

    Two shapes, split on whether we hold a validated redirect_uri:

      * pending state we recognize -> 302 to that (allowlisted) URI carrying
        `error` + `state` and no `code`, per RFC 6749 §4.1.2.1. Rendering an
        HTML page here instead leaves claude.ai waiting on a callback that never
        comes, which is the failure this suite now pins.
      * no pending state (forged/expired) -> an error page on our own origin,
        because there is no URI we are willing to 302 to.
    """

    def _assert_rejected(self, provider, resp, error="access_denied"):
        assert provider._auth_codes == {}
        assert provider._code_users == {}
        assert resp.status_code == 302
        q = redirect_params(resp)
        assert resp.headers["location"].startswith(CLAUDE_REDIRECT)
        assert q["error"] == error
        assert q["state"] == "claude-state"  # the client's own state comes back
        assert "code" not in q

    def _assert_rejected_on_our_origin(self, provider, resp):
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
        self._assert_rejected(provider, resp, "access_denied")

    async def test_wrong_audience_rejected(self, provider):
        """An id_token minted for a different Okta app must not work here."""
        _, state = await start_login(provider)
        token = make_id_token(nonce=provider._pending[state]["okta_nonce"], aud="0oaSOMEOTHERAPP")
        resp, _ = await run_callback(provider, state, id_token=token)
        self._assert_rejected(provider, resp, "server_error")

    async def test_wrong_issuer_in_id_token_rejected(self, provider):
        _, state = await start_login(provider)
        token = make_id_token(
            nonce=provider._pending[state]["okta_nonce"], iss="https://evil.okta.com"
        )
        resp, _ = await run_callback(provider, state, id_token=token)
        self._assert_rejected(provider, resp, "server_error")

    async def test_expired_id_token_rejected(self, provider):
        _, state = await start_login(provider)
        now = int(time.time())
        token = make_id_token(
            nonce=provider._pending[state]["okta_nonce"], iat=now - 3600, exp=now - 60
        )
        resp, _ = await run_callback(provider, state, id_token=token)
        self._assert_rejected(provider, resp, "server_error")

    async def test_id_token_signed_by_an_unknown_key_rejected(self, provider):
        """Signature check is real, not decorative."""
        from cryptography.hazmat.primitives.asymmetric import rsa

        rogue = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        _, state = await start_login(provider)
        token = make_id_token(nonce=provider._pending[state]["okta_nonce"], key=rogue)
        resp, _ = await run_callback(provider, state, id_token=token)
        self._assert_rejected(provider, resp, "server_error")

    @pytest.mark.parametrize("missing", ["sub", "exp", "iat", "aud", "iss"])
    async def test_id_token_missing_a_required_claim_rejected(self, provider, missing):
        _, state = await start_login(provider)
        token = make_id_token(nonce=provider._pending[state]["okta_nonce"], **{missing: None})
        resp, _ = await run_callback(provider, state, id_token=token)
        self._assert_rejected(provider, resp, "server_error")

    async def test_okta_rejecting_the_code_is_access_denied(self, provider):
        _, state = await start_login(provider)
        resp, _ = await run_callback(
            provider, state, token_status=400, token_body={"error": "invalid_grant"}
        )
        self._assert_rejected(provider, resp, "access_denied")

    async def test_token_response_without_id_token_rejected(self, provider):
        _, state = await start_login(provider)
        resp, _ = await run_callback(
            provider, state, token_body={"access_token": "opaque-okta-token"}
        )
        self._assert_rejected(provider, resp, "access_denied")

    async def test_issuer_mismatch_on_the_callback_rejected(self, provider):
        """RFC 9207: when the AS echoes `iss` it must match the one we trust —
        mix-up defence, and it fires BEFORE the code is spent."""
        _, state = await start_login(provider)
        resp, route = await run_callback(provider, state, iss="https://evil.okta.com")
        assert not route.called
        self._assert_rejected(provider, resp, "server_error")

    async def test_matching_issuer_on_the_callback_is_fine(self, provider):
        _, state = await start_login(provider)
        resp, _ = await run_callback(provider, state, iss=OKTA_ISSUER)
        assert resp.status_code == 302
        assert "code" in redirect_params(resp)

    async def test_unknown_state_rejected(self, provider):
        """No pending state means no validated redirect_uri, so this one CANNOT
        302 — bouncing to a URI we never checked is the open redirect itself."""
        resp = await provider.handle_okta_callback(
            fake_request(state="forged-state", code="okta-code")
        )
        assert resp.status_code == 400
        self._assert_rejected_on_our_origin(provider, resp)

    async def test_expired_pending_state_rejected(self, provider):
        _, state = await start_login(provider)
        provider._pending[state]["created_at"] = time.time() - 10_000
        resp = await provider.handle_okta_callback(fake_request(state=state, code="c"))
        assert resp.status_code == 400
        assert state not in provider._pending
        self._assert_rejected_on_our_origin(provider, resp)

    async def test_okta_error_param_logged_not_reflected(self, provider, caplog):
        """D3. Okta's error text is attacker-influenceable, so it goes to the log
        rather than onto a page on our own origin — or into the redirect. The
        client gets a code from our own fixed table instead."""
        _, state = await start_login(provider)
        with caplog.at_level(logging.WARNING):
            resp = await provider.handle_okta_callback(
                fake_request(state=state, error="access_denied")
            )
        self._assert_rejected(provider, resp, "access_denied")
        assert "access_denied" in caplog.text

    async def test_an_unrecognized_okta_error_becomes_server_error(self, provider):
        """Only `access_denied` passes through as itself; anything else is
        normalized, so Okta's string is never the value we emit."""
        _, state = await start_login(provider)
        resp = await provider.handle_okta_callback(
            fake_request(state=state, error="okta_internal_thing")
        )
        self._assert_rejected(provider, resp, "server_error")
        assert "okta_internal_thing" not in resp.headers["location"]

    async def test_missing_code_rejected(self, provider):
        _, state = await start_login(provider)
        resp = await provider.handle_okta_callback(fake_request(state=state))
        self._assert_rejected(provider, resp, "server_error")

    async def test_every_rejection_consumes_the_pending_state(self, provider):
        """The flow is over once the client has its error, so a replay of the
        same state must not get a second bite."""
        _, state = await start_login(provider)
        await provider.handle_okta_callback(fake_request(state=state, error="access_denied"))
        assert state not in provider._pending
        replay = await provider.handle_okta_callback(fake_request(state=state, code="c"))
        assert replay.status_code == 400  # our origin: nothing left to redirect to


class TestErrorsReachTheOAuthClient:
    """The finding this class exists for: an HTML page on our origin is invisible
    to claude.ai's connector flow. It is waiting on its callback URL, so a
    failure that never arrives there is a spinner and a dead tab, not an error.
    RFC 6749 §4.1.2.1 says deliver it to the (validated) redirect_uri."""

    async def test_group_gate_denial_redirects_with_access_denied(self):
        provider = make_provider(allowed_groups=frozenset({"MCP Admins"}))
        _client, state = await start_login(provider)
        resp, _ = await run_callback(provider, state)
        q = redirect_params(resp)
        assert resp.status_code == 302
        assert resp.headers["location"].startswith(CLAUDE_REDIRECT)
        assert q["error"] == "access_denied"
        assert "code" not in q

    async def test_the_denial_reason_stays_in_the_log(self, caplog):
        """`error_description` is our prose, not the gate's message: what a user
        failed is not the OAuth client's to render."""
        provider = make_provider(allowed_email_domains=frozenset({"allowed.example"}))
        _client, state = await start_login(provider)
        with caplog.at_level(logging.WARNING):
            resp, _ = await run_callback(provider, state)
        assert "email domain is not permitted" in caplog.text
        assert "email domain is not permitted" not in resp.headers["location"]
        assert redirect_params(resp)["error_description"] == REDIRECT_ERRORS["wrong_email_domain"]

    async def test_error_redirect_omits_state_when_the_client_sent_none(self):
        provider = make_provider()
        _client, state = await start_login(provider, state=None)
        resp = await provider.handle_okta_callback(fake_request(state=state, error="access_denied"))
        assert "state" not in redirect_params(resp)

    async def test_error_goes_to_the_clients_own_registered_uri(self):
        """Not a hardcoded claude.ai — whatever passed the allowlist for this
        client, which for a local connector is a loopback URL."""
        provider = make_provider()
        local = "http://localhost:33418/oauth/callback"
        _client, state = await start_login(provider, redirect_uri=local)
        resp = await provider.handle_okta_callback(fake_request(state=state, error="access_denied"))
        assert resp.headers["location"].startswith(local)

    async def test_a_disallowed_redirect_uri_is_still_never_a_302(self):
        """The rule that survives: the no-redirect policy is for URIs that never
        passed the allowlist, and /authorize still answers those on our origin."""
        provider = make_provider()
        client = make_client(PHISH_REDIRECT)
        with pytest.raises(RegistrationError):
            await provider.register_client(client)
        target = await provider.authorize(
            client,
            AuthorizationParams(
                state="s",
                scopes=[],
                code_challenge="c" * 43,
                redirect_uri=PHISH_REDIRECT,
                redirect_uri_provided_explicitly=True,
            ),
        )
        assert target == f"{BASE}/oauth/error?reason=redirect_not_allowed"
        assert HOSTILE not in target


class TestDenialsStayActionable:
    """The cost of delivering errors to the client instead of an on-origin page:
    quorum's 403 told the user WHY ("...not in a group permitted...", "add a
    groups claim") and a bare `access_denied` bounced into claude.ai does not.
    Nothing the gate wrote may travel, so OUR fixed descriptions have to carry
    the next step themselves — otherwise every denial becomes an IT ticket that
    the old on-origin page answered by itself.
    """

    async def test_a_group_denial_tells_the_user_to_ask_for_the_group(self):
        provider = make_provider(allowed_groups=frozenset({"MCP Admins"}))
        _client, state = await start_login(provider)
        resp, _ = await run_callback(provider, state)
        q = redirect_params(resp)
        assert q["error"] == "access_denied"
        assert q["error_description"] == REDIRECT_ERRORS["account_not_permitted"]
        assert "Okta group" in q["error_description"]

    async def test_a_domain_denial_tells_the_user_which_account_to_use(self):
        provider = make_provider(allowed_email_domains=frozenset({"allowed.example"}))
        _client, state = await start_login(provider)
        resp, _ = await run_callback(provider, state)
        q = redirect_params(resp)
        assert q["error"] == "access_denied"
        assert "FGA email" in q["error_description"]

    def test_the_two_denials_do_not_read_the_same(self):
        """If they did, splitting them would be theatre."""
        assert REDIRECT_ERRORS["account_not_permitted"] != REDIRECT_ERRORS["wrong_email_domain"]

    async def test_the_wire_code_is_always_rfc6749_vocabulary(self):
        """Our table has more keys than OAuth has codes. claude.ai parses the
        code, so only `access_denied` / `server_error` may travel on it — the
        extra keys are descriptions of an access_denied, not new codes."""
        from fga_mcp_auth.constants import RFC6749_ERROR_CODES

        for gate in (
            {"allowed_groups": frozenset({"MCP Admins"})},
            {"allowed_email_domains": frozenset({"allowed.example"})},
        ):
            provider = make_provider(**gate)
            _client, state = await start_login(provider)
            resp, _ = await run_callback(provider, state)
            assert redirect_params(resp)["error"] in RFC6749_ERROR_CODES

    async def test_okta_side_failures_stay_generic(self):
        """A group denial is the user's problem to fix; a failed token exchange
        is not, and must not be dressed up as one. Both raise AuthzDenied, so
        its DEFAULT code has to stay the generic sentence — only the two gates
        in check_authorized opt into the actionable prose."""
        provider = make_provider()
        _client, state = await start_login(provider)
        resp, _ = await run_callback(provider, state, token_status=400, token_body={})
        q = redirect_params(resp)
        assert q["error"] == "access_denied"
        assert q["error_description"] == REDIRECT_ERRORS["access_denied"]
        assert "Okta group" not in q["error_description"]


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
    call 1-800-..."). Now that errors are delivered to the client, the same rule
    covers the redirect: the outbound `error` and `error_description` come from a
    fixed table, so the string never travels either way."""

    def _sink(self, resp) -> str:
        """Everywhere attacker-supplied text could surface: page and Location."""
        return resp.body.decode() + resp.headers.get("location", "")

    async def test_okta_error_param_is_not_reflected_anywhere(self, caplog):
        provider = make_provider()
        _client, state = await start_login(provider)
        with caplog.at_level(logging.WARNING):
            resp = await provider.handle_okta_callback(
                fake_request(state=state, error="CALL 1-800-EVIL NOW")
            )
        assert "CALL 1-800-EVIL NOW" not in self._sink(resp)
        assert "1-800-EVIL" not in self._sink(resp)
        # ...but it is still recoverable for debugging.
        assert "CALL 1-800-EVIL NOW" in caplog.text

    async def test_markup_in_error_param_never_reaches_the_page(self):
        """Belt and braces: even escaped markup should be absent, not merely inert."""
        provider = make_provider()
        _client, state = await start_login(provider)
        resp = await provider.handle_okta_callback(
            fake_request(state=state, error="<script>alert(1)</script>")
        )
        sink = self._sink(resp)
        assert "<script>" not in sink
        assert "&lt;script&gt;" not in sink
        assert "alert(1)" not in sink

    async def test_the_error_code_is_always_one_of_ours(self):
        provider = make_provider()
        _client, state = await start_login(provider)
        resp = await provider.handle_okta_callback(
            fake_request(state=state, error="access_denied&code=forged")
        )
        q = redirect_params(resp)
        assert q["error"] in REDIRECT_ERRORS
        assert "code" not in q  # no query smuggling through the error string


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

    async def test_error_responses_never_contain_the_signing_or_client_secret(self):
        provider = make_provider()
        _client, state = await start_login(provider)
        resp = await provider.handle_okta_callback(fake_request(state=state, error="access_denied"))
        sink = resp.body.decode() + resp.headers.get("location", "")
        for secret in (SECRET, SERVICE_TOKEN, "okta-client-secret"):
            assert secret not in sink

    async def test_the_error_page_for_an_unknown_state_leaks_nothing(self):
        provider = make_provider()
        resp = await provider.handle_okta_callback(fake_request(state="nope", code="c"))
        for secret in (SECRET, SERVICE_TOKEN, "okta-client-secret"):
            assert secret not in resp.body.decode()

    async def test_auth_code_redirect_carries_only_code_and_state(self):
        """The 302 back to Claude must not smuggle identity or Okta material."""
        provider = make_provider()
        _client, state = await start_login(provider)
        resp, _ = await run_callback(provider, state)
        qs = parse_qs(urlparse(resp.headers["location"]).query)
        assert set(qs) == {"code", "state"}
        assert "okta-code" not in resp.headers["location"]
