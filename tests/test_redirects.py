"""The redirect allowlist — the open-redirect fix, plus the NEW-3 hardening.

Threat model: the attacker is an unauthenticated internet user. Dynamic client
registration is open (Claude needs it), so they can freely obtain a client_id and
drive /authorize, /login and /okta/callback. They cannot make Okta sign anything,
and they do not know MCP_TOKEN_SECRET or MCP_BEARER_TOKEN.
"""

from __future__ import annotations

from urllib.parse import urlparse

import pytest
from conftest import (
    BASE,
    CLAUDE_REDIRECT,
    HOSTILE,
    PHISH_REDIRECT,
    fake_request,
    make_client,
    make_provider,
    start_login,
)
from mcp.server.auth.provider import AuthorizationParams, RegistrationError
from mcp.shared.auth import OAuthClientMetadata

from fga_mcp_auth import ALLOWED_REDIRECT_DOMAINS, is_allowed_redirect


class TestRedirectAllowlist:
    @pytest.mark.parametrize(
        "uri,allowed",
        [
            ("https://claude.ai/api/mcp/auth_callback", True),
            ("https://foo.claude.ai/cb", True),
            ("https://claude.com/api/mcp/auth_callback", True),
            ("http://localhost:3000/cb", True),
            ("http://127.0.0.1:8080/cb", True),
            ("https://localhost:3000/cb", True),
            ("HTTPS://CLAUDE.AI/cb", True),
            # near-misses an attacker would actually try
            ("https://claude.ai.evil.com/cb", False),
            ("https://notclaude.ai/cb", False),
            ("https://evil.com/cb?next=https://claude.ai", False),
            ("https://claude.ai@evil.com/cb", False),  # userinfo, host is evil.com
            ("https://evil.com/claude.ai/cb", False),
            ("https://xn--claude-ai.evil/cb", False),
            ("https://evil.com/cb", False),
            ("javascript:alert(1)", False),
            ("", False),
        ],
    )
    def test_only_claude_and_localhost(self, uri, allowed):
        assert is_allowed_redirect(uri) is allowed

    @pytest.mark.parametrize(
        "uri",
        [
            "https://claude.ai.phish.example/cb",
            "https://phish.example/claude.ai",
            "https://claude.ai@phish.example/cb",
            "https://notclaude.ai/cb",
            "https://claudeai/cb",
            "https://phish.example/#.claude.ai",
            "https://phish.example/?next=https://claude.ai",
            "//phish.example/cb",
            "https://xn--claude-vua.ai/cb",
            "https://localhost.phish.example/cb",
            "https://127.0.0.1.phish.example/cb",
        ],
    )
    def test_lookalike_hosts_rejected(self, uri):
        assert is_allowed_redirect(uri) is False


class TestRedirectAllowlistHardening:
    """NEW-3. fga-quorum-mcp and fga-ob3-mcp shared a looser predicate whose
    edges were pinned AS over-broad in quorum's security suite. Those pins are
    flipped here: the package rejects what they documented as reachable."""

    def test_subdomain_of_a_loopback_entry_is_rejected(self):
        """Was allowed by the old `host.endswith("." + d)` rule. Not exploitable
        (`.localhost` is reserved by RFC 6761 and no registrable TLD is
        all-numeric) but it was never intended, and suffix-matching a loopback
        literal is meaningless."""
        assert is_allowed_redirect("https://anything.localhost/cb") is False
        assert is_allowed_redirect("https://anything.127.0.0.1/cb") is False

    def test_https_is_required_for_the_public_claude_hosts(self):
        """The old predicate looked only at the host, so a cleartext or exotic
        scheme on an allowed host passed."""
        assert is_allowed_redirect("http://claude.ai/cb") is False
        assert is_allowed_redirect("ftp://claude.ai/cb") is False
        assert is_allowed_redirect("https://claude.ai/cb") is True

    def test_http_stays_allowed_on_loopback_only(self):
        """A local connector has no certificate; a public one has no excuse."""
        assert is_allowed_redirect("http://localhost:3000/cb") is True
        assert is_allowed_redirect("http://127.0.0.1:3000/cb") is True
        assert is_allowed_redirect("http://claude.com/cb") is False

    def test_allowlist_membership_is_exactly_what_review_expects(self):
        assert {"claude.ai", "claude.com", "localhost", "127.0.0.1"} == ALLOWED_REDIRECT_DOMAINS


class TestRedirectParserConfusion:
    """urlparse is RFC 3986; browsers are WHATWG. They disagree about the
    backslash: WHATWG treats `\\` in the authority as `/`, RFC 3986 does not. So
    `https://phish.example\\@claude.ai/` is host `claude.ai` to urlparse and host
    `phish.example` to every browser — the classic allowlist bypass.

    Both source servers were saved from this only by pydantic's AnyUrl
    normalizing to WHATWG form before the predicate ever ran. That was
    load-bearing, undocumented, and someone else's behavior to change. The
    package rejects the character outright, so the defence no longer depends on
    it — but the normalization is still pinned, because if it ever stops the
    end-to-end tests below should say why.
    """

    CONFUSABLE = [
        (rf"https://{HOSTILE}\@claude.ai/cb", HOSTILE),
        (rf"https://{HOSTILE}\.claude.ai/cb", HOSTILE),
        (rf"https://{HOSTILE}\@claude.com/cb", HOSTILE),
    ]

    @pytest.mark.parametrize("raw,real_host", CONFUSABLE)
    def test_predicate_rejects_backslashes_outright(self, raw, real_host):
        """Flipped from the source suites, which asserted `is True` here and
        documented the sharp edge instead of removing it."""
        assert is_allowed_redirect(raw) is False
        # The reason it mattered: urlparse and a browser disagree about the host.
        assert urlparse(raw).hostname != real_host

    @pytest.mark.parametrize("raw,real_host", CONFUSABLE)
    def test_pydantic_normalization_also_closes_it(self, raw, real_host):
        """Belt and braces: DCR bodies are parsed into AnyUrl first."""
        meta = OAuthClientMetadata.model_validate(
            {
                "redirect_uris": [raw],
                "grant_types": ["authorization_code", "refresh_token"],
                "response_types": ["code"],
            }
        )
        normalized = str(meta.redirect_uris[0])
        assert urlparse(normalized).hostname == real_host
        assert is_allowed_redirect(normalized) is False

    @pytest.mark.parametrize("raw,_real_host", CONFUSABLE)
    async def test_registration_rejects_the_confusable_uri_end_to_end(self, raw, _real_host):
        """The whole point: this must 400 at /register, not become a client."""
        provider = make_provider()
        meta = OAuthClientMetadata.model_validate(
            {
                "redirect_uris": [raw],
                "grant_types": ["authorization_code", "refresh_token"],
                "response_types": ["code"],
            }
        )
        client = make_client(str(meta.redirect_uris[0]))
        with pytest.raises(RegistrationError) as exc:
            await provider.register_client(client)
        assert exc.value.error == "invalid_redirect_uri"
        assert provider._clients == {}


class TestRedirectAllowlistEnforcement:
    """Enforcement must live at REGISTRATION.

    Enforcing only at /authorize meant the rejection was delivered *to the
    rejected URI* — the authorize endpoint itself became the open redirect.
    """

    async def test_registration_refuses_foreign_redirect(self, provider):
        with pytest.raises(RegistrationError) as exc:
            await provider.register_client(make_client(PHISH_REDIRECT, client_id="probe"))
        assert exc.value.error == "invalid_redirect_uri"
        assert "probe" not in provider._clients
        assert await provider.get_client("probe") is None

    async def test_registration_refuses_if_any_uri_is_foreign(self, provider):
        """A good URI alongside a bad one must not launder the bad one through."""
        with pytest.raises(RegistrationError):
            await provider.register_client(
                make_client(CLAUDE_REDIRECT, PHISH_REDIRECT, client_id="probe")
            )
        assert "probe" not in provider._clients

    async def test_registration_accepts_claude(self, provider):
        await provider.register_client(make_client(CLAUDE_REDIRECT, client_id="probe"))
        assert await provider.get_client("probe") is not None

    async def test_authorize_never_redirects_to_a_rejected_uri(self, provider):
        """Defence in depth: the URL we hand the SDK must stay on our origin.

        Raising AuthorizeError instead would NOT be equivalent — the SDK's
        error_response still redirects to the attacker-registered URI.
        """
        target = await _authorize_with(provider, PHISH_REDIRECT)
        assert target.startswith(BASE + "/"), target
        assert urlparse(target).hostname == urlparse(BASE).hostname
        assert "phish.example" not in target

    async def test_rejected_authorize_creates_no_pending_login(self, provider):
        await _authorize_with(provider, PHISH_REDIRECT)
        assert provider._pending == {}

    def test_error_page_does_not_reflect_attacker_text(self, provider):
        """Reason is looked up in a fixed table — the page must never echo input."""
        resp = provider.handle_oauth_error(fake_request(reason="<script>alert(1)</script>"))
        assert resp.status_code == 400
        body = resp.body.decode()
        assert "<script>" not in body
        assert "alert(1)" not in body

    def test_error_page_explains_a_known_reason(self, provider):
        resp = provider.handle_oauth_error(fake_request(reason="redirect_not_allowed"))
        assert "redirect address" in resp.body.decode()


class TestAuthorizeNeverEmitsForeignLocation:
    """The second half of the open-redirect fix. The SDK 302s to whatever string
    authorize() returns, and its AuthorizeError path builds the error redirect on
    the REGISTERED uri — so raising would have handed the attacker the redirect.
    Returning an on-origin URL is the only safe answer."""

    async def test_rejected_redirect_answers_on_our_own_origin(self):
        provider = make_provider()
        target = await _authorize_with(provider, f"https://{HOSTILE}/cb")
        assert target.startswith(f"{BASE}/oauth/error")
        assert HOSTILE not in target
        assert urlparse(target).hostname == urlparse(BASE).hostname

    async def test_rejected_redirect_creates_no_pending_state(self):
        provider = make_provider()
        await _authorize_with(provider, f"https://{HOSTILE}/cb")
        assert provider._pending == {}

    async def test_login_hop_target_is_relative_to_our_origin(self):
        """authorize() returns "/login?state=..." — a relative URL cannot be
        pointed at another host no matter what the client registered."""
        provider = make_provider()
        _client, state = await start_login(provider)
        target = f"/login?state={state}"
        assert urlparse(target).hostname is None
        assert not target.startswith("//")  # protocol-relative = foreign host


async def _authorize_with(provider, redirect_uri: str) -> str:
    """Drive authorize() with a client that bypassed register_client."""
    return await provider.authorize(
        make_client(redirect_uri, client_id="probe"),
        AuthorizationParams(
            state="s",
            scopes=[],
            code_challenge="c" * 43,
            redirect_uri=redirect_uri,
            redirect_uri_provided_explicitly=True,
        ),
    )
