"""Group gating, at two levels.

* The server-wide login gate (`OktaOIDC.check_authorized`) — ported verbatim,
  including the fail-closed behavior that makes setting OKTA_ALLOWED_GROUPS
  today a total outage.
* T2: the per-tool `GroupGate` helper, which is new. It ships default-OFF for
  exactly the reason the login gate is dangerous: the shared FGA Okta app emits
  no `groups` claim yet.
"""

from __future__ import annotations

import contextlib

import pytest
from conftest import BASE, make_provider, make_settings, run_callback, start_login
from mcp.server.auth.middleware.auth_context import auth_context_var
from mcp.server.auth.middleware.bearer_auth import AuthenticatedUser

from fga_mcp_auth import (
    SERVICE_CLIENT_ID,
    AuthzDenied,
    FGAAccessToken,
    GroupGate,
    OktaOIDC,
    Settings,
)
from fga_mcp_auth._compat import tool_error_class

ToolError = tool_error_class()


@contextlib.contextmanager
def as_caller(token):
    """Bind an access token to the SDK's auth contextvar, the way the HTTP
    bearer middleware does on a real request."""
    reset = auth_context_var.set(AuthenticatedUser(token) if token is not None else None)
    try:
        yield
    finally:
        auth_context_var.reset(reset)


def user_token(*groups: str, client_id: str = "claude-client") -> FGAAccessToken:
    return FGAAccessToken(
        token="opaque",
        client_id=client_id,
        scopes=[],
        expires_at=None,
        sub="00u1",
        email="staff@example.org",
        groups=list(groups),
    )


# --------------------------------------------------------------------------- #
# Server-wide login gate
# --------------------------------------------------------------------------- #
class TestGroupGate:
    def _oidc(self, groups: set[str]) -> OktaOIDC:
        settings = make_settings(allowed_groups=frozenset(groups))
        return OktaOIDC(settings.okta, f"{BASE}/okta/callback")

    def test_empty_allowlist_permits_any_authenticated_fga_user(self):
        """Today's production config: no groups claim exists on the shared app,
        so an empty OKTA_ALLOWED_GROUPS = any authenticated FGA user."""
        self._oidc(set()).check_authorized({"email": "someone@example.org"})

    def test_member_of_allowed_group_permitted(self):
        self._oidc({"Quorum-Users"}).check_authorized({"groups": ["Everyone", "Quorum-Users"]})

    def test_non_member_denied(self):
        with pytest.raises(AuthzDenied):
            self._oidc({"Quorum-Users"}).check_authorized({"groups": ["Everyone"]})

    def test_missing_groups_claim_denies_rather_than_allows(self):
        """⚠️ Pinned deliberately: the shared Okta app has NO groups claim, so
        setting OKTA_ALLOWED_GROUPS today locks out the entire company. That is
        the correct (fail-closed) behaviour — treating an absent claim as "no
        restriction" would turn a misconfigured Okta app into an open door.
        Add the claim to the Okta app BEFORE setting an allowlist."""
        with pytest.raises(AuthzDenied, match="no 'groups' claim"):
            self._oidc({"Quorum-Users"}).check_authorized({"email": "someone@example.org"})

    def test_non_list_groups_claim_denies(self):
        with pytest.raises(AuthzDenied):
            self._oidc({"Quorum-Users"}).check_authorized({"groups": "Quorum-Users"})

    async def test_allowlist_without_groups_claim_denies_the_whole_login(self):
        """End-to-end version of the same trap: no code is issued at all, and
        the client is told `access_denied` rather than left waiting."""
        from urllib.parse import parse_qs, urlparse

        gated = make_provider(allowed_groups=frozenset({"Quorum-Users"}))
        _, state = await start_login(gated)
        resp, _ = await run_callback(gated, state)
        assert resp.status_code == 302
        q = parse_qs(urlparse(resp.headers["location"]).query)
        assert q["error"] == ["access_denied"]
        assert "code" not in q
        assert gated._auth_codes == {}

    async def test_member_of_allowed_group_completes_login(self):
        from conftest import CLAUDE_REDIRECT, make_id_token

        gated = make_provider(allowed_groups=frozenset({"Quorum-Users"}))
        _, state = await start_login(gated)
        token = make_id_token(
            nonce=gated._pending[state]["okta_nonce"], groups=["Everyone", "Quorum-Users"]
        )
        resp, _ = await run_callback(gated, state, id_token=token)
        assert resp.status_code == 302
        assert resp.headers["location"].startswith(CLAUDE_REDIRECT)


class TestEmailDomainGate:
    def _oidc(self, domains: set[str]) -> OktaOIDC:
        settings = make_settings(allowed_email_domains=frozenset(domains))
        return OktaOIDC(settings.okta, f"{BASE}/okta/callback")

    def test_empty_allowlist_is_inert(self):
        self._oidc(set()).check_authorized({"email": "contractor@example.com"})

    def test_permitted_domain_allowed(self):
        self._oidc({"example.org"}).check_authorized({"email": "staff@example.org"})

    def test_other_domain_denied(self):
        with pytest.raises(AuthzDenied, match="email domain"):
            self._oidc({"example.org"}).check_authorized({"email": "someone@gmail.com"})

    def test_missing_email_claim_denies(self):
        with pytest.raises(AuthzDenied):
            self._oidc({"example.org"}).check_authorized({"sub": "00u1"})

    def test_domain_comparison_is_case_insensitive(self):
        self._oidc({"Example.ORG"}).check_authorized({"email": "Someone@EXAMPLE.ORG"})


class TestLockoutSafety:
    def test_default_config_does_not_lock_everyone_out(self):
        """The allowlist-without-groups-claim trap: empty must mean "any
        authenticated FGA user", never "nobody"."""
        assert make_settings().okta.allowed_groups == frozenset()
        assert make_settings().okta.allowed_email_domains == frozenset()

    def test_group_allowlist_today_would_deny_every_login(self):
        """Documented, intended, and dangerous: the shared Okta app emits no
        groups claim, so setting OKTA_ALLOWED_GROUPS before adding that claim is
        a total outage. Pinned so the behaviour is never "discovered" in prod."""
        provider = make_provider(allowed_groups=frozenset({"FGA-GovAffairs"}))
        with pytest.raises(AuthzDenied) as exc:
            provider._okta.check_authorized({"sub": "00u1", "email": "staff@example.org"})
        assert "groups" in str(exc.value)

    def test_tool_gating_is_off_by_default(self):
        """Same trap one level down: the per-tool gate would deny every call
        today, because the shared Okta app emits no groups claim."""
        assert make_settings().tool_gating_enabled is False
        assert Settings().tool_gating_enabled is False


# --------------------------------------------------------------------------- #
# T2 — per-tool GroupGate
# --------------------------------------------------------------------------- #
class TestToolGroupGate:
    async def test_disabled_gate_returns_the_function_unwrapped(self):
        """Default-OFF must be a true no-op — same object, no runtime cost, and
        nothing to reason about on servers that have not opted in."""
        gate = GroupGate(make_settings(tool_gating=False))

        async def get_candidate():
            return "pii"

        assert gate.require("MCP Teamtailor Users")(get_candidate) is get_candidate

    async def test_enabled_gate_admits_a_group_member(self):
        gate = GroupGate(make_settings(tool_gating=True))

        @gate.require("MCP Teamtailor Users")
        async def get_candidate():
            return "pii"

        with as_caller(user_token("Everyone", "MCP Teamtailor Users")):
            assert await get_candidate() == "pii"

    async def test_enabled_gate_denies_a_non_member(self):
        gate = GroupGate(make_settings(tool_gating=True))

        @gate.require("MCP Teamtailor Users")
        async def get_candidate():
            return "pii"

        with as_caller(user_token("Everyone")), pytest.raises(ToolError, match="Teamtailor"):
            await get_candidate()

    async def test_enabled_gate_denies_a_token_with_no_groups_claim(self):
        """Fail-closed, same rule as the login gate: an Okta app that stopped
        emitting groups must deny, not open the door."""
        gate = GroupGate(make_settings(tool_gating=True))

        @gate.require("MCP Teamtailor Users")
        async def get_candidate():
            return "pii"

        with as_caller(user_token()), pytest.raises(ToolError):
            await get_candidate()

    async def test_enabled_gate_denies_when_there_is_no_caller_at_all(self):
        """stdio has no auth context. A gated server must not be run over stdio,
        and this is what happens if it is."""
        gate = GroupGate(make_settings(tool_gating=True))

        @gate.require("MCP Teamtailor Users")
        async def get_candidate():
            return "pii"

        with as_caller(None), pytest.raises(ToolError):
            await get_candidate()

    async def test_enabled_gate_admits_the_service_token(self):
        """Parity with today: socialbot's static token has unrestricted access.
        Narrowing that is a deliberate future change, not a side effect of
        turning gating on."""
        gate = GroupGate(make_settings(tool_gating=True))

        @gate.require("MCP Teamtailor Users")
        async def get_candidate():
            return "pii"

        with as_caller(user_token(client_id=SERVICE_CLIENT_ID)):
            assert await get_candidate() == "pii"

    async def test_gate_accepts_any_of_several_groups(self):
        gate = GroupGate(make_settings(tool_gating=True))

        @gate.require("HR", "Recruiting")
        async def get_candidate():
            return "pii"

        with as_caller(user_token("Recruiting")):
            assert await get_candidate() == "pii"

    def test_require_needs_at_least_one_group(self):
        gate = GroupGate(make_settings(tool_gating=True))
        with pytest.raises(ValueError):
            gate.require()

    async def test_gate_preserves_tool_metadata(self):
        """The MCP SDK reads __name__ and __doc__ off the decorated function to
        build the tool schema, so the wrapper must not eat them."""
        gate = GroupGate(make_settings(tool_gating=True))

        @gate.require("HR")
        async def get_candidate():
            """Fetch one candidate."""

        assert get_candidate.__name__ == "get_candidate"
        assert get_candidate.__doc__ == "Fetch one candidate."
