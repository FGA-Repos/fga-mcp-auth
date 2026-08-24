"""T4, the MCP SDK 1.x half: wire_sdk1 against a real FastMCP instance.

Skipped on the 2.0 leg of the matrix.
"""

from __future__ import annotations

import pytest
from conftest import HOST, REQUIRED_ENV, SDK_MAJOR, SERVICE_TOKEN, make_settings

from fga_mcp_auth import Settings
from fga_mcp_auth._compat import SdkMismatch

pytestmark = pytest.mark.skipif(SDK_MAJOR >= 2, reason="MCP SDK 1.x wiring")


@pytest.fixture
def wired(monkeypatch):
    from mcp.server.fastmcp import FastMCP

    from fga_mcp_auth import wire_sdk1

    for name, value in REQUIRED_ENV.items():
        monkeypatch.setenv(name, value)
    monkeypatch.setenv("MCP_BEARER_TOKEN", SERVICE_TOKEN)
    mcp = FastMCP(name="fga-test")
    provider = wire_sdk1(mcp, Settings())
    return mcp, provider


@pytest.fixture
def app(wired):
    mcp, _provider = wired
    return mcp.streamable_http_app()


def _routes(app) -> dict[str, set[str]]:
    return {r.path: set(getattr(r, "methods", None) or set()) for r in app.routes}


class TestHttpAppWiring:
    """The routes the design depends on must actually exist on the built app.

    An /oauth/error that 404s would still keep the user on our origin, but the
    login-hop and callback routes are load-bearing: if they aren't mounted, the
    whole Okta leg is unreachable and staff simply cannot connect.
    """

    def test_okta_routes_are_mounted(self, app):
        routes = _routes(app)
        for path in ("/login", "/okta/callback", "/oauth/error"):
            assert path in routes, f"{path} missing — {sorted(routes)}"

    def test_login_no_longer_accepts_a_password_post(self, app):
        """The shared-password form is gone; /login is a GET hop to Okta only."""
        assert "POST" not in _routes(app)["/login"]

    def test_oauth_endpoints_present(self, app):
        routes = _routes(app)
        for path in ("/register", "/authorize", "/token"):
            assert path in routes, f"{path} missing — {sorted(routes)}"

    def test_revocation_endpoint_deliberately_absent(self, app):
        """Pinned on purpose: tokens are stateless, so /revoke would 200 while
        the token kept working. Re-enable only alongside a jti denylist."""
        assert "/revoke" not in _routes(app)

    def test_issuer_is_our_public_https_origin(self, wired):
        mcp, _provider = wired
        assert str(mcp.settings.auth.issuer_url).rstrip("/") == f"https://{HOST}"

    def test_both_auth_attributes_are_set(self, wired):
        """1.x needs the provider AND a token verifier; missing either means the
        server boots but rejects (or accepts) everything."""
        mcp, provider = wired
        assert mcp._auth_server_provider is provider
        assert mcp._token_verifier is not None

    def test_dns_rebinding_protection_is_keyed_on_the_public_host(self, wired):
        mcp, _provider = wired
        security = mcp.settings.transport_security
        assert security.enable_dns_rebinding_protection is True
        assert security.allowed_hosts == [HOST]

    def test_revocation_is_advertised_as_disabled(self, wired):
        mcp, _provider = wired
        assert mcp.settings.auth.revocation_options.enabled is False

    def test_dynamic_client_registration_is_enabled(self, wired):
        """claude.ai cannot connect without it."""
        mcp, _provider = wired
        assert mcp.settings.auth.client_registration_options.enabled is True


class TestUnauthenticatedRequests:
    def test_mcp_endpoint_rejects_an_anonymous_call(self, app):
        from starlette.testclient import TestClient

        with TestClient(app) as client:
            resp = client.post(
                "/mcp",
                json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
                headers={"Accept": "application/json, text/event-stream", "Host": HOST},
            )
        assert resp.status_code == 401
        assert "www-authenticate" in {k.lower() for k in resp.headers}

    def test_mcp_endpoint_rejects_a_forged_bearer(self, app):
        from starlette.testclient import TestClient

        with TestClient(app) as client:
            resp = client.post(
                "/mcp",
                json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
                headers={
                    "Accept": "application/json, text/event-stream",
                    "Authorization": "Bearer not-a-real-token",
                    "Host": HOST,
                },
            )
        assert resp.status_code == 401

    def test_service_token_authenticates_through_the_wired_app(self, app):
        """T1, the wiring half. socialbot and the deploy-verification scripts
        reach /mcp with exactly this header; if MCP_BEARER_TOKEN ever stopped
        being honoured at the transport layer, socialbot's tool calls would
        start 401ing in production. Anything but 401 means auth let it through
        (a stateful transport then wants a session handshake, which is not what
        this test is about)."""
        from starlette.testclient import TestClient

        with TestClient(app) as client:
            resp = client.post(
                "/mcp",
                json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
                headers={
                    "Accept": "application/json, text/event-stream",
                    "Authorization": f"Bearer {SERVICE_TOKEN}",
                    "Host": HOST,
                },
            )
        assert resp.status_code != 401, resp.text


class TestHttpStartupGuard:
    """A server that boots with SSO silently disabled is the worst outcome."""

    @pytest.mark.parametrize("var", list(REQUIRED_ENV))
    def test_each_missing_var_refuses_to_wire(self, monkeypatch, var):
        from mcp.server.fastmcp import FastMCP

        from fga_mcp_auth import wire_sdk1

        for name, value in REQUIRED_ENV.items():
            if name != var:
                monkeypatch.setenv(name, value)
        with pytest.raises(RuntimeError, match=var):
            wire_sdk1(FastMCP(name="fga-test"), Settings())

    def test_all_missing_vars_are_named_at_once(self, monkeypatch):
        from mcp.server.fastmcp import FastMCP

        from fga_mcp_auth import wire_sdk1

        with pytest.raises(RuntimeError) as exc:
            wire_sdk1(FastMCP(name="fga-test"), Settings())
        for var in REQUIRED_ENV:
            assert var in str(exc.value)

    def test_the_guard_runs_before_anything_is_attached(self, monkeypatch):
        """Half-wiring a server would be worse than not wiring it."""
        from mcp.server.fastmcp import FastMCP

        from fga_mcp_auth import wire_sdk1

        mcp = FastMCP(name="fga-test")
        with pytest.raises(RuntimeError):
            wire_sdk1(mcp, Settings())
        assert mcp._auth_server_provider is None
        assert mcp.settings.auth is None


class TestSdkGate:
    def test_sdk2_helpers_refuse_to_run_here(self):
        from fga_mcp_auth import auth_kwargs

        with pytest.raises(SdkMismatch, match="wire_sdk1"):
            auth_kwargs(make_settings())
