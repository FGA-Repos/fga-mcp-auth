"""T4, the MCP SDK 2.0 half: auth_kwargs + register_auth_routes + audit_middleware.

Neither source repo had an equivalent of quorum's wiring tests on the 2.0 side,
so this file is new. Skipped on the 1.x leg of the matrix.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from conftest import HOST, REQUIRED_ENV, SDK_MAJOR, SERVICE_TOKEN, make_settings

from fga_mcp_auth import FGAAuthProvider, Settings
from fga_mcp_auth._compat import SdkMismatch

pytestmark = pytest.mark.skipif(SDK_MAJOR < 2, reason="MCP SDK 2.0 wiring")


@pytest.fixture
def wired(monkeypatch):
    from mcp.server import MCPServer

    from fga_mcp_auth import audit_middleware, auth_kwargs, register_auth_routes

    for name, value in REQUIRED_ENV.items():
        monkeypatch.setenv(name, value)
    monkeypatch.setenv("MCP_BEARER_TOKEN", SERVICE_TOKEN)
    settings = Settings()
    provider, kwargs = auth_kwargs(settings)
    mcp = MCPServer(name="fga-test", middleware=[audit_middleware(settings)], **kwargs)
    register_auth_routes(mcp, provider)
    return mcp, provider, kwargs


@pytest.fixture
def app(wired):
    """Built the way a consumer is told to build it, so the tests exercise the
    transport security the package supplies rather than one the test wrote."""
    from fga_mcp_auth import build_http_app

    mcp, _provider, _kwargs = wired
    return build_http_app(mcp, Settings(), json_response=True, stateless_http=True)


def _routes(app) -> dict[str, set[str]]:
    return {r.path: set(getattr(r, "methods", None) or set()) for r in app.routes}


class TestAuthKwargs:
    def test_returns_provider_and_auth_only(self, wired):
        """2.0 rejects being handed both an auth_server_provider and a
        token_verifier (1.x required both), so a stray verifier here is a boot
        failure in production."""
        _mcp, provider, kwargs = wired
        assert set(kwargs) == {"auth_server_provider", "auth"}
        assert kwargs["auth_server_provider"] is provider
        assert isinstance(provider, FGAAuthProvider)

    def test_issuer_is_our_public_https_origin(self, wired):
        _mcp, _provider, kwargs = wired
        assert str(kwargs["auth"].issuer_url).rstrip("/") == f"https://{HOST}"

    def test_revocation_is_advertised_as_disabled(self, wired):
        _mcp, _provider, kwargs = wired
        assert kwargs["auth"].revocation_options.enabled is False

    def test_dynamic_client_registration_is_enabled(self, wired):
        _mcp, _provider, kwargs = wired
        assert kwargs["auth"].client_registration_options.enabled is True


class TestHttpAppWiring:
    def test_okta_routes_are_mounted(self, app):
        """/login is new to SDK 2.0 consumers — the package uses one flow shape
        for both SDK lines rather than shipping two."""
        routes = _routes(app)
        for path in ("/login", "/okta/callback", "/oauth/error"):
            assert path in routes, f"{path} missing — {sorted(routes)}"

    def test_login_no_longer_accepts_a_password_post(self, app):
        assert "POST" not in _routes(app)["/login"]

    def test_oauth_endpoints_present(self, app):
        routes = _routes(app)
        for path in ("/register", "/authorize", "/token"):
            assert path in routes, f"{path} missing — {sorted(routes)}"

    def test_revocation_endpoint_deliberately_absent(self, app):
        assert "/revoke" not in _routes(app)

    def test_a_custom_token_route_cannot_shadow_the_sdk_one(self, wired):
        """The 2.0 half of the EMA mounting note in grants.py: same ordering,
        so `custom_route("/token")` is dead code here too."""
        from fga_mcp_auth import build_http_app

        mcp, _provider, _kwargs = wired

        @mcp.custom_route("/token", methods=["POST"])
        async def _shadow_token(request):  # pragma: no cover - never reached
            raise AssertionError("the SDK's /token should have matched first")

        app = build_http_app(mcp, Settings(), json_response=True, stateless_http=True)
        routes = [r for r in app.routes if r.path == "/token"]
        assert len(routes) == 2, "expected the SDK's /token and ours to coexist"
        assert getattr(routes[0].endpoint, "__name__", "") != "_shadow_token"


class TestTransportSecurity:
    """DNS-rebinding / Host-header protection, which fga-ob3-mcp passes live.

    On SDK 2.0 it is a `streamable_http_app()` kwarg, not a constructor one, so
    it is the one piece of wire_sdk1's job that `auth_kwargs` structurally cannot
    do. Before `build_http_app` existed, a consumer following the README recipe
    dropped it silently and every test stayed green — which is exactly how it
    would have gone missing from ob3 at the retrofit.
    """

    def test_build_http_app_keys_protection_on_the_public_host(self, wired):
        from fga_mcp_auth import build_http_app

        mcp, _provider, _kwargs = wired
        captured = {}

        def _capture(**kwargs):
            captured.update(kwargs)
            return "app"

        mcp.streamable_http_app = _capture
        build_http_app(mcp, Settings(), json_response=True)
        security = captured["transport_security"]
        assert security.enable_dns_rebinding_protection is True
        assert security.allowed_hosts == [HOST]
        assert captured["json_response"] is True

    def test_a_foreign_host_header_is_refused(self, app):
        """The protection doing its job end to end, not just being configured."""
        from starlette.testclient import TestClient

        with TestClient(app) as client:
            resp = client.post(
                "/mcp",
                json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
                headers={
                    "Accept": "application/json, text/event-stream",
                    "Authorization": f"Bearer {SERVICE_TOKEN}",
                    "Host": "evil.example",
                },
            )
        # 421 Misdirected Request is what the SDK's Host check answers with; a
        # plain 400 would do. What must never happen is 200.
        assert resp.status_code in (400, 421), resp.status_code

    def test_an_explicit_transport_security_wins(self, wired):
        """A consumer fronting the DO app with a vanity domain still owns the
        host list; the package only supplies the default."""
        from mcp.server.transport_security import TransportSecuritySettings

        from fga_mcp_auth import build_http_app

        mcp, _provider, _kwargs = wired
        captured = {}
        mcp.streamable_http_app = lambda **kw: captured.update(kw)
        mine = TransportSecuritySettings(
            enable_dns_rebinding_protection=True, allowed_hosts=[HOST, "mcp.thefga.org"]
        )
        build_http_app(mcp, Settings(), transport_security=mine)
        assert captured["transport_security"] is mine

    def test_local_dev_without_a_public_host_does_not_lock_itself_out(self):
        """MCP_ALLOWED_HOST is boot-required for HTTP, so this is the stdio /
        local-dev shape only — it must not produce an empty allowlist WITH
        protection on, which refuses every request."""
        from fga_mcp_auth import build_http_app

        captured = {}
        mcp = SimpleNamespace(streamable_http_app=lambda **kw: captured.update(kw))
        build_http_app(mcp, make_settings(host=None))
        assert captured["transport_security"].enable_dns_rebinding_protection is False


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
        """T1, the wiring half — see the SDK 1.x file for why this matters."""
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
    """The deliberate behavior change to fga-ob3-mcp: it used to require only
    MCP_TOKEN_SECRET and boot happily with Okta silently disabled."""

    @pytest.mark.parametrize("var", list(REQUIRED_ENV))
    def test_each_missing_var_refuses_to_wire(self, monkeypatch, var):
        from fga_mcp_auth import auth_kwargs

        for name, value in REQUIRED_ENV.items():
            if name != var:
                monkeypatch.setenv(name, value)
        with pytest.raises(RuntimeError, match=var):
            auth_kwargs(Settings())

    def test_all_missing_vars_are_named_at_once(self):
        from fga_mcp_auth import auth_kwargs

        with pytest.raises(RuntimeError) as exc:
            auth_kwargs(Settings())
        for var in REQUIRED_ENV:
            assert var in str(exc.value)


class TestSdkGate:
    def test_sdk1_helper_refuses_to_run_here(self):
        from fga_mcp_auth import wire_sdk1

        with pytest.raises(SdkMismatch, match="auth_kwargs"):
            wire_sdk1(object(), make_settings())

    def test_audit_middleware_is_available(self):
        from fga_mcp_auth import audit_middleware
        from fga_mcp_auth.audit import AuditMiddleware

        assert isinstance(audit_middleware(make_settings()), AuditMiddleware)
