"""Wiring for the MCP SDK 2.0 line (`mcp.server.MCPServer`).

    from fga_mcp_auth import (
        Settings, auth_kwargs, register_auth_routes, audit_middleware, build_http_app,
    )

    settings = Settings()
    provider, kwargs = auth_kwargs(settings)
    mcp = MCPServer(name="fga-ob3", middleware=[audit_middleware(settings)], **kwargs)
    register_auth_routes(mcp, provider)
    app = build_http_app(mcp, settings, json_response=True, stateless_http=True)

2.0 takes auth via constructor kwargs and REJECTS being handed both an
`auth_server_provider` and a `token_verifier` (1.x required both), so
`auth_kwargs` never returns a verifier.

Build the ASGI app with `build_http_app`, not `mcp.streamable_http_app()`
directly. DNS-rebinding / Host-header protection is a `streamable_http_app`
kwarg on this SDK line, not a constructor one, so it is the single piece of the
1.x helper's job that cannot live in `auth_kwargs` — and fga-ob3-mcp passes it
today. A consumer that follows the wiring recipe and calls the SDK method itself
drops that protection with every test still green, which is exactly how it would
go missing.
"""

from __future__ import annotations

import logging
from typing import Any

from .._compat import require_sdk2
from ..audit import AuditMiddleware
from ..provider import FGAAuthProvider
from ..settings import Settings

logger = logging.getLogger(__name__)


def auth_kwargs(settings: Settings) -> tuple[FGAAuthProvider, dict[str, Any]]:
    """Build the provider and the MCPServer constructor kwargs for it."""
    require_sdk2()
    from mcp.server.auth.settings import (
        AuthSettings,
        ClientRegistrationOptions,
        RevocationOptions,
    )

    # Same fail-loud guard as the 1.x helper. fga-ob3-mcp used to boot happily
    # with Okta silently disabled; it no longer can.
    settings.require_http_complete()

    provider = FGAAuthProvider(settings)
    issuer_url = settings.public_base_url

    kwargs: dict[str, Any] = {
        "auth_server_provider": provider,
        "auth": AuthSettings(
            issuer_url=issuer_url,
            resource_server_url=issuer_url,
            client_registration_options=ClientRegistrationOptions(enabled=True, valid_scopes=[]),
            # Deliberately OFF — see wiring/sdk1.py for the reasoning.
            revocation_options=RevocationOptions(enabled=False),
        ),
    }
    logger.info(
        "Okta SSO wired (MCP SDK 2.0)",
        extra={
            "server": settings.audience,
            "issuer": issuer_url,
            "service_token_enabled": bool(settings.service_token_value()),
            "tool_gating": settings.tool_gating_enabled,
        },
    )
    return provider, kwargs


def register_auth_routes(mcp: Any, provider: FGAAuthProvider) -> None:
    """Mount /login, /okta/callback and /oauth/error on an MCPServer.

    /login is new to SDK 2.0 consumers: the package uses the login-hop shape from
    fga-quorum-mcp for both SDK lines rather than shipping two flow shapes. The
    user-visible difference is one extra 302.
    """
    require_sdk2()

    @mcp.custom_route("/login", methods=["GET"])
    async def _login_get(request):
        return await provider.handle_login_get(request)

    @mcp.custom_route("/okta/callback", methods=["GET"])
    async def _okta_callback(request):
        return await provider.handle_okta_callback(request)

    @mcp.custom_route("/oauth/error", methods=["GET"])
    async def _oauth_error(request):
        return provider.handle_oauth_error(request)


def build_http_app(mcp: Any, settings: Settings, **kwargs: Any) -> Any:
    """`mcp.streamable_http_app()` with transport security already attached.

    Symmetric with wire_sdk1, which sets `mcp.settings.transport_security` for
    the 1.x consumer. Everything else passes straight through, and an explicit
    `transport_security=` wins — a consumer with extra hostnames (a vanity
    domain in front of the DO app) still owns that decision.
    """
    require_sdk2()
    from mcp.server.transport_security import TransportSecuritySettings

    kwargs.setdefault(
        "transport_security",
        TransportSecuritySettings(
            enable_dns_rebinding_protection=bool(settings.allowed_host),
            allowed_hosts=[settings.allowed_host] if settings.allowed_host else [],
        ),
    )
    return mcp.streamable_http_app(**kwargs)


def audit_middleware(settings: Settings) -> AuditMiddleware:
    """Per-tool-call audit logging. SDK 2.0 only — register it outermost."""
    require_sdk2()
    return AuditMiddleware(settings)
