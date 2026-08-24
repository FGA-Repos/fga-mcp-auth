"""Wiring for the MCP SDK 1.x line (`mcp.server.fastmcp.FastMCP`).

1.x takes auth through private attributes and `mcp.settings`, and requires BOTH
`_auth_server_provider` and `_token_verifier` to be set. Consumers should never
reach into those themselves again — that coupling is exactly what this package
absorbs.
"""

from __future__ import annotations

import logging
from typing import Any

from .._compat import require_sdk1
from ..provider import FGAAuthProvider
from ..settings import Settings

logger = logging.getLogger(__name__)


def wire_sdk1(mcp: Any, settings: Settings) -> FGAAuthProvider:
    """Attach Okta SSO to a FastMCP instance. Returns the provider.

    Order matters and is the order fga-quorum-mcp runs in production:
    fail-loud config check, provider, auth attrs, AuthSettings, transport
    security, routes.
    """
    require_sdk1()
    # SDK-touching imports live inside the function, after the gate, so
    # `import fga_mcp_auth` works under either pin.
    from mcp.server.auth.provider import ProviderTokenVerifier
    from mcp.server.auth.settings import (
        AuthSettings,
        ClientRegistrationOptions,
        RevocationOptions,
    )
    from mcp.server.transport_security import TransportSecuritySettings

    # A server that boots with SSO silently disabled is worse than one that
    # refuses to start. Names every missing var at once.
    settings.require_http_complete()

    provider = FGAAuthProvider(settings)
    issuer_url = settings.public_base_url

    mcp._auth_server_provider = provider
    mcp._token_verifier = ProviderTokenVerifier(provider)
    mcp.settings.auth = AuthSettings(
        issuer_url=issuer_url,
        resource_server_url=issuer_url,
        client_registration_options=ClientRegistrationOptions(enabled=True, valid_scopes=[]),
        # Deliberately OFF. Tokens are stateless, so revoke_token cannot
        # actually invalidate anything — advertising RFC 7009 meant returning
        # HTTP 200 to a revocation request while the token kept working. Better
        # to not claim the capability. Re-enable only alongside a jti denylist;
        # the blunt instrument remains rotating MCP_TOKEN_SECRET.
        revocation_options=RevocationOptions(enabled=False),
    )
    mcp.settings.transport_security = TransportSecuritySettings(
        enable_dns_rebinding_protection=bool(settings.allowed_host),
        allowed_hosts=[settings.allowed_host] if settings.allowed_host else [],
    )

    @mcp.custom_route("/login", methods=["GET"])
    async def _login_get(request):
        return await provider.handle_login_get(request)

    @mcp.custom_route("/okta/callback", methods=["GET"])
    async def _okta_callback(request):
        return await provider.handle_okta_callback(request)

    # On-origin error page. Exists so a rejected redirect_uri can be reported
    # without bouncing the user to the untrusted URI (see provider.authorize).
    @mcp.custom_route("/oauth/error", methods=["GET"])
    async def _oauth_error(request):
        return provider.handle_oauth_error(request)

    logger.info(
        "Okta SSO wired (MCP SDK 1.x)",
        extra={
            "server": settings.audience,
            "issuer": issuer_url,
            "service_token_enabled": bool(settings.service_token_value()),
            "tool_gating": settings.tool_gating_enabled,
        },
    )
    return provider
