"""fga-mcp-auth — FGA's shared Okta OIDC auth layer for MCP servers.

One IdP, one flow shape, both SDK lines. See README.md for wiring.

The wiring helpers are re-exported here but imported lazily: `wire_sdk1` touches
MCP SDK 1.x internals and `auth_kwargs` touches 2.0 internals, so importing both
eagerly would break under either pin.
"""

from __future__ import annotations

from typing import Any

from ._compat import SdkMismatch, sdk_major, sdk_version
from .constants import (
    ACCESS_TTL,
    ALLOWED_REDIRECT_DOMAINS,
    AUTH_CODE_TTL,
    MAX_CLIENTS,
    PENDING_TTL,
    REFRESH_TTL,
    SERVICE_CLIENT_ID,
    TOKEN_VERSION,
)
from .gating import GroupGate
from .okta import AuthzDenied, OktaOIDC
from .provider import FGAAccessToken, FGAAuthProvider, FGARefreshToken
from .redirects import is_allowed_redirect
from .settings import OktaConfig, Settings
from .tokens import InvalidTokenFormat

__version__ = "1.0.0"

_LAZY = {
    "wire_sdk1": ("fga_mcp_auth.wiring.sdk1", "wire_sdk1"),
    "auth_kwargs": ("fga_mcp_auth.wiring.sdk2", "auth_kwargs"),
    "register_auth_routes": ("fga_mcp_auth.wiring.sdk2", "register_auth_routes"),
    "audit_middleware": ("fga_mcp_auth.wiring.sdk2", "audit_middleware"),
}


def __getattr__(name: str) -> Any:
    target = _LAZY.get(name)
    if target is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    module, attr = target
    return getattr(__import__(module, fromlist=[attr]), attr)


__all__ = [
    "ACCESS_TTL",
    "ALLOWED_REDIRECT_DOMAINS",
    "AUTH_CODE_TTL",
    "MAX_CLIENTS",
    "PENDING_TTL",
    "REFRESH_TTL",
    "SERVICE_CLIENT_ID",
    "TOKEN_VERSION",
    "AuthzDenied",
    "FGAAccessToken",
    "FGAAuthProvider",
    "FGARefreshToken",
    "GroupGate",
    "InvalidTokenFormat",
    "OktaConfig",
    "OktaOIDC",
    "SdkMismatch",
    "Settings",
    "__version__",
    "audit_middleware",
    "auth_kwargs",
    "is_allowed_redirect",
    "register_auth_routes",
    "sdk_major",
    "sdk_version",
    "wire_sdk1",
]
