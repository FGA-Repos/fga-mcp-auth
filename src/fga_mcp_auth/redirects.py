"""The redirect-URI allowlist predicate.

Enforced at DCR registration (see provider.register_client), with a
defence-in-depth check in authorize(). DCR is unauthenticated — anyone can
register a client — so this predicate is the only thing standing between a
stranger and an open redirect on our origin during a staff sign-in.

Hardened relative to what shipped in fga-quorum-mcp / fga-ob3-mcp, which both
used `host == d or host.endswith("." + d)` over a flat domain set and never
looked at the scheme:

  * loopback is matched EXACTLY — `anything.localhost` and
    `anything.127.0.0.1` no longer pass. `.localhost` is reserved (RFC 6761) and
    no registrable TLD is all-numeric, so this was not exploitable; it was still
    broader than intended.
  * https is REQUIRED for claude.ai / claude.com. http and exotic schemes
    (`ftp:`) used to pass on an allowed host.
  * a literal backslash anywhere in the URI is rejected outright. urlparse is
    RFC 3986, browsers are WHATWG, and they disagree about `\\` in the authority:
    `https://phish.example\\@claude.ai/` is host `claude.ai` to urlparse and host
    `phish.example` to every browser. Both call sites happen to receive a
    pydantic `AnyUrl` that has already normalized to WHATWG form, but relying on
    that is relying on someone else's normalization; reject the character.
"""

from __future__ import annotations

from urllib.parse import urlparse

from .constants import HTTPS_REDIRECT_DOMAINS, LOOPBACK_REDIRECT_HOSTS


def is_allowed_redirect(uri: str) -> bool:
    raw = str(uri)
    if "\\" in raw:
        return False
    parsed = urlparse(raw)
    host = (parsed.hostname or "").lower()
    scheme = (parsed.scheme or "").lower()
    if not host:
        return False
    if host in LOOPBACK_REDIRECT_HOSTS:
        return scheme in ("http", "https")
    if any(host == domain or host.endswith(f".{domain}") for domain in HTTPS_REDIRECT_DOMAINS):
        return scheme == "https"
    return False
