"""URL helpers small enough that a module of their own beats a circular import."""

from __future__ import annotations

from urllib.parse import urlencode


def append_params(uri: str, params: dict[str, str]) -> str:
    sep = "&" if "?" in uri else "?"
    return f"{uri}{sep}{urlencode(params)}"
