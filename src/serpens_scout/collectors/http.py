"""Small HTTPS client with a strict destination allowlist."""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

ALLOWED_HOSTS = {
    "api.github.com",
    "dns.google",
    "research.checkpoint.com",
    "unit42.paloaltonetworks.com",
}
USER_AGENT = "serpens-scout/0.1 (+https://github.com/SkeinLLC/serpens-scout)"


def get_bytes(url: str, headers: dict[str, str] | None = None, retries: int = 2) -> bytes:
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme != "https" or parsed.hostname not in ALLOWED_HOSTS:
        raise ValueError(f"destination is not allowlisted: {parsed.hostname or url}")
    request_headers = {"User-Agent": USER_AGENT, "Accept": "*/*"}
    request_headers.update(headers or {})
    request = urllib.request.Request(url, headers=request_headers)
    for attempt in range(retries + 1):
        try:
            with urllib.request.urlopen(request, timeout=30) as response:  # noqa: S310
                return response.read()
        except (urllib.error.URLError, TimeoutError):
            if attempt == retries:
                raise
            time.sleep(0.5 * (2**attempt))
    raise RuntimeError("unreachable")


def get_json(url: str, headers: dict[str, str] | None = None) -> Any:
    return json.loads(get_bytes(url, headers=headers).decode("utf-8"))
