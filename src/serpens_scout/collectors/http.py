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


def get_bytes(url: str, headers: dict[str, str] | None = None, retries: int = 3) -> bytes:
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
        except urllib.error.HTTPError as exc:
            if exc.code == 429 and attempt < retries:
                retry_after = exc.headers.get("Retry-After", "")
                delay = float(retry_after) if retry_after.isdigit() else 0.5 * (2**attempt)
                time.sleep(min(delay, 10.0))
                continue
            raise RuntimeError(f"{parsed.hostname} returned HTTP {exc.code}") from exc
        except (urllib.error.URLError, TimeoutError) as exc:
            if attempt == retries:
                raise RuntimeError(f"request failed for {parsed.hostname}: {exc}") from exc
            time.sleep(0.5 * (2**attempt))
    raise RuntimeError("unreachable")


def get_json(url: str, headers: dict[str, str] | None = None) -> Any:
    return json.loads(get_bytes(url, headers=headers).decode("utf-8"))
