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
MAX_RESPONSE_BYTES = 10 * 1024 * 1024


def _validate_url(url: str) -> urllib.parse.ParseResult:
    parsed = urllib.parse.urlparse(url)
    if (
        parsed.scheme != "https"
        or parsed.hostname not in ALLOWED_HOSTS
        or parsed.port not in {None, 443}
        or parsed.username is not None
        or parsed.password is not None
    ):
        raise ValueError(f"destination is not allowlisted: {parsed.hostname or url}")
    return parsed


class _AllowlistedRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Allow redirects only when HTTPS and the hostname stays unchanged."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001, ANN201
        target = urllib.parse.urljoin(req.full_url, newurl)
        current = _validate_url(req.full_url)
        redirected = _validate_url(target)
        if redirected.hostname != current.hostname:
            raise urllib.error.HTTPError(
                target,
                code,
                "cross-host redirect blocked",
                headers,
                fp,
            )
        return super().redirect_request(req, fp, code, msg, headers, target)


_OPENER = urllib.request.build_opener(_AllowlistedRedirectHandler())


def _read_bounded(response, limit: int = MAX_RESPONSE_BYTES) -> bytes:  # noqa: ANN001
    length = response.headers.get("Content-Length", "")
    if length.isdigit() and int(length) > limit:
        raise RuntimeError("response exceeds size limit")
    data = response.read(limit + 1)
    if len(data) > limit:
        raise RuntimeError("response exceeds size limit")
    return data


def get_bytes(url: str, headers: dict[str, str] | None = None, retries: int = 3) -> bytes:
    parsed = _validate_url(url)
    request_headers = {"User-Agent": USER_AGENT, "Accept": "*/*"}
    request_headers.update(headers or {})
    request = urllib.request.Request(url, headers=request_headers)  # noqa: S310
    for attempt in range(retries + 1):
        try:
            # The URL and every redirect are validated immediately above.
            with _OPENER.open(request, timeout=30) as response:  # nosec B310  # noqa: S310
                return _read_bounded(response)
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


def get_json(url: str, headers: dict[str, str] | None = None) -> dict[str, Any]:
    value = json.loads(get_bytes(url, headers=headers).decode("utf-8"))
    if not isinstance(value, dict):
        raise ValueError("JSON response must be an object")
    return value
