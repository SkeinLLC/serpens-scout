"""Optional public-code baseline for AppDomainManager configuration prevalence."""

from __future__ import annotations

import base64
import binascii
import os
import time
import urllib.parse

from serpens_scout.collectors.http import get_json
from serpens_scout.configscan import scan_config_bytes

QUERIES = (
    "appDomainManagerType extension:config",
    '"etwEnable" "enabled=\\"false\\"" extension:config',
    "bypassTrustedAppStrongNames extension:config",
    '"publisherPolicy" "apply=\\"no\\"" extension:config',
    '"appDomainManagerType" "etwEnable" "bypassTrustedAppStrongNames" extension:config',
)


def _headers(token: str) -> dict[str, str]:
    return {
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {token}",
        "X-GitHub-Api-Version": "2022-11-28",
    }


def _decode_base64_content(value: str) -> bytes:
    """Decode GitHub content API payloads after removing documented line wrapping."""

    return base64.b64decode("".join(value.split()), validate=True)


def _search(query: str, token: str, per_page: int) -> dict[str, object]:
    encoded = urllib.parse.urlencode({"q": query, "per_page": per_page})
    return get_json(f"https://api.github.com/search/code?{encoded}", _headers(token))


def collect_github_baseline(limit: int = 20) -> dict[str, object]:
    token = os.getenv("GITHUB_TOKEN", "")
    if not token:
        return {"status": "skipped", "reason": "GITHUB_TOKEN is not set", "queries": []}
    query_results: list[dict[str, object]] = []
    broad_items: list[dict[str, object]] = []
    errors: list[str] = []
    for index, query in enumerate(QUERIES):
        try:
            result = _search(query, token, min(limit if index == 0 else 1, 100))
        except (OSError, RuntimeError, ValueError) as exc:
            errors.append(f"query failed: {query}: {exc}")
            query_results.append(
                {
                    "query": query,
                    "total_count": 0,
                    "incomplete_results": True,
                    "error": str(exc),
                }
            )
            continue
        query_results.append(
            {
                "query": query,
                "total_count": result.get("total_count", 0),
                "incomplete_results": result.get("incomplete_results", False),
            }
        )
        if index == 0:
            items = result.get("items", [])
            if not isinstance(items, list):
                errors.append("GitHub search response contained an invalid items field")
            else:
                broad_items = [item for item in items if isinstance(item, dict)][:limit]
        # GitHub Code Search can enforce a 10-requests-per-minute resource bucket.
        time.sleep(6.5)

    samples: list[dict[str, object]] = []
    for item in broad_items:
        repository = item.get("repository")
        item_url = item.get("url")
        path = item.get("path")
        html_url = item.get("html_url")
        if (
            not isinstance(repository, dict)
            or not isinstance(repository.get("full_name"), str)
            or not isinstance(item_url, str)
            or not isinstance(path, str)
            or not isinstance(html_url, str)
        ):
            errors.append("GitHub search response contained an invalid result item")
            continue
        try:
            content = get_json(item_url, _headers(token))
        except (OSError, RuntimeError, ValueError) as exc:
            errors.append(f"content fetch failed: {html_url}: {exc}")
            continue
        encoded_content = content.get("content")
        if content.get("encoding") != "base64" or not isinstance(encoded_content, str):
            continue
        try:
            data = _decode_base64_content(encoded_content)
        except (binascii.Error, ValueError):
            errors.append(f"content fetch returned invalid base64: {html_url}")
            continue
        full_name = repository["full_name"]
        scan = scan_config_bytes(data, f"{full_name}:{path}")
        samples.append(
            {
                "repository": full_name,
                "path": path,
                "html_url": html_url,
                "scan": scan.to_dict(),
            }
        )
        time.sleep(0.05)
    return {
        "status": "partial" if errors else "complete",
        "scope": "public GitHub Code Search; sampled results are not a known-good corpus",
        "queries": query_results,
        "sample_count": len(samples),
        "samples": samples,
        "errors": errors,
    }
