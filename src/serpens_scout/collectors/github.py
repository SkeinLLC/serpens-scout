"""Optional public-code baseline for AppDomainManager configuration prevalence."""

from __future__ import annotations

import base64
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
            broad_items = result.get("items", [])[:limit]
        time.sleep(0.15)

    samples: list[dict[str, object]] = []
    for item in broad_items:
        try:
            content = get_json(str(item["url"]), _headers(token))
        except (OSError, RuntimeError, ValueError) as exc:
            errors.append(f"content fetch failed: {item.get('html_url', 'unknown')}: {exc}")
            continue
        if content.get("encoding") != "base64" or not content.get("content"):
            continue
        data = base64.b64decode(str(content["content"]))
        scan = scan_config_bytes(data, f"{item['repository']['full_name']}:{item['path']}")
        samples.append(
            {
                "repository": item["repository"]["full_name"],
                "path": item["path"],
                "html_url": item["html_url"],
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
