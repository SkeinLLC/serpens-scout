"""Exact-name passive DNS observations through Google DNS-over-HTTPS."""

from __future__ import annotations

import urllib.parse

from serpens_scout.collectors.http import get_json


def resolve_domains(domains: list[str]) -> list[dict[str, object]]:
    observations: list[dict[str, object]] = []
    for domain in sorted(set(domains)):
        query = urllib.parse.urlencode({"name": domain, "type": "A"})
        response = get_json(f"https://dns.google/resolve?{query}")
        answers = [
            {"data": answer.get("data"), "ttl": answer.get("TTL"), "type": answer.get("type")}
            for answer in response.get("Answer", [])
            if answer.get("type") in {1, 5}
        ]
        observations.append(
            {
                "domain": domain,
                "status": response.get("Status"),
                "authenticated_data": response.get("AD", False),
                "answers": answers,
                "assessment": "hosting observation; returned IP addresses are not promoted to IOCs",
            }
        )
    return observations
