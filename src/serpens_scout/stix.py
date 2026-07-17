"""Dependency-free STIX 2.1 export."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

NAMESPACE = uuid.UUID("9f240989-57ec-4e7d-992f-a0f7858e4af6")


def _timestamp() -> str:
    return datetime.now(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _indicator(
    kind: str,
    value: str,
    source: dict[str, str],
    role: str,
    created: str,
) -> dict[str, object]:
    stix_id = f"indicator--{uuid.uuid5(NAMESPACE, f'{kind}:{value}:{role}')}"
    if kind == "domains":
        pattern = f"[domain-name:value = '{value}']"
        label = "malicious-activity"
    else:
        pattern = f"[file:hashes.'SHA-256' = '{value}']"
        label = "malicious-activity"
    return {
        "type": "indicator",
        "spec_version": "2.1",
        "id": stix_id,
        "created": created,
        "modified": created,
        "name": f"Screening Serpens {kind.rstrip('s')} - {value}",
        "description": (
            f"Public IOC from {source['publisher']}; Serpens Scout role: {role}. "
            "Attribution and maliciousness remain those of the cited source."
        ),
        "indicator_types": [label],
        "pattern": pattern,
        "pattern_type": "stix",
        "pattern_version": "2.1",
        "valid_from": created,
        "labels": ["screening-serpens", "public-reporting", role],
        "confidence": 70 if role == "unit42-baseline" else 60,
        "external_references": [
            {"source_name": source["publisher"], "url": source["url"]}
        ],
    }


def build_bundle(research: dict[str, object]) -> dict[str, object]:
    created = _timestamp()
    sources = research["sources"]
    assert isinstance(sources, dict)
    objects: list[dict[str, object]] = []
    unit = sources["unit42"]
    check = sources["checkpoint"]
    assert isinstance(unit, dict) and isinstance(check, dict)
    unit_source = unit["source"]
    check_source = check["source"]
    assert isinstance(unit_source, dict) and isinstance(check_source, dict)
    unit_iocs = unit["iocs"]
    delta = research["delta"]
    assert isinstance(unit_iocs, dict) and isinstance(delta, dict)
    for kind in ("domains", "sha256"):
        for value in unit_iocs[kind]:
            objects.append(_indicator(kind, value, unit_source, "unit42-baseline", created))
        for value in delta[kind]:
            objects.append(_indicator(kind, value, check_source, "cross-source-delta", created))
    return {
        "type": "bundle",
        "id": f"bundle--{uuid.uuid4()}",
        "objects": objects,
    }
