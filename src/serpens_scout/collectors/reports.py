"""Primary-report collection and cross-source IOC comparison."""

from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass
from datetime import UTC, datetime

from serpens_scout.collectors.http import get_bytes
from serpens_scout.extract import extract_iocs, html_to_text, section


@dataclass(frozen=True)
class SourceSpec:
    key: str
    publisher: str
    title: str
    url: str
    start: str
    ends: tuple[str, ...]


SOURCES = (
    SourceSpec(
        key="unit42",
        publisher="Palo Alto Networks Unit 42",
        title="Tracking Iranian APT Screening Serpens' 2026 Espionage Campaigns",
        url="https://unit42.paloaltonetworks.com/tracking-iran-apt-screening-serpens/",
        start="Indicators of Compromise",
        ends=("Additional Resources", "Additional References", "Conclusion"),
    ),
    SourceSpec(
        key="checkpoint",
        publisher="Check Point Research",
        title="Fast and Furious: Nimbus Manticore Operations During the Iranian Conflict",
        url=(
            "https://research.checkpoint.com/2026/"
            "fast-and-furious-nimbus-manticore-operations-during-the-iranian-conflict/"
        ),
        start="IOCs",
        ends=("GO UP", "Follow Us", "Check Point Research Publications"),
    ),
)


def collect_reports() -> dict[str, object]:
    fetched_at = datetime.now(UTC).isoformat()
    records: dict[str, dict[str, object]] = {}
    for spec in SOURCES:
        document = get_bytes(spec.url)
        text = html_to_text(document.decode("utf-8", errors="replace"))
        if spec.start.lower() not in text.lower():
            raise RuntimeError(f"IOC section marker missing from {spec.publisher}")
        ioc_section = section(text, spec.start, spec.ends)
        records[spec.key] = {
            "source": asdict(spec),
            "fetched_at": fetched_at,
            "content_sha256": hashlib.sha256(document).hexdigest(),
            "section_found": ioc_section != text,
            "iocs": extract_iocs(ioc_section),
        }

    baseline = records["unit42"]["iocs"]
    comparison = records["checkpoint"]["iocs"]
    assert isinstance(baseline, dict) and isinstance(comparison, dict)
    delta = {
        kind: sorted(set(comparison[kind]) - set(baseline[kind]))
        for kind in ("domains", "sha256")
    }
    overlap = {
        kind: sorted(set(comparison[kind]) & set(baseline[kind]))
        for kind in ("domains", "sha256")
    }
    baseline_anomalies = baseline.get("domain_anomalies", [])
    probable_corrections = []
    for domain in delta["domains"]:
        matches = [
            anomaly
            for anomaly in baseline_anomalies
            if (anomaly.startswith(domain) or domain.startswith(anomaly))
            and abs(len(anomaly) - len(domain)) <= 2
        ]
        if matches:
            probable_corrections.append(
                {"comparison_domain": domain, "baseline_anomaly": matches[0]}
            )
    return {
        "fetched_at": fetched_at,
        "sources": records,
        "delta": delta,
        "overlap": overlap,
        "probable_source_corrections": probable_corrections,
        "delta_definition": (
            "present in Check Point Research IOC section, absent from Unit 42 IOC section"
        ),
    }
