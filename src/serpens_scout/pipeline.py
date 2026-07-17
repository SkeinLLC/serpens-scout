"""Research pipeline orchestration."""

from __future__ import annotations

import json
from pathlib import Path

from serpens_scout.collectors.doh import resolve_domains
from serpens_scout.collectors.github import collect_github_baseline
from serpens_scout.collectors.reports import collect_reports
from serpens_scout.reporting import build_markdown
from serpens_scout.stix import build_bundle


def hunt(output: Path, github_limit: int = 20, skip_dns: bool = False) -> dict[str, object]:
    output.mkdir(parents=True, exist_ok=True)
    reports = collect_reports()
    delta = reports["delta"]
    assert isinstance(delta, dict)
    dns = [] if skip_dns else resolve_domains(delta["domains"])
    github = collect_github_baseline(github_limit)
    result = {
        "schema_version": "1.0",
        "reports": reports,
        "dns": dns,
        "github": github,
        "handling": "TLP:CLEAR public-source research",
    }
    (output / "findings.json").write_text(
        json.dumps(result, indent=2, sort_keys=True), encoding="utf-8"
    )
    (output / "findings.md").write_text(build_markdown(result), encoding="utf-8")
    (output / "serpens.stix.json").write_text(
        json.dumps(build_bundle(reports), indent=2, sort_keys=True), encoding="utf-8"
    )
    if github.get("status") == "complete":
        (output / "github-baseline.json").write_text(
            json.dumps(github, indent=2, sort_keys=True), encoding="utf-8"
        )
    return result
