"""Analyst-facing Markdown reporting."""

from __future__ import annotations

from collections import Counter

from serpens_scout.defang import defang


def _items(values: list[str], transform=lambda value: value) -> str:  # noqa: B008
    if not values:
        return "- None."
    return "\n".join(f"- `{transform(value)}`" for value in values)


def build_markdown(result: dict[str, object]) -> str:
    reports = result["reports"]
    assert isinstance(reports, dict)
    sources = reports["sources"]
    delta = reports["delta"]
    overlap = reports["overlap"]
    corrections = reports.get("probable_source_corrections", [])
    assert isinstance(sources, dict) and isinstance(delta, dict) and isinstance(overlap, dict)
    unit_iocs = sources["unit42"]["iocs"]
    check_iocs = sources["checkpoint"]["iocs"]
    assert isinstance(unit_iocs, dict) and isinstance(check_iocs, dict)
    dns = result.get("dns", [])
    github = result.get("github", {})
    assert isinstance(dns, list) and isinstance(github, dict)

    verdicts = Counter(
        sample["scan"]["verdict"]
        for sample in github.get("samples", [])
        if isinstance(sample, dict) and isinstance(sample.get("scan"), dict)
    )
    query_lines = []
    for query in github.get("queries", []):
        query_lines.append(f"- `{query['query']}`: **{query['total_count']}** results")
    github_text = "\n".join(query_lines) if query_lines else f"- {github.get('reason', 'not run')}"
    dns_live = sum(1 for item in dns if item.get("answers"))
    dns_errors = sum(1 for item in dns if item.get("status") == "collection-error")
    github_errors = len(github.get("errors", []))
    if github.get("samples"):
        github_finding = (
            "Public code can contain the AppDomainManager-related element names without the "
            f"malicious values. Sampled verdicts were `{dict(verdicts)}`; a presence-only "
            "signature would overstate risk."
        )
    else:
        github_finding = (
            "The public-code sample did not complete, so this run makes no prevalence claim."
        )
    unit_receipt = sources["unit42"]["content_sha256"]
    check_receipt = sources["checkpoint"]["content_sha256"]
    unit_counts = (len(unit_iocs["domains"]), len(unit_iocs["sha256"]))
    check_counts = (len(check_iocs["domains"]), len(check_iocs["sha256"]))
    material_domain_count = len(delta["domains"]) - len(corrections)
    correction_lines = "\n".join(
        f"- `{defang(item['comparison_domain'])}` likely corrects Unit 42's "
        f"`{defang(item['baseline_anomaly'])}`."
        for item in corrections
    )
    if not correction_lines:
        correction_lines = "- None detected."

    return f"""# Screening Serpens research findings

Run time: `{reports['fetched_at']}`

## Executive finding

The two primary reports do not expose the same IOC set. Check Point Research supplies
**{material_domain_count} unambiguous domain additions**, **{len(corrections)} probable source
correction**, and **{len(delta['sha256'])} SHA-256 additions** relative to Unit 42's IOC section.
These are set differences, not claims of previously unknown infrastructure or independent Skein
LLC attribution.

{github_finding}

## Collection receipt

| Source | Domains | SHA-256 | Content receipt |
|---|---:|---:|---|
| Unit 42 | {unit_counts[0]} | {unit_counts[1]} | `{unit_receipt}` |
| Check Point Research | {check_counts[0]} | {check_counts[1]} | `{check_receipt}` |

Cross-source overlap: {len(overlap['domains'])} domains and {len(overlap['sha256'])} SHA-256
hashes.

## Cross-source domain delta

{_items(delta['domains'], defang)}

## Cross-source SHA-256 delta

{_items(delta['sha256'])}

## Probable source corrections

{correction_lines}

## Passive DNS observations

Exact-name DNS-over-HTTPS queries returned an answer for **{dns_live} of {len(dns)}** delta
domains. IP addresses in `findings.json` are hosting observations only. They are not promoted
to IOCs because Azure hosting addresses are shared infrastructure. Collection errors:
**{dns_errors}**.

## Public-code prevalence check

{github_text}

Collector status: **{github.get('status', 'unknown')}**; errors: **{github_errors}**. Sampled
verdict counts: `{dict(verdicts)}`. GitHub Code Search is a convenience sample, not a
statistically representative known-good corpus. It supports the narrow conclusion that values,
not element-name presence, must drive the config signature.

## Assessment and limits

- Confidence is high that the listed delta accurately reflects the two fetched IOC sections;
  both source documents are hashed above.
- Confidence is moderate that the delta belongs in the broader actor cluster because Check
  Point maps Nimbus Manticore to UNC1549, while Unit 42 maps Screening Serpens to UNC1549.
- The collection does not prove live C2, victimization, or actor control. DNS resolution is not
  evidence of malicious traffic.
- The pipeline made no connection to a suspected domain, downloaded no sample, and submitted
  no indicator to a third-party scanner.

## Analyst next actions

1. Load `serpens.stix.json` into the TIP as source-attributed indicators.
2. Deploy the value-aware YARA and endpoint queries in audit mode.
3. Compare local telemetry against the cross-source delta, preserving source and first-seen
   timestamps.
4. Build the false-positive baseline from an approved enterprise software corpus before
   enabling prevention.
"""
