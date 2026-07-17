from __future__ import annotations

import pytest

from serpens_scout.collectors import doh, reports


def test_dns_failure_produces_partial_observation(monkeypatch) -> None:
    def fail(_url: str):
        raise RuntimeError("dns.google returned HTTP 429")

    monkeypatch.setattr(doh, "get_json", fail)
    observations = doh.resolve_domains(["reported.example"])
    assert observations[0]["status"] == "collection-error"
    assert observations[0]["answers"] == []
    assert "429" in observations[0]["error"]


def test_report_extraction_fails_closed_below_safety_threshold(monkeypatch) -> None:
    document = b"<html><h2>Indicators of Compromise</h2><p>one.example</p></html>"
    monkeypatch.setattr(reports, "get_bytes", lambda _url: document)
    with pytest.raises(RuntimeError, match="below safety threshold"):
        reports.collect_reports()
