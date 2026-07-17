from __future__ import annotations

from serpens_scout.collectors import doh


def test_dns_failure_produces_partial_observation(monkeypatch) -> None:
    def fail(_url: str):
        raise RuntimeError("dns.google returned HTTP 429")

    monkeypatch.setattr(doh, "get_json", fail)
    observations = doh.resolve_domains(["reported.example"])
    assert observations[0]["status"] == "collection-error"
    assert observations[0]["answers"] == []
    assert "429" in observations[0]["error"]
