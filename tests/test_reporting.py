from serpens_scout.reporting import build_markdown


def test_markdown_defangs_domains_but_not_hashes() -> None:
    hash_value = "a" * 64
    result = {
        "reports": {
            "fetched_at": "2026-07-17T00:00:00+00:00",
            "sources": {
                "unit42": {
                    "content_sha256": "1" * 64,
                    "iocs": {"domains": ["base.example"], "sha256": []},
                },
                "checkpoint": {
                    "content_sha256": "2" * 64,
                    "iocs": {"domains": ["delta.example"], "sha256": [hash_value]},
                },
            },
            "delta": {"domains": ["delta.example"], "sha256": [hash_value]},
            "overlap": {"domains": [], "sha256": []},
            "probable_source_corrections": [],
        },
        "dns": [],
        "github": {"status": "skipped", "reason": "no token", "queries": []},
    }
    output = build_markdown(result)
    assert "delta[.]example" in output
    assert "delta.example" not in output
    assert hash_value in output
