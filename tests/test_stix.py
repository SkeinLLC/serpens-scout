import json

from stix2 import parse

from serpens_scout.stix import build_bundle


def test_stix_contains_source_attributed_baseline_and_delta() -> None:
    source = {"publisher": "Publisher", "url": "https://publisher.example/report"}
    reports = {
        "sources": {
            "unit42": {
                "source": source,
                "iocs": {"domains": ["baseline.example"], "sha256": []},
            },
            "checkpoint": {
                "source": source,
                "iocs": {"domains": ["delta.example"], "sha256": []},
            },
        },
        "delta": {"domains": ["delta.example"], "sha256": []},
    }
    bundle = build_bundle(reports)
    assert bundle["type"] == "bundle"
    assert len(bundle["objects"]) == 2
    labels = {tuple(item["labels"]) for item in bundle["objects"]}
    assert any("unit42-baseline" in item for item in labels)
    assert any("cross-source-delta" in item for item in labels)
    parse(json.dumps(bundle), allow_custom=False)
