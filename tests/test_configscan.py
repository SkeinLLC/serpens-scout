from __future__ import annotations

import zipfile
from pathlib import Path

from serpens_scout.configscan import scan_config_bytes, scan_path

FIXTURES = Path(__file__).parent / "fixtures"


def test_value_aware_serpens_config_is_highly_suspicious() -> None:
    result = scan_config_bytes((FIXTURES / "serpens.config").read_bytes(), "serpens.config")
    assert result.verdict == "highly-suspicious"
    assert result.score == 100
    assert "etw_disabled" in result.signals
    assert "strong_name_bypass" in result.signals


def test_safe_values_are_not_promoted() -> None:
    result = scan_config_bytes((FIXTURES / "legitimate.config").read_bytes(), "legit.config")
    assert result.verdict == "context-only"
    assert result.score == 25
    assert "etw_disabled" not in result.signals
    assert "strong_name_bypass" not in result.signals


def test_archive_is_scanned_without_extraction(tmp_path: Path) -> None:
    archive = tmp_path / "delivery.zip"
    with zipfile.ZipFile(archive, "w") as output:
        output.write(FIXTURES / "serpens.config", "payload/host.exe.config")
    result = scan_path(archive)
    assert len(result) == 1
    assert result[0].verdict == "highly-suspicious"
    assert "!payload/host.exe.config" in result[0].path
    assert not (tmp_path / "payload").exists()


def test_malformed_xml_fails_closed() -> None:
    result = scan_config_bytes(b"<configuration>", "broken.config")
    assert result.verdict == "invalid-xml"
    assert result.error


def test_missing_etw_value_is_not_treated_as_disabled() -> None:
    result = scan_config_bytes(b"<configuration><runtime><etwEnable /></runtime></configuration>")
    assert "etw_disabled" not in result.signals
