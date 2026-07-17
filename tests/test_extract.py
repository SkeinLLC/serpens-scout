from serpens_scout.extract import extract_iocs, html_to_text, section


def test_extracts_only_ioc_section() -> None:
    document = """
    <html><body><p>Publisher example.com</p><h2>IOCs</h2>
    <p>bad[.]azurewebsites[.]net</p>
    <p>AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA</p>
    <h2>GO UP</h2><p>footer.example</p></body></html>
    """
    text = html_to_text(document)
    iocs = extract_iocs(section(text, "IOCs", ("GO UP",)))
    assert iocs["domains"] == ["bad.azurewebsites.net"]
    assert iocs["sha256"] == ["a" * 64]


def test_preserves_domain_like_typo_as_source_anomaly() -> None:
    iocs = extract_iocs("ramiltonsfinance.azurewebsites[.]neti")
    assert iocs["domains"] == []
    assert iocs["domain_anomalies"] == ["ramiltonsfinance.azurewebsites.neti"]


def test_html_parser_ignores_script_data() -> None:
    text = html_to_text("<p>visible.example</p><script>hidden.example</script>")
    assert "visible.example" in text
    assert "hidden.example" not in text
