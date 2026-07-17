import pytest

from serpens_scout.collectors.http import get_bytes


def test_http_client_rejects_suspected_or_unlisted_destinations() -> None:
    with pytest.raises(ValueError, match="not allowlisted"):
        get_bytes("https://suspected-c2.example/payload", retries=0)


def test_http_client_rejects_plain_http() -> None:
    with pytest.raises(ValueError, match="not allowlisted"):
        get_bytes("http://unit42.paloaltonetworks.com/", retries=0)
