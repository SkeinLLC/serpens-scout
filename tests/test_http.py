import urllib.error
import urllib.request

import pytest

from serpens_scout.collectors.http import (
    MAX_RESPONSE_BYTES,
    _AllowlistedRedirectHandler,
    _read_bounded,
    get_bytes,
    get_json,
)


def test_http_client_rejects_suspected_or_unlisted_destinations() -> None:
    with pytest.raises(ValueError, match="not allowlisted"):
        get_bytes("https://suspected-c2.example/payload", retries=0)


def test_http_client_rejects_plain_http() -> None:
    with pytest.raises(ValueError, match="not allowlisted"):
        get_bytes("http://unit42.paloaltonetworks.com/", retries=0)


def test_http_client_rejects_credentials_and_nonstandard_ports() -> None:
    with pytest.raises(ValueError, match="not allowlisted"):
        get_bytes("https://user@api.github.com/", retries=0)
    with pytest.raises(ValueError, match="not allowlisted"):
        get_bytes("https://api.github.com:444/", retries=0)


def test_redirect_handler_blocks_cross_host_redirect() -> None:
    handler = _AllowlistedRedirectHandler()
    request = urllib.request.Request("https://api.github.com/source")
    with pytest.raises(ValueError, match="not allowlisted"):
        handler.redirect_request(
            request,
            None,
            302,
            "Found",
            {},
            "https://example.com/steal-token",
        )
    with pytest.raises(urllib.error.HTTPError, match="cross-host"):
        handler.redirect_request(
            request,
            None,
            302,
            "Found",
            {},
            "https://dns.google/steal-token",
        )


def test_response_reader_enforces_content_length_and_stream_limit() -> None:
    class Response:
        def __init__(self, content: bytes, length: str = "") -> None:
            self.content = content
            self.headers = {"Content-Length": length}

        def read(self, size: int) -> bytes:
            return self.content[:size]

    with pytest.raises(RuntimeError, match="size limit"):
        _read_bounded(Response(b"", str(MAX_RESPONSE_BYTES + 1)))
    with pytest.raises(RuntimeError, match="size limit"):
        _read_bounded(Response(b"a" * (MAX_RESPONSE_BYTES + 1)))


def test_json_client_rejects_non_object_response(monkeypatch) -> None:
    monkeypatch.setattr(
        "serpens_scout.collectors.http.get_bytes",
        lambda _url, headers=None: b"[]",
    )
    with pytest.raises(ValueError, match="must be an object"):
        get_json("https://api.github.com/")
