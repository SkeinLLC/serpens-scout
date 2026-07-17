"""Conservative IOC extraction from public report text and HTML."""

from __future__ import annotations

import html
import re
from html.parser import HTMLParser

DOMAIN_RE = re.compile(
    r"(?<![A-Za-z0-9_-])(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+"
    r"(?:com|net|org|io|co|app|dev|info|me|xyz|online|site|cloud|pro|live)\b",
    re.IGNORECASE,
)
DOMAIN_LIKE_RE = re.compile(
    r"(?<![A-Za-z0-9_-])(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+"
    r"[A-Za-z]{2,10}\b",
    re.IGNORECASE,
)
SHA256_RE = re.compile(r"(?<![A-Fa-f0-9])[A-Fa-f0-9]{64}(?![A-Fa-f0-9])")


class _TextExtractor(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.parts: list[str] = []
        self._ignored = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag in {"script", "style", "svg"}:
            self._ignored += 1
        elif tag in {"p", "br", "li", "tr", "h1", "h2", "h3", "h4"}:
            self.parts.append("\n")

    def handle_endtag(self, tag: str) -> None:
        if tag in {"script", "style", "svg"} and self._ignored:
            self._ignored -= 1
        elif tag in {"p", "li", "tr"}:
            self.parts.append("\n")

    def handle_data(self, data: str) -> None:
        if not self._ignored:
            self.parts.append(data)


def html_to_text(document: str) -> str:
    parser = _TextExtractor()
    parser.feed(document)
    text = html.unescape(" ".join(parser.parts))
    return re.sub(r"[ \t]+", " ", re.sub(r"\r\n?", "\n", text))


def section(text: str, start: str, ends: tuple[str, ...]) -> str:
    start_at = text.lower().rfind(start.lower())
    if start_at < 0:
        return text
    body = text[start_at + len(start) :]
    end_points = [body.lower().find(item.lower()) for item in ends]
    valid = [point for point in end_points if point >= 0]
    return body[: min(valid)] if valid else body


def extract_iocs(text: str) -> dict[str, list[str]]:
    normalized = text.replace("[.]", ".").replace("(.)", ".")
    domains = {
        match.lower().rstrip(".")
        for match in DOMAIN_RE.findall(normalized)
        if not match.lower().endswith(("paloaltonetworks.com", "checkpoint.com"))
    }
    hashes = {match.lower() for match in SHA256_RE.findall(normalized)}
    domain_like = {match.lower().rstrip(".") for match in DOMAIN_LIKE_RE.findall(normalized)}
    anomalies = domain_like - domains
    return {
        "domains": sorted(domains),
        "sha256": sorted(hashes),
        "domain_anomalies": sorted(anomalies),
    }
