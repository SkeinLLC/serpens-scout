"""Defanging helpers for analyst-facing narrative output."""

from __future__ import annotations

import re


def defang(value: str) -> str:
    """Defang URLs, domains, and IPv4 addresses without altering hashes."""
    value = re.sub(r"(?i)^https://", "hxxps://", value)
    value = re.sub(r"(?i)^http://", "hxxp://", value)
    if "." in value and not re.fullmatch(r"[a-fA-F0-9]{32,64}", value):
        value = value.replace(".", "[.]")
    return value


def refang(value: str) -> str:
    """Normalize commonly defanged public indicators for machine processing."""
    return (
        value.strip().replace("[.]", ".").replace("(.)", ".").replace("hxxps://", "https://")
        .replace("hxxp://", "http://")
    )
