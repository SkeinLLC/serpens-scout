"""Value-aware AppDomainManager configuration scanner."""

from __future__ import annotations

import io
import json
import os
import re
import zipfile
from dataclasses import asdict, dataclass
from pathlib import Path

from defusedxml import ElementTree
from defusedxml.common import DefusedXmlException

MAX_MEMBER_BYTES = 2 * 1024 * 1024
MAX_ARCHIVE_BYTES = 50 * 1024 * 1024
MAX_RATIO = 100
MAX_DEPTH = 2
MAX_ARCHIVE_MEMBERS = 1024


@dataclass
class ScanResult:
    path: str
    score: int
    verdict: str
    signals: list[str]
    values: dict[str, str]
    error: str | None = None

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def _local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _truth(value: str | None) -> bool:
    return (value or "").strip().lower() in {"true", "1", "yes"}


def scan_config_bytes(data: bytes, path: str = "<memory>") -> ScanResult:
    if len(data) > MAX_MEMBER_BYTES:
        return ScanResult(path, 0, "not-scanned", [], {}, "file exceeds size limit")
    try:
        root = ElementTree.fromstring(data)
    except DefusedXmlException:
        return ScanResult(path, 0, "unsafe-xml", [], {}, "DTD or entity declarations blocked")
    except ElementTree.ParseError as exc:
        return ScanResult(path, 0, "invalid-xml", [], {}, str(exc))

    values: dict[str, str] = {}
    signals: list[str] = []
    for node in root.iter():
        name = _local_name(node.tag).lower()
        attrs = {key.lower(): value for key, value in node.attrib.items()}
        manager_type = attrs.get("appdomainmanagertype", "")
        manager_assembly = attrs.get("appdomainmanagerassembly", "")
        if manager_type:
            values["appDomainManagerType"] = manager_type
            signals.append("custom_appdomain_manager_type")
        if manager_assembly:
            values["appDomainManagerAssembly"] = manager_assembly
            signals.append("custom_appdomain_manager_assembly")
        if name == "probing" and attrs.get("privatepath"):
            private_path = attrs["privatepath"]
            values["privatePath"] = private_path
            entries = [item.strip() for item in private_path.replace(",", ";").split(";")]
            if any(item in {".", "./", ".\\"} for item in entries):
                signals.append("local_private_path")
        elif name == "etwenable" and attrs.get("enabled", "").strip().lower() == "false":
            values["etwEnable"] = attrs.get("enabled", "")
            signals.append("etw_disabled")
        elif name == "bypasstrustedappstrongnames" and _truth(attrs.get("enabled")):
            values["bypassTrustedAppStrongNames"] = attrs.get("enabled", "")
            signals.append("strong_name_bypass")
        elif name == "publisherpolicy" and attrs.get("apply", "").lower() == "no":
            values["publisherPolicy"] = attrs["apply"]
            signals.append("publisher_policy_disabled")
        elif name == "requiredruntime" and _truth(attrs.get("safemode")):
            values["requiredRuntime.safemode"] = attrs.get("safemode", "")
            signals.append("runtime_safemode")

    weight = {
        "custom_appdomain_manager_type": 15,
        "custom_appdomain_manager_assembly": 10,
        "local_private_path": 15,
        "etw_disabled": 25,
        "strong_name_bypass": 20,
        "publisher_policy_disabled": 10,
        "runtime_safemode": 5,
    }
    score = min(100, sum(weight[item] for item in set(signals)))
    malicious_values = {
        "etw_disabled",
        "strong_name_bypass",
        "publisher_policy_disabled",
        "runtime_safemode",
    }
    value_count = len(set(signals) & malicious_values)
    has_manager = "custom_appdomain_manager_type" in signals
    if score >= 65 and has_manager and value_count >= 2:
        verdict = "highly-suspicious"
    elif score >= 40 and (has_manager or value_count >= 2):
        verdict = "suspicious"
    elif signals:
        verdict = "context-only"
    else:
        verdict = "no-match"
    return ScanResult(path, score, verdict, sorted(set(signals)), values)


def _safe_member_name(name: str) -> str:
    return re.sub(r"[\x00-\x1f\x7f]", "?", name)


def _read_file_bounded(path: Path, limit: int) -> bytes | None:
    with path.open("rb") as handle:
        data = handle.read(limit + 1)
    return None if len(data) > limit else data


def _skip_symlink(path: Path) -> ScanResult:
    return ScanResult(str(path), 0, "not-scanned", [], {}, "symbolic links are not followed")


def _scan_config_file(path: Path) -> ScanResult:
    if path.is_symlink():
        return _skip_symlink(path)
    try:
        data = _read_file_bounded(path, MAX_MEMBER_BYTES)
    except OSError as exc:
        return ScanResult(str(path), 0, "not-scanned", [], {}, f"file read failed: {exc}")
    if data is None:
        return ScanResult(str(path), 0, "not-scanned", [], {}, "file exceeds size limit")
    return scan_config_bytes(data, str(path))


def _scan_archive_file(path: Path) -> list[ScanResult]:
    if path.is_symlink():
        return [_skip_symlink(path)]
    try:
        data = _read_file_bounded(path, MAX_ARCHIVE_BYTES)
    except OSError as exc:
        return [ScanResult(str(path), 0, "not-scanned", [], {}, f"file read failed: {exc}")]
    if data is None:
        return [ScanResult(str(path), 0, "not-scanned", [], {}, "archive exceeds size limit")]
    return _scan_archive(data, str(path), 0)


def _scan_archive(data: bytes, label: str, depth: int) -> list[ScanResult]:
    if depth > MAX_DEPTH:
        return [ScanResult(label, 0, "not-scanned", [], {}, "archive nesting limit exceeded")]
    results: list[ScanResult] = []
    total = 0
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            members = archive.infolist()
            if len(members) > MAX_ARCHIVE_MEMBERS:
                return [
                    ScanResult(
                        label,
                        0,
                        "not-scanned",
                        [],
                        {},
                        "archive member-count limit exceeded",
                    )
                ]
            for member in members:
                if member.is_dir():
                    continue
                total += member.file_size
                if total > MAX_ARCHIVE_BYTES:
                    results.append(
                        ScanResult(label, 0, "not-scanned", [], {}, "archive size limit exceeded")
                    )
                    break
                ratio = member.file_size / max(member.compress_size, 1)
                member_label = f"{label}!{_safe_member_name(member.filename)}"
                if member.flag_bits & 0x1:
                    results.append(
                        ScanResult(member_label, 0, "not-scanned", [], {}, "encrypted member")
                    )
                    continue
                if member.file_size > MAX_MEMBER_BYTES or ratio > MAX_RATIO:
                    results.append(
                        ScanResult(member_label, 0, "not-scanned", [], {}, "unsafe member limits")
                    )
                    continue
                lower = member.filename.lower()
                if not lower.endswith((".config", ".zip", ".nupkg")):
                    continue
                try:
                    with archive.open(member) as member_file:
                        member_data = member_file.read(MAX_MEMBER_BYTES + 1)
                except (OSError, RuntimeError, NotImplementedError, zipfile.BadZipFile) as exc:
                    results.append(
                        ScanResult(
                            member_label,
                            0,
                            "invalid-archive",
                            [],
                            {},
                            f"member read failed: {exc}",
                        )
                    )
                    continue
                if len(member_data) > MAX_MEMBER_BYTES:
                    results.append(
                        ScanResult(member_label, 0, "not-scanned", [], {}, "member exceeds limit")
                    )
                elif lower.endswith(".config"):
                    results.append(scan_config_bytes(member_data, member_label))
                else:
                    results.extend(_scan_archive(member_data, member_label, depth + 1))
    except (zipfile.BadZipFile, zipfile.LargeZipFile, OSError, RuntimeError) as exc:
        results.append(ScanResult(label, 0, "invalid-archive", [], {}, str(exc)))
    return results


def scan_path(path: Path) -> list[ScanResult]:
    path = path.expanduser().absolute()
    if path.is_symlink():
        return [_skip_symlink(path)]
    if path.is_dir():
        results: list[ScanResult] = []
        for root, dirs, files in os.walk(path):
            dirs[:] = [
                item
                for item in dirs
                if item not in {".git", ".venv", "node_modules"}
                and not Path(root, item).is_symlink()
            ]
            for name in files:
                candidate = Path(root, name)
                if name.lower().endswith(".config"):
                    results.append(_scan_config_file(candidate))
                elif name.lower().endswith((".zip", ".nupkg")):
                    results.extend(_scan_archive_file(candidate))
        return results
    if path.suffix.lower() == ".config":
        return [_scan_config_file(path)]
    if path.suffix.lower() in {".zip", ".nupkg"}:
        return _scan_archive_file(path)
    return [ScanResult(str(path), 0, "not-scanned", [], {}, "unsupported file type")]


def write_scan(results: list[ScanResult], output: Path) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps([item.to_dict() for item in results], indent=2), encoding="utf-8")
