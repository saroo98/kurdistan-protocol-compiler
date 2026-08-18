#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright 2026 Saro

"""Independent Python Phase 17 privacy scanner.

This implementation intentionally shares no parser, regular expressions, or
application package with the Go scanner. It emits only a categorical receipt.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import ipaddress
import json
import re
import sys
import unicodedata
import urllib.parse
from pathlib import Path

SCHEMA = "kurdistan-phase17-privacy-scanner-v1"
MAX_BYTES = 32 << 20
MAX_RECORDS = 4096
SOURCES = {"ANDROID_LOGCAT", "REMOTE_JOURNAL"}

_TERMINAL_SEQUENCE = re.compile(
    rb"(?:\x1b\[[0-?]*[ -/]*[@-~]|\x9b[0-?]*[ -/]*[@-~]|"
    rb"\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)|\x1b[P\^_X].*?\x1b\\)",
    flags=re.DOTALL,
)
_ADDRESS_TOKEN = re.compile(r"[0-9a-f:.]+(?:%[a-z0-9_.-]+)?", flags=re.IGNORECASE)
_BASE64_TOKEN = re.compile(r"[a-z0-9+/_-]{12,}={0,2}", flags=re.IGNORECASE)
_FRAME_TRACKER_CUJ = re.compile(
    r"(?m)^(?=[A-Z]/FrameTracker\()(?=[^\r\n]*CUJ=J<)(?=[^\r\n]*@org\.kurdistanvpn\.app\.internal>)[^\r\n]*$"
)
_INSTRUMENTATION_PACKAGE = "org.kurdistanvpn.app.internal.test"


def _privacy() -> dict[str, bool]:
    return {
        "payloadRetained": False,
        "destinationRetained": False,
        "dnsNameRetained": False,
        "credentialRetained": False,
        "keyRetained": False,
        "profileRetained": False,
        "rawLogRetained": False,
    }


def _receipt(raw: bytes) -> dict[str, object]:
    return {
        "schema": SCHEMA,
        "name": "PYTHON_B",
        "inputSha256": hashlib.sha256(raw).hexdigest(),
        "bytesConsumed": len(raw),
        "recordsConsumed": 0,
        "result": "FAIL",
        "truncated": False,
        "parseFailure": False,
        "backpressureFailure": False,
        "coverageGap": False,
        "privacy": _privacy(),
    }


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate key")
        result[key] = value
    return result


def _normalise(payload: bytes) -> str:
    without_terminal_sequences = _TERMINAL_SEQUENCE.sub(b"", payload)
    decoded = without_terminal_sequences.decode("utf-8", errors="ignore")
    output: list[str] = []
    for character in decoded:
        if character == "\ufeff":
            continue
        if unicodedata.category(character) in {"Cc", "Cf"}:
            if character in "\r\n\t":
                output.append(" ")
            continue
        output.append(character)
    return "".join(output)


def _normalise_android_framework_noise(text: str) -> str:
    def replace(match: re.Match[str]) -> str:
        return re.sub(r"::(?=\d{1,3}@)", "--", match.group(0))

    text = _FRAME_TRACKER_CUJ.sub(replace, text)
    raw = bytearray(text.encode("utf-8"))
    package = _INSTRUMENTATION_PACKAGE.encode("ascii")
    offset = 0
    while offset < len(raw):
        start = raw.find(package, offset)
        if start < 0:
            break
        end = start + len(package)
        before = bytes(raw[max(0, start - 256) : start]).lower()
        after = bytes(raw[end : min(len(raw), end + 256)]).lower()
        framework_reference = (
            (before.endswith(b"package [") and after.startswith(b"] reported as replaced"))
            or before.endswith(b"instrumentation[")
            or (b"/data/app/" in before and b"/base.apk" in after)
        )
        if framework_reference:
            for index in range(start, end):
                if raw[index] == ord("."):
                    raw[index] = ord("-")
        offset = end
    return raw.decode("utf-8")


def _contains_ip_address(text: str) -> bool:
    for match in _ADDRESS_TOKEN.finditer(text):
        candidate = match.group(0).strip("[](){}<>,;\"'")
        if "." not in candidate and ":" not in candidate:
            continue
        try:
            ipaddress.ip_address(candidate)
            return True
        except ValueError:
            continue
    return False


def _classify_text(text: str, privacy: dict[str, bool]) -> None:
    folded = text.casefold()
    privacy["payloadRetained"] |= "phase17_payload_canary_" in folded
    privacy["destinationRetained"] |= (
        "phase17_destination_canary_" in folded
        or re.search(r"\b(?:http|https|ws|wss)://\S+", text, flags=re.IGNORECASE) is not None
        or _contains_ip_address(text)
    )
    privacy["dnsNameRetained"] |= (
        "phase17_dns_canary_" in folded
        or re.search(r"\b(?:[a-z0-9-]+\.)+(?:invalid|example|test)\b", text, flags=re.IGNORECASE) is not None
    )
    privacy["credentialRetained"] |= re.search(
        r"(?:bearer\s+[a-z0-9._~-]+|password\s*(?:=|:)|credential\s*(?:=|:)|token\s*(?:=|:))",
        text,
        flags=re.IGNORECASE,
    ) is not None or re.search(
        r"(?:^|[^a-z0-9])(?:[a-z]:\\(?:users|documents and settings)\\[^\\/\s]+|/(?:home|root|users)/[^\s\"'<>]+)",
        text,
        flags=re.IGNORECASE,
    ) is not None
    privacy["keyRetained"] |= (
        "phase17_key_canary_" in folded
        or re.search(r"BEGIN\s+[^\r\n]*PRIVATE KEY|private[ _-]?key\s*(?:=|:)|recipient[ _-]?private", text, flags=re.IGNORECASE) is not None
    )
    privacy["profileRetained"] |= re.search(
        r"(?:\bkurd://|phase17_profile_canary_|sealed[ _-]?profile)", text, flags=re.IGNORECASE
    ) is not None


def _classify(source: str, payload: bytes, privacy: dict[str, bool]) -> None:
    text = _normalise(payload)
    if source == "ANDROID_LOGCAT":
        text = _normalise_android_framework_noise(text)
    _classify_text(text, privacy)
    if "%" in text:
        decoded_percent = urllib.parse.unquote_to_bytes(text)
        if decoded_percent != text.encode("utf-8"):
            _classify_text(_normalise(decoded_percent), privacy)
    for match in _BASE64_TOKEN.finditer(text):
        candidate = match.group(0).encode("ascii")
        if len(candidate) > 1 << 20:
            continue
        padded = candidate + b"=" * ((-len(candidate)) % 4)
        for alternate in (None, b"-_"):
            try:
                decoded = base64.b64decode(padded, altchars=alternate, validate=True)
            except (binascii.Error, ValueError):
                continue
            if decoded:
                _classify_text(_normalise(decoded), privacy)


def scan(raw: bytes, expected_bytes: int) -> dict[str, object]:
    receipt = _receipt(raw)
    if len(raw) != expected_bytes or len(raw) > MAX_BYTES:
        receipt["truncated"] = True
        return receipt
    seen: set[str] = set()
    lines = raw.splitlines()
    if raw and not raw.endswith(b"\n"):
        receipt["parseFailure"] = True
        return receipt
    for line in lines:
        if not line or int(receipt["recordsConsumed"]) >= MAX_RECORDS:
            receipt["truncated"] = int(receipt["recordsConsumed"]) >= MAX_RECORDS
            receipt["parseFailure"] = not bool(receipt["truncated"])
            return receipt
        try:
            value = json.loads(line, object_pairs_hook=_unique_object)
            if set(value) != {"source", "data"} or value["source"] not in SOURCES or not isinstance(value["data"], str):
                raise ValueError("record shape")
            payload = base64.b64decode(value["data"], validate=True)
            if len(payload) > 8 << 20:
                raise ValueError("record size")
        except (ValueError, TypeError, json.JSONDecodeError):
            receipt["parseFailure"] = True
            return receipt
        receipt["recordsConsumed"] = int(receipt["recordsConsumed"]) + 1
        seen.add(str(value["source"]))
        _classify(str(value["source"]), payload, receipt["privacy"])
    if seen != SOURCES:
        receipt["coverageGap"] = True
        return receipt
    if any(bool(value) for value in receipt["privacy"].values()):
        return receipt
    receipt["result"] = "PASS"
    return receipt


def main() -> int:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--input", required=True)
    parser.add_argument("--expected-bytes", type=int)
    try:
        arguments = parser.parse_args()
        if arguments.input == "-":
            if arguments.expected_bytes is None or arguments.expected_bytes <= 0 or arguments.expected_bytes > MAX_BYTES:
                raise ValueError("stdin size")
            size = arguments.expected_bytes
            raw = sys.stdin.buffer.read(MAX_BYTES + 1)
        else:
            if arguments.expected_bytes is not None:
                raise ValueError("file size override")
            path = Path(arguments.input)
            if path.is_symlink() or not path.is_file():
                raise ValueError("input")
            size = path.stat().st_size
            if size < 0 or size > MAX_BYTES:
                raise ValueError("size")
            raw = path.read_bytes()
            if len(raw) != size:
                raise ValueError("changed")
        result = scan(raw, size)
        sys.stdout.write(json.dumps(result, ensure_ascii=False, separators=(",", ":")) + "\n")
        return 0
    except (OSError, ValueError, SystemExit):
        sys.stderr.write("privacy_scanner_b: scanner unavailable\n")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
