#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright 2026 Saro

"""Standalone qualification tests for independent Python Scanner B."""

from __future__ import annotations

import base64
import importlib.util
import json
import subprocess
import sys
from pathlib import Path

# This test imports Scanner B from the frozen source tree. Disable bytecode
# before that import so qualification is observational and cannot mutate the
# candidate or repository inventory it is validating.
sys.dont_write_bytecode = True


def _load_scanner(script: Path):
    spec = importlib.util.spec_from_file_location("phase17_privacy_scanner_b", script)
    if spec is None or spec.loader is None:
        raise AssertionError("scanner module unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _stream(records: list[tuple[str, bytes]], ending: bytes = b"\n") -> bytes:
    lines = []
    for source, payload in records:
        lines.append(
            json.dumps(
                {"source": source, "data": base64.b64encode(payload).decode("ascii")},
                ensure_ascii=True,
                separators=(",", ":"),
            ).encode("ascii")
        )
    return ending.join(lines) + ending


def _expected_privacy(case: dict[str, object], scanner) -> dict[str, bool]:
    expected = scanner._privacy()
    supplied = case["wantPrivacy"]
    if not isinstance(supplied, dict) or any(key not in expected or value is not True for key, value in supplied.items()):
        raise AssertionError(f"invalid expected privacy: {case['name']}")
    expected.update(supplied)
    return expected


def _payload(case: dict[str, object]) -> bytes:
    text = case.get("payloadUtf8")
    encoded = case.get("payloadHex")
    if (text is None) == (encoded is None):
        raise AssertionError(f"ambiguous corpus payload: {case['name']}")
    if text is not None:
        if not isinstance(text, str):
            raise AssertionError(f"invalid UTF-8 payload: {case['name']}")
        return text.encode("utf-8")
    if not isinstance(encoded, str):
        raise AssertionError(f"invalid hex payload: {case['name']}")
    return bytes.fromhex(encoded)


def main() -> int:
    repository = Path(__file__).resolve().parents[2]
    scanner = _load_scanner(repository / "scripts" / "phase17" / "privacy_scanner_b.py")
    corpus = json.loads(
        (repository / "testdata" / "fixtures" / "phase17" / "privacy-scanner" / "corpus-v1.json").read_text(
            encoding="utf-8"
        )
    )
    if set(corpus) != {"schema", "cases"} or corpus["schema"] != "kurdistan-phase17-privacy-corpus-v1":
        raise AssertionError("privacy corpus envelope rejected")
    cases = corpus["cases"]
    if not isinstance(cases, list) or len(cases) < 25:
        raise AssertionError("privacy corpus inventory rejected")
    names: set[str] = set()
    for case in cases:
        if set(case) - {"name", "source", "payloadUtf8", "payloadHex", "wantPass", "wantPrivacy"}:
            raise AssertionError("privacy corpus contains unknown fields")
        name = case["name"]
        source = case["source"]
        if not isinstance(name, str) or not name or name in names or source not in scanner.SOURCES:
            raise AssertionError("privacy corpus case identity rejected")
        names.add(name)
        other = "REMOTE_JOURNAL" if source == "ANDROID_LOGCAT" else "ANDROID_LOGCAT"
        raw = _stream([(source, _payload(case)), (other, b"safe categorical record")])
        receipt = scanner.scan(raw, len(raw))
        if (
            (receipt["result"] == "PASS") is not case["wantPass"]
            or receipt["privacy"] != _expected_privacy(case, scanner)
            or receipt["truncated"]
            or receipt["parseFailure"]
            or receipt["backpressureFailure"]
            or receipt["coverageGap"]
        ):
            raise AssertionError(f"corpus case failed: {name}: {receipt}")

    safe_records = [("ANDROID_LOGCAT", b"safe"), ("REMOTE_JOURNAL", b"safe")]
    safe_raw = _stream(safe_records)
    completed = subprocess.run(
        [
            sys.executable,
            "-B",
            "-I",
            str(repository / "scripts" / "phase17" / "privacy_scanner_b.py"),
            "--input",
            "-",
            "--expected-bytes",
            str(len(safe_raw)),
        ],
        input=safe_raw,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=10,
    )
    if completed.returncode != 0 or json.loads(completed.stdout)["result"] != "PASS" or completed.stderr:
        raise AssertionError("Scanner B stdin contract rejected")
    crlf = _stream(safe_records, b"\r\n")
    if scanner.scan(crlf, len(crlf))["result"] != "PASS":
        raise AssertionError("CRLF stream rejected")
    for name, raw in {
        "lone CR": _stream(safe_records, b"\r"),
        "missing final newline": _stream(safe_records)[:-1],
        "truncated byte count": _stream(safe_records),
        "unknown source": _stream([("UNKNOWN", b"safe"), ("REMOTE_JOURNAL", b"safe")]),
    }.items():
        expected = len(raw) - 1 if name == "truncated byte count" else len(raw)
        if scanner.scan(raw, expected)["result"] == "PASS":
            raise AssertionError(f"malformed stream passed: {name}")

    sys.stdout.write(f"privacy scanner B qualification passed: {len(cases)} corpus cases\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
