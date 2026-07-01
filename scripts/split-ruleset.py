#!/usr/bin/env python3

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CHUNKS = ROOT / "ruleset" / "golang" / "chunks"

CHUNK_SPECS = [
    ("cwe-001-050.json", "CWE-", 1, 50),
    ("cwe-051-100.json", "CWE-", 51, 100),
    ("cwe-101-150.json", "CWE-", 101, 150),
    ("cwe-151-200.json", "CWE-", 151, 200),
    ("cwe-201-9999.json", "CWE-", 201, 9999),
    ("perf-001-050.json", "PERF-", 1, 50),
    ("perf-051-100.json", "PERF-", 51, 100),
    ("perf-101-150.json", "PERF-", 101, 150),
    ("perf-151-200.json", "PERF-", 151, 200),
    ("perf-201-224.json", "PERF-", 201, 224),
]


def numeric_id(rule_id: str, prefix: str) -> int | None:
    if not rule_id.startswith(prefix):
        return None
    try:
        return int(rule_id[len(prefix) :])
    except ValueError:
        return None


def validate_chunk(path: Path, prefix: str, start: int, end: int) -> dict:
    payload = json.loads(path.read_text())
    if not isinstance(payload, dict):
        raise SystemExit(f"{path} must contain a top-level JSON object")

    for rule_id in payload:
        value = numeric_id(rule_id, prefix)
        if value is None or not (start <= value <= end):
            raise SystemExit(f"{path} contains out-of-range rule id: {rule_id}")

    return dict(sorted(payload.items()))


def main() -> None:
    if not CHUNKS.is_dir():
        raise SystemExit(f"missing chunk dir: {CHUNKS}")

    merged: dict[str, dict] = {}
    for filename, prefix, start, end in CHUNK_SPECS:
        path = CHUNKS / filename
        if not path.exists():
            raise SystemExit(f"missing expected chunk file: {path}")
        chunk = validate_chunk(path, prefix, start, end)
        for rule_id, rule in chunk.items():
            if rule_id in merged:
                raise SystemExit(f"duplicate rule id across chunks: {rule_id}")
            merged[rule_id] = rule
        print(f"{filename}: {len(chunk)} rules")

    if len(merged) != 399:
        raise SystemExit(f"expected 399 merged top-level keys, got {len(merged)}")

    print(f"validated chunked ruleset: {len(merged)} total rules")


if __name__ == "__main__":
    main()
