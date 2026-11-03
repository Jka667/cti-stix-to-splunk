import json
from datetime import datetime, timezone
from pathlib import Path

from stix_to_splunk import to_rows

BUNDLE = json.loads((Path(__file__).parent / "samples" / "sample_bundle.json").read_text())["objects"]
NOW = datetime(2026, 11, 3, tzinfo=timezone.utc)


def test_extracts_active_indicators_with_ttps():
    rows = {r["indicator"]: r for r in to_rows(BUNDLE, NOW)}
    assert set(rows) == {
        "update-check.example", "203.0.113.45",
        "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899",
        "http://update-check.example/Payload.bin",
    }
    assert rows["update-check.example"]["mitre"] == "T1071.001"
    assert rows["update-check.example"]["ioc_source"] == "Sample CTI Team"
    assert rows["aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899"]["type"] == "file-hash-sha-256"


def test_skips_revoked_and_expired():
    indicators = {r["indicator"] for r in to_rows(BUNDLE, NOW)}
    assert "198.51.100.7" not in indicators
    assert "false-positive.example" not in indicators
