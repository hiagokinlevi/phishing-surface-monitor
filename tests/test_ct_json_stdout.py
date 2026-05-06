import json

from phishing_surface_monitor_cli import _serialize_ct_findings


def test_ct_json_stdout_valid_shape_and_fields():
    findings = [
        {
            "matched_domain": "login-example.com",
            "certificate_fingerprint": "abc123",
            "risk_score": 0.91,
            "detection_timestamp": "2026-01-02T03:04:05+00:00",
        }
    ]

    payload = _serialize_ct_findings(findings)
    raw = json.dumps(payload)
    parsed = json.loads(raw)

    assert isinstance(parsed, list)
    assert len(parsed) == 1
    row = parsed[0]
    assert row["matched_domain"] == "login-example.com"
    assert row["certificate_fingerprint"] == "abc123"
    assert row["risk_score"] == 0.91
    assert row["detection_timestamp"] == "2026-01-02T03:04:05+00:00"


def test_ct_json_stdout_empty_results_is_empty_array():
    payload = _serialize_ct_findings([])
    assert payload == []
    assert json.dumps(payload) == "[]"
