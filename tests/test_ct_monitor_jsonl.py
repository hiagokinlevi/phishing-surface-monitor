import json

import phishing_surface_monitor_cli as cli


def test_ct_monitor_jsonl_output(monkeypatch, capsys):
    sample_events = [
        {
            "domain": "login-example.com",
            "fingerprint": "AB:CD",
            "serial": "1234",
            "wildcard": True,
            "seen_at": "2026-01-01T00:00:00Z",
            "reason": "wildcard certificate observed",
        },
        {
            "matched_domain": "secure-example.com",
            "cert_fingerprint": "EF:01",
            "serial_number": "5678",
            "wildcard": False,
            "timestamp": "2026-01-02T00:00:00Z",
            "alert_reason": "new certificate registration",
        },
    ]

    monkeypatch.setattr(cli, "monitor_ct_for_domain", lambda domain: sample_events)

    rc = cli.main(["ct-monitor", "example.com", "--jsonl"])
    assert rc == 0

    out = capsys.readouterr().out.strip().splitlines()
    assert len(out) == 2

    first = json.loads(out[0])
    assert first["domain"] == "login-example.com"
    assert first["fingerprint"] == "AB:CD"
    assert first["serial"] == "1234"
    assert first["wildcard"] is True
    assert first["seen_at"] == "2026-01-01T00:00:00Z"
    assert "wildcard" in first["reason"]

    second = json.loads(out[1])
    assert second["domain"] == "secure-example.com"
    assert second["fingerprint"] == "EF:01"
    assert second["serial"] == "5678"
    assert second["wildcard"] is False
    assert second["seen_at"] == "2026-01-02T00:00:00Z"
    assert "new certificate" in second["reason"]
