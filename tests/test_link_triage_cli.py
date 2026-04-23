from __future__ import annotations

import json

from phishing_surface_monitor_cli import main


def test_link_triage_human_output_includes_reason_codes(capsys):
    rc = main([
        "link-triage",
        "http://user:pass@example.com",
        "http://example.com",
    ])
    assert rc == 0

    out = capsys.readouterr().out
    assert "REASONS" in out
    assert "EMBEDDED_CREDS" in out


def test_link_triage_json_output_preserves_results_shape(capsys):
    rc = main([
        "link-triage",
        "--json",
        "data:text/html,hello",
    ])
    assert rc == 0

    payload = json.loads(capsys.readouterr().out)
    assert "results" in payload
    assert isinstance(payload["results"], list)
    assert payload["results"]
    assert "url" in payload["results"][0]
    assert "verdict" in payload["results"][0]
    assert "reasons" in payload["results"][0]
