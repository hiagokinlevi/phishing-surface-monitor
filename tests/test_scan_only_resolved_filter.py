from argparse import Namespace

import phishing_surface_monitor_cli as cli


def test_scan_only_resolved_filters_mixed_findings(monkeypatch, capsys):
    monkeypatch.setattr(cli, "generate_typosquat_variants", lambda domain: ["resolved-example.com", "dead-example.com"])
    monkeypatch.setattr(cli, "score_similarity", lambda base, cand: 0.9)

    def fake_dns(domain):
        if domain == "resolved-example.com":
            return {"resolved": True, "a_records": ["1.2.3.4"]}
        return {"resolved": False, "a_records": []}

    monkeypatch.setattr(cli, "check_dns_resolution", fake_dns)

    args = Namespace(
        domain="example.com",
        threshold=0.75,
        min_risk=None,
        only_resolved=True,
        report=False,
        json_report=False,
    )

    rc = cli.run_scan(args)
    out = capsys.readouterr().out

    assert rc == 0
    assert "resolved-example.com" in out
    assert "dead-example.com" not in out
