from types import SimpleNamespace

import phishing_surface_monitor_cli as cli


def test_scan_fail_on_min_risk_returns_exit_code_2(monkeypatch, capsys):
    monkeypatch.setattr(
        cli,
        "run_scan",
        lambda _args: [
            {"domain": "a.example", "risk": "low"},
            {"domain": "b.example", "risk": "high"},
        ],
    )

    args = SimpleNamespace(min_risk=None, fail_on_min_risk="medium", json_stdout=False)
    rc = cli.handle_scan(args)

    assert rc == 2
    err = capsys.readouterr().err
    assert "met or exceeded risk 'medium'" in err
