from click.testing import CliRunner

from phishing_surface_monitor_cli import cli


def test_scan_sort_by_risk_orders_descending(monkeypatch):
    def fake_variants(_domain):
        return ["a-example.com", "b-example.com", "c-example.com"]

    score_map = {
        "a-example.com": {"candidate_domain": "a-example.com", "risk_score": 0.2, "risk_level": "low"},
        "b-example.com": {"candidate_domain": "b-example.com", "risk_score": 0.9, "risk_level": "high"},
        "c-example.com": {"candidate_domain": "c-example.com", "risk_score": 0.5, "risk_level": "medium"},
    }

    def fake_score(_target, candidate, threshold=0.75):
        return score_map[candidate]

    monkeypatch.setattr("phishing_surface_monitor_cli.generate_typosquat_variants", fake_variants)
    monkeypatch.setattr("phishing_surface_monitor_cli.score_domain_risk", fake_score)

    runner = CliRunner()
    result = runner.invoke(cli, ["scan", "example.com", "--sort-by-risk", "--top", "3"])

    assert result.exit_code == 0
    lines = [line for line in result.output.splitlines() if line.strip()]
    assert lines[0].startswith("b-example.com")
    assert lines[1].startswith("c-example.com")
    assert lines[2].startswith("a-example.com")
