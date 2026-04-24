from pathlib import Path

from typer.testing import CliRunner

from phishing_surface_monitor_cli import app


def test_scan_reports_written_to_output_dir(monkeypatch, tmp_path: Path):
    runner = CliRunner()

    monkeypatch.setattr(
        "phishing_surface_monitor_cli.scan_domain",
        lambda domain, threshold: {
            "domain": domain,
            "threshold": threshold,
            "findings": [],
        },
    )

    out_dir = tmp_path / "artifacts" / "reports"
    result = runner.invoke(
        app,
        [
            "scan",
            "example.com",
            "--report",
            "--json-report",
            "--output-dir",
            str(out_dir),
        ],
    )

    assert result.exit_code == 0, result.stdout
    assert (out_dir / "example.com_scan_report.md").exists()
    assert (out_dir / "example.com_scan_report.json").exists()
