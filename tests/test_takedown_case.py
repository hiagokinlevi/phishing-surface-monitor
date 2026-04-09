"""Tests for takedown case bundle creation and CLI workflow."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from click.testing import CliRunner

from reports.takedown_case import (
    create_takedown_case_bundle,
    load_findings_json,
    update_takedown_case_status,
)
from schemas.case import BrandFinding, CaseStatus, RiskLevel


def _finding(
    domain: str,
    *,
    risk: RiskLevel = RiskLevel.HIGH,
    resolves: bool = True,
) -> BrandFinding:
    return BrandFinding(
        brand_domain="example.com",
        lookalike_domain=domain,
        technique="homoglyph",
        similarity_score=0.91,
        resolves=resolves,
        a_records=["203.0.113.8"] if resolves else [],
        risk_level=risk,
        status=CaseStatus.OPEN,
    )


_FIXED_TS = datetime(2026, 4, 9, 12, 30, 0, tzinfo=timezone.utc)


class TestTakedownCaseBundle:
    def test_load_findings_json_parses_brand_findings(self, tmp_path: Path) -> None:
        payload = [_finding("login-example.net").model_dump(mode="json")]
        path = tmp_path / "findings.json"
        path.write_text(json.dumps(payload), encoding="utf-8")

        findings = load_findings_json(path)

        assert len(findings) == 1
        assert findings[0].lookalike_domain == "login-example.net"

    def test_create_case_bundle_writes_expected_files(self, tmp_path: Path) -> None:
        bundle = create_takedown_case_bundle(
            findings=[
                _finding("login-example.net", risk=RiskLevel.CRITICAL),
                _finding("portal-example.org", risk=RiskLevel.MEDIUM, resolves=False),
            ],
            brand_domain="example.com",
            output_dir=tmp_path,
            brand_owner="Example Corp",
            reporter_name="Analyst",
            reporter_email="analyst@example.com",
            registrar_name="Namecheap",
            registrar_abuse_email="abuse@example-registrar.test",
            created_at=_FIXED_TS,
        )

        case_dir = Path(bundle["case_dir"])
        assert (case_dir / "case.json").exists()
        assert (case_dir / "registrar_request.md").exists()
        assert (case_dir / "icann_complaint.md").exists()
        assert (case_dir / bundle["evidence_package"]).exists()

        case = json.loads((case_dir / "case.json").read_text(encoding="utf-8"))
        assert case["status"] == "open"
        assert case["highest_risk"] == "critical"
        assert case["findings"][0]["lookalike_domain"] == "login-example.net"
        assert "Namecheap" in (case_dir / "registrar_request.md").read_text(encoding="utf-8")
        assert "https://www.icann.org/compliance/complaint" in (
            case_dir / "icann_complaint.md"
        ).read_text(encoding="utf-8")

    def test_update_case_status_appends_history(self, tmp_path: Path) -> None:
        bundle = create_takedown_case_bundle(
            findings=[_finding("login-example.net")],
            brand_domain="example.com",
            output_dir=tmp_path,
            created_at=_FIXED_TS,
        )
        case_file = Path(bundle["case_file"])

        updated = update_takedown_case_status(
            case_file=case_file,
            status=CaseStatus.TAKEDOWN_REQUESTED,
            note="Registrar abuse notice submitted",
            changed_at=datetime(2026, 4, 9, 13, 0, 0, tzinfo=timezone.utc),
        )

        assert updated["status"] == "takedown_requested"
        assert updated["status_history"][-1]["note"] == "Registrar abuse notice submitted"


class TestTakedownCaseCli:
    def test_create_and_update_commands_work_end_to_end(self, tmp_path: Path) -> None:
        from cli.main import cli as main_cli

        findings_path = tmp_path / "findings.json"
        findings_path.write_text(
            json.dumps([
                _finding("login-example.net", risk=RiskLevel.CRITICAL).model_dump(mode="json")
            ]),
            encoding="utf-8",
        )

        runner = CliRunner()
        create_result = runner.invoke(
            main_cli,
            [
                "takedown-case",
                "create",
                "example.com",
                "--findings-json",
                str(findings_path),
                "--output-dir",
                str(tmp_path / "cases"),
                "--registrar-name",
                "Namecheap",
                "--registrar-abuse-email",
                "abuse@example-registrar.test",
            ],
        )

        assert create_result.exit_code == 0, create_result.output
        assert "Case bundle written:" in create_result.output

        case_file = next((tmp_path / "cases").glob("*/case.json"))
        update_result = runner.invoke(
            main_cli,
            [
                "takedown-case",
                "update",
                str(case_file),
                "--status",
                "takedown_requested",
                "--note",
                "Submitted registrar template",
            ],
        )

        assert update_result.exit_code == 0, update_result.output
        payload = json.loads(case_file.read_text(encoding="utf-8"))
        assert payload["status"] == "takedown_requested"
        assert payload["status_history"][-1]["note"] == "Submitted registrar template"
