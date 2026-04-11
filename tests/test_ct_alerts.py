"""Testes para alertas de Certificate Transparency e integração de CLI."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from click.testing import CliRunner

from analyzers.ct_alerts import (
    CRITICAL,
    HIGH,
    MEDIUM,
    detect_new_certificate_alerts,
    detect_wildcard_certificate_alerts,
    evaluate_ct_alerts,
    load_ct_state,
    merge_known_certificate_ids,
    save_ct_state,
)
from analyzers.ct_monitor import CtCertificate


def _cert(
    cert_id: int,
    common_name: str,
    *,
    issuer: str = "Let's Encrypt",
    logged_at: datetime | None = None,
) -> CtCertificate:
    """Cria certificado sintético para cenários de teste."""
    return CtCertificate(
        cert_id=cert_id,
        logged_at=logged_at or datetime(2026, 4, 9, tzinfo=timezone.utc),
        not_before=datetime(2026, 4, 8, tzinfo=timezone.utc),
        not_after=datetime(2026, 7, 8, tzinfo=timezone.utc),
        common_name=common_name,
        issuer=issuer,
        name_value=common_name,
    )


class TestCtStatePersistence:
    def test_load_missing_state_returns_empty_set(self, tmp_path: Path) -> None:
        assert load_ct_state(tmp_path / "missing.json") == set()

    def test_save_and_load_state_roundtrip(self, tmp_path: Path) -> None:
        path = tmp_path / "ct-state.json"
        save_ct_state(
            path,
            brand_domain="example.com",
            known_certificate_ids={5, 2, 7},
        )
        loaded = load_ct_state(path)
        assert loaded == {2, 5, 7}


class TestCtAlerts:
    def test_detect_new_certificate_alerts(self) -> None:
        certs = [_cert(10, "login-example.com"), _cert(11, "secure-example.com")]
        alerts = detect_new_certificate_alerts(certs, known_certificate_ids={11})
        assert len(alerts) == 1
        assert alerts[0].cert_id == 10
        assert alerts[0].severity == HIGH

    def test_detect_wildcard_alerts_brand_keyword_is_critical(self) -> None:
        certs = [_cert(42, "*.paypal-security-check.com")]
        alerts = detect_wildcard_certificate_alerts(certs, brand_domain="paypal.com")
        assert len(alerts) == 1
        assert alerts[0].severity == CRITICAL

    def test_detect_wildcard_alerts_without_keyword_is_medium(self) -> None:
        certs = [_cert(77, "*.random-cdn-edge.net")]
        alerts = detect_wildcard_certificate_alerts(certs, brand_domain="paypal.com")
        assert len(alerts) == 1
        assert alerts[0].severity == MEDIUM

    def test_evaluate_ct_alerts_excludes_legitimate_brand_domains(self) -> None:
        certs = [
            _cert(1, "PAYPAL.com."),
            _cert(2, "*.PayPal.com"),
            _cert(3, "*.paypal-security-check.com"),
            _cert(4, "paypal-login-secure.net"),
        ]
        batch = evaluate_ct_alerts(
            brand_domain="PayPal.com.",
            certs=certs,
            known_certificate_ids=set(),
        )
        assert batch.total_certificates == 4
        assert batch.brand_domain == "paypal.com"
        assert batch.lookalike_certificates == 2
        assert len(batch.new_registration_alerts) == 2
        assert len(batch.wildcard_alerts) == 1
        assert batch.wildcard_alerts[0].cert_id == 3

    def test_merge_known_ids(self) -> None:
        merged = merge_known_certificate_ids({1, 2}, [_cert(2, "a.com"), _cert(3, "b.com")])
        assert merged == {1, 2, 3}


class TestCtMonitorCli:
    def test_ct_monitor_cli_generates_alert_report_and_updates_state(self) -> None:
        from cli.main import cli as main_cli

        runner = CliRunner()
        with runner.isolated_filesystem():
            state_path = Path("state.json")
            save_ct_state(
                state_path,
                brand_domain="paypal.com",
                known_certificate_ids={100},
            )

            fake_certs = [
                _cert(101, "*.paypal-security-check.com"),
                _cert(102, "paypal-login-alert.net"),
                _cert(103, "paypal.com"),  # deve ser filtrado pelo lookalike filter
            ]

            from analyzers import ct_monitor as ct_monitor_module
            from cli import main as cli_main_module

            original_query_cli = cli_main_module.query_ct_logs
            original_query_module = ct_monitor_module.query_ct_logs
            captured_domains: list[str] = []
            try:
                def fake_query(domain: str, *args, **kwargs):
                    captured_domains.append(domain)
                    return fake_certs

                cli_main_module.query_ct_logs = fake_query
                ct_monitor_module.query_ct_logs = fake_query

                result = runner.invoke(
                    main_cli,
                    [
                        "ct-monitor",
                        "PayPal.com.",
                        "--state-file",
                        str(state_path),
                        "--output-json",
                        "alerts.json",
                    ],
                )
            finally:
                cli_main_module.query_ct_logs = original_query_cli
                ct_monitor_module.query_ct_logs = original_query_module

            assert result.exit_code == 0, result.output
            assert "Summary:" in result.output
            assert "new=2" in result.output
            assert "wildcard=1" in result.output
            assert captured_domains == ["paypal.com"]

            saved_state = load_ct_state(state_path)
            assert {100, 101, 102, 103}.issubset(saved_state)

            payload = json.loads(Path("alerts.json").read_text(encoding="utf-8"))
            assert payload["brand_domain"] == "paypal.com"
            assert payload["lookalike_certificates"] == 2
            assert len(payload["new_registration_alerts"]) == 2
            assert len(payload["wildcard_alerts"]) == 1

    def test_ct_monitor_fail_on_alerts_returns_nonzero(self) -> None:
        from cli.main import cli as main_cli

        runner = CliRunner()
        with runner.isolated_filesystem():
            fake_certs = [_cert(200, "*.brand-malicious.net")]

            from cli import main as cli_main_module

            original_query_cli = cli_main_module.query_ct_logs
            try:
                cli_main_module.query_ct_logs = lambda *args, **kwargs: fake_certs
                result = runner.invoke(
                    main_cli,
                    ["ct-monitor", "brand.com", "--fail-on-alerts"],
                )
            finally:
                cli_main_module.query_ct_logs = original_query_cli

            assert result.exit_code == 1

    def test_ct_monitor_rejects_invalid_brand_domain(self) -> None:
        from cli.main import cli as main_cli

        runner = CliRunner()
        result = runner.invoke(main_cli, ["ct-monitor", "https://brand.com/login"])

        assert result.exit_code == 2
        assert "hostname without URL components" in result.output
