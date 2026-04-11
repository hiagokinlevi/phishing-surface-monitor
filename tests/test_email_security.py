"""Unit tests for passive email posture analysis and CLI reporting."""
from __future__ import annotations

import json
from pathlib import Path

from click.testing import CliRunner
import pytest

from analyzers.email_security import mx_spf_checker
from analyzers.email_security.mx_spf_checker import (
    DEFAULT_DKIM_SELECTORS,
    EmailPosture,
    check_email_posture,
)


def _posture(
    *,
    has_mx: bool = False,
    spf: str | None = None,
    dmarc: str | None = None,
    dkim: dict[str, str] | None = None,
) -> EmailPosture:
    posture = EmailPosture(
        domain="test.com",
        has_mx=has_mx,
        mx_records=["mx.test.com"] if has_mx else [],
        spf_record=spf,
        dmarc_record=dmarc,
        dkim_records=dkim or {},
        tested_dkim_selectors=["default", "selector1"],
    )
    posture.gaps = mx_spf_checker._build_gaps(posture)
    return posture


class TestEmailPostureModel:
    def test_missing_controls_on_mail_receiving_domain_raise_high_risk(self) -> None:
        posture = _posture(has_mx=True)
        assert posture.risk_level == "HIGH"
        assert posture.spf_posture == "missing"
        assert posture.dmarc_posture == "missing"
        assert posture.has_dkim is False

    def test_permissive_spf_escalates_to_critical(self) -> None:
        posture = _posture(has_mx=True, spf="v=spf1 +all", dmarc="v=DMARC1; p=reject")
        assert posture.spf_posture == "permissive"
        assert posture.risk_level == "CRITICAL"

    def test_strict_controls_reduce_to_medium_when_mx_present(self) -> None:
        posture = _posture(
            has_mx=True,
            spf="v=spf1 include:_spf.example.com -all",
            dmarc="v=DMARC1; p=reject",
            dkim={"default": "v=DKIM1; k=rsa; p=abc123"},
        )
        assert posture.spf_posture == "strict"
        assert posture.dmarc_posture == "reject"
        assert posture.risk_level == "MEDIUM"

    def test_no_mail_receiver_without_auth_controls_is_still_high_signal(self) -> None:
        posture = _posture()
        assert posture.risk_level == "HIGH"

    def test_to_dict_exposes_gap_details_and_selector_list(self) -> None:
        posture = _posture(has_mx=True)
        payload = posture.to_dict()
        assert payload["tested_dkim_selectors"] == ["default", "selector1"]
        assert payload["gaps"][0]["control"] == "mx"


class TestEmailPostureLookups:
    def test_check_email_posture_normalizes_domain_and_selectors(self, monkeypatch) -> None:
        lookup_calls: list[tuple[str, float]] = []

        monkeypatch.setattr(
            mx_spf_checker,
            "_mx_lookup",
            lambda domain, timeout=3.0: lookup_calls.append((domain, timeout)) or ["mx1.example.com"],
        )

        def fake_txt_lookup(domain: str, timeout: float = 3.0) -> list[str]:
            lookup_calls.append((domain, timeout))
            if domain == "xn--exmple-cua.com":
                return ["v=spf1 -all"]
            if domain == "_dmarc.xn--exmple-cua.com":
                return ["v=DMARC1; p=reject"]
            if domain == "default._domainkey.xn--exmple-cua.com":
                return ["v=DKIM1; p=abc"]
            return []

        monkeypatch.setattr(mx_spf_checker, "_txt_lookup", fake_txt_lookup)

        posture = check_email_posture(
            " Exämple.com. ",
            timeout=1.5,
            dkim_selectors=[" Default. ", "selector1", "DEFAULT"],
        )

        assert posture.domain == "xn--exmple-cua.com"
        assert posture.tested_dkim_selectors == ["default", "selector1"]
        assert posture.dkim_records == {"default": "v=DKIM1; p=abc"}
        assert lookup_calls[0] == ("xn--exmple-cua.com", 1.5)
        assert ("_dmarc.xn--exmple-cua.com", 1.5) in lookup_calls
        assert ("default._domainkey.xn--exmple-cua.com", 1.5) in lookup_calls

    def test_check_email_posture_uses_default_selectors(self, monkeypatch) -> None:
        txt_records = {
            "example.com": ["v=spf1 include:spf.example.net ~all"],
            "_dmarc.example.com": ["v=DMARC1; p=none"],
            "default._domainkey.example.com": ["v=DKIM1; p=abc"],
        }

        monkeypatch.setattr(
            mx_spf_checker,
            "_mx_lookup",
            lambda domain, timeout=3.0: ["mx1.example.com"] if domain == "example.com" else [],
        )
        monkeypatch.setattr(
            mx_spf_checker,
            "_txt_lookup",
            lambda domain, timeout=3.0: txt_records.get(domain, []),
        )

        posture = check_email_posture("example.com")
        assert posture.has_mx is True
        assert posture.spf_posture == "softfail"
        assert posture.dmarc_posture == "none"
        assert posture.dkim_records == {"default": "v=DKIM1; p=abc"}
        assert posture.tested_dkim_selectors == list(DEFAULT_DKIM_SELECTORS)

    def test_check_email_posture_rejects_invalid_domain(self) -> None:
        with pytest.raises(ValueError, match="without URL components"):
            check_email_posture("https://example.com/login")

    @pytest.mark.parametrize("timeout", [0, -1.0, float("inf"), float("nan")])
    def test_check_email_posture_rejects_invalid_timeout(self, timeout: float) -> None:
        with pytest.raises(ValueError, match="finite number greater than 0"):
            check_email_posture("example.com", timeout=timeout)

    @pytest.mark.parametrize(
        ("selectors", "message"),
        [
            ([""], "non-empty DNS label"),
            (["bad.selector"], "single DNS label"),
            (["selector/path"], "without URL components"),
        ],
    )
    def test_check_email_posture_rejects_invalid_selectors(
        self,
        selectors: list[str],
        message: str,
    ) -> None:
        with pytest.raises(ValueError, match=message):
            check_email_posture("example.com", dkim_selectors=selectors)


class TestEmailPostureCli:
    def test_cli_uses_explicit_candidates_and_writes_json(self, tmp_path: Path) -> None:
        from cli.main import cli as main_cli
        from cli import main as cli_main_module

        runner = CliRunner()
        output_path = tmp_path / "email-posture.json"

        original_check = cli_main_module.check_email_posture
        try:
            cli_main_module.check_email_posture = lambda domain, timeout, dkim_selectors: EmailPosture(
                domain=domain,
                has_mx=domain == "login-example.net",
                mx_records=["mx.login-example.net"] if domain == "login-example.net" else [],
                spf_record=None if domain == "login-example.net" else "v=spf1 -all",
                dmarc_record=None if domain == "login-example.net" else "v=DMARC1; p=reject",
                dkim_records={},
                tested_dkim_selectors=list(dkim_selectors),
                gaps=(
                    [
                        mx_spf_checker.EmailGap(
                            control="spf",
                            severity="HIGH",
                            summary="No SPF record was found.",
                            recommendation="Treat mail from this lookalike as ungoverned.",
                        )
                    ]
                    if domain == "login-example.net"
                    else []
                ),
            )

            result = runner.invoke(
                main_cli,
                [
                    "email-posture",
                    "example.com",
                    "login-example.net",
                    "example-security.org",
                    "--selector",
                    "selectorA",
                    "--output-json",
                    str(output_path),
                ],
            )
        finally:
            cli_main_module.check_email_posture = original_check

        assert result.exit_code == 0, result.output
        assert "Email Abuse Posture for example.com" in result.output
        assert "login-example.net" in result.output
        assert "Summary:" in result.output

        payload = json.loads(output_path.read_text(encoding="utf-8"))
        assert payload["brand_domain"] == "example.com"
        assert payload["tested_dkim_selectors"] == ["selectorA"]
        assert payload["results"][0]["domain"] == "login-example.net"
        assert payload["results"][0]["posture"]["risk_level"] == "HIGH"

    def test_cli_auto_generates_candidates_when_not_supplied(self) -> None:
        from cli.main import cli as main_cli
        from cli import main as cli_main_module

        runner = CliRunner()

        class Variant:
            def __init__(self, domain: str, similarity_score: float) -> None:
                self.domain = domain
                self.similarity_score = similarity_score

        original_generate = cli_main_module.generate_typosquats
        original_check = cli_main_module.check_email_posture
        try:
            cli_main_module.generate_typosquats = lambda domain: [
                Variant("login-example.net", 0.91),
                Variant("portal-example.net", 0.84),
                Variant("ignore-me.net", 0.4),
            ]
            cli_main_module.check_email_posture = lambda domain, timeout, dkim_selectors: _posture(
                has_mx=domain == "portal-example.net",
                dmarc="v=DMARC1; p=reject",
                dkim={"default": "v=DKIM1; p=abc"},
            )

            result = runner.invoke(
                main_cli,
                ["email-posture", "example.com", "--threshold", "0.8", "--limit", "2"],
            )
        finally:
            cli_main_module.generate_typosquats = original_generate
            cli_main_module.check_email_posture = original_check

        assert result.exit_code == 0, result.output
        assert "login-example.net" in result.output
        assert "portal-example.net" in result.output
        assert "ignore-me.net" not in result.output
