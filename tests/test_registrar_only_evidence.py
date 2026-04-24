from phishing_surface_monitor_cli import _render_registrar_only_markdown


def test_registrar_only_markdown_filters_icann_and_general_sections() -> None:
    payload = {
        "domain": "login-example-support.com",
        "registrar": {"name": "Example Registrar LLC", "abuse_contact": "abuse@example-registrar.test"},
        "timestamps": {"first_seen": "2026-01-01T12:00:00Z", "last_seen": "2026-01-02T12:00:00Z"},
        "risk": {"score": 0.93, "level": "high", "summary": "Likely phishing impersonation"},
        "supporting_indicators": [
            "MX configured with suspicious provider",
            "New CT issuance for lookalike CN",
        ],
        "icann": {"whois_server": "whois.example"},
        "narrative": "Long-form general narrative that should not appear",
    }

    md = _render_registrar_only_markdown(payload)

    assert "## Registrar Details" in md
    assert "## Risk Summary" in md
    assert "## Supporting Indicators" in md
    assert "Example Registrar LLC" in md
    assert "abuse@example-registrar.test" in md

    assert "ICANN" not in md
    assert "general narrative" not in md.lower()
    assert "narrative" not in md.lower()
