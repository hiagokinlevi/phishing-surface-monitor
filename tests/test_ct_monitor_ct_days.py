from datetime import datetime, timezone

from cli.ct_monitor import filter_ct_findings_by_days


def test_filter_ct_findings_by_days_includes_boundary_and_excludes_older():
    now = datetime(2026, 1, 8, 0, 0, 0, tzinfo=timezone.utc)

    findings = [
        {"id": "new", "not_before": "2026-01-07T23:59:59Z"},
        {"id": "boundary", "not_before": "2026-01-01T00:00:00Z"},
        {"id": "old", "not_before": "2025-12-31T23:59:59Z"},
    ]

    filtered = filter_ct_findings_by_days(findings, ct_days=7, now=now)
    ids = [f["id"] for f in filtered]

    assert "new" in ids
    assert "boundary" in ids
    assert "old" not in ids
