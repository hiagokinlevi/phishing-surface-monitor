"""
Domain Alert Webhook Sender
==============================
Sends Slack Block Kit notifications and generic webhook payloads when new
lookalike domains are detected during a phishing surface scan.

Supports:
  - Slack (Block Kit format, capped at 10 blocks)
  - Generic JSON webhook (e.g. Microsoft Teams, PagerDuty, SIEM ingest)

All HTTP calls use stdlib urllib only — no requests/httpx required.

Usage:
    from alerting.domain_alerts import DomainAlertConfig, send_domain_alert

    config = DomainAlertConfig(
        url="https://hooks.slack.com/services/T00/B00/xxx",
        channel="slack",
        brand_domain="example.com",
        severity_threshold="high",   # only alert on high or critical
    )

    result = send_domain_alert(findings, config, dry_run=True)
    print(result.payload_preview)

For dry_run=True (the default), no HTTP request is sent.
Always test with dry_run=True before wiring into production pipelines.
"""
from __future__ import annotations

import json
from ipaddress import ip_address
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Optional

from schemas.case import BrandFinding, RiskLevel


# ---------------------------------------------------------------------------
# Risk ordering
# ---------------------------------------------------------------------------

_RISK_ORDER: dict[str, int] = {
    "critical": 4,
    "high":     3,
    "medium":   2,
    "low":      1,
    "info":     0,
}

# Slack attachment colours per risk level
_SLACK_COLORS: dict[str, str] = {
    "critical": "#b91c1c",   # red-700
    "high":     "#c2410c",   # orange-700
    "medium":   "#d97706",   # amber-600
    "low":      "#2563eb",   # blue-600
    "info":     "#6b7280",   # gray-500
}

# Slack emoji per risk level
_RISK_EMOJI: dict[str, str] = {
    "critical": ":rotating_light:",
    "high":     ":warning:",
    "medium":   ":yellow_circle:",
    "low":      ":information_source:",
    "info":     ":white_circle:",
}

# Max Slack blocks to avoid API limit (50) and readability threshold
_MAX_SLACK_BLOCKS = 10


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

@dataclass
class DomainAlertConfig:
    """
    Configuration for a single webhook alert destination.

    Attributes:
        url:                Webhook URL to POST to.
        channel:            "slack" for Slack Block Kit, "generic" for plain JSON.
        brand_domain:       The brand being monitored (included in alert text).
        severity_threshold: Minimum risk level to alert on (default "high").
                            Findings below this threshold are filtered out.
        source_label:       Optional label for the source system.
        timeout_seconds:    HTTP request timeout in seconds.
        allow_insecure_http:
                            When True, permit plain HTTP for non-production
                            lab endpoints. Defaults to False.
    """

    url: str
    channel: str = "slack"           # "slack" | "generic"
    brand_domain: str = ""
    severity_threshold: str = "high"
    source_label: str = "phishing-surface-monitor"
    timeout_seconds: int = 10
    allow_insecure_http: bool = False

    def meets_threshold(self, finding: BrandFinding) -> bool:
        """Return True if the finding's risk level meets the alert threshold."""
        threshold = _RISK_ORDER.get(self.severity_threshold.lower(), 3)
        return _RISK_ORDER.get(finding.risk_level.value, 0) >= threshold


# ---------------------------------------------------------------------------
# Alert result
# ---------------------------------------------------------------------------

@dataclass
class DomainAlertResult:
    """Result of sending a domain alert."""

    success: bool
    dry_run: bool
    channel: str
    findings_alerted: int
    payload_preview: str = ""
    http_status: Optional[int] = None
    error: Optional[str] = None


# ---------------------------------------------------------------------------
# Slack payload builder
# ---------------------------------------------------------------------------

def build_slack_payload(
    findings: list[BrandFinding],
    config: DomainAlertConfig,
) -> dict:
    """
    Build a Slack Block Kit payload for new domain findings.

    The payload includes a header, scan summary, and one section per finding
    (capped at _MAX_SLACK_BLOCKS to stay within Slack's limits).

    Args:
        findings: Findings that meet the alert threshold.
        config:   Alert configuration (brand_domain, source_label, etc.).

    Returns:
        Slack API-compatible dict with a 'blocks' list.
    """
    highest_risk = max(
        findings,
        key=lambda f: _RISK_ORDER.get(f.risk_level.value, 0),
        default=None,
    )
    risk_label = highest_risk.risk_level.value.upper() if highest_risk else "UNKNOWN"
    emoji = _RISK_EMOJI.get(risk_label.lower(), ":warning:")
    resolving = sum(1 for f in findings if f.resolves)

    blocks = [
        {
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": f"{emoji} New Lookalike Domains Detected: {config.brand_domain}",
                "emoji": True,
            },
        },
        {
            "type": "section",
            "fields": [
                {
                    "type": "mrkdwn",
                    "text": f"*Brand:*\n{config.brand_domain}",
                },
                {
                    "type": "mrkdwn",
                    "text": f"*Highest Risk:*\n{risk_label}",
                },
                {
                    "type": "mrkdwn",
                    "text": f"*Total Domains:*\n{len(findings)}",
                },
                {
                    "type": "mrkdwn",
                    "text": f"*Actively Resolving:*\n{resolving}",
                },
            ],
        },
        {
            "type": "divider",
        },
    ]

    # Per-finding sections (cap to avoid exceeding Slack limits)
    sorted_findings = sorted(
        findings,
        key=lambda f: _RISK_ORDER.get(f.risk_level.value, 0),
        reverse=True,
    )

    # Reserve 2 slots for: potential overflow context block + source context block
    remaining_slots = max(0, _MAX_SLACK_BLOCKS - len(blocks) - 2)
    shown = sorted_findings[:remaining_slots]
    overflow = len(findings) - len(shown)

    for f in shown:
        risk_emoji = _RISK_EMOJI.get(f.risk_level.value, ":white_circle:")
        resolve_str = "Resolves" if f.resolves else "Not resolving"
        sim_pct = f"{f.similarity_score * 100:.1f}%"
        blocks.append(
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": (
                        f"{risk_emoji} *{f.lookalike_domain}* — "
                        f"{f.risk_level.value.upper()} | {resolve_str} | "
                        f"Similarity: {sim_pct} | Technique: {f.technique}"
                    ),
                },
            }
        )

    if overflow > 0:
        blocks.append(
            {
                "type": "context",
                "elements": [
                    {
                        "type": "mrkdwn",
                        "text": f"_…and {overflow} more finding(s) not shown_",
                    }
                ],
            }
        )

    blocks.append(
        {
            "type": "context",
            "elements": [
                {
                    "type": "mrkdwn",
                    "text": f"Source: {config.source_label}",
                }
            ],
        }
    )

    return {"blocks": blocks}


# ---------------------------------------------------------------------------
# Generic webhook payload builder
# ---------------------------------------------------------------------------

def build_generic_payload(
    findings: list[BrandFinding],
    config: DomainAlertConfig,
) -> dict:
    """
    Build a generic JSON webhook payload for new domain findings.

    Suitable for Microsoft Teams incoming webhooks, SIEM ingest endpoints,
    or any service that accepts plain JSON.

    Args:
        findings: Findings that meet the alert threshold.
        config:   Alert configuration.

    Returns:
        Plain dict serialisable to JSON.
    """
    return {
        "source":        config.source_label,
        "brand_domain":  config.brand_domain,
        "alert_type":    "new_lookalike_domains",
        "total":         len(findings),
        "resolving":     sum(1 for f in findings if f.resolves),
        "highest_risk":  max(
            (f.risk_level.value for f in findings),
            key=lambda r: _RISK_ORDER.get(r, 0),
            default="info",
        ),
        "findings": [
            {
                "domain":           f.lookalike_domain,
                "risk_level":       f.risk_level.value,
                "resolves":         f.resolves,
                "similarity_score": round(f.similarity_score, 4),
                "technique":        f.technique,
                "detected_at":      f.detected_at.isoformat(),
            }
            for f in sorted(
                findings,
                key=lambda f: _RISK_ORDER.get(f.risk_level.value, 0),
                reverse=True,
            )
        ],
    }


# ---------------------------------------------------------------------------
# HTTP sender
# ---------------------------------------------------------------------------

def _validate_webhook_url(url: str, *, allow_insecure_http: bool) -> None:
    """
    Reject obviously unsafe live-send destinations before opening a socket.

    This keeps production alerts from being redirected to non-HTTP schemes,
    plaintext HTTP endpoints by default, or explicit localhost/private IP
    targets that create an avoidable SSRF path.
    """
    parsed = urllib.parse.urlparse(url.strip())
    scheme = parsed.scheme.lower()

    if scheme not in {"http", "https"}:
        raise ValueError("Webhook URL must use http or https.")

    if scheme != "https" and not allow_insecure_http:
        raise ValueError("Webhook URL must use https unless allow_insecure_http=True.")

    host = parsed.hostname
    if not host:
        raise ValueError("Webhook URL must include a hostname.")

    normalized_host = host.rstrip(".").lower()
    if normalized_host == "localhost" or normalized_host.endswith(".localhost"):
        raise ValueError("Webhook URL cannot target localhost.")

    try:
        addr = ip_address(normalized_host)
    except ValueError:
        return

    if (
        addr.is_private
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_reserved
        or addr.is_unspecified
        or addr.is_multicast
    ):
        raise ValueError("Webhook URL cannot target a local or reserved IP address.")


def _post_json(url: str, payload: dict, timeout: int) -> int:
    """
    POST JSON payload to a URL.  Returns the HTTP status code.

    Raises:
        urllib.error.URLError: On connection failure or timeout.
    """
    body = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url=url,
        data=body,
        method="POST",
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.status


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def send_domain_alert(
    findings: list[BrandFinding],
    config: DomainAlertConfig,
    dry_run: bool = True,
) -> DomainAlertResult:
    """
    Send a domain alert webhook for new lookalike domain detections.

    Only findings that meet config.severity_threshold are included.
    If no findings meet the threshold, the function returns success=True
    with findings_alerted=0 and no HTTP request is sent.

    Args:
        findings:  All brand findings from the current scan.
        config:    Webhook destination and alert configuration.
        dry_run:   When True (default), build the payload but skip the HTTP call.

    Returns:
        DomainAlertResult with success status, findings count, and payload preview.
    """
    # Filter findings by threshold
    eligible = [f for f in findings if config.meets_threshold(f)]

    if not eligible:
        return DomainAlertResult(
            success=True,
            dry_run=dry_run,
            channel=config.channel,
            findings_alerted=0,
            payload_preview="(no findings met the alert threshold)",
        )

    # Build payload
    if config.channel == "slack":
        payload = build_slack_payload(eligible, config)
    else:
        payload = build_generic_payload(eligible, config)

    payload_preview = json.dumps(payload, indent=2)[:500]

    if dry_run:
        return DomainAlertResult(
            success=True,
            dry_run=True,
            channel=config.channel,
            findings_alerted=len(eligible),
            payload_preview=payload_preview,
        )

    # Send HTTP request
    try:
        _validate_webhook_url(
            config.url,
            allow_insecure_http=config.allow_insecure_http,
        )
        status = _post_json(config.url, payload, timeout=config.timeout_seconds)
        success = 200 <= status < 300
        return DomainAlertResult(
            success=success,
            dry_run=False,
            channel=config.channel,
            findings_alerted=len(eligible),
            payload_preview=payload_preview,
            http_status=status,
            error=None if success else f"HTTP {status}",
        )
    except Exception as exc:
        return DomainAlertResult(
            success=False,
            dry_run=False,
            channel=config.channel,
            findings_alerted=0,
            payload_preview=payload_preview,
            error=str(exc),
        )
