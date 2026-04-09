"""
Email Header Security Analyzer
================================
Analyzes raw or parsed email headers for phishing and spoofing indicators:
SPF/DKIM/DMARC authentication results, From/Reply-To mismatches, suspicious
routing, lookalike display names, and encoding anomalies.

Operates on header dicts — no live DNS resolution required.

Check IDs
----------
EH-001   SPF authentication failed or missing
EH-002   DKIM authentication failed or missing
EH-003   DMARC authentication failed or missing
EH-004   From domain does not match Reply-To domain
EH-005   Display name impersonates known brand (lookalike name detection)
EH-006   Suspicious X-Mailer or User-Agent (mass mailer or phishing kit)
EH-007   Excessive or unusual hop count (>10 Received headers)
EH-008   From domain is recently registered or disposable (TLD signal)

Usage::

    from analyzers.email_header_analyzer import EmailHeaderAnalyzer, EmailHeaders

    headers = EmailHeaders(
        headers={
            "From": "PayPal Security <security@paypa1.com>",
            "Authentication-Results": "spf=fail; dkim=fail; dmarc=fail",
            "Reply-To": "hacker@evil.ru",
            "Received": ["hop1", "hop2", ..., "hop11"],
        }
    )
    analyzer = EmailHeaderAnalyzer()
    report = analyzer.analyze(headers)
    for finding in report.findings:
        print(finding.to_dict())
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


# ---------------------------------------------------------------------------
# Severity levels
# ---------------------------------------------------------------------------

class EHSeverity(Enum):
    """Severity classification for email header findings."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


# ---------------------------------------------------------------------------
# Known indicator data
# ---------------------------------------------------------------------------

# Display-name brand list used by EH-005
_BRAND_NAMES: List[str] = [
    "paypal",
    "amazon",
    "google",
    "microsoft",
    "apple",
    "netflix",
    "facebook",
    "instagram",
    "twitter",
    "bank",
    "irs",
    "fedex",
    "dhl",
    "ups",
    "chase",
    "wells fargo",
    "citibank",
]

# Substring patterns (lowercased) for suspicious sending software (EH-006)
_SUSPICIOUS_MAILERS: List[str] = [
    "phpmailer",
    "sendblaster",
    "atompark",
    "mailchimp",   # bulk sender — treated as MEDIUM
    "massmailer",
    "bulkmailer",
    "xmailer/hack",
    "emkei",
    "pepipost",
]

# TLDs commonly associated with disposable / free-registration domains (EH-008)
_DISPOSABLE_TLDS: set = {
    ".tk",
    ".ml",
    ".ga",
    ".cf",
    ".gq",
    ".xyz",
    ".top",
    ".click",
    ".link",
    ".online",
    ".site",
}

# Weight assigned to each check for risk-score calculation
_CHECK_WEIGHTS: Dict[str, int] = {
    "EH-001": 35,
    "EH-002": 30,
    "EH-003": 35,
    "EH-004": 30,
    "EH-005": 40,
    "EH-006": 20,
    "EH-007": 15,
    "EH-008": 25,
}


# ---------------------------------------------------------------------------
# Data containers
# ---------------------------------------------------------------------------

@dataclass
class EmailHeaders:
    """
    Thin wrapper around a raw header dict.

    The dict may store individual header values as plain strings or as a
    list of strings (e.g. multiple ``Received`` entries).  All key lookups
    are case-insensitive.
    """

    headers: Dict[str, Any]  # key → str | List[str]

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _normalised_key(self, key: str) -> Optional[str]:
        """Return the first dict key that matches *key* case-insensitively."""
        target = key.lower()
        for k in self.headers:
            if k.lower() == target:
                return k
        return None

    # ------------------------------------------------------------------
    # Public accessors
    # ------------------------------------------------------------------

    def get(self, key: str) -> Optional[str]:
        """
        Case-insensitive single-value lookup.

        If the stored value is a list the first element is returned.
        Returns ``None`` when the header is absent.
        """
        matched = self._normalised_key(key)
        if matched is None:
            return None
        value = self.headers[matched]
        if isinstance(value, list):
            return value[0] if value else None
        return str(value)

    def get_all(self, key: str) -> List[str]:
        """
        Case-insensitive multi-value lookup.

        Returns every value stored for *key*.  If the stored value is a
        plain string it is wrapped in a single-element list.  Returns an
        empty list when the header is absent.
        """
        matched = self._normalised_key(key)
        if matched is None:
            return []
        value = self.headers[matched]
        if isinstance(value, list):
            return [str(v) for v in value]
        return [str(value)]


@dataclass
class EHFinding:
    """
    A single security finding produced by one of the header checks.

    Attributes
    ----------
    check_id    : Identifier such as "EH-001".
    severity    : EHSeverity value.
    title       : Short human-readable label.
    detail      : Explanation of the specific issue found.
    evidence    : Raw header value or fragment that triggered the finding.
    remediation : Recommended corrective action.
    """

    check_id: str
    severity: EHSeverity
    title: str
    detail: str
    evidence: str = ""
    remediation: str = ""

    def summary(self) -> str:
        """Return a single-line summary string."""
        return f"[{self.severity.value}] {self.check_id}: {self.title}"

    def to_dict(self) -> Dict[str, Any]:
        """Serialise the finding to a plain dict."""
        return {
            "check_id": self.check_id,
            "severity": self.severity.value,
            "title": self.title,
            "detail": self.detail,
            "evidence": self.evidence,
            "remediation": self.remediation,
        }


@dataclass
class EHReport:
    """
    Aggregated result of analysing one set of email headers.

    Attributes
    ----------
    findings         : All EHFinding objects raised during analysis.
    risk_score       : Integer 0–100 representing aggregate risk.
    headers_analyzed : Number of distinct header keys examined.
    generated_at     : Unix timestamp of report creation.
    """

    findings: List[EHFinding]
    risk_score: int
    headers_analyzed: int
    generated_at: float

    # ------------------------------------------------------------------
    # Computed properties
    # ------------------------------------------------------------------

    @property
    def total_findings(self) -> int:
        """Total number of findings."""
        return len(self.findings)

    @property
    def critical_findings(self) -> int:
        """Number of CRITICAL severity findings."""
        return sum(1 for f in self.findings if f.severity == EHSeverity.CRITICAL)

    @property
    def high_findings(self) -> int:
        """Number of HIGH severity findings."""
        return sum(1 for f in self.findings if f.severity == EHSeverity.HIGH)

    # ------------------------------------------------------------------
    # Grouping helpers
    # ------------------------------------------------------------------

    def findings_by_check(self) -> Dict[str, List[EHFinding]]:
        """Return findings grouped by check_id."""
        result: Dict[str, List[EHFinding]] = {}
        for finding in self.findings:
            result.setdefault(finding.check_id, []).append(finding)
        return result

    # ------------------------------------------------------------------
    # Serialisation
    # ------------------------------------------------------------------

    def summary(self) -> str:
        """Return a multi-line human-readable summary."""
        lines = [
            f"EHReport — risk_score={self.risk_score}/100",
            f"  findings: {self.total_findings} "
            f"(critical={self.critical_findings}, high={self.high_findings})",
            f"  headers_analyzed: {self.headers_analyzed}",
        ]
        for f in self.findings:
            lines.append(f"  {f.summary()}")
        return "\n".join(lines)

    def to_dict(self) -> Dict[str, Any]:
        """Serialise the entire report to a plain dict."""
        return {
            "risk_score": self.risk_score,
            "headers_analyzed": self.headers_analyzed,
            "generated_at": self.generated_at,
            "total_findings": self.total_findings,
            "critical_findings": self.critical_findings,
            "high_findings": self.high_findings,
            "findings": [f.to_dict() for f in self.findings],
        }


# ---------------------------------------------------------------------------
# Analyser
# ---------------------------------------------------------------------------

class EmailHeaderAnalyzer:
    """
    Runs all EH-001 … EH-008 checks against an ``EmailHeaders`` instance.

    Parameters
    ----------
    known_brands : Optional list of lowercase brand strings to detect in
                   display names.  Defaults to ``_BRAND_NAMES``.
    max_hops     : Maximum number of ``Received`` headers before EH-007 fires.
                   Defaults to 10.
    """

    def __init__(
        self,
        known_brands: Optional[List[str]] = None,
        max_hops: int = 10,
    ) -> None:
        self._brands: List[str] = known_brands if known_brands is not None else _BRAND_NAMES
        self._max_hops: int = max_hops

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------

    def analyze(self, headers: EmailHeaders) -> EHReport:
        """
        Run all checks against *headers* and return an ``EHReport``.

        The risk score is the sum of weights for every unique check that
        fires, capped at 100.
        """
        findings: List[EHFinding] = []

        # Run each check; collect findings
        findings.extend(self._check_eh001_spf(headers))
        findings.extend(self._check_eh002_dkim(headers))
        findings.extend(self._check_eh003_dmarc(headers))
        findings.extend(self._check_eh004_reply_to_mismatch(headers))
        findings.extend(self._check_eh005_brand_display_name(headers))
        findings.extend(self._check_eh006_suspicious_mailer(headers))
        findings.extend(self._check_eh007_hop_count(headers))
        findings.extend(self._check_eh008_disposable_tld(headers))

        # Risk score: sum weights for unique check IDs, cap at 100
        fired_checks = {f.check_id for f in findings}
        raw_score = sum(_CHECK_WEIGHTS.get(cid, 0) for cid in fired_checks)
        risk_score = min(raw_score, 100)

        return EHReport(
            findings=findings,
            risk_score=risk_score,
            headers_analyzed=len(headers.headers),
            generated_at=time.time(),
        )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _extract_domain(header_value: str) -> str:
        """
        Extract the sending domain from a header value.

        Handles angle-bracket addresses (``Display Name <user@domain.tld>``)
        and bare addresses (``user@domain.tld``).  Returns an empty string
        when no valid address can be parsed.
        """
        # Try angle-bracket form first
        angle_match = re.search(r"<([^>]+)>", header_value)
        if angle_match:
            address = angle_match.group(1).strip()
        else:
            # Fall back to bare address
            bare_match = re.search(r"[\w.+-]+@[\w.-]+\.[a-zA-Z]{2,}", header_value)
            if bare_match:
                address = bare_match.group(0).strip()
            else:
                return ""

        # Extract domain part (everything after the last "@")
        if "@" in address:
            return address.split("@")[-1].lower()
        return ""

    @staticmethod
    def _parse_auth_value(auth_header: str, protocol: str) -> Optional[str]:
        """
        Extract the result token for *protocol* from an Authentication-Results
        header value.

        Example input:  ``"spf=pass; dkim=fail; dmarc=none"``
        For protocol    ``"dkim"`` this returns ``"fail"``.
        Returns ``None`` if the protocol token is not present.
        """
        # Match  protocol=result  where result is a single word
        pattern = re.compile(
            rf"\b{re.escape(protocol)}\s*=\s*([a-zA-Z]+)",
            re.IGNORECASE,
        )
        match = pattern.search(auth_header)
        if match:
            return match.group(1).lower()
        return None

    # ------------------------------------------------------------------
    # Individual checks
    # ------------------------------------------------------------------

    def _check_eh001_spf(self, headers: EmailHeaders) -> List[EHFinding]:
        """EH-001 — SPF authentication failed or missing."""
        auth = headers.get("Authentication-Results")
        if auth is None:
            # Header entirely absent — treat as MEDIUM (cannot confirm SPF)
            return [
                EHFinding(
                    check_id="EH-001",
                    severity=EHSeverity.MEDIUM,
                    title="SPF authentication result missing",
                    detail=(
                        "No Authentication-Results header found. "
                        "SPF verification status cannot be confirmed."
                    ),
                    evidence="(header absent)",
                    remediation=(
                        "Ensure receiving MTA adds Authentication-Results and "
                        "that the sending domain publishes a valid SPF record."
                    ),
                )
            ]

        spf_result = self._parse_auth_value(auth, "spf")
        if spf_result is None:
            # Header present but no SPF token — treat as MEDIUM
            return [
                EHFinding(
                    check_id="EH-001",
                    severity=EHSeverity.MEDIUM,
                    title="SPF result absent from Authentication-Results",
                    detail="Authentication-Results header contains no SPF result.",
                    evidence=auth,
                    remediation=(
                        "Verify the sending domain has a published SPF record and "
                        "that the receiving MTA evaluates SPF."
                    ),
                )
            ]

        if spf_result in ("fail", "softfail", "none"):
            severity = EHSeverity.HIGH if spf_result == "fail" else EHSeverity.MEDIUM
            return [
                EHFinding(
                    check_id="EH-001",
                    severity=severity,
                    title=f"SPF authentication {spf_result}",
                    detail=(
                        f"SPF result is '{spf_result}', indicating the sending server "
                        "is not authorised to send on behalf of the claimed domain."
                    ),
                    evidence=auth,
                    remediation=(
                        "Verify the sender's SPF record includes all legitimate sending "
                        "servers.  Reject or quarantine messages with spf=fail."
                    ),
                )
            ]

        return []

    def _check_eh002_dkim(self, headers: EmailHeaders) -> List[EHFinding]:
        """EH-002 — DKIM authentication failed or missing."""
        auth = headers.get("Authentication-Results")
        if auth is None:
            return [
                EHFinding(
                    check_id="EH-002",
                    severity=EHSeverity.MEDIUM,
                    title="DKIM authentication result missing",
                    detail=(
                        "No Authentication-Results header found. "
                        "DKIM verification status cannot be confirmed."
                    ),
                    evidence="(header absent)",
                    remediation=(
                        "Ensure the sending domain publishes a DKIM public key and "
                        "that the sending MTA signs outbound messages."
                    ),
                )
            ]

        dkim_result = self._parse_auth_value(auth, "dkim")
        if dkim_result is None:
            return [
                EHFinding(
                    check_id="EH-002",
                    severity=EHSeverity.MEDIUM,
                    title="DKIM result absent from Authentication-Results",
                    detail="Authentication-Results header contains no DKIM result.",
                    evidence=auth,
                    remediation=(
                        "Confirm the sending domain has DKIM configured and that the "
                        "receiving MTA validates DKIM signatures."
                    ),
                )
            ]

        if dkim_result in ("fail", "none"):
            severity = EHSeverity.HIGH if dkim_result == "fail" else EHSeverity.MEDIUM
            return [
                EHFinding(
                    check_id="EH-002",
                    severity=severity,
                    title=f"DKIM authentication {dkim_result}",
                    detail=(
                        f"DKIM result is '{dkim_result}', suggesting the message body "
                        "or headers may have been tampered with, or no signature exists."
                    ),
                    evidence=auth,
                    remediation=(
                        "Ensure outbound mail is signed with a valid DKIM key and that "
                        "the private key has not been compromised."
                    ),
                )
            ]

        return []

    def _check_eh003_dmarc(self, headers: EmailHeaders) -> List[EHFinding]:
        """EH-003 — DMARC authentication failed or missing."""
        auth = headers.get("Authentication-Results")
        if auth is None:
            return [
                EHFinding(
                    check_id="EH-003",
                    severity=EHSeverity.MEDIUM,
                    title="DMARC authentication result missing",
                    detail=(
                        "No Authentication-Results header found. "
                        "DMARC policy enforcement cannot be confirmed."
                    ),
                    evidence="(header absent)",
                    remediation=(
                        "Publish a DMARC record for the sending domain and configure "
                        "a policy of 'quarantine' or 'reject'."
                    ),
                )
            ]

        dmarc_result = self._parse_auth_value(auth, "dmarc")
        if dmarc_result is None:
            return [
                EHFinding(
                    check_id="EH-003",
                    severity=EHSeverity.MEDIUM,
                    title="DMARC result absent from Authentication-Results",
                    detail="Authentication-Results header contains no DMARC result.",
                    evidence=auth,
                    remediation=(
                        "Verify the sending domain has a valid DMARC DNS record and "
                        "that the receiving MTA evaluates DMARC."
                    ),
                )
            ]

        if dmarc_result in ("fail", "none"):
            severity = EHSeverity.HIGH if dmarc_result == "fail" else EHSeverity.MEDIUM
            return [
                EHFinding(
                    check_id="EH-003",
                    severity=severity,
                    title=f"DMARC authentication {dmarc_result}",
                    detail=(
                        f"DMARC result is '{dmarc_result}'. The message does not align "
                        "with the domain owner's published authentication policy."
                    ),
                    evidence=auth,
                    remediation=(
                        "Publish a DMARC policy of 'reject' for the sending domain and "
                        "ensure SPF and DKIM are correctly configured."
                    ),
                )
            ]

        return []

    def _check_eh004_reply_to_mismatch(self, headers: EmailHeaders) -> List[EHFinding]:
        """EH-004 — From domain does not match Reply-To domain."""
        from_header = headers.get("From")
        reply_to_header = headers.get("Reply-To")

        if not from_header or not reply_to_header:
            return []

        from_domain = self._extract_domain(from_header)
        reply_to_domain = self._extract_domain(reply_to_header)

        if not from_domain or not reply_to_domain:
            return []

        if from_domain != reply_to_domain:
            return [
                EHFinding(
                    check_id="EH-004",
                    severity=EHSeverity.HIGH,
                    title="From/Reply-To domain mismatch",
                    detail=(
                        f"The From domain '{from_domain}' differs from the Reply-To "
                        f"domain '{reply_to_domain}'.  Replies will be redirected to a "
                        "domain not affiliated with the claimed sender."
                    ),
                    evidence=f"From: {from_header}  |  Reply-To: {reply_to_header}",
                    remediation=(
                        "Treat messages where Reply-To redirects to an unrelated domain "
                        "with heightened suspicion.  Do not reply without verifying the "
                        "sender out-of-band."
                    ),
                )
            ]

        return []

    def _check_eh005_brand_display_name(self, headers: EmailHeaders) -> List[EHFinding]:
        """EH-005 — Display name impersonates a known brand."""
        from_header = headers.get("From")
        if not from_header:
            return []

        # Extract display name — text before the opening angle bracket
        angle_pos = from_header.find("<")
        if angle_pos > 0:
            display_name = from_header[:angle_pos].strip().strip('"').lower()
        else:
            # No angle bracket; the whole value may be the display name
            # Only consider it if there is no @ sign (i.e. not a bare address)
            if "@" in from_header:
                display_name = ""
            else:
                display_name = from_header.strip().lower()

        if not display_name:
            return []

        for brand in self._brands:
            if brand in display_name:
                return [
                    EHFinding(
                        check_id="EH-005",
                        severity=EHSeverity.CRITICAL,
                        title="Display name impersonates known brand",
                        detail=(
                            f"The From display name '{display_name}' contains the brand "
                            f"keyword '{brand}'.  This is a common phishing tactic to "
                            "trick recipients into trusting the message."
                        ),
                        evidence=from_header,
                        remediation=(
                            "Do not trust the display name alone.  Inspect the actual "
                            "sending address and verify it belongs to the claimed brand's "
                            "official domain."
                        ),
                    )
                ]

        return []

    def _check_eh006_suspicious_mailer(self, headers: EmailHeaders) -> List[EHFinding]:
        """EH-006 — Suspicious X-Mailer or User-Agent header."""
        findings: List[EHFinding] = []

        for header_name in ("X-Mailer", "User-Agent"):
            value = headers.get(header_name)
            if not value:
                continue
            value_lower = value.lower()
            for pattern in _SUSPICIOUS_MAILERS:
                if pattern in value_lower:
                    findings.append(
                        EHFinding(
                            check_id="EH-006",
                            severity=EHSeverity.MEDIUM,
                            title=f"Suspicious sending software detected in {header_name}",
                            detail=(
                                f"The {header_name} value '{value}' matches the known "
                                f"bulk-mailer or phishing-kit pattern '{pattern}'."
                            ),
                            evidence=f"{header_name}: {value}",
                            remediation=(
                                "Investigate whether the message originated from a "
                                "legitimate bulk-send campaign or a compromised / "
                                "malicious sending infrastructure."
                            ),
                        )
                    )
                    # One finding per header is sufficient
                    break

        return findings

    def _check_eh007_hop_count(self, headers: EmailHeaders) -> List[EHFinding]:
        """EH-007 — Excessive hop count (more than max_hops Received headers)."""
        received = headers.get_all("Received")
        hop_count = len(received)

        if hop_count > self._max_hops:
            return [
                EHFinding(
                    check_id="EH-007",
                    severity=EHSeverity.LOW,
                    title="Excessive email hop count",
                    detail=(
                        f"The message passed through {hop_count} mail servers "
                        f"(threshold: {self._max_hops}).  An unusually long routing path "
                        "can indicate message laundering or obfuscation."
                    ),
                    evidence=f"Received header count: {hop_count}",
                    remediation=(
                        "Review the routing path for unexpected intermediate servers or "
                        "open relays.  Cross-reference with the sending domain's "
                        "authorised mail infrastructure."
                    ),
                )
            ]

        return []

    def _check_eh008_disposable_tld(self, headers: EmailHeaders) -> List[EHFinding]:
        """EH-008 — From domain uses a disposable or suspicious TLD."""
        from_header = headers.get("From")
        if not from_header:
            return []

        domain = self._extract_domain(from_header)
        if not domain:
            return []

        # TLD is everything from the last "." onward
        dot_pos = domain.rfind(".")
        if dot_pos == -1:
            return []

        tld = domain[dot_pos:]  # includes the leading dot, e.g. ".tk"

        if tld in _DISPOSABLE_TLDS:
            return [
                EHFinding(
                    check_id="EH-008",
                    severity=EHSeverity.MEDIUM,
                    title="From domain uses a disposable or high-risk TLD",
                    detail=(
                        f"The sending domain '{domain}' uses the TLD '{tld}' which is "
                        "commonly associated with free, anonymous, or disposable domain "
                        "registrations often abused in phishing campaigns."
                    ),
                    evidence=f"From domain: {domain}",
                    remediation=(
                        "Treat messages from disposable-TLD domains with elevated "
                        "suspicion.  Consider rejecting or quarantining such messages "
                        "depending on your organisation's risk appetite."
                    ),
                )
            ]

        return []
