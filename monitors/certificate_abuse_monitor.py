# certificate_abuse_monitor.py — TLS/SSL certificate abuse monitor for brand protection
#
# Analyzes certificate metadata for suspicious or abusive configurations.
# Offline analysis only — no live TLS connections are made.
# Part of the Cyber Port phishing-surface-monitor project.
#
# Copyright 2024 Hiago Kin Levi
# Licensed under the Creative Commons Attribution 4.0 International (CC BY 4.0)
# https://creativecommons.org/licenses/by/4.0/
#
# SPDX-License-Identifier: CC-BY-4.0

from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional

# ---------------------------------------------------------------------------
# Check registry — maps check ID → weight used when computing risk_score.
# risk_score = min(100, sum of weights for all unique fired check IDs)
# ---------------------------------------------------------------------------
_CHECK_WEIGHTS: Dict[str, int] = {
    "CERT-ABU-001": 25,  # Certificate issued for suspicious domain variant
    "CERT-ABU-002": 20,  # Wildcard certificate covering brand keyword domain
    "CERT-ABU-003": 20,  # Certificate from untrusted/unknown CA
    "CERT-ABU-004": 15,  # Certificate expired
    "CERT-ABU-005": 15,  # Excessive SAN count (mass-issuance pattern)
    "CERT-ABU-006": 25,  # Self-signed certificate
    "CERT-ABU-007": 15,  # Certificate validity period too long
}

# ---------------------------------------------------------------------------
# Well-known trusted certificate authorities (case-insensitive substring match)
# ---------------------------------------------------------------------------
_DEFAULT_TRUSTED_CAS: List[str] = [
    "Let's Encrypt",
    "DigiCert",
    "Sectigo",
    "GlobalSign",
    "Entrust",
    "Amazon",
    "Google Trust Services",
    "Microsoft",
    "Comodo",
    "GoDaddy",
    "IdenTrust",
    "Actalis",
    "Buypass",
    "ZeroSSL",
    "ISRG Root",
]

# Action words that — when appearing alongside a brand keyword in a hostname —
# indicate a phishing / brand-abuse pattern rather than a legitimate domain.
_PHISHING_ACTION_WORDS: List[str] = [
    "login",
    "secure",
    "verify",
    "update",
    "account",
    "signin",
    "portal",
    "support",
    "helpdesk",
]


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


@dataclass
class CertificateInfo:
    """Parsed metadata from a TLS/SSL certificate (no live connection required)."""

    # CN field from the Subject distinguished name
    common_name: str

    # Subject Alternative Names — list of hostnames covered by the cert
    subject_alt_names: List[str]

    # Full CA name as it appears in the Issuer field, e.g. "Let's Encrypt"
    issuer_name: str

    # True when Subject == Issuer (self-signed)
    is_self_signed: bool = False

    # Validity window as Unix timestamps (seconds since epoch)
    not_before: float = 0.0
    not_after: float = 0.0

    # Hex or decimal serial number string; None if unavailable
    serial_number: Optional[str] = None

    # e.g. "sha256WithRSAEncryption", "ecdsa-with-SHA256"
    signature_algorithm: str = "sha256WithRSAEncryption"

    # RSA/DSA key size in bits; None for EC keys or when unavailable
    key_size_bits: Optional[int] = None

    def to_dict(self) -> Dict:
        """Serialize to a plain dictionary (JSON-safe types)."""
        return {
            "common_name": self.common_name,
            "subject_alt_names": list(self.subject_alt_names),
            "issuer_name": self.issuer_name,
            "is_self_signed": self.is_self_signed,
            "not_before": self.not_before,
            "not_after": self.not_after,
            "serial_number": self.serial_number,
            "signature_algorithm": self.signature_algorithm,
            "key_size_bits": self.key_size_bits,
        }


@dataclass
class CertAbuseFinding:
    """A single abuse-check finding raised against a certificate."""

    # Structured identifier matching a key in _CHECK_WEIGHTS
    check_id: str

    # "HIGH" | "MEDIUM" | "LOW"
    severity: str

    # CN of the certificate that triggered the finding
    common_name: str

    # Issuer field of the certificate
    issuer_name: str

    # Human-readable explanation of what was detected
    message: str

    # Actionable remediation guidance
    recommendation: str

    def to_dict(self) -> Dict:
        """Serialize to a plain dictionary."""
        return {
            "check_id": self.check_id,
            "severity": self.severity,
            "common_name": self.common_name,
            "issuer_name": self.issuer_name,
            "message": self.message,
            "recommendation": self.recommendation,
        }


@dataclass
class CertAbuseResult:
    """Aggregated analysis result for a single CertificateInfo."""

    # All findings raised for this certificate (may be empty)
    findings: List[CertAbuseFinding] = field(default_factory=list)

    # Composite risk score in [0, 100]; computed from _CHECK_WEIGHTS
    risk_score: int = 0

    def summary(self) -> str:
        """One-line human-readable summary of the analysis result."""
        if not self.findings:
            return f"No abuse findings detected. Risk score: {self.risk_score}/100."
        severities = [f.severity for f in self.findings]
        high = severities.count("HIGH")
        medium = severities.count("MEDIUM")
        low = severities.count("LOW")
        parts: List[str] = []
        if high:
            parts.append(f"{high} HIGH")
        if medium:
            parts.append(f"{medium} MEDIUM")
        if low:
            parts.append(f"{low} LOW")
        return (
            f"{len(self.findings)} finding(s) detected "
            f"({', '.join(parts)}). Risk score: {self.risk_score}/100."
        )

    def by_severity(self) -> Dict[str, List[CertAbuseFinding]]:
        """Group findings by severity label for easy downstream filtering."""
        groups: Dict[str, List[CertAbuseFinding]] = {
            "HIGH": [],
            "MEDIUM": [],
            "LOW": [],
        }
        for finding in self.findings:
            # Guard against unexpected severity values
            bucket = finding.severity if finding.severity in groups else "LOW"
            groups[bucket].append(finding)
        return groups

    def to_dict(self) -> Dict:
        """Serialize the full result to a nested dictionary."""
        return {
            "findings": [f.to_dict() for f in self.findings],
            "risk_score": self.risk_score,
            "summary": self.summary(),
            "by_severity": {
                sev: [f.to_dict() for f in items]
                for sev, items in self.by_severity().items()
            },
        }


# ---------------------------------------------------------------------------
# Monitor
# ---------------------------------------------------------------------------


class CertificateAbuseMonitor:
    """
    Analyzes TLS/SSL certificate metadata for brand-abuse indicators.

    All checks are performed offline against the CertificateInfo fields;
    no network connections are ever opened.

    Parameters
    ----------
    brand_keywords:
        One or more brand strings to look for inside hostnames
        (case-insensitive substring matching).
    trusted_cas:
        Allowlist of CA name fragments.  Defaults to _DEFAULT_TRUSTED_CAS.
    max_validity_days:
        Maximum acceptable certificate lifetime in days.  Defaults to 398
        (the post-2020 browser-enforced limit).
    """

    def __init__(
        self,
        brand_keywords: List[str],
        trusted_cas: Optional[List[str]] = None,
        max_validity_days: int = 398,
    ) -> None:
        # Store lower-cased copies so every comparison is O(n) string scan
        self._brand_keywords: List[str] = [k.lower() for k in brand_keywords]
        self._trusted_cas: List[str] = (
            [ca.lower() for ca in trusted_cas]
            if trusted_cas is not None
            else [ca.lower() for ca in _DEFAULT_TRUSTED_CAS]
        )
        self._max_validity_days: int = max_validity_days

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def analyze(self, cert: CertificateInfo) -> CertAbuseResult:
        """Run all abuse checks against a single certificate."""
        findings: List[CertAbuseFinding] = []

        # Each check appends to `findings` if it fires.
        self._check_suspicious_domain(cert, findings)
        self._check_wildcard_brand(cert, findings)
        self._check_untrusted_ca(cert, findings)
        self._check_expired(cert, findings)
        self._check_excessive_sans(cert, findings)
        self._check_self_signed(cert, findings)
        self._check_validity_too_long(cert, findings)

        # risk_score: sum weights for unique check IDs that fired, capped at 100
        fired_ids = {f.check_id for f in findings}
        risk_score = min(100, sum(_CHECK_WEIGHTS.get(cid, 0) for cid in fired_ids))

        return CertAbuseResult(findings=findings, risk_score=risk_score)

    def analyze_many(self, certs: List[CertificateInfo]) -> List[CertAbuseResult]:
        """Run analyze() over a list of certificates and return one result per cert."""
        return [self.analyze(cert) for cert in certs]

    # ------------------------------------------------------------------
    # Internal check helpers
    # ------------------------------------------------------------------

    def _all_names(self, cert: CertificateInfo) -> List[str]:
        """Return CN + all SANs as a single list (lower-cased)."""
        names = [cert.common_name.lower()] + [s.lower() for s in cert.subject_alt_names]
        return names

    def _hostname_contains_brand(self, hostname: str) -> bool:
        """Return True if any brand keyword appears in *hostname* (lower-cased)."""
        return any(kw in hostname for kw in self._brand_keywords)

    def _is_suspicious_brand_hostname(self, hostname: str) -> bool:
        """
        Return True when *hostname* contains a brand keyword AND also shows
        phishing intent — indicated by the presence of an action word or by
        the brand keyword appearing between hyphens/dots with other words.

        Legitimate examples that must NOT fire:
            paypal.com        — only the TLD is different; no action word present
            google.com        — same

        Suspicious examples that MUST fire:
            paypal-login.com      — action word "login"
            secure-paypal.com     — action word "secure"
            paypal-secure.com     — action word "secure"
            login.paypal-id.net   — action word "login" AND brand between separators
        """
        h = hostname.lower()

        if not self._hostname_contains_brand(h):
            return False

        # Strip leading wildcard so "*.paypal-login.com" is handled like
        # "paypal-login.com" in this check (CERT-ABU-001, not CERT-ABU-002)
        if h.startswith("*."):
            h = h[2:]

        # Check 1: an action word appears anywhere in the hostname
        for action in _PHISHING_ACTION_WORDS:
            if action in h:
                return True

        # Check 2: brand keyword appears between word-separators (hyphens or dots)
        # alongside at least one other word — e.g. "brand-word.tld" or "word.brand.tld"
        # We split on hyphens and dots and verify the brand keyword is one token
        # among multiple tokens (which means extra words are present).
        for kw in self._brand_keywords:
            if kw in h:
                # Split the hostname (strip TLD heuristically by dropping last segment)
                tokens = re.split(r"[-.]", h)
                # Filter to non-empty tokens
                tokens = [t for t in tokens if t]
                # If the brand keyword appears as a token AND there are other tokens,
                # the cert is for a brand-lookalike domain structure.
                if any(t == kw for t in tokens) and len(tokens) > 2:
                    return True
                # Also flag when the brand keyword is an infix token (surrounded by
                # hyphens/dots) even if it is a substring of a token:
                # e.g. "mypaypalaccount.com" → token "mypaypalaccount" contains kw
                # but we already handled action words above; here handle structural
                # cases like "paypal-id.com" → tokens ["paypal","id","com"]
                # len > 2 is already checked above; this branch handles when the
                # keyword is a pure substring inside a compound token.
                for token in tokens:
                    if token != kw and kw in token:
                        # The brand is embedded inside a longer token — suspicious
                        return True

        return False

    def _check_suspicious_domain(
        self, cert: CertificateInfo, findings: List[CertAbuseFinding]
    ) -> None:
        """CERT-ABU-001: Certificate issued for suspicious brand-impersonation domain."""
        triggered_names: List[str] = []

        for name in self._all_names(cert):
            if self._is_suspicious_brand_hostname(name):
                triggered_names.append(name)

        if not triggered_names:
            return

        names_str = ", ".join(triggered_names[:5])  # cap display at 5 entries
        findings.append(
            CertAbuseFinding(
                check_id="CERT-ABU-001",
                severity="HIGH",
                common_name=cert.common_name,
                issuer_name=cert.issuer_name,
                message=(
                    f"Certificate covers suspicious brand-impersonation hostname(s): "
                    f"{names_str}"
                ),
                recommendation=(
                    "Submit a certificate abuse report to the issuing CA and request "
                    "revocation.  Monitor CT logs for further issuances to similar domains."
                ),
            )
        )

    def _check_wildcard_brand(
        self, cert: CertificateInfo, findings: List[CertAbuseFinding]
    ) -> None:
        """CERT-ABU-002: Wildcard certificate whose domain contains a brand keyword."""
        triggered: List[str] = []

        for name in self._all_names(cert):
            # Must start with wildcard marker
            if not name.startswith("*."):
                continue
            # The part after "*." is the actual domain — check for brand keywords
            domain_part = name[2:]
            if self._hostname_contains_brand(domain_part):
                triggered.append(name)

        if not triggered:
            return

        findings.append(
            CertAbuseFinding(
                check_id="CERT-ABU-002",
                severity="HIGH",
                common_name=cert.common_name,
                issuer_name=cert.issuer_name,
                message=(
                    f"Wildcard certificate covers brand keyword domain(s): "
                    f"{', '.join(triggered)}"
                ),
                recommendation=(
                    "File a CA/B Forum complaint and a UDRP/URS domain dispute.  "
                    "Alert your brand-protection team immediately."
                ),
            )
        )

    def _check_untrusted_ca(
        self, cert: CertificateInfo, findings: List[CertAbuseFinding]
    ) -> None:
        """CERT-ABU-003: Certificate issued by an untrusted or unknown CA."""
        # Self-signed certs are handled by CERT-ABU-006; exclude them here to
        # avoid double-counting the same structural problem.
        if cert.is_self_signed:
            return

        issuer_lower = cert.issuer_name.lower()
        for trusted in self._trusted_cas:
            if trusted in issuer_lower:
                return  # matched a trusted CA — not suspicious

        findings.append(
            CertAbuseFinding(
                check_id="CERT-ABU-003",
                severity="HIGH",
                common_name=cert.common_name,
                issuer_name=cert.issuer_name,
                message=(
                    f"Certificate was issued by an unrecognized CA: '{cert.issuer_name}'.  "
                    f"It does not match any entry in the trusted CA list."
                ),
                recommendation=(
                    "Verify the CA's legitimacy and root program membership.  "
                    "Treat the certificate as untrusted until the issuer is confirmed."
                ),
            )
        )

    def _check_expired(
        self, cert: CertificateInfo, findings: List[CertAbuseFinding]
    ) -> None:
        """CERT-ABU-004: Certificate has passed its not_after expiry timestamp."""
        now = time.time()
        if now <= cert.not_after:
            return

        expiry_delta = int((now - cert.not_after) / 86400)
        findings.append(
            CertAbuseFinding(
                check_id="CERT-ABU-004",
                severity="MEDIUM",
                common_name=cert.common_name,
                issuer_name=cert.issuer_name,
                message=(
                    f"Certificate expired approximately {expiry_delta} day(s) ago "
                    f"(not_after={cert.not_after:.0f})."
                ),
                recommendation=(
                    "An expired certificate is still detectable in CT logs and may "
                    "indicate abandoned phishing infrastructure.  Document and report."
                ),
            )
        )

    def _check_excessive_sans(
        self, cert: CertificateInfo, findings: List[CertAbuseFinding]
    ) -> None:
        """CERT-ABU-005: Certificate carries more than 50 Subject Alternative Names."""
        count = len(cert.subject_alt_names)
        if count <= 50:
            return

        findings.append(
            CertAbuseFinding(
                check_id="CERT-ABU-005",
                severity="MEDIUM",
                common_name=cert.common_name,
                issuer_name=cert.issuer_name,
                message=(
                    f"Certificate contains {count} SAN entries, exceeding the "
                    f"50-entry threshold.  This pattern is typical of bulk-issuance "
                    f"phishing infrastructure."
                ),
                recommendation=(
                    "Cross-reference all SAN entries against known brand assets.  "
                    "Report bulk-issuance abuse to the CA."
                ),
            )
        )

    def _check_self_signed(
        self, cert: CertificateInfo, findings: List[CertAbuseFinding]
    ) -> None:
        """CERT-ABU-006: Certificate is self-signed (not issued by a public CA)."""
        if not cert.is_self_signed:
            return

        findings.append(
            CertAbuseFinding(
                check_id="CERT-ABU-006",
                severity="HIGH",
                common_name=cert.common_name,
                issuer_name=cert.issuer_name,
                message=(
                    "Certificate is self-signed.  Browsers do not trust self-signed "
                    "certificates; they are commonly used in malware C2 and phishing kits."
                ),
                recommendation=(
                    "Correlate the CN/IP with threat-intelligence feeds.  "
                    "Block at the perimeter and report to your SIEM/SOC."
                ),
            )
        )

    def _check_validity_too_long(
        self, cert: CertificateInfo, findings: List[CertAbuseFinding]
    ) -> None:
        """CERT-ABU-007: Certificate validity window exceeds the configured maximum."""
        validity_seconds = cert.not_after - cert.not_before
        max_seconds = self._max_validity_days * 86400

        if validity_seconds <= max_seconds:
            return

        actual_days = int(validity_seconds / 86400)
        findings.append(
            CertAbuseFinding(
                check_id="CERT-ABU-007",
                severity="MEDIUM",
                common_name=cert.common_name,
                issuer_name=cert.issuer_name,
                message=(
                    f"Certificate validity period is {actual_days} day(s), which "
                    f"exceeds the {self._max_validity_days}-day recommended maximum.  "
                    f"Long-lived certificates evade short-rotation revocation windows."
                ),
                recommendation=(
                    "Flag the issuing CA for non-compliance.  "
                    "Prefer certificates with 90-day or shorter lifetimes for brand domains."
                ),
            )
        )
