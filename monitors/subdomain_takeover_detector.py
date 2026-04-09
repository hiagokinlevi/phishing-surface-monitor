# subdomain_takeover_detector.py
# Subdomain takeover vulnerability detector.
# Analyzes DNS record configurations for takeover-vulnerable patterns.
# Offline analysis only — no live DNS queries are performed.
#
# Copyright (c) 2026 Cyber Port
# Licensed under Creative Commons Attribution 4.0 International (CC BY 4.0)
# https://creativecommons.org/licenses/by/4.0/
#
# SPDX-License-Identifier: CC-BY-4.0

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional

# ---------------------------------------------------------------------------
# Known vulnerable CNAME target patterns → cloud/SaaS service names.
# These services may allow unclaimed subdomain registration, making a
# dangling CNAME (has_response=False) an immediate takeover opportunity.
# ---------------------------------------------------------------------------
_VULNERABLE_SERVICES: Dict[str, str] = {
    "github.io": "GitHub Pages",
    "s3.amazonaws.com": "AWS S3",
    "s3-website": "AWS S3 Website",
    "cloudfront.net": "AWS CloudFront",
    "azurewebsites.net": "Azure Web Apps",
    "azurefd.net": "Azure Front Door",
    "blob.core.windows.net": "Azure Blob Storage",
    "trafficmanager.net": "Azure Traffic Manager",
    "storage.googleapis.com": "Google Cloud Storage",
    "c.storage.googleapis.com": "Google Cloud Storage",
    "appspot.com": "Google App Engine",
    "firebaseapp.com": "Firebase",
    "heroku.com": "Heroku",
    "herokuapp.com": "Heroku",
    "zendesk.com": "Zendesk",
    "helpscoutdocs.com": "HelpScout",
    "readme.io": "Readme.io",
    "ghost.io": "Ghost",
    "myshopify.com": "Shopify",
    "statuspage.io": "StatusPage",
    "unbouncepages.com": "Unbounce",
    "surge.sh": "Surge",
    "netlify.com": "Netlify",
    "netlify.app": "Netlify",
    "vercel.app": "Vercel",
}

# ---------------------------------------------------------------------------
# Check weights used to compute risk_score.
# risk_score = min(100, sum of weights for unique check IDs fired in a scan).
# ---------------------------------------------------------------------------
_CHECK_WEIGHTS: Dict[str, int] = {
    "STKO-001": 45,  # CNAME → vulnerable service, no response (dangling)
    "STKO-002": 25,  # CNAME → vulnerable service, currently responding
    "STKO-003": 25,  # NS delegation with no response (zone takeover)
    "STKO-004": 25,  # Dangling A/AAAA record
    "STKO-005": 15,  # CNAME chain depth >= 3
    "STKO-006": 15,  # Cloud provider ephemeral IP in A/AAAA record
    "STKO-007": 15,  # Suspicious dev/staging subdomain pointing to cloud
}

# Development/staging subdomain keyword patterns flagged by STKO-007.
_STAGING_KEYWORDS: List[str] = [
    "dev", "test", "staging", "uat", "demo",
    "beta", "preview", "sandbox",
]

# Cloud provider IP prefix patterns flagged by STKO-006 (common elastic/ephemeral ranges).
_CLOUD_IP_PREFIXES: List[str] = [
    # AWS common elastic IPs
    "52.", "54.", "3.",
    # Azure
    "104.", "40.", "20.",
    # GCP
    "34.", "35.",
]


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class SubdomainRecord:
    """Represents a single DNS record for a subdomain."""

    subdomain: str          # Full subdomain, e.g. "dev.example.com"
    record_type: str        # "A", "AAAA", "CNAME", "NS", "MX"
    value: str              # Record value (IP, CNAME target, nameserver, …)
    ttl: int = 300
    has_response: bool = True  # False = DNS record exists but target doesn't respond

    def to_dict(self) -> Dict:
        """Serialize to a plain dictionary."""
        return {
            "subdomain": self.subdomain,
            "record_type": self.record_type,
            "value": self.value,
            "ttl": self.ttl,
            "has_response": self.has_response,
        }


@dataclass
class TakeoverFinding:
    """A single detected vulnerability finding."""

    check_id: str                        # e.g. "STKO-001"
    severity: str                        # "CRITICAL", "HIGH", "MEDIUM"
    subdomain: str                       # Affected subdomain
    record_type: str                     # DNS record type involved
    message: str                         # Human-readable description
    recommendation: str                  # Remediation guidance
    cname_target: Optional[str] = None   # CNAME value, when applicable
    service_name: Optional[str] = None   # Resolved cloud/SaaS service name

    def to_dict(self) -> Dict:
        """Serialize to a plain dictionary."""
        return {
            "check_id": self.check_id,
            "severity": self.severity,
            "subdomain": self.subdomain,
            "record_type": self.record_type,
            "cname_target": self.cname_target,
            "service_name": self.service_name,
            "message": self.message,
            "recommendation": self.recommendation,
        }


@dataclass
class TakeoverScanResult:
    """Aggregated result of scanning a set of SubdomainRecords."""

    findings: List[TakeoverFinding] = field(default_factory=list)
    risk_score: int = 0  # 0–100 composite risk score

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def summary(self) -> str:
        """Return a one-line human-readable summary of the scan result."""
        total = len(self.findings)
        if total == 0:
            return "No subdomain takeover vulnerabilities detected. Risk score: 0/100."
        counts = self.by_severity()
        parts: List[str] = []
        for severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            n = counts.get(severity, 0)
            if n:
                parts.append(f"{n} {severity}")
        detail = ", ".join(parts)
        return (
            f"{total} finding(s) detected ({detail}). "
            f"Risk score: {self.risk_score}/100."
        )

    def by_severity(self) -> Dict[str, List[TakeoverFinding]]:
        """Return findings grouped by severity label."""
        grouped: Dict[str, List[TakeoverFinding]] = {}
        for finding in self.findings:
            grouped.setdefault(finding.severity, []).append(finding)
        return grouped

    def to_dict(self) -> Dict:
        """Serialize to a plain dictionary."""
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
# Detector
# ---------------------------------------------------------------------------

class SubdomainTakeoverDetector:
    """
    Offline subdomain takeover vulnerability detector.

    All analysis is performed against the supplied SubdomainRecord data;
    no live DNS lookups are made.
    """

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def scan(self, records: List[SubdomainRecord]) -> TakeoverScanResult:
        """
        Scan a list of SubdomainRecord objects and return a TakeoverScanResult.

        Runs all seven checks (STKO-001 through STKO-007) and computes the
        composite risk_score from the unique check IDs that fired.
        """
        findings: List[TakeoverFinding] = []

        # Run per-record checks
        for record in records:
            findings.extend(self._check_stko_001(record))
            findings.extend(self._check_stko_002(record))
            findings.extend(self._check_stko_003(record))
            findings.extend(self._check_stko_004(record))
            findings.extend(self._check_stko_006(record))
            findings.extend(self._check_stko_007(record))

        # Run list-level checks (needs full record set)
        findings.extend(self._check_stko_005(records))

        # Compute risk score from unique fired check IDs
        fired_ids = {f.check_id for f in findings}
        risk_score = min(100, sum(_CHECK_WEIGHTS[cid] for cid in fired_ids))

        return TakeoverScanResult(findings=findings, risk_score=risk_score)

    def scan_many(
        self, record_lists: List[List[SubdomainRecord]]
    ) -> List[TakeoverScanResult]:
        """
        Scan multiple independent record lists and return one result per list.

        Useful for batch analysis of different domains or zones.
        """
        return [self.scan(records) for records in record_lists]

    # ------------------------------------------------------------------
    # Check implementations
    # ------------------------------------------------------------------

    @staticmethod
    def _match_vulnerable_service(value: str) -> Optional[str]:
        """
        Return the first matching service name if *value* contains a key
        from _VULNERABLE_SERVICES, else None.
        """
        for pattern, service in _VULNERABLE_SERVICES.items():
            if pattern in value:
                return service
        return None

    def _check_stko_001(self, record: SubdomainRecord) -> List[TakeoverFinding]:
        """
        STKO-001: CNAME pointing to a known vulnerable service with no response.
        Severity: CRITICAL. Weight: 45.
        """
        if record.record_type != "CNAME":
            return []
        if record.has_response:
            return []  # Responding — handled by STKO-002 instead

        service = self._match_vulnerable_service(record.value)
        if service is None:
            return []

        return [TakeoverFinding(
            check_id="STKO-001",
            severity="CRITICAL",
            subdomain=record.subdomain,
            record_type=record.record_type,
            cname_target=record.value,
            service_name=service,
            message=(
                f"Dangling CNAME '{record.subdomain}' points to "
                f"'{record.value}' ({service}) which is not responding. "
                "The service endpoint may be unclaimed and vulnerable to takeover."
            ),
            recommendation=(
                f"Immediately remove the CNAME record for '{record.subdomain}' "
                f"or claim the '{service}' resource it points to. "
                "Dangling CNAMEs to unclaimed cloud/SaaS endpoints allow attackers "
                "to serve malicious content under your domain."
            ),
        )]

    def _check_stko_002(self, record: SubdomainRecord) -> List[TakeoverFinding]:
        """
        STKO-002: CNAME pointing to a known vulnerable service, currently responding.
        Severity: HIGH. Weight: 25.
        """
        if record.record_type != "CNAME":
            return []
        if not record.has_response:
            return []  # Not responding — handled by STKO-001 instead

        service = self._match_vulnerable_service(record.value)
        if service is None:
            return []

        return [TakeoverFinding(
            check_id="STKO-002",
            severity="HIGH",
            subdomain=record.subdomain,
            record_type=record.record_type,
            cname_target=record.value,
            service_name=service,
            message=(
                f"CNAME '{record.subdomain}' points to '{record.value}' ({service}) "
                "and is currently responding. If the service resource is ever released, "
                "it becomes immediately vulnerable to subdomain takeover."
            ),
            recommendation=(
                f"Verify that your organization owns and controls the '{service}' "
                f"resource at '{record.value}'. Monitor this record for response "
                "changes and enforce lifecycle policies to prevent accidental resource deletion."
            ),
        )]

    def _check_stko_003(self, record: SubdomainRecord) -> List[TakeoverFinding]:
        """
        STKO-003: NS delegation to a nameserver that is not responding.
        Severity: HIGH. Weight: 25.
        """
        if record.record_type != "NS":
            return []
        if record.has_response:
            return []

        return [TakeoverFinding(
            check_id="STKO-003",
            severity="HIGH",
            subdomain=record.subdomain,
            record_type=record.record_type,
            cname_target=None,
            service_name=None,
            message=(
                f"NS record for '{record.subdomain}' delegates to '{record.value}' "
                "which is not responding. An attacker may be able to register this "
                "nameserver and take over DNS resolution for the zone."
            ),
            recommendation=(
                f"Remove the NS delegation for '{record.subdomain}' to '{record.value}' "
                "or ensure the nameserver is operational and owned by your organization. "
                "Dangling NS delegations are exploitable via zone takeover."
            ),
        )]

    def _check_stko_004(self, record: SubdomainRecord) -> List[TakeoverFinding]:
        """
        STKO-004: A or AAAA record with no response (dangling IP).
        Severity: HIGH. Weight: 25.
        """
        if record.record_type not in ("A", "AAAA"):
            return []
        if record.has_response:
            return []

        return [TakeoverFinding(
            check_id="STKO-004",
            severity="HIGH",
            subdomain=record.subdomain,
            record_type=record.record_type,
            cname_target=None,
            service_name=None,
            message=(
                f"{'A' if record.record_type == 'A' else 'AAAA'} record for "
                f"'{record.subdomain}' resolves to '{record.value}' which is not "
                "responding. The IP may have been released and could be re-assigned "
                "to an attacker-controlled host."
            ),
            recommendation=(
                f"Remove the stale {record.record_type} record for '{record.subdomain}' "
                f"pointing to '{record.value}', or verify the host is operational. "
                "Recycled IPs can allow attackers to serve content under your subdomain."
            ),
        )]

    @staticmethod
    def _check_stko_005(records: List[SubdomainRecord]) -> List[TakeoverFinding]:
        """
        STKO-005: CNAME chain of depth >= 3 detected in the record set.
        Severity: MEDIUM. Weight: 15.
        """
        # Build a map of cname_source -> cname_target for all CNAME records.
        cname_map: Dict[str, str] = {
            r.subdomain: r.value
            for r in records
            if r.record_type == "CNAME"
        }

        if not cname_map:
            return []

        findings: List[TakeoverFinding] = []
        already_flagged = set()  # avoid duplicate findings for same chain root

        for start in cname_map:
            if start in already_flagged:
                continue

            chain: List[str] = [start]
            visited = {start}
            current = start

            # Follow the chain until we leave the known cname_map or hit a loop
            while current in cname_map:
                target = cname_map[current]
                if target in visited:
                    break  # loop — stop here, still count current chain length
                visited.add(target)
                chain.append(target)
                current = target

            if len(chain) >= 3:
                # Flag the chain root and mark all members to avoid re-reporting
                already_flagged.update(chain)
                chain_str = " → ".join(chain)
                findings.append(TakeoverFinding(
                    check_id="STKO-005",
                    severity="MEDIUM",
                    subdomain=start,
                    record_type="CNAME",
                    cname_target=cname_map[start],
                    service_name=None,
                    message=(
                        f"Deep CNAME chain detected starting at '{start}' "
                        f"(depth {len(chain) - 1}): {chain_str}. "
                        "Long chains increase attack surface and complicate auditing."
                    ),
                    recommendation=(
                        "Flatten the CNAME chain to a single hop where possible. "
                        "Each intermediate CNAME is an additional point of failure "
                        "that may be independently claimed or abandoned."
                    ),
                ))

        return findings

    def _check_stko_006(self, record: SubdomainRecord) -> List[TakeoverFinding]:
        """
        STKO-006: A/AAAA record value matches known ephemeral cloud IP prefixes.
        Severity: MEDIUM. Weight: 15.
        """
        if record.record_type not in ("A", "AAAA"):
            return []

        matched_prefix: Optional[str] = None
        for prefix in _CLOUD_IP_PREFIXES:
            if record.value.startswith(prefix):
                matched_prefix = prefix
                break

        if matched_prefix is None:
            return []

        # Determine which provider this prefix belongs to
        if matched_prefix in ("52.", "54.", "3."):
            provider = "AWS"
        elif matched_prefix in ("104.", "40.", "20."):
            provider = "Azure"
        else:
            provider = "GCP"

        return [TakeoverFinding(
            check_id="STKO-006",
            severity="MEDIUM",
            subdomain=record.subdomain,
            record_type=record.record_type,
            cname_target=None,
            service_name=provider,
            message=(
                f"{record.record_type} record for '{record.subdomain}' resolves to "
                f"'{record.value}', which falls within a common {provider} ephemeral "
                "IP range. These IPs are frequently recycled and may be re-assigned "
                "to other customers."
            ),
            recommendation=(
                f"Verify that '{record.value}' is an Elastic/Static IP exclusively "
                f"assigned to your {provider} account. Prefer using a CNAME to a "
                "stable DNS name rather than a raw cloud IP to avoid IP recycling risks."
            ),
        )]

    def _check_stko_007(self, record: SubdomainRecord) -> List[TakeoverFinding]:
        """
        STKO-007: Suspicious dev/staging subdomain name + CNAME to vulnerable service.
        Severity: MEDIUM. Weight: 15.
        """
        if record.record_type != "CNAME":
            return []

        subdomain_lower = record.subdomain.lower()
        keyword_match = next(
            (kw for kw in _STAGING_KEYWORDS if kw in subdomain_lower), None
        )
        if keyword_match is None:
            return []

        service = self._match_vulnerable_service(record.value)
        if service is None:
            return []

        return [TakeoverFinding(
            check_id="STKO-007",
            severity="MEDIUM",
            subdomain=record.subdomain,
            record_type=record.record_type,
            cname_target=record.value,
            service_name=service,
            message=(
                f"Subdomain '{record.subdomain}' contains the keyword '{keyword_match}' "
                f"and points to '{record.value}' ({service}). "
                "Development and staging subdomains are frequently abandoned and are "
                "prime targets for subdomain takeover."
            ),
            recommendation=(
                f"Review whether '{record.subdomain}' is still actively used. "
                "Remove the CNAME if the environment has been decommissioned, "
                "or apply the same security controls as production environments."
            ),
        )]
