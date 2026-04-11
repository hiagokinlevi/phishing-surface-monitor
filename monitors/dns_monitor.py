# dns_monitor.py — DNS change monitoring module for brand protection
#
# Compares two DNS snapshots to detect suspicious changes (no live DNS queries).
# Part of the Cyber Port phishing-surface-monitor project.
#
# Copyright 2024 Hiago Kin Levi
# Licensed under the Creative Commons Attribution 4.0 International (CC BY 4.0)
# https://creativecommons.org/licenses/by/4.0/
#
# SPDX-License-Identifier: CC-BY-4.0

from __future__ import annotations

import math
import re
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Check registry — maps check ID → weight used when computing risk_score.
# risk_score = min(100, sum of weights for all unique fired check IDs)
# ---------------------------------------------------------------------------
_CHECK_WEIGHTS: Dict[str, int] = {
    "DNS-MON-001": 25,   # New or changed MX record
    "DNS-MON-002": 30,   # NS record changed
    "DNS-MON-003": 15,   # A/AAAA record value changed
    "DNS-MON-004": 20,   # New CNAME record added
    "DNS-MON-005": 15,   # DNSSEC records removed
    "DNS-MON-006": 35,   # SPF permissive change (+all)
    "DNS-MON-007": 20,   # New subdomain with suspicious pattern
}

# Suspicious subdomain prefixes checked by DNS-MON-007
_SUSPICIOUS_PREFIXES: List[str] = [
    "auth", "login", "secure", "account", "verify",
    "update", "support", "helpdesk", "portal", "webmail",
]

# Entropy threshold for DGA-like subdomain detection in DNS-MON-007
_DGA_ENTROPY_THRESHOLD: float = 3.2

# Severity constants
CRITICAL = "CRITICAL"
HIGH = "HIGH"
MEDIUM = "MEDIUM"
LOW = "LOW"


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _shannon_entropy(s: str) -> float:
    """Calculate Shannon entropy (bits) of the given string.

    Returns 0.0 for empty strings.  Used by DNS-MON-007 to detect
    DGA-like subdomain labels.
    """
    if not s:
        return 0.0
    counts: Dict[str, int] = {}
    for c in s:
        counts[c] = counts.get(c, 0) + 1
    length = len(s)
    return -sum((v / length) * math.log2(v / length) for v in counts.values())


def _is_subdomain_of(name: str, domain: str) -> bool:
    """Return True when *name* is a proper subdomain of *domain*.

    Both inputs are lowercased and trailing dots are stripped before
    comparison so DNS-normalised names are handled correctly.
    """
    name = name.lower().rstrip(".")
    domain = domain.lower().rstrip(".")
    # A proper subdomain must end with '.<domain>' and have something before it
    return name != domain and name.endswith("." + domain)


def _subdomain_label(name: str, domain: str) -> str:
    """Return the leftmost label(s) that make *name* a subdomain of *domain*.

    Examples:
        _subdomain_label("login.example.com", "example.com") -> "login"
        _subdomain_label("a.b.example.com", "example.com")   -> "a.b"
    """
    name = name.lower().rstrip(".")
    domain = domain.lower().rstrip(".")
    # Strip the parent domain and the separating dot
    return name[: len(name) - len(domain) - 1]


def _is_suspicious_subdomain(label: str) -> bool:
    """Return True when *label* matches a known-suspicious prefix or looks
    like a DGA name (contains digits at start/end AND high Shannon entropy).

    The label argument is everything to the left of the monitored domain,
    e.g., for "login.example.com" against "example.com" the label is "login".
    We examine only the leftmost component for prefix/entropy tests.
    """
    # Use only the leftmost label for single-label checks
    leftmost = label.split(".")[0]

    # Explicit suspicious-prefix list (DNS-MON-007 spec). Attackers often
    # combine multiple lure words in one label, e.g. "login-secure", so we
    # match complete hyphen/underscore-delimited tokens rather than requiring
    # the entire label to equal a single prefix.
    tokens = [token for token in re.split(r"[-_]+", leftmost) if token]
    if any(token in _SUSPICIOUS_PREFIXES for token in tokens):
        return True

    # DGA heuristic: digits at start or end AND high entropy
    has_digits_at_boundary = (
        (leftmost and leftmost[0].isdigit()) or
        (leftmost and leftmost[-1].isdigit())
    )
    if has_digits_at_boundary and _shannon_entropy(leftmost) > _DGA_ENTROPY_THRESHOLD:
        return True

    return False


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class DnsRecord:
    """Single DNS resource record.

    Attributes:
        record_type: RR type string — "A", "AAAA", "MX", "NS", "CNAME",
                     "TXT", "DS", or "DNSKEY".
        name:        Owner name of the record (hostname), e.g. "example.com"
                     or "mail.example.com".
        value:       Record-specific RDATA as a string, e.g. "1.2.3.4" for A,
                     "10 mail.example.com" for MX.
        ttl:         Time-to-live in seconds (default 3600).
    """
    record_type: str
    name: str
    value: str
    ttl: int = 3600

    def to_dict(self) -> Dict[str, object]:
        """Serialise this record to a plain dictionary."""
        return {
            "record_type": self.record_type,
            "name": self.name,
            "value": self.value,
            "ttl": self.ttl,
        }


@dataclass
class DnsSnapshot:
    """Point-in-time collection of DNS records for a brand domain.

    Attributes:
        domain:      The apex domain being monitored, e.g. "example.com".
        records:     All DNS records captured at this point in time.
        captured_at: Unix timestamp when the snapshot was taken.
    """
    domain: str
    records: List[DnsRecord] = field(default_factory=list)
    captured_at: float = field(default_factory=time.time)

    @classmethod
    def from_records_dict(
        cls,
        domain: str,
        records_dict: Dict[str, List[str]],
        captured_at: float = 0.0,
    ) -> "DnsSnapshot":
        """Build a :class:`DnsSnapshot` from a compact dictionary.

        The dictionary maps RR type strings to lists of RDATA strings::

            {
                "A":  ["93.184.216.34"],
                "MX": ["10 mail.example.com"],
                "NS": ["ns1.example.com", "ns2.example.com"],
            }

        All records are assigned the owner *domain* as their ``name``
        unless the RDATA itself implies a different name (which this helper
        does not attempt to parse — callers should use the full constructor
        for multi-name snapshots).
        """
        records: List[DnsRecord] = []
        for rtype, values in records_dict.items():
            for value in values:
                records.append(DnsRecord(record_type=rtype, name=domain, value=value))
        return cls(domain=domain, records=records, captured_at=captured_at)

    def to_dict(self) -> Dict[str, object]:
        """Serialise this snapshot to a plain dictionary."""
        return {
            "domain": self.domain,
            "captured_at": self.captured_at,
            "records": [r.to_dict() for r in self.records],
        }


@dataclass
class DnsAlert:
    """A single finding raised by one of the DNS-MON checks.

    Attributes:
        check_id:      Identifier from ``_CHECK_WEIGHTS``, e.g. "DNS-MON-001".
        severity:      One of CRITICAL / HIGH / MEDIUM / LOW.
        domain:        The brand domain this alert belongs to.
        record_type:   RR type that triggered the alert.
        record_name:   Owner name of the affected record.
        old_value:     RDATA value from the baseline snapshot, or None.
        new_value:     RDATA value from the current snapshot, or None.
        message:       Human-readable description of the finding.
        recommendation: Suggested remediation action.
    """
    check_id: str
    severity: str
    domain: str
    record_type: str
    record_name: str
    old_value: Optional[str]
    new_value: Optional[str]
    message: str
    recommendation: str

    def to_dict(self) -> Dict[str, object]:
        """Serialise this alert to a plain dictionary."""
        return {
            "check_id": self.check_id,
            "severity": self.severity,
            "domain": self.domain,
            "record_type": self.record_type,
            "record_name": self.record_name,
            "old_value": self.old_value,
            "new_value": self.new_value,
            "message": self.message,
            "recommendation": self.recommendation,
        }


@dataclass
class DnsMonitorResult:
    """Aggregated result of comparing a baseline against a current snapshot.

    Attributes:
        domain:     The brand domain that was compared.
        alerts:     All :class:`DnsAlert` instances raised during comparison.
        risk_score: Integer 0–100 computed as the sum of weights for every
                    unique check ID that fired, capped at 100.
    """
    domain: str
    alerts: List[DnsAlert] = field(default_factory=list)
    risk_score: int = 0

    def summary(self) -> str:
        """Return a single-line human-readable summary of this result.

        Format::

            [example.com] risk_score=45 alerts=3 (CRITICAL:1 HIGH:1 MEDIUM:1)
        """
        by_sev = self.by_severity()
        # Build severity breakdown string, omitting severities with 0 alerts
        sev_order = [CRITICAL, HIGH, MEDIUM, LOW]
        parts = [f"{sev}:{len(by_sev[sev])}" for sev in sev_order if by_sev.get(sev)]
        sev_str = " ".join(parts) if parts else "none"
        return (
            f"[{self.domain}] risk_score={self.risk_score} "
            f"alerts={len(self.alerts)} ({sev_str})"
        )

    def by_severity(self) -> Dict[str, List[DnsAlert]]:
        """Return alerts grouped by severity level.

        The returned dict always contains all four severity keys
        (CRITICAL, HIGH, MEDIUM, LOW), even when the corresponding list
        is empty.  This makes downstream iteration predictable.
        """
        groups: Dict[str, List[DnsAlert]] = {
            CRITICAL: [],
            HIGH: [],
            MEDIUM: [],
            LOW: [],
        }
        for alert in self.alerts:
            # Gracefully handle unexpected severity strings
            groups.setdefault(alert.severity, []).append(alert)
        return groups

    def to_dict(self) -> Dict[str, object]:
        """Serialise this result to a plain dictionary."""
        return {
            "domain": self.domain,
            "risk_score": self.risk_score,
            "alerts": [a.to_dict() for a in self.alerts],
            "summary": self.summary(),
        }


# ---------------------------------------------------------------------------
# Monitor
# ---------------------------------------------------------------------------

class DnsMonitor:
    """Stateless DNS change detector.

    All comparison logic is deterministic and offline — no live DNS queries
    are performed.  Instantiate once and reuse for multiple comparisons.

    Usage::

        monitor = DnsMonitor()
        result  = monitor.compare(baseline_snapshot, current_snapshot)
        print(result.summary())
    """

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def compare(
        self,
        baseline: DnsSnapshot,
        current: DnsSnapshot,
    ) -> DnsMonitorResult:
        """Compare *current* against *baseline* and return a result object.

        Each of the seven DNS-MON checks is run in order.  Alerts are
        accumulated and a risk_score is computed from the unique set of
        fired check IDs.

        Args:
            baseline: Previously captured snapshot to compare against.
            current:  Freshly captured snapshot to evaluate.

        Returns:
            :class:`DnsMonitorResult` containing all alerts and risk score.
        """
        domain = baseline.domain
        alerts: List[DnsAlert] = []

        # Run every check and collect alerts
        alerts.extend(self._check_001_mx(domain, baseline, current))
        alerts.extend(self._check_002_ns(domain, baseline, current))
        alerts.extend(self._check_003_a_changed(domain, baseline, current))
        alerts.extend(self._check_004_cname(domain, baseline, current))
        alerts.extend(self._check_005_dnssec(domain, baseline, current))
        alerts.extend(self._check_006_spf(domain, baseline, current))
        alerts.extend(self._check_007_suspicious_subdomain(domain, baseline, current))

        # risk_score = sum of weights for unique fired check IDs, capped at 100
        fired_ids = {a.check_id for a in alerts}
        risk_score = min(100, sum(_CHECK_WEIGHTS.get(cid, 0) for cid in fired_ids))

        return DnsMonitorResult(domain=domain, alerts=alerts, risk_score=risk_score)

    def compare_many(
        self,
        pairs: List[Tuple[DnsSnapshot, DnsSnapshot]],
    ) -> List[DnsMonitorResult]:
        """Run :meth:`compare` over a list of (baseline, current) pairs.

        Pairs are processed independently in list order.

        Args:
            pairs: Each element is a ``(baseline, current)`` tuple.

        Returns:
            List of :class:`DnsMonitorResult`, one per input pair, in order.
        """
        return [self.compare(baseline, current) for baseline, current in pairs]

    # ------------------------------------------------------------------
    # Internal helpers — record filtering
    # ------------------------------------------------------------------

    @staticmethod
    def _records_of_type(
        snapshot: DnsSnapshot,
        rtype: str,
    ) -> List[DnsRecord]:
        """Return all records in *snapshot* whose ``record_type`` equals *rtype*."""
        return [r for r in snapshot.records if r.record_type == rtype]

    @staticmethod
    def _values_of_type(
        snapshot: DnsSnapshot,
        rtype: str,
    ) -> List[str]:
        """Return the RDATA values of all records in *snapshot* for *rtype*."""
        return [r.value for r in snapshot.records if r.record_type == rtype]

    # ------------------------------------------------------------------
    # DNS-MON-001: New or changed MX record
    # ------------------------------------------------------------------

    def _check_001_mx(
        self,
        domain: str,
        baseline: DnsSnapshot,
        current: DnsSnapshot,
    ) -> List[DnsAlert]:
        """Detect newly added MX records or MX RDATA changes.

        Fires when any MX value present in *current* was not present in
        *baseline*.  This covers both brand-new MX entries and changes to
        existing ones (the old RDATA disappears and a new one appears).
        """
        alerts: List[DnsAlert] = []
        baseline_mx = set(self._values_of_type(baseline, "MX"))
        current_mx = set(self._values_of_type(current, "MX"))

        # Any MX value in current that did not exist in baseline is suspicious
        for new_val in sorted(current_mx - baseline_mx):
            alerts.append(DnsAlert(
                check_id="DNS-MON-001",
                severity=HIGH,
                domain=domain,
                record_type="MX",
                record_name=domain,
                old_value=None if not baseline_mx else ", ".join(sorted(baseline_mx)),
                new_value=new_val,
                message=(
                    f"MX record change detected for {domain}: "
                    f"new value '{new_val}' was not present in baseline."
                ),
                recommendation=(
                    "Verify that this mail exchange change was authorised. "
                    "Unauthorised MX changes can redirect inbound email to "
                    "attacker-controlled servers."
                ),
            ))
        return alerts

    # ------------------------------------------------------------------
    # DNS-MON-002: NS record changed
    # ------------------------------------------------------------------

    def _check_002_ns(
        self,
        domain: str,
        baseline: DnsSnapshot,
        current: DnsSnapshot,
    ) -> List[DnsAlert]:
        """Detect additions or removals of NS records.

        NS changes can indicate domain hijacking — any divergence between
        the baseline and current NS record sets is flagged.
        """
        alerts: List[DnsAlert] = []
        baseline_ns = set(self._values_of_type(baseline, "NS"))
        current_ns = set(self._values_of_type(current, "NS"))

        # Newly added NS records not seen in baseline
        for added in sorted(current_ns - baseline_ns):
            alerts.append(DnsAlert(
                check_id="DNS-MON-002",
                severity=HIGH,
                domain=domain,
                record_type="NS",
                record_name=domain,
                old_value=", ".join(sorted(baseline_ns)) if baseline_ns else None,
                new_value=added,
                message=(
                    f"NS record added for {domain}: '{added}' was not in baseline. "
                    "This may indicate domain hijacking or unauthorised delegation change."
                ),
                recommendation=(
                    "Immediately verify the domain's NS configuration with your "
                    "registrar. NS changes that were not authorised may indicate "
                    "domain takeover."
                ),
            ))

        # NS records removed from baseline
        for removed in sorted(baseline_ns - current_ns):
            alerts.append(DnsAlert(
                check_id="DNS-MON-002",
                severity=HIGH,
                domain=domain,
                record_type="NS",
                record_name=domain,
                old_value=removed,
                new_value=", ".join(sorted(current_ns)) if current_ns else None,
                message=(
                    f"NS record removed for {domain}: '{removed}' is absent from "
                    "current snapshot. This may indicate domain hijacking."
                ),
                recommendation=(
                    "Verify with your registrar that NS changes were authorised. "
                    "Unexpected NS removal can be a precursor to domain takeover."
                ),
            ))

        return alerts

    # ------------------------------------------------------------------
    # DNS-MON-003: A / AAAA record value changed
    # ------------------------------------------------------------------

    def _check_003_a_changed(
        self,
        domain: str,
        baseline: DnsSnapshot,
        current: DnsSnapshot,
    ) -> List[DnsAlert]:
        """Detect IP address changes for A and AAAA records.

        Only fires when the same *name* had a different *value* in baseline
        vs current (i.e., a genuine value change, not a brand-new record).
        """
        alerts: List[DnsAlert] = []

        for rtype in ("A", "AAAA"):
            # Build {name: set_of_values} maps for both snapshots
            baseline_map: Dict[str, set] = {}
            for r in self._records_of_type(baseline, rtype):
                baseline_map.setdefault(r.name, set()).add(r.value)

            current_map: Dict[str, set] = {}
            for r in self._records_of_type(current, rtype):
                current_map.setdefault(r.name, set()).add(r.value)

            # Only examine names that exist in BOTH snapshots
            for name in sorted(set(baseline_map) & set(current_map)):
                old_vals = baseline_map[name]
                new_vals = current_map[name]
                if old_vals == new_vals:
                    continue  # No change — nothing to report

                # At least one value changed for this name
                for new_val in sorted(new_vals - old_vals):
                    alerts.append(DnsAlert(
                        check_id="DNS-MON-003",
                        severity=MEDIUM,
                        domain=domain,
                        record_type=rtype,
                        record_name=name,
                        old_value=", ".join(sorted(old_vals)),
                        new_value=new_val,
                        message=(
                            f"{rtype} record for '{name}' changed: "
                            f"'{', '.join(sorted(old_vals))}' → '{new_val}'."
                        ),
                        recommendation=(
                            "Confirm the IP change corresponds to a planned "
                            "infrastructure migration.  Unexpected IP changes can "
                            "indicate DNS hijacking or BGP hijacking."
                        ),
                    ))

        return alerts

    # ------------------------------------------------------------------
    # DNS-MON-004: New CNAME record added
    # ------------------------------------------------------------------

    def _check_004_cname(
        self,
        domain: str,
        baseline: DnsSnapshot,
        current: DnsSnapshot,
    ) -> List[DnsAlert]:
        """Detect new CNAME records that were absent from the baseline.

        New CNAMEs can redirect brand traffic to attacker-controlled hosts.
        """
        alerts: List[DnsAlert] = []
        # Build a set of (name, value) pairs for each snapshot
        baseline_cnames = {(r.name, r.value) for r in self._records_of_type(baseline, "CNAME")}
        current_cnames = {(r.name, r.value) for r in self._records_of_type(current, "CNAME")}

        for name, value in sorted(current_cnames - baseline_cnames):
            alerts.append(DnsAlert(
                check_id="DNS-MON-004",
                severity=HIGH,
                domain=domain,
                record_type="CNAME",
                record_name=name,
                old_value=None,
                new_value=value,
                message=(
                    f"New CNAME record detected: '{name}' → '{value}'. "
                    "This record was not present in the baseline snapshot."
                ),
                recommendation=(
                    "Verify the new CNAME was created intentionally. "
                    "CNAMEs pointing to attacker-controlled domains can "
                    "enable subdomain takeover and brand traffic hijacking."
                ),
            ))

        return alerts

    # ------------------------------------------------------------------
    # DNS-MON-005: DNSSEC records removed
    # ------------------------------------------------------------------

    def _check_005_dnssec(
        self,
        domain: str,
        baseline: DnsSnapshot,
        current: DnsSnapshot,
    ) -> List[DnsAlert]:
        """Detect removal of DNSSEC (DS / DNSKEY) records.

        Only fires when DNSSEC *was* present in the baseline (for the
        monitored apex domain) but is now absent — a potential downgrade
        attack.  If DNSSEC was never configured no alert is raised.
        """
        alerts: List[DnsAlert] = []

        # Filter DS / DNSKEY records for the apex domain only
        def _dnssec_records(snap: DnsSnapshot) -> List[DnsRecord]:
            return [
                r for r in snap.records
                if r.record_type in ("DS", "DNSKEY")
                and r.name.lower().rstrip(".") == domain.lower().rstrip(".")
            ]

        baseline_dnssec = _dnssec_records(baseline)
        current_dnssec = _dnssec_records(current)

        # Only alert if baseline had DNSSEC and current does not
        if baseline_dnssec and not current_dnssec:
            old_summary = "; ".join(
                f"{r.record_type} {r.value}" for r in baseline_dnssec
            )
            alerts.append(DnsAlert(
                check_id="DNS-MON-005",
                severity=MEDIUM,
                domain=domain,
                record_type="DS/DNSKEY",
                record_name=domain,
                old_value=old_summary,
                new_value=None,
                message=(
                    f"DNSSEC records for {domain} have been removed. "
                    "Baseline contained DS/DNSKEY records that are now absent. "
                    "This may indicate a DNSSEC downgrade attack."
                ),
                recommendation=(
                    "Re-enable DNSSEC immediately. Contact your registrar to "
                    "confirm the DS record removal was not authorised. A DNSSEC "
                    "downgrade exposes resolvers to cache poisoning attacks."
                ),
            ))

        return alerts

    # ------------------------------------------------------------------
    # DNS-MON-006: SPF permissive change (+all)
    # ------------------------------------------------------------------

    def _check_006_spf(
        self,
        domain: str,
        baseline: DnsSnapshot,
        current: DnsSnapshot,
    ) -> List[DnsAlert]:
        """Detect introduction of '+all' in an SPF TXT record.

        Fires when the SPF record changed between baseline and current AND
        the new record contains '+all', which allows any host to send mail
        on behalf of the domain.
        """
        alerts: List[DnsAlert] = []

        # Locate the SPF record (v=spf1 …) in each snapshot for the apex domain
        def _find_spf(snap: DnsSnapshot) -> Optional[str]:
            for r in snap.records:
                if (
                    r.record_type == "TXT"
                    and r.name.lower().rstrip(".") == domain.lower().rstrip(".")
                    and "v=spf1" in r.value.lower()
                ):
                    return r.value
            return None

        old_spf = _find_spf(baseline)
        new_spf = _find_spf(current)

        # Alert only when the SPF record changed AND +all appeared in new record
        if new_spf is None:
            return alerts  # No current SPF — different check (not in scope here)
        if old_spf == new_spf:
            return alerts  # Unchanged — no alert

        if "+all" in new_spf.lower():
            alerts.append(DnsAlert(
                check_id="DNS-MON-006",
                severity=CRITICAL,
                domain=domain,
                record_type="TXT",
                record_name=domain,
                old_value=old_spf,
                new_value=new_spf,
                message=(
                    f"SPF record for {domain} was changed to include '+all', "
                    "making the policy fully permissive. Any host can now send "
                    "email claiming to be from this domain."
                ),
                recommendation=(
                    "Immediately update the SPF record to use '-all' (hard fail) "
                    "or '~all' (soft fail). Investigate who made this change. "
                    "A '+all' SPF policy enables trivial email spoofing."
                ),
            ))

        return alerts

    # ------------------------------------------------------------------
    # DNS-MON-007: New subdomain with suspicious pattern
    # ------------------------------------------------------------------

    def _check_007_suspicious_subdomain(
        self,
        domain: str,
        baseline: DnsSnapshot,
        current: DnsSnapshot,
    ) -> List[DnsAlert]:
        """Detect new A/AAAA subdomains that match suspicious patterns.

        A subdomain is considered suspicious when it:
        - Is a proper subdomain of the monitored domain,
        - Was not present in the baseline (name × record_type × value),
        - AND its label matches either a known-bad prefix list OR a
          DGA heuristic (digits at start/end + Shannon entropy > 3.2).
        """
        alerts: List[DnsAlert] = []

        # Collect all (name, rtype, value) present in baseline for A/AAAA
        baseline_names = {
            r.name.lower().rstrip(".")
            for r in baseline.records
            if r.record_type in ("A", "AAAA")
        }

        # Examine each A/AAAA record in current
        seen_names: set = set()  # Deduplicate per name to avoid duplicate alerts
        for r in current.records:
            if r.record_type not in ("A", "AAAA"):
                continue
            norm_name = r.name.lower().rstrip(".")
            if not _is_subdomain_of(norm_name, domain):
                continue  # Not a subdomain of the monitored domain
            if norm_name in baseline_names:
                continue  # Was already present in baseline
            if norm_name in seen_names:
                continue  # Already alerted for this name

            label = _subdomain_label(norm_name, domain)
            if not _is_suspicious_subdomain(label):
                continue  # Not matching any suspicious pattern

            seen_names.add(norm_name)
            alerts.append(DnsAlert(
                check_id="DNS-MON-007",
                severity=HIGH,
                domain=domain,
                record_type=r.record_type,
                record_name=r.name,
                old_value=None,
                new_value=r.value,
                message=(
                    f"New suspicious subdomain detected: '{r.name}' → '{r.value}'. "
                    f"Label '{label}' matches known-suspicious patterns "
                    "(phishing prefix or DGA-like name)."
                ),
                recommendation=(
                    "Investigate who created this subdomain and whether it is "
                    "serving legitimate content. Suspicious subdomains are a "
                    "common vector for phishing and credential harvesting attacks "
                    "targeting brand users."
                ),
            ))

        return alerts
