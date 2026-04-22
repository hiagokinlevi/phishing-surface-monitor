from __future__ import annotations

import hashlib
from typing import Any

import requests

from alerting.alert_manager import AlertManager
from logger import get_logger

logger = get_logger(__name__)


class CTMonitor:
    """Monitor Certificate Transparency entries via crt.sh for a target domain."""

    def __init__(self, alert_manager: AlertManager | None = None, timeout: int = 15) -> None:
        self.alert_manager = alert_manager or AlertManager()
        self.timeout = timeout
        # Per-run, in-memory dedup cache for emitted alerts.
        # Keyed by (cert fingerprint, matched domain)
        self._emitted_pairs: set[tuple[str, str]] = set()

    def _fetch_ct_entries(self, domain: str) -> list[dict[str, Any]]:
        url = f"https://crt.sh/?q=%25.{domain}&output=json"
        resp = requests.get(url, timeout=self.timeout)
        resp.raise_for_status()

        data = resp.json()
        if isinstance(data, dict):
            return [data]
        if isinstance(data, list):
            return [entry for entry in data if isinstance(entry, dict)]
        return []

    @staticmethod
    def _normalize_name_value(name_value: str) -> list[str]:
        parts = [p.strip().lower() for p in name_value.split("\n") if p.strip()]
        return parts

    @staticmethod
    def _extract_domains(entry: dict[str, Any]) -> list[str]:
        name_value = str(entry.get("name_value", "") or "")
        common_name = str(entry.get("common_name", "") or "")

        domains: list[str] = []
        if name_value:
            domains.extend(CTMonitor._normalize_name_value(name_value))
        if common_name:
            domains.extend([common_name.strip().lower()])

        # stable unique preserve order
        seen: set[str] = set()
        unique_domains: list[str] = []
        for d in domains:
            if d not in seen:
                seen.add(d)
                unique_domains.append(d)
        return unique_domains

    @staticmethod
    def _certificate_fingerprint(entry: dict[str, Any]) -> str:
        # Prefer explicit identifiers if present from crt.sh output variants.
        for field in ("fingerprint_sha256", "sha256", "cert_sha256", "serial_number", "id"):
            value = entry.get(field)
            if value is not None and str(value).strip():
                return f"{field}:{str(value).strip().lower()}"

        # Fallback: stable hash of selected certificate-identifying fields.
        material = "|".join(
            [
                str(entry.get("issuer_name", "") or "").strip().lower(),
                str(entry.get("common_name", "") or "").strip().lower(),
                str(entry.get("name_value", "") or "").strip().lower(),
                str(entry.get("not_before", "") or "").strip().lower(),
                str(entry.get("not_after", "") or "").strip().lower(),
            ]
        )
        return "derived:" + hashlib.sha256(material.encode("utf-8")).hexdigest()

    def _emit_ct_alert(self, cert_fp: str, domain: str, entry: dict[str, Any]) -> bool:
        key = (cert_fp, domain)
        if key in self._emitted_pairs:
            return False

        self._emitted_pairs.add(key)
        self.alert_manager.send_alert(
            {
                "type": "ct_certificate",
                "domain": domain,
                "certificate_fingerprint": cert_fp,
                "entry": entry,
            }
        )
        return True

    def monitor(self, domain: str) -> list[dict[str, Any]]:
        domain = domain.strip().lower()
        emitted: list[dict[str, Any]] = []

        try:
            entries = self._fetch_ct_entries(domain)
        except requests.RequestException as exc:
            logger.error("CT fetch failed for %s: %s", domain, exc)
            return emitted

        for entry in entries:
            cert_fp = self._certificate_fingerprint(entry)
            for cert_domain in self._extract_domains(entry):
                if domain not in cert_domain:
                    continue
                if self._emit_ct_alert(cert_fp, cert_domain, entry):
                    emitted.append(
                        {
                            "type": "ct_certificate",
                            "domain": cert_domain,
                            "certificate_fingerprint": cert_fp,
                            "entry": entry,
                        }
                    )

        return emitted
