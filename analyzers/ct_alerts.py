"""Alertas defensivos para monitoramento de Certificate Transparency.

Este módulo adiciona governança operacional sobre resultados de CT:
- identificação de novos certificados (registro novo);
- alerta de certificados wildcard;
- persistência simples de estado para comparação entre execuções;
- saída estruturada para integração em workflows de triagem.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
import json
from pathlib import Path
from typing import Iterable

from analyzers.ct_monitor import CtCertificate, filter_lookalikes


CRITICAL = "critical"
HIGH = "high"
MEDIUM = "medium"


def _now_utc() -> datetime:
    """Retorna horário atual em UTC com timezone explícito."""
    return datetime.now(timezone.utc)


def _brand_keywords(brand_domain: str) -> set[str]:
    """Extrai palavras-chave do domínio para avaliação de risco."""
    labels = [label.strip().lower() for label in brand_domain.split(".") if label.strip()]
    if not labels:
        return set()
    head = labels[0]
    keywords = {head}
    keywords.update(token for token in head.replace("_", "-").split("-") if token)
    return {k for k in keywords if len(k) >= 3}


@dataclass(slots=True)
class CtAlert:
    """Representa um alerta de monitoramento CT."""

    alert_type: str
    severity: str
    cert_id: int
    common_name: str
    issuer: str
    logged_at: datetime | None
    message: str

    def to_dict(self) -> dict[str, object]:
        """Serializa alerta para dicionário JSON-safe."""
        return {
            "alert_type": self.alert_type,
            "severity": self.severity,
            "cert_id": self.cert_id,
            "common_name": self.common_name,
            "issuer": self.issuer,
            "logged_at": self.logged_at.isoformat() if self.logged_at else None,
            "message": self.message,
        }


@dataclass(slots=True)
class CtAlertBatch:
    """Agrega resultados de alerta de um ciclo de monitoramento."""

    brand_domain: str
    checked_at: datetime = field(default_factory=_now_utc)
    total_certificates: int = 0
    lookalike_certificates: int = 0
    new_registration_alerts: list[CtAlert] = field(default_factory=list)
    wildcard_alerts: list[CtAlert] = field(default_factory=list)

    def all_alerts(self) -> list[CtAlert]:
        """Retorna todos os alertas do ciclo em uma lista única."""
        return [*self.new_registration_alerts, *self.wildcard_alerts]

    def to_dict(self) -> dict[str, object]:
        """Serializa o lote completo para relatório JSON."""
        return {
            "brand_domain": self.brand_domain,
            "checked_at": self.checked_at.isoformat(),
            "total_certificates": self.total_certificates,
            "lookalike_certificates": self.lookalike_certificates,
            "new_registration_alerts": [item.to_dict() for item in self.new_registration_alerts],
            "wildcard_alerts": [item.to_dict() for item in self.wildcard_alerts],
            "all_alerts": [item.to_dict() for item in self.all_alerts()],
        }


def load_ct_state(state_file: str | Path) -> set[int]:
    """Carrega IDs de certificados já conhecidos de um arquivo de estado."""
    path = Path(state_file)
    if not path.exists():
        return set()
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return set()

    raw_ids = payload.get("known_certificate_ids", [])
    result: set[int] = set()
    for item in raw_ids:
        try:
            result.add(int(item))
        except (TypeError, ValueError):
            continue
    return result


def save_ct_state(
    state_file: str | Path,
    *,
    brand_domain: str,
    known_certificate_ids: Iterable[int],
    checked_at: datetime | None = None,
) -> None:
    """Persiste estado de monitoramento para comparação em execuções futuras."""
    path = Path(state_file)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "brand_domain": brand_domain,
        "checked_at": (checked_at or _now_utc()).isoformat(),
        "known_certificate_ids": sorted({int(cid) for cid in known_certificate_ids}),
    }
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def detect_new_certificate_alerts(
    certs: Iterable[CtCertificate],
    *,
    known_certificate_ids: set[int],
) -> list[CtAlert]:
    """Identifica certificados ainda não vistos no estado anterior."""
    alerts: list[CtAlert] = []
    for cert in certs:
        if cert.cert_id in known_certificate_ids:
            continue
        alerts.append(
            CtAlert(
                alert_type="new_certificate_registration",
                severity=HIGH,
                cert_id=cert.cert_id,
                common_name=cert.common_name,
                issuer=cert.issuer,
                logged_at=cert.logged_at,
                message=(
                    f"New certificate observed for '{cert.common_name}' "
                    f"(cert_id={cert.cert_id})."
                ),
            )
        )
    return alerts


def detect_wildcard_certificate_alerts(
    certs: Iterable[CtCertificate],
    *,
    brand_domain: str,
) -> list[CtAlert]:
    """Detecta certificados wildcard com potencial de abuso de marca."""
    keywords = _brand_keywords(brand_domain)
    alerts: list[CtAlert] = []
    for cert in certs:
        cn = cert.common_name.lower().strip()
        if not cn.startswith("*."):
            continue

        keyword_match = any(keyword in cn for keyword in keywords)
        severity = CRITICAL if keyword_match else MEDIUM
        alerts.append(
            CtAlert(
                alert_type="wildcard_certificate_alert",
                severity=severity,
                cert_id=cert.cert_id,
                common_name=cert.common_name,
                issuer=cert.issuer,
                logged_at=cert.logged_at,
                message=(
                    "Wildcard certificate observed; review for potential impersonation "
                    f"risk against brand '{brand_domain}'."
                ),
            )
        )
    return alerts


def evaluate_ct_alerts(
    *,
    brand_domain: str,
    certs: list[CtCertificate],
    known_certificate_ids: set[int],
) -> CtAlertBatch:
    """Executa avaliação completa de alertas para um lote CT."""
    lookalike_certs = filter_lookalikes(certs, brand_domain=brand_domain)
    return CtAlertBatch(
        brand_domain=brand_domain,
        total_certificates=len(certs),
        lookalike_certificates=len(lookalike_certs),
        new_registration_alerts=detect_new_certificate_alerts(
            lookalike_certs,
            known_certificate_ids=known_certificate_ids,
        ),
        wildcard_alerts=detect_wildcard_certificate_alerts(
            lookalike_certs,
            brand_domain=brand_domain,
        ),
    )


def merge_known_certificate_ids(
    previous_ids: set[int],
    certs: Iterable[CtCertificate],
) -> set[int]:
    """Une estado anterior com IDs observados no ciclo atual."""
    merged = set(previous_ids)
    merged.update(int(cert.cert_id) for cert in certs)
    return merged
