"""Deterministic incident grouping for synthetic alerts."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime
from typing import Iterable

from .models import Alert
from .mitre import technique_for
from .scoring import risk_score


@dataclass(frozen=True, slots=True)
class EnrichedAlert:
    """Alert plus the prototype's analyst-facing enrichment."""

    reference: str
    alert: Alert
    risk_score: int
    mitre_id: str
    mitre_name: str
    status: str = "new"
    incident_id: str | None = None
    anomaly_score: float | None = None

    def to_dict(self) -> dict[str, object]:
        payload = self.alert.to_dict()
        payload.update(
            {
                "reference": self.reference,
                "risk_score": self.risk_score,
                "mitre_id": self.mitre_id,
                "mitre_name": self.mitre_name,
                "status": self.status,
                "incident_id": self.incident_id,
            }
        )
        if self.anomaly_score is not None:
            payload["anomaly_score"] = round(self.anomaly_score, 6)
        return payload


@dataclass(frozen=True, slots=True)
class Incident:
    incident_id: str
    ip: str
    alert_references: tuple[str, ...]
    attack_types: tuple[str, ...]
    risk_score: int
    status: str = "new"

    def to_dict(self) -> dict[str, object]:
        return {
            "incident_id": self.incident_id,
            "ip": self.ip,
            "alert_references": list(self.alert_references),
            "attack_types": list(self.attack_types),
            "risk_score": self.risk_score,
            "status": self.status,
        }


def _incident_id(ip: str, timestamp: datetime) -> str:
    source = f"{ip}|{timestamp.isoformat()}".encode("utf-8")
    return f"inc-{hashlib.sha256(source).hexdigest()[:12]}"


def _alert_sort_key(alert: Alert) -> tuple[datetime, str, str, str]:
    """Provide a canonical tie-breaker for same-time alert records."""

    digest = hashlib.sha256(
        json.dumps(alert.to_dict(), sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    return (alert.timestamp, alert.attack_type, alert.ip, digest)


def enrich_alerts(alerts: Iterable[Alert]) -> list[EnrichedAlert]:
    """Add stable references, ATT&CK tags, and risk scores."""

    ordered = sorted(alerts, key=_alert_sort_key)
    enriched: list[EnrichedAlert] = []
    for index, alert in enumerate(ordered, start=1):
        technique = technique_for(alert.attack_type)
        enriched.append(
            EnrichedAlert(
                reference=f"alert-{index:03d}",
                alert=alert,
                risk_score=risk_score(alert),
                mitre_id=technique["id"],
                mitre_name=technique["name"],
            )
        )
    return enriched


def group_incidents(alerts: Iterable[EnrichedAlert]) -> tuple[list[EnrichedAlert], list[Incident]]:
    """Group alerts from the same synthetic source IP into one incident."""

    grouped: dict[str, list[EnrichedAlert]] = {}
    for alert in alerts:
        grouped.setdefault(alert.alert.ip, []).append(alert)

    incidents: list[Incident] = []
    assigned: list[EnrichedAlert] = []
    for ip in sorted(grouped):
        members = sorted(
            grouped[ip],
            key=lambda item: (
                item.alert.timestamp,
                item.alert.attack_type,
                item.reference,
                json.dumps(item.alert.to_dict(), sort_keys=True, separators=(",", ":")),
            ),
        )
        incident_id = _incident_id(ip, members[0].alert.timestamp)
        incident = Incident(
            incident_id=incident_id,
            ip=ip,
            alert_references=tuple(item.reference for item in members),
            attack_types=tuple(sorted({item.alert.attack_type for item in members})),
            risk_score=min(100, max(item.risk_score for item in members) + max(0, len(members) - 1) * 5),
        )
        incidents.append(incident)
        assigned.extend(
            EnrichedAlert(
                reference=item.reference,
                alert=item.alert,
                risk_score=item.risk_score,
                mitre_id=item.mitre_id,
                mitre_name=item.mitre_name,
                status=item.status,
                incident_id=incident_id,
                anomaly_score=item.anomaly_score,
            )
            for item in members
        )
    assigned.sort(
        key=lambda item: (
            item.alert.timestamp,
            item.alert.attack_type,
            item.alert.ip,
            item.reference,
        )
    )
    return assigned, incidents
