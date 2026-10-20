"""Offline MiniSOC prototype workflow and deterministic sample snapshots."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from .anomaly import Anomaly, detect_anomalies
from .attack_simulator import DEFAULT_SEED, generate_events
from .detectors import detect_all
from .incidents import EnrichedAlert, Incident, group_incidents, enrich_alerts
from .models import LogEvent
from .parsers import parse_lines
from .response import ResponseAction, simulate_auto_block


@dataclass(frozen=True, slots=True)
class Snapshot:
    scenario: str
    seed: int
    events: tuple[LogEvent, ...]
    alerts: tuple[EnrichedAlert, ...]
    incidents: tuple[Incident, ...]
    anomalies: tuple[Anomaly, ...]
    responses: tuple[ResponseAction, ...]

    def to_dict(self) -> dict[str, object]:
        timestamps = [event.timestamp for event in self.events]
        return {
            "scenario": self.scenario,
            "seed": self.seed,
            "summary": {
                "event_count": len(self.events),
                "alert_count": len(self.alerts),
                "incident_count": len(self.incidents),
                "high_alert_count": sum(item.alert.severity == "high" for item in self.alerts),
                "synthetic_source_count": len({item.alert.ip for item in self.alerts}),
                "activity_start": _timestamp(min(timestamps)) if timestamps else None,
                "activity_end": _timestamp(max(timestamps)) if timestamps else None,
            },
            "events": [_event_dict(event) for event in self.events],
            "alerts": [alert.to_dict() for alert in self.alerts],
            "incidents": [incident.to_dict() for incident in self.incidents],
            "anomalies": [anomaly.to_dict() for anomaly in self.anomalies],
            "responses": [response.to_dict() for response in self.responses],
        }


def _timestamp(value) -> str:
    return value.isoformat().replace("+00:00", "Z")


def _event_dict(event: LogEvent) -> dict[str, object]:
    return {
        "event_id": event.event_id,
        "source": event.source,
        "timestamp": _timestamp(event.timestamp),
        "ip": event.ip,
        "event_type": event.event_type,
        "raw": event.raw,
        "port": event.port,
        "target": event.target,
        "method": event.method,
        "status": event.status,
        "username": event.username,
        "metadata": dict(event.metadata),
    }


def events_for_scenario(scenario: str, seed: int = DEFAULT_SEED) -> list[LogEvent]:
    """Return only generated sample events; no filesystem or live input is read."""

    if scenario == "mixed":
        return generate_events(seed=seed)
    if scenario == "normal":
        from .attack_simulator import generate_normal_logs

        return parse_lines(generate_normal_logs(count=40, seed=seed))
    raise ValueError("scenario must be 'mixed' or 'normal'")


def build_snapshot(scenario: str = "mixed", seed: int = DEFAULT_SEED) -> Snapshot:
    """Run the complete sample-data pipeline deterministically."""

    events = tuple(events_for_scenario(scenario, seed))
    raw_alerts = detect_all(events)
    enriched, incidents = group_incidents(enrich_alerts(raw_alerts))
    anomaly_results = tuple(detect_anomalies(events))
    anomaly_by_ip = {result.ip: result.score for result in anomaly_results}
    with_scores = tuple(
        EnrichedAlert(
            reference=item.reference,
            alert=item.alert,
            risk_score=item.risk_score,
            mitre_id=item.mitre_id,
            mitre_name=item.mitre_name,
            status=item.status,
            incident_id=item.incident_id,
            anomaly_score=anomaly_by_ip.get(item.alert.ip),
        )
        for item in enriched
    )
    return Snapshot(
        scenario=scenario,
        seed=seed,
        events=events,
        alerts=with_scores,
        incidents=tuple(incidents),
        anomalies=anomaly_results,
        responses=tuple(simulate_auto_block(with_scores)),
    )
