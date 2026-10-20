"""Offline Isolation Forest anomaly scoring over synthetic IP aggregates."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from .models import LogEvent


@dataclass(frozen=True, slots=True)
class Anomaly:
    ip: str
    score: float
    is_anomaly: bool
    features: tuple[float, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "ip": self.ip,
            "score": round(self.score, 6),
            "is_anomaly": self.is_anomaly,
            "features": list(self.features),
        }


def _features(events: Iterable[LogEvent]) -> dict[str, tuple[float, ...]]:
    grouped: dict[str, list[LogEvent]] = {}
    for event in events:
        grouped.setdefault(event.ip, []).append(event)
    result: dict[str, tuple[float, ...]] = {}
    for ip, records in grouped.items():
        result[ip] = (
            float(len(records)),
            float(sum(event.event_type == "auth_failure" for event in records)),
            float(sum(event.event_type == "connection_attempt" for event in records)),
            float(len({event.port for event in records if event.port is not None})),
            float(sum(event.event_type == "http_request" for event in records)),
            float(sum(event.status in {400, 401, 403, 404} for event in records)),
        )
    return result


def detect_anomalies(
    events: Iterable[LogEvent],
    contamination: str | float = "auto",
    random_state: int = 42,
) -> list[Anomaly]:
    """Fit scikit-learn IsolationForest on the supplied synthetic aggregates."""

    feature_map = _features(events)
    if len(feature_map) < 2:
        return [
            Anomaly(ip=ip, score=0.0, is_anomaly=False, features=features)
            for ip, features in sorted(feature_map.items())
        ]
    try:
        from sklearn.ensemble import IsolationForest
    except ImportError as exc:  # pragma: no cover - exercised in setup failures
        raise RuntimeError(
            "scikit-learn is required for anomaly detection; install requirements.txt"
        ) from exc

    ips = sorted(feature_map)
    matrix = [feature_map[ip] for ip in ips]
    model = IsolationForest(
        contamination=contamination,
        random_state=random_state,
        n_estimators=100,
    )
    model.fit(matrix)
    scores = model.decision_function(matrix)
    labels = model.predict(matrix)
    return [
        Anomaly(ip=ip, score=float(score), is_anomaly=bool(label == -1), features=feature_map[ip])
        for ip, score, label in zip(ips, scores, labels)
    ]
