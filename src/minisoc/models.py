"""Canonical records shared by parsers, detectors, and the simulator."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Mapping


def utc_timestamp(value: datetime) -> datetime:
    """Return an aware UTC timestamp or reject an ambiguous naive value."""

    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("timestamps must be timezone-aware")
    return value.astimezone(timezone.utc)


@dataclass(frozen=True, slots=True)
class LogEvent:
    """A normalized event from one supported fake log format."""

    event_id: str
    source: str
    timestamp: datetime
    ip: str
    event_type: str
    raw: str
    port: int | None = None
    target: str | None = None
    method: str | None = None
    status: int | None = None
    username: str | None = None
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "timestamp", utc_timestamp(self.timestamp))


@dataclass(frozen=True, slots=True)
class Alert:
    """A stable, explainable detection result."""

    ip: str
    attack_type: str
    timestamp: datetime
    severity: str
    evidence: tuple[Mapping[str, Any], ...]

    def __post_init__(self) -> None:
        object.__setattr__(self, "timestamp", utc_timestamp(self.timestamp))
        object.__setattr__(self, "evidence", tuple(self.evidence))

    def to_dict(self) -> dict[str, Any]:
        """Return the required alert shape using JSON-friendly values."""

        return {
            "ip": self.ip,
            "attack_type": self.attack_type,
            "timestamp": self.timestamp.isoformat().replace("+00:00", "Z"),
            "severity": self.severity,
            "evidence": [dict(item) for item in self.evidence],
        }
