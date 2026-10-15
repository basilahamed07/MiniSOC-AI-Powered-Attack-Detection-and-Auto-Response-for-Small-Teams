"""Shared test helpers for fake MiniSOC telemetry."""

from datetime import datetime, timezone

from minisoc.models import LogEvent


def event(
    event_id: str,
    timestamp: datetime,
    ip: str,
    event_type: str,
    *,
    port: int | None = None,
    target: str | None = None,
) -> LogEvent:
    return LogEvent(
        event_id=event_id,
        source="ssh" if event_type != "http_request" else "nginx",
        timestamp=timestamp.astimezone(timezone.utc),
        ip=ip,
        event_type=event_type,
        raw=f"fake:{event_id}",
        port=port,
        target=target,
    )
