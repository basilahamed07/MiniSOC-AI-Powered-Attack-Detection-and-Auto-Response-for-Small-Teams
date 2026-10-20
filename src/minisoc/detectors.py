"""Explainable, offline detection rules for canonical MiniSOC events."""

from __future__ import annotations

import re
import hashlib
import json
from collections import defaultdict, deque
from datetime import timedelta
from typing import Iterable
from urllib.parse import unquote_plus, urlsplit

from .models import Alert, LogEvent

BRUTE_FORCE_WINDOW = timedelta(seconds=60)
PORT_SCAN_WINDOW = timedelta(seconds=30)

_SQL_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("union_select", re.compile(r"\bunion(?:\s+all)?\s+select\b", re.IGNORECASE)),
    (
        "boolean_tautology",
        re.compile(
            r"(?:['\"]?\s*)\b(?:or|and)\b\s+"
            r"['\"]?\d+['\"]?\s*=\s*['\"]?\d+['\"]?",
            re.IGNORECASE,
        ),
    ),
    (
        "quoted_comment",
        re.compile(r"['\"]\s*(?:--|#|/\*)", re.IGNORECASE),
    ),
    (
        "stacked_statement",
        re.compile(r";\s*(?:select|insert|update|delete|drop)\b", re.IGNORECASE),
    ),
    (
        "time_function",
        re.compile(r"\b(?:sleep|benchmark)\s*\(", re.IGNORECASE),
    ),
)


def _ordered(events: Iterable[LogEvent]) -> list[LogEvent]:
    """Sort by UTC timestamp while preserving input order for ties."""

    return [
        event
        for _, event in sorted(
            enumerate(events), key=lambda item: (item[1].timestamp, item[0])
        )
    ]


def _event_evidence(event: LogEvent) -> dict[str, object]:
    evidence: dict[str, object] = {
        "event_id": event.event_id,
        "timestamp": event.timestamp.isoformat().replace("+00:00", "Z"),
        "raw": event.raw,
    }
    if event.port is not None:
        evidence["port"] = event.port
    if event.target is not None:
        evidence["target"] = event.target
    if event.username is not None:
        evidence["username"] = event.username
    return evidence


def detect_brute_force(
    events: Iterable[LogEvent],
    threshold: int = 5,
    window: timedelta = BRUTE_FORCE_WINDOW,
) -> list[Alert]:
    """Detect threshold-crossing failed SSH logins for each source IP."""

    if threshold < 1 or window.total_seconds() <= 0:
        raise ValueError("threshold and window must be positive")

    failures: dict[str, deque[LogEvent]] = defaultdict(deque)
    alerted: dict[str, bool] = defaultdict(bool)
    alerts: list[Alert] = []
    for event in _ordered(events):
        if event.event_type != "auth_failure":
            continue
        window_events = failures[event.ip]
        window_events.append(event)
        while window_events and event.timestamp - window_events[0].timestamp > window:
            window_events.popleft()

        if len(window_events) < threshold:
            alerted[event.ip] = False
        elif not alerted[event.ip]:
            alerts.append(
                Alert(
                    ip=event.ip,
                    attack_type="brute_force",
                    timestamp=event.timestamp,
                    severity="high",
                    evidence=tuple(_event_evidence(item) for item in window_events),
                )
            )
            alerted[event.ip] = True
    return alerts


def detect_port_scans(
    events: Iterable[LogEvent],
    threshold: int = 10,
    window: timedelta = PORT_SCAN_WINDOW,
) -> list[Alert]:
    """Detect synthetic destination-port scans by source IP.

    The ``port`` field is populated only by synthetic connection events. This
    rule never inspects the host or opens a socket.
    """

    if threshold < 1 or window.total_seconds() <= 0:
        raise ValueError("threshold and window must be positive")

    observations: dict[str, deque[tuple[LogEvent, int]]] = defaultdict(deque)
    counts: dict[str, dict[int, int]] = defaultdict(lambda: defaultdict(int))
    alerted: dict[str, bool] = defaultdict(bool)
    alerts: list[Alert] = []

    for event in _ordered(events):
        if event.event_type != "connection_attempt" or event.port is None:
            continue
        queue = observations[event.ip]
        per_port = counts[event.ip]
        queue.append((event, event.port))
        per_port[event.port] += 1

        while queue and event.timestamp - queue[0][0].timestamp > window:
            expired, expired_port = queue.popleft()
            per_port[expired_port] -= 1
            if per_port[expired_port] == 0:
                del per_port[expired_port]

        distinct_ports = len(per_port)
        if distinct_ports < threshold:
            alerted[event.ip] = False
        elif not alerted[event.ip]:
            # Include the first current observation for each distinct port so
            # evidence explains the threshold without duplicate noise.
            first_by_port: dict[int, LogEvent] = {}
            for queued_event, queued_port in queue:
                first_by_port.setdefault(queued_port, queued_event)
            evidence_events = [
                first_by_port[port] for port in sorted(first_by_port)
            ]
            alerts.append(
                Alert(
                    ip=event.ip,
                    attack_type="port_scan",
                    timestamp=event.timestamp,
                    severity="medium",
                    evidence=tuple(_event_evidence(item) for item in evidence_events),
                )
            )
            alerted[event.ip] = True
    return alerts


def _decoded_target(target: str) -> str:
    """Decode a request target at most twice and omit URL fragments."""

    decoded = target
    for _ in range(2):
        next_value = unquote_plus(decoded)
        if next_value == decoded:
            break
        decoded = next_value
    try:
        parsed = urlsplit(decoded)
    except ValueError:
        return decoded
    return parsed.path + (f"?{parsed.query}" if parsed.query else "")


def detect_sql_injection(events: Iterable[LogEvent]) -> list[Alert]:
    """Flag explainable SQL-injection signatures in HTTP targets."""

    alerts: list[Alert] = []
    for event in _ordered(events):
        if event.event_type != "http_request" or not event.target:
            continue
        decoded = _decoded_target(event.target)
        matched_rule = next(
            (name for name, pattern in _SQL_PATTERNS if pattern.search(decoded)), None
        )
        if matched_rule is None:
            continue
        evidence = _event_evidence(event)
        evidence.update({"matched_rule": matched_rule, "decoded_target": decoded})
        alerts.append(
            Alert(
                ip=event.ip,
                attack_type="sql_injection",
                timestamp=event.timestamp,
                severity="high",
                evidence=(evidence,),
            )
        )
    return alerts


def detect_path_traversal(events: Iterable[LogEvent]) -> list[Alert]:
    """Flag decoded URL paths containing a traversal segment."""

    alerts: list[Alert] = []
    for event in _ordered(events):
        if event.event_type != "http_request" or not event.target:
            continue
        decoded = _decoded_target(event.target).replace("\\", "/")
        segments = decoded.split("/")
        if ".." not in segments:
            continue
        evidence = _event_evidence(event)
        evidence.update({"matched_rule": "parent_path_segment", "decoded_target": decoded})
        alerts.append(
            Alert(
                ip=event.ip,
                attack_type="path_traversal",
                timestamp=event.timestamp,
                severity="high",
                evidence=(evidence,),
            )
        )
    return alerts


def detect_all(events: Iterable[LogEvent]) -> list[Alert]:
    """Run all Session 1 rules and return deterministically ordered alerts."""

    event_list = list(events)
    alerts = [
        *detect_brute_force(event_list),
        *detect_port_scans(event_list),
        *detect_sql_injection(event_list),
        *detect_path_traversal(event_list),
    ]
    def sort_key(alert: Alert) -> tuple[object, str, str, str]:
        digest = hashlib.sha256(
            json.dumps(alert.to_dict(), sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()
        return (alert.timestamp, alert.attack_type, alert.ip, digest)

    return sorted(alerts, key=sort_key)
