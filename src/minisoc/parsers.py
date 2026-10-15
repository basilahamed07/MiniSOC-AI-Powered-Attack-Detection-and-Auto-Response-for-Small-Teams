"""Safe parsers for the fake SSH and Nginx log formats used by MiniSOC."""

from __future__ import annotations

import ipaddress
import json
import re
from datetime import datetime, timezone
from typing import Any, Iterable

from .models import LogEvent

_ISO_TIMESTAMP = re.compile(
    r"(?P<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2}))"
)
_SYSLOG_PREFIX = re.compile(
    r"^(?P<timestamp>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
)
_FAILED_PASSWORD = re.compile(
    r"Failed password for (?:(?:invalid|illegal) user )?"
    r"(?P<username>\S+) from (?P<ip>\S+) port (?P<client_port>\d+)"
)
_ACCEPTED_PASSWORD = re.compile(
    r"Accepted password for (?P<username>\S+) from (?P<ip>\S+) "
    r"port (?P<client_port>\d+)"
)
_SYNTHETIC_CONNECTION = re.compile(
    r"Connection attempt from (?P<ip>\S+) to port (?P<port>\d+)"
)
_NGINX = re.compile(
    r'^(?P<ip>\S+)\s+\S+\s+\S+\s+'
    r'\[(?P<timestamp>[^\]]+)\]\s+'
    r'"(?P<method>\S+)\s+(?P<target>\S+)\s+HTTP/\d(?:\.\d)?"\s+'
    r'(?P<status>\d{3})\s+(?P<body_bytes>\S+)'
    r'(?:\s+"(?P<referer>[^"]*)"\s+"(?P<user_agent>[^"]*)")?\s*$'
)


def _parse_ip(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        return None


def _parse_port(value: Any) -> int | None:
    try:
        port = int(value)
    except (TypeError, ValueError):
        return None
    return port if 1 <= port <= 65535 else None


def _parse_timestamp(value: Any, default_year: int = 2026) -> datetime | None:
    if not isinstance(value, str):
        return None
    text = value.strip()
    try:
        if "T" in text:
            parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
            if parsed.tzinfo is None or parsed.utcoffset() is None:
                return None
            return parsed.astimezone(timezone.utc)
        parsed = datetime.strptime(text, "%d/%b/%Y:%H:%M:%S %z")
        return parsed.astimezone(timezone.utc)
    except ValueError:
        pass

    try:
        parsed = datetime.strptime(text, "%b %d %H:%M:%S")
        return parsed.replace(year=default_year, tzinfo=timezone.utc)
    except ValueError:
        return None


def _timestamp_from_ssh_line(line: str, default_year: int) -> datetime | None:
    iso_match = _ISO_TIMESTAMP.search(line)
    if iso_match:
        return _parse_timestamp(iso_match.group("timestamp"), default_year)
    syslog_match = _SYSLOG_PREFIX.match(line)
    if syslog_match:
        return _parse_timestamp(syslog_match.group("timestamp"), default_year)
    return None


def _event_from_json(line: str, line_number: int, default_year: int) -> LogEvent | None:
    try:
        payload = json.loads(line)
    except (TypeError, json.JSONDecodeError):
        return None
    if not isinstance(payload, dict):
        return None

    service = payload.get("service")
    if service not in {"ssh", "nginx"}:
        return None
    timestamp = _parse_timestamp(
        payload.get("timestamp", payload.get("ts")), default_year
    )
    ip = _parse_ip(payload.get("ip", payload.get("src_ip")))
    event_type = payload.get("event_type", payload.get("kind"))
    if timestamp is None or ip is None or not isinstance(event_type, str):
        return None

    port = _parse_port(payload.get("port", payload.get("dst_port")))
    if payload.get("port", payload.get("dst_port")) is not None and port is None:
        return None
    status = payload.get("status")
    if status is not None:
        try:
            status = int(status)
        except (TypeError, ValueError):
            return None
        if not 100 <= status <= 599:
            return None

    target = payload.get("target", payload.get("path"))
    if target is not None and not isinstance(target, str):
        return None
    method = payload.get("method")
    if method is not None and not isinstance(method, str):
        return None
    username = payload.get("username", payload.get("user"))
    if username is not None and not isinstance(username, str):
        return None

    known = {
        "service", "timestamp", "ts", "ip", "src_ip", "event_type", "kind",
        "port", "dst_port", "status", "target", "path", "method", "username", "user",
    }
    metadata = {key: value for key, value in payload.items() if key not in known}
    return LogEvent(
        event_id=f"{service}:{line_number}",
        source=service,
        timestamp=timestamp,
        ip=ip,
        event_type=event_type,
        raw=line,
        port=port,
        target=target,
        method=method,
        status=status,
        username=username,
        metadata=metadata,
    )


def parse_ssh_line(
    line: str, line_number: int = 1, default_year: int = 2026
) -> LogEvent | None:
    """Parse one SSH auth or synthetic connection line safely."""

    if not isinstance(line, str) or not line.strip():
        return None
    timestamp = _timestamp_from_ssh_line(line, default_year)
    if timestamp is None:
        return None

    match = _FAILED_PASSWORD.search(line)
    if match:
        ip = _parse_ip(match.group("ip"))
        client_port = _parse_port(match.group("client_port"))
        if ip is None or client_port is None:
            return None
        return LogEvent(
            event_id=f"ssh:{line_number}",
            source="ssh",
            timestamp=timestamp,
            ip=ip,
            event_type="auth_failure",
            raw=line,
            username=match.group("username"),
            metadata={"client_port": client_port},
        )

    match = _ACCEPTED_PASSWORD.search(line)
    if match:
        ip = _parse_ip(match.group("ip"))
        client_port = _parse_port(match.group("client_port"))
        if ip is None or client_port is None:
            return None
        return LogEvent(
            event_id=f"ssh:{line_number}",
            source="ssh",
            timestamp=timestamp,
            ip=ip,
            event_type="auth_success",
            raw=line,
            username=match.group("username"),
            metadata={"client_port": client_port},
        )

    match = _SYNTHETIC_CONNECTION.search(line)
    if match:
        ip = _parse_ip(match.group("ip"))
        port = _parse_port(match.group("port"))
        if ip is None or port is None:
            return None
        return LogEvent(
            event_id=f"ssh:{line_number}",
            source="ssh",
            timestamp=timestamp,
            ip=ip,
            event_type="connection_attempt",
            raw=line,
            port=port,
        )
    return None


def parse_nginx_line(
    line: str, line_number: int = 1, default_year: int = 2026
) -> LogEvent | None:
    """Parse one Nginx combined access-log line safely."""

    if not isinstance(line, str) or not line.strip():
        return None
    match = _NGINX.match(line.strip())
    if not match:
        return None
    ip = _parse_ip(match.group("ip"))
    timestamp = _parse_timestamp(match.group("timestamp"), default_year)
    try:
        status = int(match.group("status"))
    except ValueError:
        return None
    if ip is None or timestamp is None or not 100 <= status <= 599:
        return None
    metadata = {
        "body_bytes": match.group("body_bytes"),
        "referer": match.group("referer") or "",
        "user_agent": match.group("user_agent") or "",
    }
    return LogEvent(
        event_id=f"nginx:{line_number}",
        source="nginx",
        timestamp=timestamp,
        ip=ip,
        event_type="http_request",
        raw=line,
        target=match.group("target"),
        method=match.group("method"),
        status=status,
        metadata=metadata,
    )


def parse_line(line: str, line_number: int = 1, default_year: int = 2026) -> LogEvent | None:
    """Dispatch one line to the JSON, SSH, or Nginx parser.

    Parsing is intentionally fail-closed: unsupported or malformed lines return
    ``None`` and never stop a later line from being processed.
    """

    if not isinstance(line, str) or not line.strip():
        return None
    stripped = line.strip()
    if stripped.startswith("{"):
        return _event_from_json(stripped, line_number, default_year)
    return parse_ssh_line(line, line_number, default_year) or parse_nginx_line(
        line, line_number, default_year
    )


def parse_lines(
    lines: Iterable[str], default_year: int = 2026
) -> list[LogEvent]:
    """Parse all supported lines while isolating malformed input."""

    events: list[LogEvent] = []
    for line_number, line in enumerate(lines, start=1):
        try:
            event = parse_line(line, line_number, default_year)
        except (TypeError, ValueError, KeyError, OverflowError):
            event = None
        if event is not None:
            events.append(event)
    return events
