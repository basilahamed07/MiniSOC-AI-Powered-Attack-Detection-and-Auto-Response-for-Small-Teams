from datetime import datetime, timedelta, timezone

from minisoc.detectors import (
    detect_all,
    detect_brute_force,
    detect_path_traversal,
    detect_port_scans,
    detect_sql_injection,
)
from minisoc.models import LogEvent


BASE = datetime(2026, 10, 15, 12, 0, tzinfo=timezone.utc)


def make_event(
    index: int,
    seconds: float,
    ip: str,
    kind: str,
    *,
    port: int | None = None,
    target: str | None = None,
) -> LogEvent:
    return LogEvent(
        event_id=f"event:{index}",
        source="nginx" if kind == "http_request" else "ssh",
        timestamp=BASE + timedelta(seconds=seconds),
        ip=ip,
        event_type=kind,
        raw=f"fake:{index}",
        port=port,
        target=target,
    )


def test_brute_force_threshold_and_inclusive_boundary() -> None:
    events = [
        make_event(i, i * 15, "198.51.100.10", "auth_failure")
        for i in range(5)
    ]

    alerts = detect_brute_force(events)

    assert len(alerts) == 1
    assert alerts[0].attack_type == "brute_force"
    assert len(alerts[0].evidence) == 5


def test_brute_force_outside_window_and_rearm() -> None:
    events = [
        make_event(i, i * 15, "198.51.100.10", "auth_failure")
        for i in range(5)
    ]
    events.extend(
        make_event(10 + i, 200 + i * 10, "198.51.100.10", "auth_failure")
        for i in range(5)
    )

    assert len(detect_brute_force(events)) == 2


def test_brute_force_isolated_by_ip_and_success_does_not_count() -> None:
    events = [
        make_event(i, i, "198.51.100.10", "auth_failure") for i in range(3)
    ] + [
        make_event(10 + i, i, "198.51.100.11", "auth_failure") for i in range(2)
    ] + [
        make_event(20 + i, i, "198.51.100.10", "auth_success") for i in range(5)
    ]

    assert detect_brute_force(events) == []


def test_port_scan_requires_ten_distinct_ports() -> None:
    events = [
        make_event(i, i * 3, "198.51.100.20", "connection_attempt", port=3000 + i)
        for i in range(10)
    ]

    alerts = detect_port_scans(events)

    assert len(alerts) == 1
    assert alerts[0].attack_type == "port_scan"
    assert len(alerts[0].evidence) == 10


def test_port_scan_ignores_duplicates_and_old_ports() -> None:
    duplicate_events = [
        make_event(i, i, "198.51.100.20", "connection_attempt", port=3000)
        for i in range(12)
    ]
    assert detect_port_scans(duplicate_events) == []

    old_events = [
        make_event(i, i * 4, "198.51.100.20", "connection_attempt", port=3000 + i)
        for i in range(10)
    ]
    assert detect_port_scans(old_events) == []


def test_sql_injection_samples_are_flagged_without_broad_keyword_matches() -> None:
    payloads = (
        "/search?q=%27%20OR%201%3D1",
        "/search?q=UNION%20SELECT%20username%20FROM%20users",
        "/search?q=admin%27--",
        "/search?q=SLEEP%285%29",
    )
    events = [
        make_event(i, i, "203.0.113.10", "http_request", target=payload)
        for i, payload in enumerate(payloads)
    ]
    benign = make_event(
        100,
        100,
        "192.0.2.100",
        "http_request",
        target="/search?q=union+jack+orchestra",
    )

    alerts = detect_sql_injection([*events, benign])

    assert len(alerts) == len(payloads)
    assert all(alert.attack_type == "sql_injection" for alert in alerts)


def test_path_traversal_samples_are_flagged_but_double_dots_inside_words_are_not() -> None:
    payloads = (
        "/download/../../etc/passwd",
        "/download/%2e%2e/%2e%2e/etc/passwd",
        "/download/%252e%252e%252fetc/passwd",
        r"/download/..\..\secret.txt",
    )
    events = [
        make_event(i, i, "203.0.113.20", "http_request", target=payload)
        for i, payload in enumerate(payloads)
    ]
    benign = make_event(
        100,
        100,
        "192.0.2.100",
        "http_request",
        target="/release/version..2.txt",
    )

    alerts = detect_path_traversal([*events, benign])

    assert len(alerts) == len(payloads)
    assert all(alert.attack_type == "path_traversal" for alert in alerts)


def test_normal_traffic_file_has_no_alerts() -> None:
    from minisoc.attack_simulator import generate_normal_logs
    from minisoc.parsers import parse_lines

    events = parse_lines(generate_normal_logs(count=1000))

    assert len(events) == 1000
    assert detect_all(events) == []


def test_alert_serialization_has_required_fields() -> None:
    event = make_event(1, 0, "198.51.100.10", "auth_failure")
    alert = detect_brute_force(
        [
            make_event(i, i, "198.51.100.10", "auth_failure")
            for i in range(5)
        ]
    )[0]

    assert set(alert.to_dict()) == {
        "ip",
        "attack_type",
        "timestamp",
        "severity",
        "evidence",
    }
    assert event.event_type == "auth_failure"
