from minisoc.parsers import parse_line, parse_lines


def test_parse_ssh_failed_login_and_success() -> None:
    failed = parse_line(
        "2026-10-15T12:00:00Z sshd: Failed password for invalid user root "
        "from 192.0.2.10 port 2200 ssh2"
    )
    success = parse_line(
        "Oct 15 12:00:01 host sshd[12]: Accepted password for demo "
        "from 192.0.2.10 port 2201 ssh2"
    )

    assert failed is not None
    assert failed.event_type == "auth_failure"
    assert failed.username == "root"
    assert failed.ip == "192.0.2.10"
    assert success is not None
    assert success.event_type == "auth_success"


def test_parse_synthetic_connection_uses_destination_port() -> None:
    parsed = parse_line(
        "2026-10-15T12:00:00Z sshd: Connection attempt from "
        "198.51.100.20 to port 443"
    )

    assert parsed is not None
    assert parsed.event_type == "connection_attempt"
    assert parsed.port == 443


def test_parse_nginx_combined_access_line() -> None:
    parsed = parse_line(
        '203.0.113.10 - - [15/Oct/2026:12:00:02 +0000] '
        '"GET /search?q=blue+team HTTP/1.1" 200 128 "-" "MiniSOC/1.0"'
    )

    assert parsed is not None
    assert parsed.source == "nginx"
    assert parsed.event_type == "http_request"
    assert parsed.target == "/search?q=blue+team"
    assert parsed.status == 200


def test_parse_json_fixture_line() -> None:
    parsed = parse_line(
        '{"ts":"2026-10-15T12:00:00Z","service":"ssh",'
        '"kind":"connection_attempt","src_ip":"192.0.2.20",'
        '"dst_port":22}'
    )

    assert parsed is not None
    assert parsed.event_type == "connection_attempt"
    assert parsed.port == 22


def test_bad_and_empty_lines_are_skipped_without_stopping_valid_lines() -> None:
    events = parse_lines(
        [
            "",
            "not a supported log line",
            '{"service":"ssh","kind":"auth_failure"}',
            "2026-10-15T12:00:00Z sshd: Failed password for demo from "
            "192.0.2.10 port 2200 ssh2",
            '203.0.113.10 - - [not-a-date] "GET / HTTP/1.1" 200 1 "-" "-"',
        ]
    )

    assert len(events) == 1
    assert events[0].event_id == "ssh:4"


def test_invalid_ip_and_port_are_rejected() -> None:
    assert (
        parse_line(
            "2026-10-15T12:00:00Z sshd: Connection attempt from "
            "not-an-ip to port 22"
        )
        is None
    )
    assert (
        parse_line(
            "2026-10-15T12:00:00Z sshd: Connection attempt from "
            "192.0.2.20 to port 70000"
        )
        is None
    )
