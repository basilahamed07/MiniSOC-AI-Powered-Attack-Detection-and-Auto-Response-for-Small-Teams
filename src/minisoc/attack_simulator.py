"""Generate repeatable fake SSH and Nginx telemetry for offline testing."""

from __future__ import annotations

import argparse
import random
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Iterable

if __package__ in {None, ""}:  # Support `python src/minisoc/attack_simulator.py`.
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from minisoc.parsers import parse_lines
else:
    from .parsers import parse_lines

DEFAULT_SEED = 20261015
BASE_TIME = datetime(2026, 10, 15, 12, 0, tzinfo=timezone.utc)


def _iso(timestamp: datetime) -> str:
    return timestamp.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _ssh_line(timestamp: datetime, message: str) -> str:
    return f"{_iso(timestamp)} sshd: {message}"


def _nginx_line(
    timestamp: datetime,
    ip: str,
    target: str,
    status: int = 200,
    method: str = "GET",
) -> str:
    return (
        f'{ip} - - [{timestamp.strftime("%d/%b/%Y:%H:%M:%S +0000")}] '
        f'"{method} {target} HTTP/1.1" {status} 128 "-" "MiniSOC-simulator/1.0"'
    )


def _generate_normal_records(
    count: int, seed: int
) -> list[tuple[datetime, int, str]]:
    if count < 0:
        raise ValueError("count must not be negative")
    rng = random.Random(seed)
    targets = (
        "/",
        "/health",
        "/login?next=%2Fdashboard",
        "/static/app.js",
        "/search?q=blue+team",
    )
    statuses = (200, 200, 200, 304, 404)
    records: list[tuple[datetime, int, str]] = []
    for index in range(count):
        timestamp = BASE_TIME + timedelta(
            seconds=rng.randrange(0, max(1, count * 3 + 1)),
            microseconds=index,
        )
        records.append(
            (
                timestamp,
                index,
                _nginx_line(
                    timestamp,
                    "192.0.2.100",
                    rng.choice(targets),
                    rng.choice(statuses),
                ),
            )
        )
    return records


def generate_normal_logs(count: int = 40, seed: int = DEFAULT_SEED) -> list[str]:
    """Generate normal traffic that stays below every Session 1 threshold."""

    records = _generate_normal_records(count, seed)
    return [line for _, _, line in sorted(records, key=lambda item: (item[0], item[1]))]


def generate_logs(seed: int = DEFAULT_SEED, normal_lines: int = 40) -> list[str]:
    """Generate normal traffic mixed with one scenario for each attack rule."""

    if normal_lines < 0:
        raise ValueError("normal_lines must not be negative")
    records = _generate_normal_records(normal_lines, seed)
    ordinal = normal_lines

    brute_ip = "198.51.100.10"
    for offset in (10, 20, 30, 40, 70):
        records.append(
            (
                BASE_TIME + timedelta(seconds=offset),
                ordinal,
                _ssh_line(
                    BASE_TIME + timedelta(seconds=offset),
                    f"Failed password for invalid user demo from {brute_ip} port {2200 + ordinal} ssh2",
                ),
            )
        )
        ordinal += 1

    scanner_ip = "198.51.100.20"
    for port_offset in range(10):
        offset = 100 + port_offset * 3
        timestamp = BASE_TIME + timedelta(seconds=offset)
        records.append(
            (
                timestamp,
                ordinal,
                _ssh_line(
                    timestamp,
                    f"Connection attempt from {scanner_ip} to port {3000 + port_offset}",
                ),
            )
        )
        ordinal += 1

    sql_timestamp = BASE_TIME + timedelta(seconds=160)
    records.append(
        (
            sql_timestamp,
            ordinal,
            _nginx_line(
                sql_timestamp,
                "203.0.113.10",
                "/search?q=%27%20OR%201%3D1--",
                status=400,
            ),
        )
    )
    ordinal += 1

    traversal_timestamp = BASE_TIME + timedelta(seconds=180)
    records.append(
        (
            traversal_timestamp,
            ordinal,
            _nginx_line(
                traversal_timestamp,
                "203.0.113.20",
                "/static/%2e%2e/%2e%2e/etc/passwd",
                status=404,
            ),
        )
    )

    return [line for _, _, line in sorted(records, key=lambda item: (item[0], item[1]))]


def generate_events(seed: int = DEFAULT_SEED, normal_lines: int = 40):
    """Generate and parse a deterministic mixed scenario."""

    return parse_lines(generate_logs(seed=seed, normal_lines=normal_lines))


def main(argv: Iterable[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seed", type=int, default=DEFAULT_SEED)
    parser.add_argument("--normal-lines", type=int, default=40)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(list(argv) if argv is not None else None)

    lines = generate_logs(seed=args.seed, normal_lines=args.normal_lines)
    output = "\n".join(lines) + ("\n" if lines else "")
    if args.output is None:
        print(output, end="")
    else:
        args.output.write_text(output, encoding="utf-8", newline="\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
