import subprocess
import sys

from minisoc.attack_simulator import DEFAULT_SEED, generate_events, generate_logs
from minisoc.detectors import detect_all
from minisoc.parsers import parse_lines


def test_simulator_is_repeatable() -> None:
    assert generate_logs(seed=DEFAULT_SEED) == generate_logs(seed=DEFAULT_SEED)


def test_simulator_contains_all_attack_types_and_detects_each() -> None:
    events = generate_events(seed=DEFAULT_SEED)
    alerts = detect_all(events)

    assert {alert.attack_type for alert in alerts} == {
        "brute_force",
        "port_scan",
        "sql_injection",
        "path_traversal",
    }


def test_simulator_cli_is_repeatable() -> None:
    command = [
        sys.executable,
        "src/minisoc/attack_simulator.py",
        "--seed",
        str(DEFAULT_SEED),
    ]
    first = subprocess.run(command, check=True, capture_output=True, text=True)
    second = subprocess.run(command, check=True, capture_output=True, text=True)

    assert first.stdout == second.stdout
    assert first.stderr == second.stderr == ""
    assert len(parse_lines(first.stdout.splitlines())) > 0
