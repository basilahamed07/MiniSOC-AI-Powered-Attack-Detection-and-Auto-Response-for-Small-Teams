# MiniSOC

MiniSOC is an offline security-operations simulator and analysis workflow. It turns generated security telemetry into parsed events, explainable detections, alerts, and incident evidence.

## Status

Session 1 implementation is approved, with a focus on:

- parsers and canonical event normalization;
- transparent detections, including synthetic port-scan detection; and
- a fake-data-only, deterministic simulator.

Session 1 foundation is implemented. The existing launcher is preserved and is not part of the application.

## Safety boundary

All simulator input is fake or synthetic. MiniSOC must never scan the host or any real system, access host telemetry, open sockets, send network traffic, invoke real scanning tools, or perform a real port scan. A port scan in a scenario is only a sequence of synthetic port-scan events.

## Full target scope

The original MiniSOC target is represented by this planning baseline:

- synthetic scenario and event generation;
- parsers for supported fixture formats;
- canonical event validation and normalization;
- rule-based, explainable detections and severity;
- alert creation, deduplication, correlation, and triage state;
- incident timelines and analyst evidence views;
- event/alert search and filtering;
- offline evidence export or summary; and
- reproducible tests and demonstration scenarios.

The later roadmap includes risk scoring, incidents, SQLite, MITRE tags, offline anomaly detection, simulated blocking, a Flask dashboard, and incident reports.

Session 1 deliberately builds the data and detection foundation before presentation and triage features.

## Documentation map

- `CLAUDE.md` — operating rules and safety boundary.
- `docs/PROJECT_MEMORY.md` — durable project context and scope.
- `docs/ARCHITECTURE.md` — proposed component and data-flow design.
- `docs/IMPLEMENTATION_PLAN.md` — staged delivery plan and checks.
- `docs/TASKS.md` — task IDs, statuses, dependencies, and evidence rules.
- `docs/DECISIONS.md` — accepted constraints and unresolved proposals.
- `docs/TEST_STRATEGY.md` — planned functional and safety verification.
- `docs/CHANGELOG.md` — documentation and implementation history.

## Setup

MiniSOC targets Python 3.12.3. Create a project-local environment and install the pinned test dependencies:

```text
python -m venv .venv
```

Windows PowerShell:

```text
.\.venv\Scripts\Activate.ps1
python -m pip install --requirement requirements.txt
```

Linux/macOS:

```text
source .venv/bin/activate
python -m pip install --requirement requirements.txt
```

## Run the fake simulator

The simulator writes fake SSH and Nginx lines to standard output. It never opens sockets, reads the host, sends traffic, invokes scanning tools, or performs a real port scan.

```text
python src/minisoc/attack_simulator.py --seed 20261015
```

The same seed produces byte-identical output. Synthetic port-scan behavior is represented only by connection-event log lines.

## Test

```text
pytest
```

## Docker

```text
docker build --tag minisoc .
docker run --rm minisoc
```

The container command runs the deterministic fake simulator. No live collection or network access is required.

## Deploy

There is no production deployment target in the current scope. Later work may add a local Flask dashboard and report export, but MiniSOC remains an offline demonstration tool.

## Verification status

The current foundation verification is recorded in `docs/IMPLEMENTATION_PLAN.md`, `docs/TASKS.md`, and `docs/TEST_STRATEGY.md`.
