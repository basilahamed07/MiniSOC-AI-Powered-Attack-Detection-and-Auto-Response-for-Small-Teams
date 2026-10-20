# MiniSOC

MiniSOC is an offline security-operations simulator and analysis workflow. It turns generated security telemetry into parsed events, explainable detections, alerts, and incident evidence.

## Status

The offline prototype is implemented. The launcher is a portable convenience
wrapper and is not part of the application.

## Safety boundary

All simulator and analysis input is fake or synthetic. MiniSOC must never scan the host or any real system, access host telemetry, open collection sockets, send outbound traffic, invoke real scanning tools, or perform a real port scan. The optional Flask dashboard may listen on a local demo port solely to serve the synthetic UI. A port scan in a scenario is only a sequence of synthetic port-scan events.

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

The prototype also includes risk scoring, incidents, SQLite, MITRE tags, offline anomaly detection, simulated blocking, a Flask dashboard, and incident reports. `GOOD_SESSION_PROMPT.md` is a reusable continuation prompt for future LLM sessions.

The prototype includes the full local sample-data flow. Production features such as live ingestion, authentication, multi-user triage, and real blocking remain intentionally out of scope.

## Documentation map

- `CLAUDE.md` — operating rules and safety boundary.
- `docs/PROJECT_MEMORY.md` — durable project context and scope.
- `docs/ARCHITECTURE.md` — component and data-flow design.
- `docs/IMPLEMENTATION_PLAN.md` — staged delivery plan and checks.
- `docs/TASKS.md` — task IDs, statuses, dependencies, and evidence rules.
- `docs/DECISIONS.md` — accepted constraints and unresolved proposals.
- `docs/TEST_STRATEGY.md` — functional and safety verification.
- `docs/CHANGELOG.md` — documentation and implementation history.
- `PROTOTYPE_CHECKLIST.md` — capability and verification checklist.
- `GOOD_SESSION_PROMPT.md` — continuation prompt for future LLM sessions.

## Setup

MiniSOC targets Python 3.12.3, recorded in `.python-version`. Create a
project-local environment and install the locked dependencies:

On Linux, verify that the selected interpreter is exactly the pinned version.
`.python-version` is honored by tools such as pyenv/asdf; it does not change a
normal shell's `python` command. If Python 3.12.3 is not installed, use the
Docker workflow below instead of silently using another runtime.

```text
python3.12 --version
python3.12 -m venv .venv
```

Windows PowerShell:

```text
.\.venv\Scripts\Activate.ps1
python -m pip install --requirement requirements.lock
```

Linux/macOS:

```text
source .venv/bin/activate
python --version
python -m pip install --requirement requirements.lock
```

The repository also includes `.env.example` as a non-secret template for the
deterministic seed and log-level settings. The current CLI does not
automatically load `.env`; use the documented CLI flags for runtime behavior.
`.env` is ignored by Git and must not contain credentials or other secrets.

## Run the fake simulator

The simulator writes fake SSH and Nginx lines to standard output. It never opens sockets, reads the host, sends traffic, invokes scanning tools, or performs a real port scan.

```text
python src/minisoc/attack_simulator.py --seed 20261015
```

The same seed produces byte-identical output. Synthetic port-scan behavior is represented only by connection-event log lines.

To write the synthetic sample dataset to a file:

```text
python src/minisoc/attack_simulator.py --seed 20261015 --output samples/mixed.log
```

Do not substitute real logs for this sample dataset.

## Run the prototype dashboard

PowerShell:

```text
$env:PYTHONPATH="src"
python -m minisoc.app --host 127.0.0.1 --port 8000 --db minisoc.sqlite3
```

Linux/macOS:

```text
PYTHONPATH=src python -m minisoc.app --host 127.0.0.1 --port 8000 --db minisoc.sqlite3
```

Open `http://127.0.0.1:8000/dashboard`. The dashboard renders only generated
sample data. Useful routes include `/healthz`, `/api/snapshot`,
`/reports/json`, and `/reports/markdown`. Use `?scenario=normal` to view the
zero-alert state.

## Test

```text
pytest
```

This is the project's single test command. It runs the complete offline suite
from `tests/` using the pinned dependencies.

## Docker

```text
docker build --tag minisoc .
docker run --rm --publish 127.0.0.1:8000:8000 minisoc
```

Run the same test command inside the built image:

```text
docker run --rm minisoc python -m pytest
```

Open `http://127.0.0.1:8000/dashboard`. The published port is for the local
dashboard only; the application performs no live collection or outbound
network access.

The equivalent Compose command is:

```text
docker compose up --build
```

The Compose file explicitly publishes to `127.0.0.1`. Do not use a bare
`-p 8000:8000` command if the dashboard must remain local-only.

## Deploy

There is no production deployment target in the current scope. Docker demonstrates the local Flask dashboard and report export, but MiniSOC remains an offline demonstration tool.

## Verification status

The prototype verification is recorded in `docs/IMPLEMENTATION_PLAN.md`, `docs/TASKS.md`, and `docs/TEST_STRATEGY.md`. Use `GOOD_SESSION_PROMPT.md` when continuing the project with another LLM session.
