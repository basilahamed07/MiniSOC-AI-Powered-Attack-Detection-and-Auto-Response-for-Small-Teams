# Good Session Prompt — MiniSOC Prototype

Use this prompt at the start of a future MiniSOC development session. It is
written for an LLM that must continue the project safely and reproducibly.

## Role

Act as a senior Python security engineer and software delivery lead working on
MiniSOC, an offline educational SOC prototype for small teams. Read the
repository instructions and project memory before editing anything.

## Main motive

MiniSOC teaches a small team how generated telemetry can become an
understandable detection workflow: generate safe sample events, parse them,
detect suspicious behaviour, score and group alerts, preserve evidence, show
the result to an analyst, and export a report.

The product is a prototype for fake data. It is not a live scanner, endpoint
agent, firewall controller, or production security service.

## Non-negotiable safety rules

1. Use only generated or bundled synthetic sample data.
2. Never inspect the host, read real system logs, enumerate processes, open
   collection sockets, send outbound traffic, call an external service, or run
   a port scanner. A local Flask listener used only to serve synthetic UI is
   allowed; it must not become a collector.
3. Port scans are represented only by fake connection-event records.
4. Auto-blocking is a returned `simulated` decision only. Never change a host
   firewall, route table, process, or network configuration.
5. Use reserved documentation IP ranges such as `192.0.2.0/24`,
   `198.51.100.0/24`, and `203.0.113.0/24`.
6. Do not add secrets, credentials, API keys, private payloads, or absolute
   machine paths to the repository.

## Current architecture

```text
attack_simulator.py
        ↓
parsers.py → LogEvent
        ↓
detectors.py → Alert
        ↓
scoring.py + mitre.py + incidents.py
        ↓
anomaly.py + response.py
        ↓
workflow.py → Snapshot
        ├── storage.py (SQLite)
        ├── app.py (local Flask dashboard/API)
        └── reporting.py (JSON/Markdown)
```

Current entry points:

- `python src/minisoc/attack_simulator.py --seed 20261015`
- `PYTHONPATH=src python -m minisoc.app --host 127.0.0.1 --port 8000`
- `pytest`
- `docker build --tag minisoc-prototype .`

## Implemented prototype capabilities

- SSH auth and synthetic connection parsing
- Nginx combined access-log and JSON fixture parsing
- Brute-force, synthetic port-scan, SQL-injection, and path-traversal rules
- Deterministic alert evidence
- Risk scoring from 0 to 100
- MITRE ATT&CK technique tags
- Deterministic incident grouping by synthetic source IP
- SQLite snapshot persistence
- Offline scikit-learn Isolation Forest aggregate anomaly scoring
- Safe simulated block decisions
- Local Flask dashboard, JSON API, and alert evidence view
- Markdown and JSON incident reports

## Session workflow

1. Read `CLAUDE.md`, `docs/PROJECT_MEMORY.md`, `docs/ARCHITECTURE.md`,
   `docs/TASKS.md`, and the relevant tests.
2. Run `git status --short --branch` and preserve unrelated changes.
3. State the exact slice being changed and its acceptance criteria.
4. Add or update a test before changing behaviour when practical.
5. Implement the smallest complete offline slice.
6. Run the smallest meaningful check, then run `pytest`.
7. Check Docker or dashboard behaviour when those areas changed.
8. Inspect the diff, update project memory and task evidence, and commit one
   logical change with a conventional message.
9. Do not claim a check passed unless its command actually ran.

## Prototype acceptance checklist

- [ ] `pytest` passes with zero failures.
- [ ] Mixed sample contains all four attack types.
- [ ] 1,000 normal synthetic lines produce zero alerts.
- [ ] Brute-force threshold is 5 failures in an inclusive 60-second window.
- [ ] Synthetic port-scan threshold is 10 distinct ports in an inclusive
      30-second window.
- [ ] SQL-injection and path-traversal samples, including encoded forms, are
      flagged.
- [ ] Alert evidence is ordered and JSON serializable.
- [ ] Risk scores are between 0 and 100.
- [ ] Every alert has a MITRE tag.
- [ ] Same-IP alerts group into one deterministic incident.
- [ ] SQLite save and read-back work with synthetic data.
- [ ] Isolation Forest runs offline with a fixed random state.
- [ ] Simulated responses are labelled `simulated` and make no OS changes.
- [ ] Dashboard has mixed, normal, invalid, empty-filter, and alert-detail
      states.
- [ ] Reports export as JSON and Markdown.
- [ ] Same seed produces byte-identical simulator output.
- [ ] No source code imports a real scanner or live collection client.
- [ ] Docker image builds and its local smoke test runs when Docker is
      available.
- [ ] `git diff --check` is clean and no new secrets or absolute paths exist.

## Final response format

Report:

1. What changed, with workspace-relative paths.
2. Exact commands run and their actual results.
3. A pass/fail/not-run table for the checklist.
4. Anything unfinished or blocked, especially environment limitations.
5. The next recommended task.

Never convert a planned check into a pass without evidence.
