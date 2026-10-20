# MiniSOC Project Memory

**Last updated:** 2026-10-20

## Snapshot

MiniSOC is an offline, small-scale security operations center simulator. The local sample-data prototype is complete: canonical records, SSH/Nginx parsers, four explainable detections, structured alerts, scoring, incidents, SQLite, anomaly scoring, simulated responses, a Flask dashboard, and reports.

## Goal

Demonstrate a complete, understandable security-operations loop using generated telemetry: generate a scenario, parse events, normalize them, detect suspicious behavior, and preserve evidence for later alert and incident workflows.

## Full scope baseline

The planned product scope is:

1. **Synthetic telemetry:** deterministic scenarios for authentication, process, DNS, file, HTTP, network-connection, and port-scan-like activity.
2. **Ingestion and parsers:** accept documented fixture representations and convert them into a canonical event shape.
3. **Normalization and validation:** consistent timestamps, actors, hosts as synthetic identifiers, network fields, event type, and source metadata.
4. **Detection:** explainable rules with matching conditions, severity, confidence, rule ID, and evidence references.
5. **Alert and incident workflow:** deduplication, correlation, status, priority, notes, ownership, and an incident timeline.
6. **Analyst experience:** event and alert search/filtering, detection explanations, timeline views, and synthetic evidence display.
7. **Offline output:** reproducible scenario reports and evidence export/summary.
8. **Quality and delivery:** deterministic fixtures, unit/integration/scenario checks, documentation, and a reproducible project command set.

## Prototype status

The local sample-data prototype includes:

- canonical event and detection contracts;
- a fake-data-only simulator and scenario fixtures;
- SSH, Nginx, and documented JSON parsing and validation;
- brute-force, synthetic port-scan, SQL-injection, and path-traversal rules;
- risk scoring, incident grouping, SQLite storage, and MITRE enrichment;
- offline anomaly detection and simulated blocking;
- a local Flask dashboard, API, and evidence views; and
- deterministic JSON and Markdown reports.

Live collection, real port scanning, and production deployment remain out of scope. The Flask listener is allowed only as a local/demo presentation surface for synthetic results.

## Hard constraints

- Simulator data is fake/synthetic only.
- The simulator must never scan the host or any real system.
- No local host inspection, live telemetry collection, socket access, network traffic, real port scanning, or invocation of scanning utilities.
- Port-scan behavior is represented only by synthetic port-scan events.
- Technical choices made for the prototype are recorded as **Accepted for prototype** in `docs/DECISIONS.md`; production choices remain **Proposed**.
- Actual prototype checks are recorded in the implementation plan and test strategy.
- The launcher is a convenience wrapper outside MiniSOC application scope; it resolves `omnirush.cmd` through `PATH` and must not contain machine-specific paths.

## Current implementation

- `src/minisoc/models.py` defines `LogEvent` and the required `Alert` serialization shape.
- `src/minisoc/parsers.py` parses SSH auth lines, synthetic connection lines, Nginx combined lines, and structured JSON fixture lines.
- `src/minisoc/detectors.py` implements brute force, synthetic port scan, SQL injection, path traversal, and combined detection.
- `src/minisoc/attack_simulator.py` emits seeded normal and attack traffic without host or network access.
- `tests/` contains parser, detector, false-positive, integration, and repeatability checks.
- `src/minisoc/scoring.py`, `mitre.py`, and `incidents.py` enrich alerts for analyst use.
- `src/minisoc/storage.py` persists synthetic snapshots to SQLite.
- `src/minisoc/anomaly.py` uses a fixed-seed Isolation Forest over synthetic source aggregates.
- `src/minisoc/response.py` returns simulated block decisions only.
- `src/minisoc/app.py` renders the local dashboard, API, evidence views, and reports.
- `PROTOTYPE_CHECKLIST.md` records capability and verification status, including the Docker environment gap.

## Open questions

Production-grade authentication, live ingestion, multi-user persistence, and deployment topology remain unresolved and out of prototype scope. The local prototype choices are recorded as accepted in `docs/DECISIONS.md`.

## Continuity note

The full-scope list above is the working MiniSOC baseline. No live collection or real port scanning may be introduced later.
