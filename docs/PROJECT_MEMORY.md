# MiniSOC Project Memory

**Last updated:** 2026-10-15

## Snapshot

MiniSOC is an offline, small-scale security operations center simulator. Session 1 foundation implementation is complete: canonical records, SSH/Nginx parsers, four explainable detections, structured alerts, and a deterministic simulator.

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

## Session 1 focus

Session 1 will establish the foundation:

- define the canonical event and detection contracts; **complete**
- implement the fake-data-only simulator and scenario fixtures; **complete**
- implement parsers and validation for SSH, Nginx, and documented JSON fixtures; **complete**
- implement initial explainable detections, including synthetic port-scan events; **complete**
- connect simulator → parser → detection flow; **complete**
- record offline functional and safety evidence; **verified by the foundation test suite and source review**

Alert triage UI, risk scoring, incident workflow, SQLite storage, MITRE enrichment, anomaly detection, simulated blocking, exports, and dashboard work remain later-scope work.

## Hard constraints

- Simulator data is fake/synthetic only.
- The simulator must never scan the host or any real system.
- No local host inspection, live telemetry collection, socket access, network traffic, real port scanning, or invocation of scanning utilities.
- Port-scan behavior is represented only by synthetic port-scan events.
- Technical choices not explicitly specified by the user remain **Proposed** in `docs/DECISIONS.md`.
- Actual foundation checks have been run and are recorded in the implementation plan; later-feature checks remain not run.
- The only clean-release exception is the preserved pre-existing launcher, which contains its original absolute Windows command path. The launcher was not modified because it is outside MiniSOC scope.

## Current implementation

- `src/minisoc/models.py` defines `LogEvent` and the required `Alert` serialization shape.
- `src/minisoc/parsers.py` parses SSH auth lines, synthetic connection lines, Nginx combined lines, and structured JSON fixture lines.
- `src/minisoc/detectors.py` implements brute force, synthetic port scan, SQL injection, path traversal, and combined detection.
- `src/minisoc/attack_simulator.py` emits seeded normal and attack traffic without host or network access.
- `tests/` contains parser, detector, false-positive, integration, and repeatability checks.

## Open questions

Risk scoring, incident grouping, storage, UI approach, detection configuration, ATT&CK enrichment, and export format are unresolved. They are tracked as proposed decisions rather than silently assumed choices.

## Continuity note

The full-scope list above is the working MiniSOC baseline. Session 1 implementation is intentionally limited to fake telemetry, parsing, detection, and deterministic evidence. No live collection or real port scanning may be introduced later.
