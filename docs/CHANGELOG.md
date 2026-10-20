# MiniSOC Changelog

## 2026-10-15 — Planning baseline

### Added

- Persistent MiniSOC project instructions and README.
- Project memory, proposed architecture, implementation plan, task register, decision log, and test strategy.
- Full-scope baseline covering synthetic telemetry, parsers, detections, alert/incident workflow, analyst views, and offline evidence output.
- Session 1 approval for parsers, detections, and the fake-data-only simulator.
- Explicit prohibition on host scanning, real-system access, live collection, network activity, and real port scanning.
- Synthetic port-scan event requirement and evidence rules.

## 2026-10-15 — Session 1 foundation

### Added

- Pinned Python/runtime and project configuration files.
- Canonical `LogEvent` and structured `Alert` records.
- SSH authentication and synthetic connection-event parser.
- Nginx combined access-log and JSON fixture parsing.
- Brute-force, synthetic port-scan, SQL-injection, and path-traversal detection.
- Seeded fake traffic simulator with normal traffic and all four attack types.
- Pytest coverage for parser edge cases, thresholds, false positives, integration, and repeatability.
- Dockerfile and Docker ignore rules for the offline foundation.

### Verification

- `pytest` — 18 passed in 0.59 seconds on Python 3.12.3.
- Later-session functionality remains unimplemented.

## 2026-10-15 — Offline prototype completion

### Added

- Transparent 0–100 risk scoring and MITRE ATT&CK technique tags.
- Deterministic incident grouping by synthetic source IP.
- SQLite persistence for generated events, enriched alerts, incidents, anomalies, and simulated responses.
- Offline Isolation Forest aggregate anomaly scoring with a fixed random state.
- Safe simulated auto-block decisions; no host firewall or OS changes.
- Local Flask dashboard, JSON API, health route, alert evidence detail, filters, and normal/invalid states.
- Deterministic Markdown and JSON incident reports.
- Sample-data documentation and `GOOD_SESSION_PROMPT.md` for future LLM sessions.

### Verification

- `pytest` — 32 passed in the Linux validation container.
- Local dashboard smoke test passed on loopback for health, dashboard, and Markdown report routes.
- Added SQLite load/read-back, deterministic tie-order, seed-bound, and report-evidence regression coverage.
- Docker build/smoke validation remains environment-dependent.

## 2026-10-20 — Rebuildability hardening

### Changed

- Documented the locked dependency install, pinned Python 3.12.3 runtime, local-only Docker/Compose run commands, and the single `pytest` test command.
- Replaced the launcher’s user-specific absolute path with a `PATH` lookup for `omnirush.cmd`.
- Recorded the `.env.example` and tracked-file portability checks.

### Verification

- `pytest` — 32 passed on Python 3.11.2 in the Linux validation container.
- `python3 -m pip check` and `python3 -m compileall -q src tests` — passed.
- `git diff --check` and the tracked-file secret/absolute-path scan — passed.
- Docker build and runtime smoke test — not run because Docker is unavailable in the validation container.
