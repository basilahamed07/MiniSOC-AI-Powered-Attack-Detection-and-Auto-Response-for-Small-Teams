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

### Verification

- Documentation status recorded.
- Actual implementation checks: not run; source implementation does not yet exist.
