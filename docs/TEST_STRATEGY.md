# MiniSOC Test Strategy

**Status:** Offline sample-data prototype and rebuildability checks executed; production-only checks remain out of scope.

## Test principles

- Use only bundled or generated fake data.
- Keep scenarios deterministic by controlling the seed and clock inputs.
- Test parser, normalization, detection, and safety boundaries independently before the vertical flow.
- Assert both positive detections and meaningful negative cases.
- Preserve rule explanations and synthetic evidence in test results.
- Treat any host inspection, socket use, network request, real telemetry read, or scanning-tool invocation as a failure.

## Planned test layers

### Unit checks

- Canonical event validation and type normalization.
- Parser handling of valid, missing-field, malformed, and unknown-event inputs.
- Detection matching, thresholds, severity, confidence, and explanation text.
- Seeded simulator output and scenario boundaries.

### Integration checks

- Each fixture format through parser and normalization.
- Simulator output through parser into the detection engine.
- Synthetic port-scan sequence produces expected detection evidence without performing a scan.

### Scenario checks

- Benign synthetic activity does not create the suspicious detection.
- Repeated synthetic authentication failures create the expected detection.
- A synthetic port-scan sequence creates the expected detection and references only synthetic event IDs.
- Mixed scenarios preserve event ordering and evidence linkage.

### Safety checks

- Inspect dependencies and code paths for OS/network/scan APIs.
- Run with network and host-access calls blocked or mocked to prove the simulator does not require them.
- Verify the port-scan scenario emits records rather than invoking a scanner.
- Verify all identifiers and telemetry values are generated or fixture-provided.

## Planned versus actual

| Area | Planned check | Actual status |
|---|---|---|
| Parsers | Unit and malformed-input checks | Passed: `pytest`, 2026-10-15 |
| Detections | Positive, negative, threshold, and explanation checks | Passed: `pytest`, 2026-10-15 |
| Simulator | Seed repeatability and fake-data-only checks | Passed: `pytest`, 2026-10-15 |
| Synthetic port scan | Event-only scenario and detection evidence | Passed: `pytest`, 2026-10-15 |
| Vertical flow | Offline simulator → parser → detection check | Passed: `pytest`, 2026-10-15 |
| Safety | No host/network/real-scan access check | Passed by source review, 2026-10-15 |
| Prototype features | SQLite, scoring, incidents, ML, dashboard, reports | Passed: `pytest` 32 passed, 2026-10-15 |
| Clean release | No secrets or machine-specific absolute paths in tracked files | Passed after replacing the launcher path with a `PATH` lookup, 2026-10-20 |
| Prototype integration | Scoring, MITRE, incidents, SQLite, anomaly, response, Flask, reports | Passed: `pytest` 32 passed, 2026-10-15 |
| Docker | Build and local dashboard smoke test | Not run: Docker CLI unavailable in the current validation container |
| Local dashboard smoke | Loopback `/healthz`, `/dashboard`, and Markdown report | Passed: local Flask process smoke test on `127.0.0.1:18002`, 2026-10-20 |
| Python target runtime | Python 3.12.3 test run | Not run: Python 3.12.3 unavailable in current validation container; tests ran on Python 3.11.2 |
| Rebuildability files | Lockfile, runtime pin, Dockerfile, README, env template, and portable launcher | Passed by tracked-file inspection, 2026-10-20 |
| Clean dependency rebuild | New project-local virtual environment installed `requirements.lock`, passed `pip check`, and ran `pytest` | Passed: 32 tests on Python 3.11.2, 2026-10-20 |

## Prototype sample-data acceptance

- Mixed scenario: 57 generated events and four alerts.
- Normal scenario: 40 generated events and zero alerts.
- Alert fields include deterministic evidence, risk score, MITRE technique, status, and incident reference.
- SQLite round-trip stores events, alerts, incidents, anomalies, and simulated responses.
- Dashboard tests cover mixed, normal, invalid, alert detail, health, API, and report routes.
- The source AST check found no network/scanning imports in the application source.

## Evidence format

When checks exist, record the task ID, exact command, date, environment/runtime, inputs or seed, expected result, actual result, and retained output path. A future test command is not evidence until it has been executed.
