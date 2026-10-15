# MiniSOC Test Strategy

**Status:** Session 1 foundation checks executed; later-feature checks remain planned.

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
| Later features | SQLite, scoring, incidents, ML, dashboard, reports | Not run; not implemented |
| Clean release | No secrets or absolute paths in newly created MiniSOC files | Not fully passed because the preserved launcher has a pre-existing absolute path |

## Evidence format

When checks exist, record the task ID, exact command, date, environment/runtime, inputs or seed, expected result, actual result, and retained output path. A future test command is not evidence until it has been executed.
