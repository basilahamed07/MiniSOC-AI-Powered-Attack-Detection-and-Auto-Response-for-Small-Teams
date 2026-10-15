# MiniSOC Implementation Plan

**Status:** Session 1 foundation complete; later sessions proposed.

## Delivery sequence

### Foundation and Session 1 — approved

1. Define the canonical event, parser result, and detection result contracts. **Complete** in `src/minisoc/models.py`.
2. Add deterministic fake scenarios and fixtures. **Complete** in `src/minisoc/attack_simulator.py`.
3. Build parser adapters and normalization/validation. **Complete** in `src/minisoc/parsers.py`.
4. Add initial explainable detections, including synthetic port-scan behavior. **Complete** in `src/minisoc/detectors.py`.
5. Connect the simulator, parsers, and detection engine in an offline vertical flow. **Complete** in `tests/test_simulator.py`.
6. Run the planned unit, integration, scenario, and safety checks. **Foundation checks complete; see actual checks below**.

### Later sessions — proposed

7. Add risk scoring and ATT&CK technique enrichment.
8. Add alert deduplication, correlation, incident timelines, and triage state.
9. Add SQLite persistence.
10. Add offline Isolation Forest anomaly detection and simulated blocking.
11. Add analyst search/filtering and evidence views.
12. Add synthetic evidence export/reporting.
13. Package the reproducible setup, run, test, and deployment workflow.

## Session 1 acceptance criteria

- A named seed produces repeatable fake events without host or network access.
- A synthetic port-scan scenario is represented as events only and is parsed successfully.
- Malformed fixture input is rejected with actionable validation output.
- At least one detection produces explainable evidence and references the matching synthetic events.
- The simulator → parser → normalization → detection path works offline.
- Safety checks demonstrate that host inspection, socket/network access, and real scanning are not used.
- Results are recorded with task IDs and exact commands.

## Planned checks

| Check | Purpose | Status |
|---|---|---|
| Parser unit checks | Valid and malformed fixture behavior | Passed via `pytest` |
| Normalization contract checks | Required fields and stable types | Passed via `pytest` |
| Detection unit checks | Positive, negative, threshold, and explanation behavior | Passed via `pytest` |
| Synthetic scenario checks | Deterministic output and synthetic port-scan sequence | Passed via `pytest` |
| Offline integration check | Simulator through detection output | Passed via `pytest` |
| Safety checks | No host inspection, sockets, network calls, or real scan tools | Passed by source review and test execution |

## Actual checks

Actual foundation check executed on 2026-10-15 with Python 3.12.3:

```text
pytest
18 passed in 0.59s
```

The simulator repeatability test launches the CLI twice with seed `20261015` and compares stdout and stderr. The 1,000-line normal-traffic test parses all lines and asserts zero alerts. Later-session checks remain not run because those features do not exist yet.

Foundation acceptance evidence:

| Check | Actual result |
|---|---|
| Brute force | Passed: 100 seeded scenarios all produced a brute-force alert. |
| Synthetic port scan | Passed: 100 seeded scenarios all produced a port-scan alert from event records only. |
| SQL injection | Passed: all four representative payloads were flagged by `pytest`. |
| Path traversal | Passed: plain, encoded, double-encoded, and backslash samples were flagged by `pytest`. |
| False positives | Passed: 1,000 generated normal lines produced zero alerts. |
| Parser edge cases | Passed: empty, malformed, invalid IP, invalid port, and invalid timestamp inputs were safe. |
| Test suite | Passed: `pytest` collected 18 tests and reported 18 passed. |
| Repeatability | Passed: two CLI runs with seed `20261015` were byte-identical at 5,876 bytes. |
| Clean repository | Not fully passed: the preserved pre-existing launcher contains its original absolute Windows path. New MiniSOC files contain no secrets or machine-specific paths. |

## Change control

Any scope expansion, live-data proposal, or technical choice must be added to `docs/DECISIONS.md` with a status. Directly specified safety constraints cannot be weakened by an implementation decision.
