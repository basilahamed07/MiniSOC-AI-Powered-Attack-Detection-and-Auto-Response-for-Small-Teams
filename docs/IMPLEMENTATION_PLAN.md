# MiniSOC Implementation Plan

**Status:** Offline sample-data prototype complete; production hardening remains future work.

## Delivery sequence

### Foundation and Session 1 — approved

1. Define the canonical event, parser result, and detection result contracts. **Complete** in `src/minisoc/models.py`.
2. Add deterministic fake scenarios and fixtures. **Complete** in `src/minisoc/attack_simulator.py`.
3. Build parser adapters and normalization/validation. **Complete** in `src/minisoc/parsers.py`.
4. Add initial explainable detections, including synthetic port-scan behavior. **Complete** in `src/minisoc/detectors.py`.
5. Connect the simulator, parsers, and detection engine in an offline vertical flow. **Complete** in `tests/test_simulator.py`.
6. Run the planned unit, integration, scenario, and safety checks. **Foundation checks complete; see actual checks below**.

### Prototype completion — complete

7. Add risk scoring and ATT&CK technique enrichment. **Complete**.
8. Add alert deduplication, correlation, incident timelines, and triage state. **Complete for deterministic same-IP grouping and read-only status**.
9. Add SQLite persistence. **Complete**.
10. Add offline Isolation Forest anomaly detection and simulated blocking. **Complete**.
11. Add analyst search/filtering and evidence views. **Complete for local Flask dashboard**.
12. Add synthetic evidence export/reporting. **Complete for JSON and Markdown**.
13. Package the reproducible setup, run, test, and deployment workflow. **Implemented for pinned dependencies, Dockerfile, README, local commands, and portable launcher; Docker execution remains to be verified on a Docker-enabled host**.

### Future product work — proposed

- Live ingestion is explicitly out of scope for this project.
- Authentication, multi-user workflows, production deployment, and richer persisted triage are not part of this prototype.

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

Actual prototype checks executed with Python 3.11.2 in the Linux validation container:

```text
pytest
32 passed in 25.28s
```

The simulator repeatability test launches the CLI twice with seed `20261015` and compares stdout and stderr. The 1,000-line normal-traffic test parses all lines and asserts zero alerts. Prototype tests cover SQLite round-trips, reports, Flask routes, risk scoring, MITRE enrichment, incidents, Isolation Forest, and simulated responses.

Foundation acceptance evidence:

| Check | Actual result |
|---|---|
| Brute force | Passed: 100 seeded scenarios all produced a brute-force alert. |
| Synthetic port scan | Passed: 100 seeded scenarios all produced a port-scan alert from event records only. |
| SQL injection | Passed: all four representative payloads were flagged by `pytest`. |
| Path traversal | Passed: plain, encoded, double-encoded, and backslash samples were flagged by `pytest`. |
| False positives | Passed: 1,000 generated normal lines produced zero alerts. |
| Parser edge cases | Passed: empty, malformed, invalid IP, invalid port, and invalid timestamp inputs were safe. |
| Test suite | Passed: `pytest` collected 32 tests and reported 32 passed. |
| Repeatability | Passed: two CLI runs with seed `20261015` were byte-identical at 5,819 bytes. |
| Prototype enrichment | Passed: scoring, MITRE tags, incidents, SQLite, anomaly scoring, responses, dashboard, and reports covered by `pytest`. |
| Hardening regressions | Passed: SQLite load consistency, seed bounds, deterministic same-time ordering, and evidence-rich Markdown reports covered by `pytest`. |
| Clean repository | Passed: tracked-file scan found no machine-specific absolute paths or secrets; the launcher resolves `omnirush.cmd` through `PATH`. |

## Change control

Any scope expansion, live-data proposal, or technical choice must be added to `docs/DECISIONS.md` with a status. Directly specified safety constraints cannot be weakened by an implementation decision.
