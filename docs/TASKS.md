# MiniSOC Task Register

**Last updated:** 2026-10-15

## Status definitions

- **Accepted:** explicitly authorized scope or constraint.
- **DONE:** artifact exists and required evidence is recorded.
- **TODO:** planned work with no implementation evidence yet.
- **IN_PROGRESS:** actively being implemented.
- **Proposed:** future work awaiting an explicit decision.
- **Blocked:** cannot proceed until a named dependency is resolved.

## Tasks

| ID | Task | Status | Dependency | Required evidence |
|---|---|---|---|---|
| DOC-001 | Create persistent MiniSOC planning baseline | Complete | None | The nine requested planning files exist and cross-reference the same scope and safety rules. |
| S1-001 | Define canonical event and detection contracts | DONE | None | `src/minisoc/models.py`; covered by `pytest` on 2026-10-15. |
| S1-002 | Build deterministic fake-data simulator | DONE | S1-001 | `src/minisoc/attack_simulator.py`; seeded CLI repeatability test passed. |
| S1-003 | Implement parser adapters and normalization | DONE | S1-001 | `src/minisoc/parsers.py`; valid, malformed, and invalid-field tests passed. |
| S1-004 | Implement initial explainable detections | DONE | S1-001, S1-003 | `src/minisoc/detectors.py`; positive, negative, threshold, and evidence tests passed. |
| S1-005 | Add synthetic port-scan scenario | DONE | S1-002, S1-003, S1-004 | Synthetic connection events only; port-scan tests passed with no scan/network API. |
| S1-006 | Integrate simulator → parser → detection flow | DONE | S1-002–S1-005 | `tests/test_simulator.py`; all four attack types detected from the seeded scenario. |
| S1-007 | Run Session 1 functional and safety checks | DONE | S1-006 | `pytest`: 18 passed on Python 3.12.3, 2026-10-15; source safety review completed. |
| S2-001 | Add risk scoring, ATT&CK tags, alert correlation, triage state, and incident timeline | TODO | Session 1 completion | Acceptance scenario and integration evidence. |
| S3-001 | Add SQLite persistence, offline anomaly detection, and simulated blocking | TODO | S2-001 | Offline storage and safe-response evidence. |
| S4-001 | Add analyst search, dashboard, report export, and delivery commands | TODO | S3-001 | User-flow evidence plus reproducible artifacts. |

## Evidence rules

1. Every completed implementation task needs an artifact, the exact check or command used, its result, and the date.
2. Generated evidence must identify the scenario and seed; nondeterministic output is insufficient for Session 1.
3. Detection evidence must include the rule ID, matched synthetic event IDs, explanation, and expected negative cases where relevant.
4. Safety evidence must show that the implementation does not inspect the host, access real system telemetry, open sockets, send network traffic, invoke scanning tools, or perform a real port scan.
5. A plan, code review, or fixture alone does not count as an actual implementation check.
6. S1 tasks are marked `DONE` only because the implementation exists and `pytest` ran successfully; later tasks remain `TODO` until implemented and verified.
