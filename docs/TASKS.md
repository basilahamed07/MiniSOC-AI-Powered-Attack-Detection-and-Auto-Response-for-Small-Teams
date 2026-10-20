# MiniSOC Task Register

**Last updated:** 2026-10-20

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
| S1-007 | Run Session 1 functional and safety checks | DONE | S1-006 | Foundation checks were run during Session 1; the complete prototype suite now covers the same foundation plus later features. |
| S2-001 | Add risk scoring, ATT&CK tags, alert correlation, triage state, and incident timeline | DONE | Session 1 completion | `src/minisoc/scoring.py`, `mitre.py`, `incidents.py`; prototype tests passed. |
| S3-001 | Add SQLite persistence, offline anomaly detection, and simulated blocking | DONE | S2-001 | `storage.py`, `anomaly.py`, `response.py`; SQLite, Isolation Forest, and safe-response tests passed. |
| S4-001 | Add analyst search, dashboard, report export, and delivery commands | DONE | S3-001 | `app.py`, templates, `reporting.py`, Docker/README; Flask and report tests passed. |
| S5-001 | Keep the prototype sample-data-only and document production gaps | IN_PROGRESS | S4-001 | `pytest` and clean-path scan passed; Docker build/run remains unverified because the validation container has no Docker CLI. |
| REL-001 | Make the project rebuildable from a clean Linux checkout | IN_PROGRESS | S5-001 | `.python-version`, `requirements.lock`, `Dockerfile`, `.env.example`, portable launcher, and README commands are present; release checks are recorded below, with Docker execution blocked by the environment. |

## Evidence rules

1. Every completed implementation task needs an artifact, the exact check or command used, its result, and the date.
2. Generated evidence must identify the scenario and seed; nondeterministic output is insufficient for Session 1.
3. Detection evidence must include the rule ID, matched synthetic event IDs, explanation, and expected negative cases where relevant.
4. Safety evidence must show that the implementation does not inspect the host, access real system telemetry, open sockets, send network traffic, invoke scanning tools, or perform a real port scan.
5. A plan, code review, or fixture alone does not count as an actual implementation check.
6. S1–S4 tasks are marked `DONE` because implementation exists and the exact `pytest` checks ran successfully; S5 remains active until Docker availability is confirmed and the final release review is recorded.

## Rebuildability release evidence

The release hardening checklist for REL-001 is:

- Git repository with history: existing commits are present; this change is committed after final review.
- Dependency lockfile: `requirements.lock` pins every installed Python package.
- Runtime pin: `.python-version` specifies Python `3.12.3`; the Docker base uses the same version.
- Container workflow: `Dockerfile` builds the dashboard image and starts the local-only Flask app.
- Single test command: `pytest`.
- Documentation: `README.md` contains setup, simulator, dashboard, Docker, Compose, and test commands.
- Configuration: `.env.example` contains only non-secret demo settings and `.env` is ignored.
- Portability: the launcher resolves `omnirush.cmd` through `PATH`; no machine-specific absolute path remains in tracked files.
- Remaining verification gap: execute the documented Docker build, container test, and loopback dashboard smoke test on a host with Docker installed.
