# MiniSOC Project Instructions

## Current status

- The offline prototype is complete for the planned local sample-data workflow: parsers, detections, alerts, scoring, incidents, SQLite, ML anomaly scoring, simulated response, dashboard, and reports.
- Future work is polish and release hardening; live collection remains out of scope.
- The launcher is a convenience wrapper outside the application; it must resolve `omnirush.cmd` through `PATH` and must not embed machine-specific paths.

## Non-negotiable simulator boundary

The simulator and analysis pipeline use fake, deterministic data only. They must never inspect the local machine, open collection sockets, send outbound traffic, invoke port-scanning tools, or access any real system. The local Flask dashboard may listen on a loopback/demo port only to serve synthetic results; it must not collect live data. Port-scan behavior is represented only by synthetic port-scan events produced by the simulator or fixtures.

Any future live collection, host inspection, or real port scanning is outside MiniSOC scope. A feature is not complete if it requires such access.

## Product scope

MiniSOC is planned as a small, explainable security-operations workflow for generated telemetry:

1. Generate repeatable synthetic security events and scenarios.
2. Parse supported event formats into a canonical event model.
3. Normalize, validate, and retain events for analysis.
4. Run transparent detections for suspicious activity, including synthetic port-scan behavior.
5. Create, correlate, prioritize, and triage alerts/incidents.
6. Provide analyst views for event search, alert state, incident timelines, and evidence.
7. Export or summarize synthetic evidence for demonstrations and offline checks.

The full-scope baseline is detailed in `docs/PROJECT_MEMORY.md` and `docs/ARCHITECTURE.md`.

## Working rules

- Keep implementation offline and reproducible.
- Prefer small, testable components with explicit input and output contracts.
- Keep technical choices marked **Proposed** until they are explicitly accepted.
- Record task IDs, artifacts, checks, and results in `docs/TASKS.md`.
- Record decisions and their status in `docs/DECISIONS.md`.
- Do not claim implementation completion without the evidence required by the task.
- Planned checks and actual checks are separate; only commands recorded as executed may be marked **Passed**.
- The test command is `pytest`.
