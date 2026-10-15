# MiniSOC Decisions

**Last updated:** 2026-10-15

Status is intentionally conservative: only requirements directly specified for this planning update are **Accepted**. Unresolved technical choices remain **Proposed**.

## Accepted

| ID | Decision | Basis |
|---|---|---|
| D-001 | Session 1 implementation is approved. | Direct user instruction. |
| D-002 | The simulator uses fake/synthetic data only. | Direct user instruction. |
| D-003 | The simulator must never scan the host or any real system. | Direct user instruction. |
| D-004 | Port-scan behavior is represented only by synthetic port-scan events; no real port scanning is performed. | Direct user clarification. |
| D-005 | Use Python 3.12.3 with a `src/` package layout and pinned requirements. | User requirement plus available runtime. |
| D-006 | Use immutable `LogEvent` and `Alert` dataclasses with JSON-friendly alert serialization. | Session 1 implementation contract. |
| D-007 | Parse SSH auth lines, a documented synthetic connection line, Nginx combined lines, and structured JSON fixtures. | Keeps the foundation explainable while supporting required telemetry. |
| D-008 | Normalize aware timestamps to UTC and use inclusive detection windows. | Deterministic threshold semantics. |
| D-009 | Suppress repeated brute-force and port-scan alerts until their active window drops below threshold; emit one alert per malicious HTTP request. | Prevents alert floods while preserving request evidence. |

## Proposed / unresolved

| ID | Question | Current proposal | Resolution gate |
|---|---|---|---|
| D-010 | How should risk scoring combine severity, volume, confidence, and correlation? | Define and test a transparent 0–100 formula in Session 2. | Before risk-scoring implementation. |
| D-011 | What SQLite schema and migration approach should be used? | Use a small standard-library SQLite schema with explicit migrations. | Before storage implementation. |
| D-012 | What UI or report surface is needed after Session 1? | Use a local-only Flask dashboard and Markdown/JSON reports. | Before dashboard/report implementation. |
| D-013 | What is the final export/deployment workflow? | Keep Docker and pinned dependency instructions reproducible. | Before release work. |

No proposed decision may enable live collection, host inspection, real port scanning, network traffic, or access to a real system. Such behavior conflicts with D-002 through D-004.
