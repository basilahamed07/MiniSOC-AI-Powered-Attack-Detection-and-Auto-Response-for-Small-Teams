# MiniSOC Decisions

**Last updated:** 2026-10-15

Decisions used by the local prototype are **Accepted for prototype**. Production-only choices remain **Proposed** and must not weaken the fake-data-only safety boundary.

## Accepted constraints

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
| D-010 | Use transparent rule baselines of brute force 65, port scan 50, SQL injection 85, and path traversal 75, plus up to 15 evidence-volume points, capped at 100. | Explainable prototype scoring. |
| D-011 | Map brute force to T1110, port scan to T1046, and web exploitation rules to T1190. | Stable prototype ATT&CK tags. |
| D-012 | Group alerts with the same synthetic source IP into one deterministic incident. | Simple local analyst workflow. |
| D-013 | Persist snapshots with standard-library SQLite and replace the current sample snapshot atomically. | Offline, reproducible storage. |
| D-014 | Use scikit-learn Isolation Forest with fixed random state 42 over per-IP synthetic aggregate features. | Offline anomaly prototype without external AI services. |
| D-015 | Auto-blocking returns `simulated` actions for risk scores at least 65 and never changes the host. | Safe response demonstration. |
| D-016 | Use a local-only Flask dashboard with generated mixed/normal scenarios and JSON/Markdown reports. | Small, explainable prototype surface. |

## Accepted for prototype

The prototype implementation uses D-005 through D-016 below. These decisions are accepted for the local sample-data build only; they do not authorize live collection or production deployment.

## Proposed / unresolved

| ID | Question | Current proposal | Resolution gate |
|---|---|---|---|
| D-017 | Should the prototype add authentication, live ingestion, or multi-user deployment? | No; keep these outside the fake-data-only prototype. | Future product scope decision. |
| D-018 | What is the final production deployment workflow? | Not defined; Docker currently demonstrates the local sample-data dashboard. | Future release decision. |

No proposed decision may enable live collection, host inspection, real port scanning, network traffic, or access to a real system. Such behavior conflicts with D-002 through D-004.
