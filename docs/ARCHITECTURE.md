# MiniSOC Architecture

**Status:** Session 1 foundation implemented; later persistence and analyst components remain proposed.

## Boundary

MiniSOC is an offline pipeline operating on generated fixtures. It has no live collector and no permission to inspect or scan the host or any real system. Every host, user, address, process, and port in a scenario is a synthetic identifier or value.

## Logical components

1. **Scenario generator (Session 1)** — emits deterministic fake events for named scenarios, including a synthetic port-scan scenario.
2. **Fixture repository (Session 1)** — stores small, reviewable input examples and expected outcomes.
3. **Parser adapters (Session 1)** — convert SSH auth, synthetic connection, Nginx combined, and structured JSON fixture lines into canonical events.
4. **Normalizer and validator (Session 1)** — validates required fields, normalizes types/time values to aware UTC values, and safely skips malformed events.
5. **Detection engine (Session 1)** — evaluates normalized event windows for brute force, synthetic port scan, SQL injection, and path traversal.
6. **Alert and correlation layer (later)** — groups related detections, deduplicates alerts, and builds incident timelines.
7. **Analyst presentation (later)** — provides event search, alert triage, explanations, and evidence views.
8. **Offline report/export (later)** — produces reproducible synthetic evidence summaries.

## Conceptual flow

```text
scenario name + seed
        |
        v
synthetic generator -> fixture/event stream -> parser adapters
                                               |
                                               v
                                  normalized canonical events
                                               |
                                               v
                                  detection rules + evidence
                                               |
                                               v
                              alerts/incidents -> analyst views
```

The generator must be injectable into the pipeline as a data source. It must not discover its environment or call operating-system/network APIs. The synthetic port-scan scenario emits event records; it never performs a scan.

## Initial contracts

The implemented `LogEvent` carries `event_id`, `source`, UTC `timestamp`, source `ip`, `event_type`, raw provenance, and optional port, target, method, status, username, and metadata fields. The implemented `Alert` carries the required `ip`, `attack_type`, `timestamp`, `severity`, and ordered `evidence` fields and serializes to JSON-friendly values.

Risk score, ATT&CK technique, incident ID, and persistence fields are later extensions and remain **Proposed** in `docs/DECISIONS.md`.

## Design properties

- **Deterministic:** the same scenario and seed produce the same fixture stream.
- **Explainable:** each detection identifies the rule and matched evidence.
- **Offline:** all checks run against bundled or generated fake data.
- **Composable:** parsers, normalization, and detections can be tested independently.
- **Safe by construction:** no live collection, host scanning, socket access, or real port scanning path exists.

## Deferred architecture

Live integrations, real endpoint/network collection, real port scanning, production-scale storage, authentication, deployment topology, and external alerting are outside the MiniSOC scope defined here.
