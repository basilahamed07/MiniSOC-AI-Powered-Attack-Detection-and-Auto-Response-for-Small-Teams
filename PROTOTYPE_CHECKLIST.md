# MiniSOC offline prototype checklist

**Scope:** generated sample data only. No real logs, host inspection, sockets
for collection, outbound traffic, real port scans, or host firewall changes.

## Product capabilities

- [x] Parse SSH authentication events.
- [x] Parse synthetic connection events for port-scan demonstrations.
- [x] Parse Nginx combined access logs.
- [x] Parse documented JSON fixtures.
- [x] Detect brute force: 5+ failures from one IP in an inclusive 60-second window.
- [x] Detect synthetic port scan: 10+ distinct ports from one IP in an inclusive 30-second window.
- [x] Detect SQL injection in decoded URL targets.
- [x] Detect path traversal in decoded URL paths.
- [x] Produce structured alerts with evidence.
- [x] Generate deterministic normal and attack sample data.
- [x] Calculate transparent 0–100 risk scores.
- [x] Add MITRE ATT&CK tags.
- [x] Group same-IP alerts into deterministic incidents.
- [x] Persist synthetic snapshots to SQLite.
- [x] Run offline Isolation Forest anomaly scoring.
- [x] Return simulated block decisions without changing the host.
- [x] Render a local Flask dashboard and JSON API.
- [x] Export JSON and Markdown reports.

## Verification evidence

- [x] `python3 -m pytest` — 32 tests passed in the Linux validation container on Python 3.11.2.
- [x] `python3 -m compileall -q src tests` — passed.
- [x] `python3 -m pip check` — no broken requirements.
- [x] 100/100 seeded mixed scenarios detected all four attack types.
- [x] 1,000 normal generated lines produced zero alerts.
- [x] `PYTHONPATH=src python3 src/minisoc/attack_simulator.py --seed 20261015` run twice; both outputs were byte-identical at 5,819 bytes.
- [x] Source AST review found no live network or scanning imports.
- [x] `git diff --check` passes for new and changed MiniSOC files.
- [x] Local dashboard smoke test on `127.0.0.1:18002` passed for `/healthz`, `/dashboard`, and `/reports/markdown`.
- [ ] Python 3.12.3 test run — not run: only Python 3.11.2 is available in the current validation container.
- [ ] Docker image build and container smoke test — not run: Docker CLI is unavailable in the current validation container.
- [ ] Compose smoke test — not run: Docker CLI is unavailable in the current validation container.
- [x] Tracked-file portability and secret scan — no machine-specific absolute paths or secret assignments found; the launcher resolves `omnirush.cmd` through `PATH`.

## Prototype boundaries still intentionally unfinished

- [ ] Live log ingestion.
- [ ] Real network or endpoint collection.
- [ ] Real firewall or IP blocking.
- [ ] Production authentication and multi-user triage.
- [ ] Production deployment or external alerting.
