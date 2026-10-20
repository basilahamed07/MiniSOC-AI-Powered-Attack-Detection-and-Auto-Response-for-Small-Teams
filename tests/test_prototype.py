from pathlib import Path

from minisoc.attack_simulator import DEFAULT_SEED
from minisoc.incidents import group_incidents, enrich_alerts
from minisoc.models import Alert
from minisoc.response import simulate_auto_block
from minisoc.reporting import export_json, export_markdown
from minisoc.scoring import risk_score
from minisoc.storage import SQLiteStore
from minisoc.workflow import build_snapshot


def test_mixed_snapshot_has_full_prototype_enrichment() -> None:
    snapshot = build_snapshot(seed=DEFAULT_SEED)

    assert len(snapshot.events) == 57
    assert len(snapshot.alerts) == 4
    assert len(snapshot.incidents) == 4
    assert {alert.mitre_id for alert in snapshot.alerts} == {"T1110", "T1046", "T1190"}
    assert all(0 <= alert.risk_score <= 100 for alert in snapshot.alerts)
    assert {action.ip for action in snapshot.responses} == {
        "198.51.100.10",
        "198.51.100.20",
        "203.0.113.10",
        "203.0.113.20",
    }
    assert all(action.status == "simulated" for action in snapshot.responses)


def test_normal_snapshot_has_no_alerts_or_simulated_blocks() -> None:
    snapshot = build_snapshot(scenario="normal", seed=DEFAULT_SEED)

    assert len(snapshot.events) == 40
    assert snapshot.alerts == ()
    assert snapshot.incidents == ()
    assert snapshot.responses == ()


def test_risk_score_is_bounded_and_evidence_sensitive() -> None:
    snapshot = build_snapshot()
    sql = next(item.alert for item in snapshot.alerts if item.alert.attack_type == "sql_injection")
    brute = next(item.alert for item in snapshot.alerts if item.alert.attack_type == "brute_force")

    assert risk_score(sql) == 85
    assert risk_score(brute) == 73
    assert all(0 <= risk_score(item.alert) <= 100 for item in snapshot.alerts)


def test_incidents_group_same_ip_deterministically() -> None:
    snapshot = build_snapshot()
    enriched = enrich_alerts([item.alert for item in snapshot.alerts])
    assigned, incidents = group_incidents(enriched)

    assert [incident.incident_id for incident in incidents] == [
        "inc-9ca3fbe5f7a3",
        "inc-e2203b078f4a",
        "inc-df592e02759b",
        "inc-a76da8e31995",
    ]
    assert {item.incident_id for item in assigned} == {
        incident.incident_id for incident in incidents
    }


def test_same_timestamp_alert_order_is_canonical() -> None:
    timestamp = next(iter(build_snapshot().alerts)).alert.timestamp
    first = Alert(
        ip="198.51.100.77",
        attack_type="sql_injection",
        timestamp=timestamp,
        severity="high",
        evidence=({"event_id": "event-b", "raw": "b"},),
    )
    second = Alert(
        ip="198.51.100.77",
        attack_type="sql_injection",
        timestamp=timestamp,
        severity="high",
        evidence=({"event_id": "event-a", "raw": "a"},),
    )

    forward = enrich_alerts([first, second])
    reverse = enrich_alerts([second, first])

    assert [item.alert.evidence[0]["event_id"] for item in forward] == [
        "event-a",
        "event-b",
    ]
    assert [item.reference for item in forward] == [item.reference for item in reverse]


def test_sqlite_round_trip_persists_sample_snapshot() -> None:
    snapshot = build_snapshot()
    with SQLiteStore() as store:
        store.save_snapshot(snapshot)
        assert len(store.rows("events")) == len(snapshot.events)
        assert len(store.rows("alerts")) == len(snapshot.alerts)
        assert len(store.rows("incidents")) == len(snapshot.incidents)
        assert len(store.rows("anomalies")) == len(snapshot.anomalies)
        assert len(store.rows("responses")) == len(snapshot.responses)
        assert store.rows("alerts")[0]["mitre_id"] == "T1110"
        restored = store.load_snapshot()
        assert restored.scenario == snapshot.scenario
        assert restored.seed == snapshot.seed
        assert restored.to_dict() == snapshot.to_dict()


def test_sqlite_file_round_trip_preserves_metadata_and_anomaly_scores(tmp_path: Path) -> None:
    database = tmp_path / "sample.sqlite3"
    snapshot = build_snapshot()
    with SQLiteStore(database) as store:
        store.save_snapshot(snapshot)
    with SQLiteStore(database) as store:
        restored = store.load_snapshot()
        assert restored.to_dict() == snapshot.to_dict()


def test_reports_are_created_from_synthetic_snapshot(tmp_path: Path) -> None:
    snapshot = build_snapshot()
    json_path = export_json(snapshot, tmp_path / "report.json")
    markdown_path = export_markdown(snapshot, tmp_path / "report.md")

    assert "synthetic" in json_path.read_text(encoding="utf-8").lower() or "scenario" in json_path.read_text(encoding="utf-8")
    markdown = markdown_path.read_text(encoding="utf-8")
    assert "MiniSOC Synthetic Incident Report" in markdown
    assert "alert-001" in markdown
    assert "ssh:5" in markdown
    assert "Incident timelines" in markdown


def test_auto_block_is_only_a_simulated_decision() -> None:
    snapshot = build_snapshot()
    actions = simulate_auto_block(snapshot.alerts)

    assert actions
    assert all(action.action == "block_ip" for action in actions)
    assert all(action.status == "simulated" for action in actions)
    assert all("risk_score" in action.reason for action in actions)
