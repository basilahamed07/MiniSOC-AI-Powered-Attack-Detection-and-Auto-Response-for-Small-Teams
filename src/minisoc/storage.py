"""Small SQLite repository for reproducible synthetic snapshots."""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime
from pathlib import Path

from .anomaly import Anomaly
from .incidents import EnrichedAlert, Incident
from .models import Alert, LogEvent
from .response import ResponseAction
from .workflow import Snapshot


def _datetime(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


class SQLiteStore:
    """Persist a prototype snapshot using only the Python standard library."""

    def __init__(self, path: str | Path = ":memory:") -> None:
        self.path = str(path)
        self.connection = sqlite3.connect(self.path)
        self.connection.row_factory = sqlite3.Row
        self.initialise()

    def initialise(self) -> None:
        self.connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS events (
                event_id TEXT PRIMARY KEY, source TEXT NOT NULL, timestamp TEXT NOT NULL,
                ip TEXT NOT NULL, event_type TEXT NOT NULL, raw TEXT NOT NULL,
                port INTEGER, target TEXT, method TEXT, status INTEGER,
                username TEXT, metadata_json TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS alerts (
                reference TEXT PRIMARY KEY, ip TEXT NOT NULL, attack_type TEXT NOT NULL,
                timestamp TEXT NOT NULL, severity TEXT NOT NULL, evidence_json TEXT NOT NULL,
                risk_score INTEGER NOT NULL, mitre_id TEXT NOT NULL, mitre_name TEXT NOT NULL,
                status TEXT NOT NULL, incident_id TEXT, anomaly_score REAL
            );
            CREATE TABLE IF NOT EXISTS incidents (
                incident_id TEXT PRIMARY KEY, ip TEXT NOT NULL, alert_references_json TEXT NOT NULL,
                attack_types_json TEXT NOT NULL, risk_score INTEGER NOT NULL, status TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS anomalies (
                ip TEXT PRIMARY KEY, score REAL NOT NULL, is_anomaly INTEGER NOT NULL,
                features_json TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS responses (
                action_id TEXT PRIMARY KEY, ip TEXT NOT NULL, action TEXT NOT NULL,
                status TEXT NOT NULL, reason TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS snapshot_meta (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                scenario TEXT NOT NULL,
                seed INTEGER NOT NULL
            );
            """
        )
        columns = {
            row[1] for row in self.connection.execute("PRAGMA table_info(alerts)")
        }
        if "anomaly_score" not in columns:
            self.connection.execute("ALTER TABLE alerts ADD COLUMN anomaly_score REAL")
        self.connection.commit()

    def save_snapshot(self, snapshot: Snapshot) -> None:
        """Replace the stored sample snapshot atomically."""

        if not -(2**63) <= snapshot.seed <= (2**63 - 1):
            raise ValueError("seed must fit SQLite's signed 64-bit integer range")
        with self.connection:
            for table in (
                "events",
                "alerts",
                "incidents",
                "anomalies",
                "responses",
                "snapshot_meta",
            ):
                self.connection.execute(f"DELETE FROM {table}")
            self.connection.execute(
                "INSERT INTO snapshot_meta (id, scenario, seed) VALUES (1, ?, ?)",
                (snapshot.scenario, snapshot.seed),
            )
            for event in snapshot.events:
                self.connection.execute(
                    """INSERT INTO events
                    (event_id, source, timestamp, ip, event_type, raw, port, target,
                     method, status, username, metadata_json)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        event.event_id,
                        event.source,
                        event.timestamp.isoformat(),
                        event.ip,
                        event.event_type,
                        event.raw,
                        event.port,
                        event.target,
                        event.method,
                        event.status,
                        event.username,
                        json.dumps(dict(event.metadata), sort_keys=True),
                    ),
                )
            for alert in snapshot.alerts:
                self.connection.execute(
                    """INSERT INTO alerts
                    (reference, ip, attack_type, timestamp, severity, evidence_json,
                     risk_score, mitre_id, mitre_name, status, incident_id, anomaly_score)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        alert.reference,
                        alert.alert.ip,
                        alert.alert.attack_type,
                        alert.alert.timestamp.isoformat(),
                        alert.alert.severity,
                        json.dumps(alert.alert.to_dict()["evidence"], sort_keys=True),
                        alert.risk_score,
                        alert.mitre_id,
                        alert.mitre_name,
                        alert.status,
                        alert.incident_id,
                        alert.anomaly_score,
                    ),
                )
            for incident in snapshot.incidents:
                self.connection.execute(
                    """INSERT INTO incidents
                    (incident_id, ip, alert_references_json, attack_types_json,
                     risk_score, status)
                    VALUES (?, ?, ?, ?, ?, ?)""",
                    (
                        incident.incident_id,
                        incident.ip,
                        json.dumps(incident.alert_references),
                        json.dumps(incident.attack_types),
                        incident.risk_score,
                        incident.status,
                    ),
                )
            for anomaly in snapshot.anomalies:
                self.connection.execute(
                    "INSERT INTO anomalies (ip, score, is_anomaly, features_json) VALUES (?, ?, ?, ?)",
                    (anomaly.ip, anomaly.score, int(anomaly.is_anomaly), json.dumps(anomaly.features)),
                )
            for response in snapshot.responses:
                self.connection.execute(
                    "INSERT INTO responses (action_id, ip, action, status, reason) VALUES (?, ?, ?, ?, ?)",
                    (response.action_id, response.ip, response.action, response.status, response.reason),
                )

    def load_snapshot(self) -> Snapshot:
        """Reconstruct the last saved synthetic snapshot from SQLite."""

        self.connection.execute("BEGIN")
        try:
            metadata = self.connection.execute(
                "SELECT scenario, seed FROM snapshot_meta WHERE id = 1"
            ).fetchone()
            event_rows = list(self.connection.execute("SELECT * FROM events ORDER BY rowid"))
            alert_rows = list(self.connection.execute("SELECT * FROM alerts ORDER BY rowid"))
            incident_rows = list(
                self.connection.execute("SELECT * FROM incidents ORDER BY rowid")
            )
            anomaly_rows = list(
                self.connection.execute("SELECT * FROM anomalies ORDER BY rowid")
            )
            response_rows = list(
                self.connection.execute("SELECT * FROM responses ORDER BY rowid")
            )
        except Exception:
            self.connection.rollback()
            raise
        self.connection.rollback()
        if metadata is None:
            raise ValueError("no snapshot has been saved")

        events = tuple(
            LogEvent(
                event_id=row["event_id"],
                source=row["source"],
                timestamp=_datetime(row["timestamp"]),
                ip=row["ip"],
                event_type=row["event_type"],
                raw=row["raw"],
                port=row["port"],
                target=row["target"],
                method=row["method"],
                status=row["status"],
                username=row["username"],
                metadata=json.loads(row["metadata_json"]),
            )
            for row in event_rows
        )
        alerts: list[EnrichedAlert] = []
        for row in alert_rows:
            raw_alert = Alert(
                ip=row["ip"],
                attack_type=row["attack_type"],
                timestamp=_datetime(row["timestamp"]),
                severity=row["severity"],
                evidence=tuple(json.loads(row["evidence_json"])),
            )
            alerts.append(
                EnrichedAlert(
                    reference=row["reference"],
                    alert=raw_alert,
                    risk_score=row["risk_score"],
                    mitre_id=row["mitre_id"],
                    mitre_name=row["mitre_name"],
                    status=row["status"],
                    incident_id=row["incident_id"],
                    anomaly_score=row["anomaly_score"],
                )
            )
        incidents = tuple(
            Incident(
                incident_id=row["incident_id"],
                ip=row["ip"],
                alert_references=tuple(json.loads(row["alert_references_json"])),
                attack_types=tuple(json.loads(row["attack_types_json"])),
                risk_score=row["risk_score"],
                status=row["status"],
            )
            for row in incident_rows
        )
        anomalies = tuple(
            Anomaly(
                ip=row["ip"],
                score=float(row["score"]),
                is_anomaly=bool(row["is_anomaly"]),
                features=tuple(json.loads(row["features_json"])),
            )
            for row in anomaly_rows
        )
        responses = tuple(
            ResponseAction(
                action_id=row["action_id"],
                ip=row["ip"],
                action=row["action"],
                status=row["status"],
                reason=row["reason"],
            )
            for row in response_rows
        )
        return Snapshot(
            scenario=metadata["scenario"],
            seed=metadata["seed"],
            events=events,
            alerts=tuple(alerts),
            incidents=incidents,
            anomalies=anomalies,
            responses=responses,
        )

    def rows(self, table: str) -> list[dict[str, object]]:
        if table not in {
            "events",
            "alerts",
            "incidents",
            "anomalies",
            "responses",
            "snapshot_meta",
        }:
            raise ValueError("unsupported table")
        return [dict(row) for row in self.connection.execute(f"SELECT * FROM {table} ORDER BY rowid")]

    def close(self) -> None:
        self.connection.close()

    def __enter__(self) -> "SQLiteStore":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()
