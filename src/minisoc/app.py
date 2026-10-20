"""Local-only Flask dashboard for the synthetic MiniSOC prototype."""

from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path
from typing import Iterable

from flask import Flask, Response, jsonify, redirect, render_template, request, url_for

from .attack_simulator import DEFAULT_SEED
from .reporting import export_markdown
from .storage import SQLiteStore
from .workflow import Snapshot, build_snapshot


def create_app(
    db_path: str | Path | None = None,
    default_seed: int = DEFAULT_SEED,
    default_scenario: str = "mixed",
) -> Flask:
    """Create a read-only dashboard that only renders generated sample data."""

    app = Flask(__name__, template_folder="templates")

    def get_snapshot() -> Snapshot:
        scenario = request.args.get("scenario", default_scenario)
        seed_text = request.args.get("seed", str(default_seed))
        try:
            seed = int(seed_text)
        except ValueError as exc:
            raise ValueError("seed must be an integer") from exc
        snapshot = build_snapshot(scenario=scenario, seed=seed)
        if db_path is not None:
            with SQLiteStore(db_path) as store:
                store.save_snapshot(snapshot)
        return snapshot

    @app.get("/")
    def index() -> Response:
        return redirect(url_for("dashboard"))

    @app.get("/healthz")
    def healthz() -> Response:
        return jsonify({"status": "ok", "mode": "synthetic-only", "network_collection": False})

    @app.get("/api/snapshot")
    def api_snapshot() -> Response:
        try:
            return jsonify(get_snapshot().to_dict())
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 400

    @app.get("/dashboard")
    def dashboard() -> str | tuple[str, int]:
        try:
            snapshot = get_snapshot()
        except ValueError as exc:
            return render_template("error.html", message=str(exc)), 400
        filters = {
            "severity": request.args.get("severity", ""),
            "attack_type": request.args.get("attack_type", ""),
            "ip": request.args.get("ip", ""),
        }
        alerts = [
            alert
            for alert in snapshot.alerts
            if (not filters["severity"] or alert.alert.severity == filters["severity"])
            and (not filters["attack_type"] or alert.alert.attack_type == filters["attack_type"])
            and (not filters["ip"] or alert.alert.ip == filters["ip"])
        ]
        top_attackers = [
            {"ip": ip, "alert_count": count}
            for ip, count in Counter(item.alert.ip for item in snapshot.alerts).most_common()
        ]
        timeline = sorted(
            (
                {
                    "timestamp": item.alert.timestamp,
                    "reference": item.reference,
                    "attack_type": item.alert.attack_type,
                    "ip": item.alert.ip,
                }
                for item in snapshot.alerts
            ),
            key=lambda item: item["timestamp"],
        )
        summary = snapshot.to_dict()["summary"]
        return render_template(
            "dashboard.html",
            snapshot=snapshot,
            summary=summary,
            alerts=alerts,
            filters=filters,
            top_attackers=top_attackers,
            timeline=timeline,
        )

    @app.get("/alerts/<reference>")
    def alert_detail(reference: str) -> str | tuple[str, int]:
        try:
            snapshot = get_snapshot()
        except ValueError as exc:
            return render_template("error.html", message=str(exc)), 400
        alert = next((item for item in snapshot.alerts if item.reference == reference), None)
        if alert is None:
            return render_template("error.html", message="alert reference was not found"), 404
        return render_template("alert.html", snapshot=snapshot, alert=alert)

    @app.get("/reports/<report_format>")
    def report(report_format: str) -> Response | tuple[str, int]:
        if report_format not in {"json", "markdown"}:
            return jsonify({"error": "format must be json or markdown"}), 400
        try:
            snapshot = get_snapshot()
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 400
        if report_format == "json":
            return Response(
                json.dumps(snapshot.to_dict(), indent=2, sort_keys=True) + "\n",
                mimetype="application/json",
                headers={"Content-Disposition": "attachment; filename=minisoc-report.json"},
            )
        if report_format == "markdown":
            from tempfile import TemporaryDirectory

            with TemporaryDirectory() as directory:
                path = export_markdown(snapshot, Path(directory) / "report.md")
                content = path.read_text(encoding="utf-8")
            return Response(
                content,
                mimetype="text/markdown",
                headers={"Content-Disposition": "attachment; filename=minisoc-report.md"},
            )


    return app


def main(argv: Iterable[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="127.0.0.1", help="local bind host")
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--seed", type=int, default=DEFAULT_SEED)
    parser.add_argument("--scenario", choices=("mixed", "normal"), default="mixed")
    parser.add_argument("--db", type=Path)
    args = parser.parse_args(list(argv) if argv is not None else None)
    app = create_app(
        db_path=args.db,
        default_seed=args.seed,
        default_scenario=args.scenario,
    )
    app.run(host=args.host, port=args.port, debug=False, use_reloader=False)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
