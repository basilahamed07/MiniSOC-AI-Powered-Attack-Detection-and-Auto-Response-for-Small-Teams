from minisoc.app import create_app


def test_dashboard_and_health_endpoints_use_sample_data_only() -> None:
    app = create_app()
    app.config.update(TESTING=True)
    client = app.test_client()

    health = client.get("/healthz")
    dashboard = client.get("/dashboard?scenario=mixed&seed=20261015")
    api = client.get("/api/snapshot?scenario=mixed&seed=20261015")

    assert health.status_code == 200
    assert health.get_json()["network_collection"] is False
    assert dashboard.status_code == 200
    assert b"Synthetic security operations" in dashboard.data
    assert b"sql injection" in dashboard.data.lower()
    assert b"Top attackers" in dashboard.data
    assert b"Incident timeline" in dashboard.data
    assert api.status_code == 200
    assert api.get_json()["summary"]["alert_count"] == 4


def test_dashboard_normal_and_invalid_states() -> None:
    app = create_app()
    app.config.update(TESTING=True)
    client = app.test_client()

    normal = client.get("/dashboard?scenario=normal&seed=20261015")
    invalid = client.get("/dashboard?scenario=live&seed=20261015")
    bad_seed = client.get("/api/snapshot?scenario=mixed&seed=not-a-number")

    assert normal.status_code == 200
    assert b"No detections in this synthetic run" in normal.data
    assert invalid.status_code == 400
    assert bad_seed.status_code == 400


def test_alert_detail_and_reports_are_available() -> None:
    app = create_app()
    app.config.update(TESTING=True)
    client = app.test_client()

    detail = client.get("/alerts/alert-001?scenario=mixed&seed=20261015")
    json_report = client.get("/reports/json?scenario=mixed&seed=20261015")
    markdown_report = client.get("/reports/markdown?scenario=mixed&seed=20261015")
    invalid_report = client.get("/reports/xml?scenario=mixed&seed=20261015")
    missing = client.get("/alerts/alert-999?scenario=mixed&seed=20261015")

    assert detail.status_code == 200
    assert b"Evidence chain" in detail.data
    assert json_report.status_code == 200
    assert json_report.json["scenario"] == "mixed"
    assert markdown_report.status_code == 200
    assert b"MiniSOC Synthetic Incident Report" in markdown_report.data
    assert b"ssh:5" in markdown_report.data
    assert invalid_report.status_code == 400
    assert missing.status_code == 404


def test_database_backed_app_rejects_sqlite_overflow_seed(tmp_path) -> None:
    app = create_app(db_path=tmp_path / "snapshot.sqlite3")
    app.config.update(TESTING=True)

    response = app.test_client().get(
        "/api/snapshot?scenario=mixed&seed=999999999999999999999999999999"
    )

    assert response.status_code == 400
    assert "signed 64-bit" in response.get_json()["error"]
