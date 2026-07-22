from fastapi.testclient import TestClient

from cyberdeck_api.main import app, reports_dir


client = TestClient(app)


def test_analysis_requires_authorized_scope():
    response = client.post(
        "/api/analysis",
        json={
            "domains": ["example.com"],
            "authorized_scope": False,
            "real_only": True,
            "mode": "snapshot",
            "lookback_days": 30,
        },
    )

    assert response.status_code == 403
    assert "authorized_scope" in response.json()["detail"]


def test_attack_surface_rejects_invalid_domains():
    response = client.get("/api/attack-surface", params={"domains": "not a domain"})

    assert response.status_code == 422
    assert "Invalid domain" in response.json()["detail"]


def test_report_catalog_includes_download_url():
    report_path = reports_dir / "download-test.html"
    report_path.write_text("<html><body>ok</body></html>", encoding="utf-8")
    try:
        response = client.get("/api/reports")
    finally:
        report_path.unlink(missing_ok=True)

    assert response.status_code == 200
    report = next(item for item in response.json() if item["name"] == "download-test.html")
    assert report["download_url"] == "/api/reports/download-test.html/download"


def test_report_download_serves_attachment():
    report_path = reports_dir / "download-test.html"
    report_path.write_text("<html><body>ok</body></html>", encoding="utf-8")
    try:
        response = client.get("/api/reports/download-test.html/download")
    finally:
        report_path.unlink(missing_ok=True)

    assert response.status_code == 200
    assert "attachment" in response.headers["content-disposition"]
    assert response.text == "<html><body>ok</body></html>"


def test_report_download_blocks_path_traversal():
    response = client.get("/api/reports/%2E%2E/pyproject.toml/download")

    assert response.status_code == 404


def test_report_archive_downloads_zip():
    report_path = reports_dir / "archive-test.html"
    report_path.write_text("<html><body>zip</body></html>", encoding="utf-8")
    try:
        response = client.get("/api/reports/archive")
    finally:
        report_path.unlink(missing_ok=True)

    assert response.status_code == 200
    assert response.headers["content-type"] == "application/zip"
    assert "cyberdecisionengine-reports.zip" in response.headers["content-disposition"]


def test_report_delete_removes_only_reports():
    report_path = reports_dir / "delete-test.html"
    report_path.write_text("<html><body>delete</body></html>", encoding="utf-8")
    response = client.delete("/api/reports/delete-test.html")

    assert response.status_code == 200
    assert response.json()["status"] == "deleted"
    assert not report_path.exists()


def test_report_delete_blocks_path_traversal():
    response = client.delete("/api/reports/%2E%2E/pyproject.toml")

    assert response.status_code == 404
