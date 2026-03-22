from Shivamini import app


def test_shivamini_routes_render():
    client = app.test_client()
    for path in ["/", "/campaigns", "/jobs", "/job/job-240301-a", "/config", "/domains"]:
        response = client.get(path)
        assert response.status_code == 200

    html = client.get("/").get_data(as_text=True)
    assert "Dashboard frontend skeleton" in html
    assert "Shivamini" in html


def test_shivamini_api_payloads():
    client = app.test_client()

    dashboard = client.get("/api/dashboard")
    assert dashboard.status_code == 200
    dashboard_json = dashboard.get_json()
    assert dashboard_json["campaign"]["id"] == "cmp-demo-001"
    assert len(dashboard_json["kpis"]) >= 4

    job = client.get("/api/job/job-240301-a")
    assert job.status_code == 200
    job_json = job.get_json()
    assert job_json["job_id"] == "job-240301-a"
    assert len(job_json["chunks"]) >= 1
