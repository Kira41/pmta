from Shivamini import app


def test_shivamini_routes_render():
    client = app.test_client()
    for path in ["/", "/campaigns", "/send", "/jobs", "/job/job-240301-a", "/config", "/domains"]:
        response = client.get(path)
        assert response.status_code == 200

    html = client.get("/").get_data(as_text=True)
    assert "Dashboard frontend skeleton" in html
    assert "Excel audience workflow" in html
    assert "Operations snapshot" in html
    assert "Dashboard fake notes" in html
    assert "Shivamini" in html

    jobs_html = client.get("/jobs").get_data(as_text=True)
    assert 'aria-label="Shivamini navigation"' in jobs_html
    assert "full `jobs.html` CSS/layout" in jobs_html
    assert 'data-jobid="83b5cd63007e"' in jobs_html
    assert "PMTA Live Panel" in jobs_html
    assert "Chunk preflight" in jobs_html

    send_html = client.get("/send").get_data(as_text=True)
    assert "SMTP Mail Sender" in send_html
    assert "Preflight &amp; Send Controls" in send_html
    assert "Save Domains" in send_html


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
