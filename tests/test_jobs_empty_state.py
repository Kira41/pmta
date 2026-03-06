import shiva


def test_jobs_page_renders_no_jobs_empty_card_when_list_is_empty():
    original_jobs = shiva.JOBS
    shiva.JOBS = {}
    try:
        client = shiva.app.test_client()
        response = client.get('/jobs')
        html = response.get_data(as_text=True)
        assert response.status_code == 200
        assert 'id="jobsListEmpty"' in html
        assert 'display:block' in html
        assert 'No jobs yet.' in html
    finally:
        shiva.JOBS = original_jobs


def test_jobs_page_hides_no_jobs_empty_card_when_jobs_exist():
    original_jobs = shiva.JOBS
    shiva.JOBS = {
        'job-1': shiva.SendJob(id='job-1', created_at=shiva.now_iso(), campaign_id='camp-1', status='done')
    }
    try:
        client = shiva.app.test_client()
        response = client.get('/jobs')
        html = response.get_data(as_text=True)
        assert response.status_code == 200
        assert 'id="jobsListEmpty"' in html
        assert 'display:none' in html
        assert "listEmpty.style.display = cards.length === 0 ? '' : 'none';" in html
    finally:
        shiva.JOBS = original_jobs
