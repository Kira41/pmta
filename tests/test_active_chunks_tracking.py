import shiva


def test_upsert_active_chunk_replaces_same_chunk_without_duplicate():
    job = shiva.SendJob(id='j-lane', created_at=shiva.now_iso(), campaign_id='c-lane')

    job.upsert_active_chunk('0|gmail.com', {'chunk_id': 2, 'size': 100, 'status': 'running'})
    job.upsert_active_chunk('0|gmail.com', {'chunk_id': 2, 'size': 100, 'status': 'backoff', 'attempt': 1})

    assert len(job.active_chunks_info) == 1
    row = job.active_chunks_info[0]
    assert row['lane'] == '0|gmail.com'
    assert row['status'] == 'backoff'
    assert row['attempt'] == 1


def test_upsert_active_chunk_keeps_multiple_chunks_in_same_lane():
    job = shiva.SendJob(id='j-lane-3', created_at=shiva.now_iso(), campaign_id='c-lane-3')

    job.upsert_active_chunk('0|gmail.com', {'chunk_id': 2, 'size': 100, 'status': 'running'})
    job.upsert_active_chunk('0|gmail.com', {'chunk_id': 3, 'size': 120, 'status': 'running'})

    assert len(job.active_chunks_info) == 2
    assert {int(x['chunk_id']) for x in job.active_chunks_info} == {2, 3}


def test_remove_active_chunk_deletes_only_requested_lane():
    job = shiva.SendJob(id='j-lane-2', created_at=shiva.now_iso(), campaign_id='c-lane-2')

    job.upsert_active_chunk('0|gmail.com', {'chunk_id': 1, 'size': 10})
    job.upsert_active_chunk('1|yahoo.com', {'chunk_id': 3, 'size': 12})

    job.remove_active_chunk('0|gmail.com')

    assert len(job.active_chunks_info) == 1
    assert job.active_chunks_info[0]['lane'] == '1|yahoo.com'


def test_remove_active_chunk_deletes_only_requested_chunk_when_chunk_id_provided():
    job = shiva.SendJob(id='j-lane-4', created_at=shiva.now_iso(), campaign_id='c-lane-4')

    job.upsert_active_chunk('0|gmail.com', {'chunk_id': 1, 'size': 10})
    job.upsert_active_chunk('0|gmail.com', {'chunk_id': 2, 'size': 12})

    job.remove_active_chunk('0|gmail.com', 1)

    assert len(job.active_chunks_info) == 1
    assert int(job.active_chunks_info[0]['chunk_id']) == 2



def test_job_api_v2_chunk_payload_is_normalized_and_additive_fields_present():
    client = shiva.app.test_client()
    job = shiva.SendJob(id='job-v2-api-1', created_at=shiva.now_iso(), campaign_id='camp-v2')
    job.debug_parallel_lanes_snapshot = {'mode': 'v2', 'updated_at': shiva.now_iso()}
    job.chunks_total = 6
    job.chunks_done = 2
    job.chunks_backoff = 1
    job.chunks_abandoned = 1
    job.current_chunk = 12
    job.current_chunk_info = {'chunk': '12', 'lane': '1|gmail.com', 'status': 'running', 'sender': 's1@example.com', 'receiver_domain': 'GMAIL.COM', 'attempt': '2', 'size': '50', 'blacklist': None}
    job.active_chunks_info = [
        {'chunk': '12', 'lane': '1|gmail.com', 'status': 'running', 'sender': 's1@example.com', 'receiver_domain': 'gmail.com', 'attempt': '2', 'size': '50', 'spam_score': '4.7', 'blacklist': 'none'},
    ]
    job.chunk_states = [
        {'chunk': '10', 'lane': '0|yahoo.com', 'status': 'done', 'sender': 's0@example.com', 'receiver_domain': 'yahoo.com', 'attempt': 1, 'size': 40, 'spam_score': 3.2, 'blacklist': ''},
        {'chunk': '12', 'lane': '1|gmail.com', 'status': 'backoff', 'sender': 's1@example.com', 'receiver_domain': 'gmail.com', 'attempt': 2, 'size': 50, 'next_retry_ts': 1712345678},
    ]
    job.backoff_items = [
        {'chunk': '12', 'lane': '1|gmail.com', 'status': 'backoff', 'sender': 's1@example.com', 'receiver_domain': 'gmail.com', 'attempt': '2', 'size': '50', 'next_retry_ts': '1712345678'},
    ]

    with shiva.JOBS_LOCK:
        shiva.JOBS[job.id] = job

    resp = client.get(f'/api/job/{job.id}')
    assert resp.status_code == 200
    body = resp.get_json()

    assert body['telemetry_source'] == 'v2'
    assert body['chunk_unique_total'] >= body['chunk_unique_done'] >= 2
    assert body['chunk_attempts_total'] >= body['chunk_unique_done']

    live_row = body['active_chunks_info'][0]
    assert live_row['chunk'] == live_row['chunk_id'] == 12
    assert live_row['lane_id'] == '1|gmail.com'
    assert live_row['status'] == 'running'
    assert live_row['size'] == 50
    assert live_row['sender_mail'] == 's1@example.com'
    assert live_row['target_domain'] == 'gmail.com'
    assert live_row['attempt'] == 2
    assert 'spam_score' in live_row
    assert 'blacklist' in live_row

    assert body['active_chunks_count'] == 1
    assert body['active_backoff_chunks_count'] == 0

    current = body['current_chunk_info']
    assert current['chunk'] == current['chunk_id'] == 12
    assert current['lane_id'] == '1|gmail.com'
    assert current['sender_mail'] == 's1@example.com'
    assert current['target_domain'] == 'gmail.com'


def test_job_api_legacy_chunk_payload_keeps_legacy_fields_without_v2_additions():
    client = shiva.app.test_client()
    job = shiva.SendJob(id='job-legacy-api-1', created_at=shiva.now_iso(), campaign_id='camp-legacy')
    job.debug_parallel_lanes_snapshot = {'mode': 'legacy', 'updated_at': shiva.now_iso()}
    job.chunks_total = 3
    job.chunks_done = 1
    job.current_chunk = 9
    job.current_chunk_info = {'chunk': 9, 'sender': 'legacy@example.com', 'receiver_domain': 'example.net', 'size': 10}

    with shiva.JOBS_LOCK:
        shiva.JOBS[job.id] = job

    resp = client.get(f'/api/job/{job.id}')
    assert resp.status_code == 200
    body = resp.get_json()

    assert body['chunks_total'] == 3
    assert body['chunks_done'] == 1
    assert body['current_chunk'] == 9
    assert body['chunk_unique_total'] is None
    assert body['chunk_unique_done'] is None
    assert body['chunk_attempts_total'] is None
    assert body['telemetry_source'] is None
    assert body['current_chunk_info']['chunk_id'] == 9
    assert body['current_chunk_info']['sender_mail'] == 'legacy@example.com'
    assert body['current_chunk_info']['target_domain'] == 'example.net'


def test_job_api_v2_active_backoff_count_tracks_multiple_live_rows():
    client = shiva.app.test_client()
    job = shiva.SendJob(id='job-v2-api-2', created_at=shiva.now_iso(), campaign_id='camp-v2-2')
    job.debug_parallel_lanes_snapshot = {'mode': 'v2', 'updated_at': shiva.now_iso()}
    job.current_chunk = 99
    job.current_chunk_info = {'chunk': 99, 'status': 'running'}
    job.active_chunks_info = [
        {'chunk': '21', 'lane': '0|gmail.com', 'status': 'backoff', 'sender': 'a@example.com', 'receiver_domain': 'gmail.com', 'attempt': '2', 'size': '20'},
        {'chunk': '22', 'lane': '1|yahoo.com', 'status': 'running', 'sender': 'b@example.com', 'receiver_domain': 'yahoo.com', 'attempt': '1', 'size': '20'},
        {'chunk': '23', 'lane': '2|outlook.com', 'status': 'backoff', 'sender': 'c@example.com', 'receiver_domain': 'outlook.com', 'attempt': '3', 'size': '20'},
    ]

    with shiva.JOBS_LOCK:
        shiva.JOBS[job.id] = job

    resp = client.get(f'/api/job/{job.id}')
    assert resp.status_code == 200
    body = resp.get_json()

    assert body['active_chunks_count'] == 3
    assert body['active_backoff_chunks_count'] == 2
    assert body['current_chunk'] == 99
    assert body['current_chunk_info']['chunk_id'] == 99
