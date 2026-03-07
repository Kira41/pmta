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
