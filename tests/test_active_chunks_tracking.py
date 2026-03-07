import shiva


def test_upsert_active_chunk_replaces_same_lane_without_duplicate():
    job = shiva.SendJob(id='j-lane', created_at=shiva.now_iso(), campaign_id='c-lane')

    job.upsert_active_chunk('0|gmail.com', {'chunk_id': 2, 'size': 100, 'status': 'running'})
    job.upsert_active_chunk('0|gmail.com', {'chunk_id': 2, 'size': 100, 'status': 'backoff', 'attempt': 1})

    assert len(job.active_chunks_info) == 1
    row = job.active_chunks_info[0]
    assert row['lane'] == '0|gmail.com'
    assert row['status'] == 'backoff'
    assert row['attempt'] == 1


def test_remove_active_chunk_deletes_only_requested_lane():
    job = shiva.SendJob(id='j-lane-2', created_at=shiva.now_iso(), campaign_id='c-lane-2')

    job.upsert_active_chunk('0|gmail.com', {'chunk_id': 1, 'size': 10})
    job.upsert_active_chunk('1|yahoo.com', {'chunk_id': 3, 'size': 12})

    job.remove_active_chunk('0|gmail.com')

    assert len(job.active_chunks_info) == 1
    assert job.active_chunks_info[0]['lane'] == '1|yahoo.com'
