import shiva


def test_push_chunk_state_updates_running_entry_to_done_without_duplicate():
    job = shiva.SendJob(id='j1', created_at=shiva.now_iso(), campaign_id='c1')

    job.push_chunk_state({
        'chunk': 3,
        'status': 'running',
        'target_domain': 'gmail.com',
        'attempt': 0,
        'size': 10,
    })
    job.push_chunk_state({
        'chunk': 3,
        'status': 'done',
        'target_domain': 'gmail.com',
        'attempt': 0,
        'size': 10,
    })

    assert len(job.chunk_states) == 1
    assert job.chunk_states[0]['status'] == 'done'


def test_push_chunk_state_appends_done_when_running_entry_not_found():
    job = shiva.SendJob(id='j2', created_at=shiva.now_iso(), campaign_id='c2')

    job.push_chunk_state({
        'chunk': 4,
        'status': 'done',
        'target_domain': 'yahoo.com',
        'attempt': 0,
        'size': 8,
    })

    assert len(job.chunk_states) == 1
    assert job.chunk_states[0]['status'] == 'done'
