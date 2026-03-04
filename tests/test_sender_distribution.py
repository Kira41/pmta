import shiva


def test_map_provider_domains_to_sender_indexes_balances_domain_count():
    providers = [f"d{i}.example" for i in range(50)]
    senders = [f"sender{i}@mail.example" for i in range(5)]

    out = shiva.map_provider_domains_to_sender_indexes(providers, senders)

    assert len(out) == 50
    counts = {i: 0 for i in range(len(senders))}
    for idx in out.values():
        counts[idx] += 1
    assert sorted(counts.values()) == [10, 10, 10, 10, 10]


def test_map_provider_domains_to_sender_indexes_handles_remainder_evenly():
    providers = [f"d{i}.example" for i in range(7)]
    senders = ["a@one.example", "b@two.example", "c@three.example"]

    out = shiva.map_provider_domains_to_sender_indexes(providers, senders)

    counts = {i: 0 for i in range(len(senders))}
    for idx in out.values():
        counts[idx] += 1
    assert sorted(counts.values()) == [2, 2, 3]
