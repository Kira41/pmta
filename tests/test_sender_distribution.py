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


def test_normalize_and_partition_recipients_balances_each_domain():
    senders = [f"support@domain{i}.com" for i in range(1, 6)]
    recipients = [
        *(f"u{i}@gmail.com" for i in range(17)),
        *(f"u{i}@yahoo.com" for i in range(11)),
        " bad@",
        "u0@gmail.com",
        "User@GMAIL.com",
        "no-at-sign",
    ]

    buckets, stats = shiva.normalize_and_partition_recipients(recipients, senders, seed="campaign-1")

    assert stats["totals_match"] is True
    assert stats["domain_spread_ok"] is True
    assert stats["invalid_count"] == 2
    assert stats["deduplicated_count"] >= 1

    for domain in ("gmail.com", "yahoo.com"):
        domain_counts = [len((buckets.get(s) or {}).get(domain) or []) for s in senders]
        assert max(domain_counts) - min(domain_counts) <= 1
