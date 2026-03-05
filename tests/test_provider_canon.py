import shiva


def test_canonical_provider_alias_suffix_and_unknown():
    assert shiva.canonical_provider(
        "gmail.com",
        alias_map={"gmail.com": "google"},
        suffix_map={"example.com": "example"},
        unknown_group="other",
    ) == "google"
    assert shiva.canonical_provider(
        "mx.mail.example.com",
        alias_map={},
        suffix_map={"example.com": "example"},
        unknown_group="other",
    ) == "example"
    assert shiva.canonical_provider("unknown.tld", unknown_group="other") == "other"


def test_canonical_provider_mx_fingerprint_optional():
    mx_hosts = ["gmail-smtp-in.l.google.com"]
    assert shiva.canonical_provider("random.tld", mx_hosts, use_mx_fingerprint=False, unknown_group="other") == "other"
    assert shiva.canonical_provider("random.tld", mx_hosts, use_mx_fingerprint=True, unknown_group="other") == "google"


def test_budget_manager_provider_group_resolver_enforces_shared_cap():
    cfg = shiva.BudgetConfig(enabled=True, provider_max_inflight_default=1)
    canon = shiva.ProviderCanon.from_env(
        enabled=True,
        enforce=True,
        export=False,
        debug=False,
        alias_json='{"hotmail.com":"microsoft","outlook.com":"microsoft"}',
        suffix_json="",
        use_mx_fingerprint=False,
        unknown_group="other",
    )
    bm = shiva.BudgetManager(cfg, provider_key_resolver=canon.lane_provider_key)
    bm.on_start((0, "hotmail.com"), 1.0)
    allow, reason = bm.can_start((0, "outlook.com"), 2.0, False, False)
    assert allow is False
    assert reason == "provider_inflight_cap"
