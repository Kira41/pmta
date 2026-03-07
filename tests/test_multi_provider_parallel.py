import shiva


def test_multi_provider_parallel_disabled_by_flag():
    out = shiva._should_enable_multi_provider_parallel(
        flag_enabled=False,
        sender_count=5,
        provider_domain_count=3,
        lane_parallel_limit=8,
        allow_single_provider=False,
        force_disable_concurrency=False,
    )
    assert out["enabled"] is False
    assert out["reason"] == "feature_flag_off"
    assert out["fallback_to_sequential"] is True


def test_multi_provider_parallel_disabled_for_single_provider():
    out = shiva._should_enable_multi_provider_parallel(
        flag_enabled=True,
        sender_count=5,
        provider_domain_count=1,
        lane_parallel_limit=8,
        allow_single_provider=False,
        force_disable_concurrency=False,
    )
    assert out["enabled"] is False
    assert out["reason"] == "single_provider"


def test_multi_provider_parallel_enabled_and_capped_by_lane_limit():
    out = shiva._should_enable_multi_provider_parallel(
        flag_enabled=True,
        sender_count=5,
        provider_domain_count=3,
        lane_parallel_limit=2,
        allow_single_provider=False,
        force_disable_concurrency=False,
    )
    assert out["enabled"] is True
    assert out["effective_parallel_lanes"] == 2
    assert out["fallback_to_sequential"] is False


def test_multi_provider_parallel_force_disabled():
    out = shiva._should_enable_multi_provider_parallel(
        flag_enabled=True,
        sender_count=5,
        provider_domain_count=3,
        lane_parallel_limit=8,
        allow_single_provider=False,
        force_disable_concurrency=True,
    )
    assert out["enabled"] is False
    assert out["reason"] == "force_disable_concurrency"


def test_multi_provider_parallel_enabled_for_single_provider_when_allowed():
    out = shiva._should_enable_multi_provider_parallel(
        flag_enabled=True,
        sender_count=4,
        provider_domain_count=1,
        lane_parallel_limit=8,
        allow_single_provider=True,
        force_disable_concurrency=False,
    )
    assert out["enabled"] is True
    assert out["reason"] == "enabled"
    assert out["effective_parallel_lanes"] == 1
    assert out["allow_single_provider"] is True


def test_multi_provider_parallel_targets_provider_domain_count_when_possible():
    out = shiva._should_enable_multi_provider_parallel(
        flag_enabled=True,
        sender_count=2,
        provider_domain_count=5,
        lane_parallel_limit=8,
        allow_single_provider=False,
        force_disable_concurrency=False,
    )
    assert out["enabled"] is True
    assert out["target_lane_count"] == 5
    assert out["effective_parallel_lanes"] == 5


def test_multi_provider_parallel_allows_single_sender():
    out = shiva._should_enable_multi_provider_parallel(
        flag_enabled=True,
        sender_count=1,
        provider_domain_count=3,
        lane_parallel_limit=8,
        allow_single_provider=False,
        force_disable_concurrency=False,
    )
    assert out["enabled"] is True
    assert out["reason"] == "enabled"
    assert out["effective_parallel_lanes"] == 3


def test_multi_provider_parallel_disabled_for_missing_sender_pool():
    out = shiva._should_enable_multi_provider_parallel(
        flag_enabled=True,
        sender_count=0,
        provider_domain_count=3,
        lane_parallel_limit=8,
        allow_single_provider=False,
        force_disable_concurrency=False,
    )
    assert out["enabled"] is False
    assert out["reason"] == "insufficient_senders"
