from shiva import _normalize_bad_request_log_message


def test_normalize_tls_probe_bad_request_message():
    msg = "Bad request syntax ('\\x16\\x03\\x01\\x00ô...')"
    assert _normalize_bad_request_log_message(msg) == (
        "Bad request syntax (likely TLS/HTTPS probe on HTTP port)"
    )


def test_normalize_non_tls_bad_request_message():
    msg = "Bad request syntax ('\\x00\\x01garbage')"
    assert _normalize_bad_request_log_message(msg) == (
        "Bad request syntax (malformed/non-HTTP bytes)"
    )


def test_normalize_irrelevant_message_returns_none():
    assert _normalize_bad_request_log_message("404 not found") is None
