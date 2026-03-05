import json

import shiva


def test_sanitize_form_data_keeps_large_recipients_list():
    recipients = "\n".join(f"user{i}@example.com" for i in range(60000))
    clean = shiva._sanitize_form_data({"recipients": recipients, "body": "x" * 500000})

    assert clean["recipients"] == recipients
    assert len(clean["body"]) == 400000


def test_fit_form_payload_keeps_json_valid_and_prioritizes_recipients():
    recipients = "\n".join(f"u{i}@x.com" for i in range(120))
    clean = {
        "recipients": recipients,
        "body": "A" * 30000000,
        "subject": "S" * 3000000,
        "from_name": "N" * 3000000,
    }

    fitted = shiva._fit_form_payload(clean)
    payload = json.dumps(fitted, ensure_ascii=False).encode("utf-8")

    assert len(payload) <= 25000000
    assert fitted["recipients"] == recipients
    assert len(fitted["body"]) < len(clean["body"])
