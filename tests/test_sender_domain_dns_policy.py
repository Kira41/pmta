import json

import shiva


def test_dns_txt_lookup_falls_back_to_doh(monkeypatch):
    class _BoomResolver:
        def resolve(self, *_args, **_kwargs):
            raise RuntimeError("resolver down")

    class _Resp:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def read(self):
            return json.dumps(
                {
                    "Status": 0,
                    "Answer": [
                        {"data": '"v=spf1 include:_spf.google.com ~all"'},
                    ],
                }
            ).encode("utf-8")

    monkeypatch.setattr(shiva, "DNS_RESOLVER", _BoomResolver())
    monkeypatch.setattr(shiva, "urlopen", lambda *_args, **_kwargs: _Resp())

    out = shiva._dns_txt_lookup("example.com")
    assert out["ok"] is True
    assert any(r.lower().startswith("v=spf1") for r in out["records"])


def test_compute_sender_domain_states_uses_common_dkim_selector_fallback(monkeypatch):
    monkeypatch.setattr(shiva, "_dkim_selectors_from_env", lambda: [])

    def _fake_lookup(name: str):
        if name == "example.com":
            return {"ok": True, "records": ["v=spf1 -all"], "error": ""}
        if name == "_dmarc.example.com":
            return {"ok": True, "records": ["v=DMARC1; p=none"], "error": ""}
        if name == "default._domainkey.example.com":
            return {"ok": True, "records": ["v=DKIM1; p=abc"], "error": ""}
        return {"ok": True, "records": [], "error": ""}

    monkeypatch.setattr(shiva, "_dns_txt_lookup", _fake_lookup)
    monkeypatch.setattr(shiva, "domain_mail_route", lambda _dom: {"status": "pass", "mx_hosts": ["mx.example.com"]})
    monkeypatch.setattr(shiva, "resolve_sender_domain_ips", lambda _dom: [])
    monkeypatch.setattr(shiva, "check_domain_dnsbl", lambda _dom: [])
    monkeypatch.setattr(shiva, "check_ip_dnsbl", lambda _ip: [])
    monkeypatch.setattr(shiva, "SHIVA_DISABLE_BLACKLIST", True)

    rows = shiva.compute_sender_domain_states({"example.com": 2})
    assert rows[0]["dkim"]["status"] == "pass"
    assert rows[0]["dkim"]["selector"] == "default"
