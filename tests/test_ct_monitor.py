# Copyright 2024 Hiago Kin Levi
# Licensed under the Creative Commons Attribution 4.0 International (CC BY 4.0)
# https://creativecommons.org/licenses/by/4.0/

from __future__ import annotations

import json
import os
import sys
import urllib.request

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from analyzers.ct_monitor import CtCertificate, filter_lookalikes, query_ct_logs


class _FakeResponse:
    def __init__(self, payload: list[dict[str, object]]) -> None:
        self._payload = payload

    def __enter__(self) -> "_FakeResponse":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        return None

    def read(self) -> bytes:
        return json.dumps(self._payload).encode("utf-8")


def test_query_ct_logs_normalizes_domains_before_request(monkeypatch: pytest.MonkeyPatch):
    captured: dict[str, object] = {}

    def fake_urlopen(request: urllib.request.Request, timeout: float):
        captured["url"] = request.full_url
        captured["timeout"] = timeout
        return _FakeResponse(
            [
                {
                    "id": 7,
                    "entry_timestamp": "2026-04-10T00:00:00Z",
                    "not_before": "2026-04-09T00:00:00Z",
                    "not_after": "2026-07-09T00:00:00Z",
                    "common_name": "xn--exmple-cua.com",
                    "issuer_name": "Example CA",
                    "name_value": "xn--exmple-cua.com",
                }
            ]
        )

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)

    certs = query_ct_logs("  Exämple.com. ", include_subdomains=True, timeout=2.5)

    assert captured["url"] == "https://crt.sh/?q=%25.xn--exmple-cua.com&output=json"
    assert captured["timeout"] == 2.5
    assert len(certs) == 1
    assert certs[0].common_name == "xn--exmple-cua.com"


@pytest.mark.parametrize(
    ("domain", "message"),
    [
        ("", "non-empty hostname"),
        ("https://example.com/login", "without URL components"),
        ("bad_domain!.example.com", "invalid hostname characters"),
    ],
)
def test_query_ct_logs_rejects_invalid_domains(domain: str, message: str):
    with pytest.raises(ValueError, match=message):
        query_ct_logs(domain)


@pytest.mark.parametrize("timeout", [0, -1.0])
def test_query_ct_logs_rejects_non_positive_timeout(timeout: float):
    with pytest.raises(ValueError, match="timeout must be greater than 0"):
        query_ct_logs("example.com", timeout=timeout)


def test_filter_lookalikes_normalizes_brand_domain_and_common_names():
    certs = [
        CtCertificate(1, None, None, None, "PAYPAL.com.", "Issuer", "PAYPAL.com."),
        CtCertificate(2, None, None, None, "*.PayPal.com", "Issuer", "*.PayPal.com"),
        CtCertificate(3, None, None, None, "paypal-security-check.com", "Issuer", "paypal-security-check.com"),
    ]

    filtered = filter_lookalikes(certs, brand_domain="PayPal.com.")

    assert [cert.cert_id for cert in filtered] == [3]
