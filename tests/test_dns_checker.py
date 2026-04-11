# Copyright 2024 Hiago Kin Levi
# Licensed under the Creative Commons Attribution 4.0 International (CC BY 4.0)
# https://creativecommons.org/licenses/by/4.0/

from __future__ import annotations

import os
import socket
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from analyzers.dns_checker import check_dns


def test_check_dns_restores_default_timeout_after_success(monkeypatch: pytest.MonkeyPatch):
    original_timeout = socket.getdefaulttimeout()
    socket.setdefaulttimeout(9.5)

    def fake_getaddrinfo(domain: str, port, family: int):
        assert domain == "example.com"
        assert port is None
        assert family == socket.AF_INET
        return [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("203.0.113.10", 0)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("203.0.113.10", 0)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("203.0.113.11", 0)),
        ]

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)

    try:
        result = check_dns("example.com", timeout=1.25)
        assert result.domain == "example.com"
        assert result.resolves is True
        assert set(result.a_records) == {"203.0.113.10", "203.0.113.11"}
        assert socket.getdefaulttimeout() == 9.5
    finally:
        socket.setdefaulttimeout(original_timeout)


def test_check_dns_normalizes_hostnames_before_resolution(monkeypatch: pytest.MonkeyPatch):
    original_timeout = socket.getdefaulttimeout()
    socket.setdefaulttimeout(5.0)

    def fake_getaddrinfo(domain: str, port, family: int):
        assert domain == "xn--exmple-cua.com"
        assert port is None
        assert family == socket.AF_INET
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("198.51.100.5", 0))]

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)

    try:
        result = check_dns("  Exämple.com. ", timeout=1.0)
        assert result.domain == "xn--exmple-cua.com"
        assert result.resolves is True
        assert result.a_records == ["198.51.100.5"]
        assert socket.getdefaulttimeout() == 5.0
    finally:
        socket.setdefaulttimeout(original_timeout)


def test_check_dns_restores_default_timeout_after_resolution_failure(
    monkeypatch: pytest.MonkeyPatch,
):
    original_timeout = socket.getdefaulttimeout()
    socket.setdefaulttimeout(7.0)

    def fake_getaddrinfo(domain: str, port, family: int):
        raise socket.timeout()

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)

    try:
        result = check_dns("example.com", timeout=2.0)
        assert result.domain == "example.com"
        assert result.resolves is False
        assert result.a_records == []
        assert socket.getdefaulttimeout() == 7.0
    finally:
        socket.setdefaulttimeout(original_timeout)


@pytest.mark.parametrize(
    ("domain", "message"),
    [
        ("", "non-empty hostname"),
        (" https://example.com/login ", "without URL components"),
        ("192.0.2.10", "not an IP address"),
        ("bad_domain!.example.com", "invalid hostname characters"),
        ("example..com", "empty labels"),
    ],
)
def test_check_dns_rejects_invalid_domains(domain: str, message: str):
    original_timeout = socket.getdefaulttimeout()
    socket.setdefaulttimeout(4.0)

    try:
        with pytest.raises(ValueError, match=message):
            check_dns(domain, timeout=1.0)
        assert socket.getdefaulttimeout() == 4.0
    finally:
        socket.setdefaulttimeout(original_timeout)


@pytest.mark.parametrize("timeout", [0, -1.0])
def test_check_dns_rejects_non_positive_timeout(timeout: float):
    original_timeout = socket.getdefaulttimeout()
    socket.setdefaulttimeout(4.0)

    try:
        with pytest.raises(ValueError, match="timeout must be greater than 0"):
            check_dns("example.com", timeout=timeout)
        assert socket.getdefaulttimeout() == 4.0
    finally:
        socket.setdefaulttimeout(original_timeout)
