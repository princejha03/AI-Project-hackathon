"""CheckmarxClient's retry wrapper: transient failures get retried with
bounded backoff, real ones fail fast. No real network calls -- requests and
time.sleep are both faked."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest
import requests

from truesignal import checkmarx_client
from truesignal.checkmarx_client import _MAX_ATTEMPTS, _request_with_retry


class _FakeResponse:
    def __init__(self, status_code: int):
        self.status_code = status_code
        self.reason = "status"


def _no_sleep(monkeypatch):
    """Retries must still happen, just without slowing the test suite down
    with real backoff delays."""
    monkeypatch.setattr(checkmarx_client.time, "sleep", lambda seconds: None)


def test_succeeds_immediately_without_retrying(monkeypatch):
    _no_sleep(monkeypatch)
    calls = []

    def fake_request(method, url, **kwargs):
        calls.append((method, url))
        return _FakeResponse(200)

    monkeypatch.setattr(requests, "request", fake_request)
    resp = _request_with_retry("GET", "https://example.test/x")
    assert resp.status_code == 200
    assert len(calls) == 1


def test_retries_a_retryable_status_then_succeeds(monkeypatch):
    _no_sleep(monkeypatch)
    responses = [_FakeResponse(503), _FakeResponse(200)]

    def fake_request(method, url, **kwargs):
        return responses.pop(0)

    monkeypatch.setattr(requests, "request", fake_request)
    resp = _request_with_retry("GET", "https://example.test/x")
    assert resp.status_code == 200
    assert responses == []  # both queued responses were consumed


def test_does_not_retry_a_non_retryable_status(monkeypatch):
    _no_sleep(monkeypatch)
    calls = []

    def fake_request(method, url, **kwargs):
        calls.append(1)
        return _FakeResponse(404)

    monkeypatch.setattr(requests, "request", fake_request)
    resp = _request_with_retry("GET", "https://example.test/x")
    assert resp.status_code == 404
    assert len(calls) == 1, "a real client error must fail fast, not waste retries"


def test_retries_a_connection_error_then_succeeds(monkeypatch):
    _no_sleep(monkeypatch)
    attempts = {"n": 0}

    def fake_request(method, url, **kwargs):
        attempts["n"] += 1
        if attempts["n"] == 1:
            raise requests.exceptions.ConnectionError("simulated network blip")
        return _FakeResponse(200)

    monkeypatch.setattr(requests, "request", fake_request)
    resp = _request_with_retry("GET", "https://example.test/x")
    assert resp.status_code == 200
    assert attempts["n"] == 2


def test_gives_up_after_max_attempts(monkeypatch):
    _no_sleep(monkeypatch)
    calls = []

    def fake_request(method, url, **kwargs):
        calls.append(1)
        raise requests.exceptions.ConnectionError("persistent outage")

    monkeypatch.setattr(requests, "request", fake_request)
    with pytest.raises(requests.exceptions.ConnectionError):
        _request_with_retry("GET", "https://example.test/x")
    assert len(calls) == _MAX_ATTEMPTS, "must stop retrying at the documented cap, not loop forever"
