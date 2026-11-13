
import json

from backend.privacy import sarvam_client


def test_missing_key_uses_local_fallback(monkeypatch):

    monkeypatch.setenv(
        "SARVAM_API_KEY",
        "replace_with_your_own_key"
    )

    result = sarvam_client.analyze_sanitized_context(
        "This document explains office procedures."
    )

    assert result["status"] == "fallback"
    assert result["provider"] == "local"
    assert result["reason"] == "api_key_not_configured"


def test_empty_input_uses_fallback():

    result = sarvam_client.analyze_sanitized_context("")

    assert result["status"] == "fallback"
    assert result["reason"] == "empty_input"


def test_unmasked_email_is_never_sent(monkeypatch):

    monkeypatch.setenv("SARVAM_API_KEY", "fake-test-key")

    def fake_post(*args, **kwargs):
        raise AssertionError("Sarvam must not receive raw PII")

    monkeypatch.setattr(
        sarvam_client.httpx,
        "post",
        fake_post
    )

    result = sarvam_client.analyze_sanitized_context(
        "Contact rahul@example.com"
    )

    assert result["status"] == "fallback"
    assert result["reason"] == "possible_unmasked_sensitive_data"


def test_sarvam_success_and_usage_tracking(monkeypatch):

    monkeypatch.setenv("SARVAM_API_KEY", "fake-test-key")

    sanitized_text = "This document explains office procedures."

    class FakeResponse:

        def raise_for_status(self):
            pass

        def json(self):
            return {
                "choices": [
                    {
                        "message": {
                            "content": json.dumps({
                                "requires_special_handling": False,
                                "sensitivity_level": "low",
                                "categories": []
                            })
                        }
                    }
                ],
                "usage": {
                    "prompt_tokens": 20,
                    "completion_tokens": 15,
                    "total_tokens": 35
                }
            }

    def fake_post(url, headers, json, timeout):

        assert url == sarvam_client.SARVAM_URL

        assert json["messages"][1]["content"] == sanitized_text

        assert headers["api-subscription-key"] == "fake-test-key"

        return FakeResponse()

    monkeypatch.setattr(
        sarvam_client.httpx,
        "post",
        fake_post
    )

    tracker = sarvam_client.UsageTracker()

    before = sarvam_client.usage_tracker.get_stats()

    result = sarvam_client.analyze_sanitized_context(
        sanitized_text
    )

    after = sarvam_client.usage_tracker.get_stats()

    assert result["status"] == "success"
    assert result["provider"] == "sarvam"

    assert result["usage"]["total_tokens"] == 35

    assert after["total_tokens"] - before["total_tokens"] == 35
