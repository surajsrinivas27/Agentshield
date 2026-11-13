
import json
import logging
import os
from pathlib import Path
from threading import Lock
from typing import Literal

import httpx
from dotenv import load_dotenv
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from .detector import detect_sensitive_data


# Load the project's root .env file
PROJECT_ROOT = Path(__file__).resolve().parents[2]
load_dotenv(PROJECT_ROOT / ".env")

SARVAM_URL = "https://api.sarvam.ai/v1/chat/completions"
SARVAM_MODEL = os.getenv("SARVAM_MODEL", "sarvam-105b")

logger = logging.getLogger(__name__)


# --------------------------------------------------
# 1. Validate Sarvam's contextual analysis response
# --------------------------------------------------

class ContextAssessment(BaseModel):
    model_config = ConfigDict(extra="forbid")

    requires_special_handling: bool

    sensitivity_level: Literal[
        "low", "medium", "high", "unknown"
    ]

    categories: list[
        Literal[
            "HEALTH",
            "FINANCIAL",
            "EMPLOYMENT",
            "IDENTITY",
            "SECURITY",
            "OTHER"
        ]
    ] = Field(max_length=6)


# --------------------------------------------------
# 2. Track actual API usage
# --------------------------------------------------

class UsageTracker:

    def __init__(self):
        self.lock = Lock()

        self.stats = {
            "total_requests": 0,
            "successful_requests": 0,
            "failed_requests": 0,
            "prompt_tokens": 0,
            "completion_tokens": 0,
            "total_tokens": 0
        }

    def record(self, success, usage=None):

        usage = usage or {}

        with self.lock:

            self.stats["total_requests"] += 1

            if success:
                self.stats["successful_requests"] += 1
            else:
                self.stats["failed_requests"] += 1

            for field in (
                "prompt_tokens",
                "completion_tokens",
                "total_tokens"
            ):
                self.stats[field] += max(
                    0, int(usage.get(field, 0) or 0)
                )

    def get_stats(self):

        with self.lock:
            return dict(self.stats)


usage_tracker = UsageTracker()


def get_usage_stats():
    return usage_tracker.get_stats()


# --------------------------------------------------
# 3. Local fallback
# --------------------------------------------------

def local_fallback(reason):

    return {
        "status": "fallback",
        "provider": "local",
        "assessment": None,
        "reason": reason,
        "usage": {
            "prompt_tokens": 0,
            "completion_tokens": 0,
            "total_tokens": 0
        }
    }


# --------------------------------------------------
# 4. Analyze sanitized text using Sarvam AI
# --------------------------------------------------

def analyze_sanitized_context(sanitized_text: str):

    if not isinstance(sanitized_text, str):
        raise TypeError("Input must be a string")

    if not sanitized_text.strip():
        return local_fallback("empty_input")

    # Security guard: do not send text if local
    # detection identifies potentially unmasked PII.
    remaining_entities = detect_sensitive_data(
        sanitized_text
    )

    if remaining_entities:
        return local_fallback(
            "possible_unmasked_sensitive_data"
        )

    # Check for a valid API key
    api_key = os.getenv("SARVAM_API_KEY", "").strip()

    if not api_key or api_key == "replace_with_your_own_key":
        return local_fallback("api_key_not_configured")

    # Ask Sarvam only for contextual classification.
    # It must not identify people or make authorization decisions.
    payload = {
        "model": SARVAM_MODEL,
        "messages": [
            {
                "role": "system",
                "content": (
                    "You are a privacy-context classifier. "
                    "Analyze only the sanitized text provided. "
                    "Do not identify people, reconstruct identities, "
                    "repeat personal data, or make authorization "
                    "decisions. Return JSON with exactly these fields: "
                    "requires_special_handling (boolean), "
                    "sensitivity_level (low, medium, high, unknown), "
                    "categories (list containing only HEALTH, "
                    "FINANCIAL, EMPLOYMENT, IDENTITY, SECURITY, OTHER). "
                    "Return an empty categories list when no sensitive "
                    "context is present."
                )
            },
            {
                "role": "user",
                "content": sanitized_text
            }
        ],
        "temperature": 0.1,
        "max_tokens": 150,
        "reasoning_effort":None,
        "response_format": {
            "type": "json_object"
        }
    }

    headers = {
        "api-subscription-key": api_key,
        "Content-Type": "application/json"
    }

    try:

        response = httpx.post(
            SARVAM_URL,
            headers=headers,
            json=payload,
            timeout=15.0
        )

        response.raise_for_status()

        data = response.json()

        content = data["choices"][0]["message"]["content"]

        if not isinstance(content, str):
            raise ValueError("Invalid Sarvam response content")

        parsed_content = json.loads(content)

        # Validate AI output before accepting it
        assessment = ContextAssessment.model_validate(
            parsed_content
        )

        # Capture actual API usage reported by Sarvam
        actual_usage = data.get("usage") or {}

        usage = {
            "prompt_tokens": int(
                actual_usage.get("prompt_tokens", 0) or 0
            ),
            "completion_tokens": int(
                actual_usage.get("completion_tokens", 0) or 0
            ),
            "total_tokens": int(
                actual_usage.get("total_tokens", 0) or 0
            )
        }

        usage_tracker.record(
            success=True,
            usage=usage
        )

        return {
            "status": "success",
            "provider": "sarvam",
            "assessment": assessment.model_dump(),
            "usage": usage
        }

    except (
        httpx.HTTPError,
        KeyError,
        IndexError,
        TypeError,
        ValueError,
        ValidationError
    ) as error:

        # Never log the original text or API key
        logger.warning(
            "Sarvam request failed; using local fallback. Error: %s",
            type(error).__name__
        )

        usage_tracker.record(success=False)

        return local_fallback("sarvam_unavailable")
