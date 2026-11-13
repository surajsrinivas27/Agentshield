
import json
import re
from pathlib import Path

from presidio_analyzer import AnalyzerEngine
from presidio_analyzer.nlp_engine import NlpEngineProvider


# --------------------------------------------------
# 1. Configure Microsoft Presidio
# --------------------------------------------------

configuration = {
    "nlp_engine_name": "spacy",
    "models": [
        {
            "lang_code": "en",
            "model_name": "en_core_web_sm"
        }
    ]
}

provider = NlpEngineProvider(nlp_configuration=configuration)
nlp_engine = provider.create_engine()

analyzer = AnalyzerEngine(
    nlp_engine=nlp_engine,
    supported_languages=["en"]
)


# --------------------------------------------------
# 2. Custom Regex detection rules
# --------------------------------------------------

REGEX_RULES = [

    # Detect names after common labels
    (
        re.compile(
            r"\b(?i:employee|customer|patient|user|manager|person)\s+"
            r"([A-Z][a-z]{1,30}(?:\s+[A-Z][a-z]{1,30})?)\b"
        ),
        "PERSON",
        1,
        0.85
    ),

    # Email addresses
    (
        re.compile(
            r"(?<![\w.+-])[\w.+-]+@[\w-]+(?:\.[\w-]+)+"
        ),
        "EMAIL",
        0,
        0.99
    ),

    # Indian mobile numbers
    (
        re.compile(
            r"(?<!\d)(?:\+91[\s-]?)?[6-9]\d{4}[\s-]?\d{5}(?!\d)"
        ),
        "PHONE",
        0,
        0.99
    ),

    # Credit card number candidates
    (
        re.compile(
            r"(?<!\d)(?:\d[ -]?){12,18}\d(?!\d)"
        ),
        "CREDIT_CARD",
        0,
        0.99
    ),

    # Common API key patterns
    (
        re.compile(
            r"\b(?:sk-[A-Za-z0-9_-]{16,}|"
            r"ghp_[A-Za-z0-9]{20,}|"
            r"AIza[A-Za-z0-9_-]{20,}|"
            r"AKIA[0-9A-Z]{16})\b"
        ),
        "API_KEY",
        0,
        0.99
    ),

    # Bearer tokens
    (
        re.compile(
            r"(?i)\bBearer\s+([A-Za-z0-9._~+/=-]+)"
        ),
        "TOKEN",
        1,
        0.99
    ),

    # Secrets and tokens assigned in configuration text
    (
        re.compile(
            r"""(?i)\b(?:api[_-]?key|access[_-]?token|"""
            r"""secret|password)\s*[:=]\s*["']?"""
            r"""([A-Za-z0-9._~+/=-]{8,})"""
        ),
        "TOKEN",
        1,
        0.99
    )
]


# --------------------------------------------------
# 3. Credit card validation using Luhn algorithm
# --------------------------------------------------

def is_valid_card(number):

    digits = "".join(
        char for char in number if char.isdigit()
    )

    if not 13 <= len(digits) <= 19:
        return False

    total = 0

    for index, digit in enumerate(reversed(digits)):

        value = int(digit)

        if index % 2 == 1:
            value *= 2

            if value > 9:
                value -= 9

        total += value

    return total % 10 == 0


# --------------------------------------------------
# 4. Load configurable custom sensitive-data rules
# --------------------------------------------------

def load_custom_rules():

    config_path = Path(__file__).with_name("custom_rules.json")

    with open(config_path, "r", encoding="utf-8") as file:
        config = json.load(file)

    if not isinstance(config, dict):
        raise ValueError("Custom rules configuration must be an object")

    rules = config.get("rules", [])

    if not isinstance(rules, list):
        raise ValueError("Custom rules must be a list")

    compiled_rules = []

    for rule in rules:

        if not isinstance(rule, dict):
            raise ValueError("Each custom rule must be an object")

        value = rule.get("value")
        entity_type = rule.get("type")
        confidence = rule.get("confidence")

        if not isinstance(value, str) or not value.strip():
            raise ValueError("Custom rule value must be a non-empty string")

        if entity_type != "OTHER_CONFIGURED":
            raise ValueError("Custom rule type must be OTHER_CONFIGURED")

        if (
            isinstance(confidence, bool)
            or not isinstance(confidence, (int, float))
            or not 0 <= confidence <= 1
        ):
            raise ValueError("Custom rule confidence must be between 0 and 1")

        compiled_rules.append(
            (
                re.compile(re.escape(value), re.IGNORECASE),
                entity_type,
                float(confidence)
            )
        )

    return compiled_rules


# --------------------------------------------------
# 5. Main sensitive information detection function
# --------------------------------------------------

def detect_sensitive_data(text):

    if not isinstance(text, str):
        raise TypeError("Input text must be a string")

    detected = {}

    # STEP A: Existing Regex detection
    for pattern, entity_type, group, confidence in REGEX_RULES:

        for match in pattern.finditer(text):

            start, end = match.span(group)

            # Validate credit card candidates
            if entity_type == "CREDIT_CARD":

                if not is_valid_card(match.group(group)):
                    continue

            key = (start, end)

            detected[key] = {
                "start": start,
                "end": end,
                "type": entity_type,
                "confidence": confidence
            }

    # STEP B: Configurable custom-rule detection
    for pattern, entity_type, confidence in load_custom_rules():

        for match in pattern.finditer(text):

            start, end = match.span()

            key = (start, end)

            if key not in detected:

                detected[key] = {
                    "start": start,
                    "end": end,
                    "type": entity_type,
                    "confidence": confidence
                }

    # STEP C: Microsoft Presidio detection
    results = analyzer.analyze(
        text=text,
        language="en",
        entities=[
            "PERSON",
            "EMAIL_ADDRESS",
            "PHONE_NUMBER",
            "CREDIT_CARD",
            "LOCATION",
            "IBAN_CODE",
            "US_SSN"
        ]
    )

    # Convert Presidio categories to our API categories
    type_mapping = {
        "EMAIL_ADDRESS": "EMAIL",
        "PHONE_NUMBER": "PHONE"
    }

    for result in results:

        entity_type = type_mapping.get(
            result.entity_type,
            result.entity_type
        )

        key = (result.start, result.end)

        # Keep existing Regex or custom-rule result
        # if the exact span has already been detected.
        if key not in detected:

            detected[key] = {
                "start": result.start,
                "end": result.end,
                "type": entity_type,
                "confidence": round(float(result.score), 2)
            }

    # STEP D: Sort results by their positions
    entities = sorted(
        detected.values(),
        key=lambda item: (item["start"], item["end"])
    )

    return entities
