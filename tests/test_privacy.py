
from backend.privacy.detector import detect_sensitive_data


def find_entity(text, entity_type):
    entities = detect_sensitive_data(text)

    matching = [
        entity for entity in entities
        if entity["type"] == entity_type
    ]

    assert matching, f"{entity_type} was not detected"

    return matching[0]


def test_person_detection():
    text = "Employee Rahul"

    entity = find_entity(text, "PERSON")

    assert text[entity["start"]:entity["end"]] == "Rahul"


def test_email_detection():
    text = "Contact rahul@example.com"

    entity = find_entity(text, "EMAIL")

    assert text[entity["start"]:entity["end"]] == "rahul@example.com"


def test_phone_detection():
    text = "Contact 9876543210"

    entity = find_entity(text, "PHONE")

    assert text[entity["start"]:entity["end"]] == "9876543210"


def test_credit_card_detection():
    text = "Card 4111 1111 1111 1111"

    entity = find_entity(text, "CREDIT_CARD")

    assert text[entity["start"]:entity["end"]] == "4111 1111 1111 1111"


def test_api_key_detection():
    text = "My key is sk-1234567890abcdef"

    entity = find_entity(text, "API_KEY")

    assert text[entity["start"]:entity["end"]] == "sk-1234567890abcdef"


def test_token_detection():
    text = "Authorization: Bearer abcdefghijklmnop"

    entity = find_entity(text, "TOKEN")

    assert text[entity["start"]:entity["end"]] == "abcdefghijklmnop"


def test_entity_positions_are_valid():
    text = "Employee Rahul, email rahul@example.com"

    entities = detect_sensitive_data(text)

    for entity in entities:
        assert entity["start"] >= 0
        assert entity["end"] > entity["start"]
        assert entity["end"] <= len(text)
        assert 0 <= entity["confidence"] <= 1
