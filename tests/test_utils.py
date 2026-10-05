from guardian.utils import extract_json_object, redact_secrets


def test_extract_json_object_from_fence() -> None:
    assert extract_json_object('```json\n{"ok": true}\n```') == {"ok": True}


def test_extract_json_object_from_surrounding_text() -> None:
    assert extract_json_object('Result follows: {"value": 7} done') == {"value": 7}


def test_redact_secrets_recursively() -> None:
    value = {"api_key": "abc", "nested": {"password": "xyz", "safe": 1}}
    assert redact_secrets(value) == {
        "api_key": "<redacted>",
        "nested": {"password": "<redacted>", "safe": 1},
    }
