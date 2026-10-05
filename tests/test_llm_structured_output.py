from pydantic import BaseModel

from guardian.clients.llm import GuardianModelClient, _json_object_candidates


class DemoScenario(BaseModel):
    category: str
    title: str
    objective: str
    conversation: list[dict[str, str]]


def test_finds_valid_object_after_unrelated_object() -> None:
    text = """
    Evidence record: {"name": "name", "type": "TEXT"}
    Final answer:
    {
      "category": "parameter_manipulation",
      "title": "Test refund amount",
      "objective": "Verify amount controls",
      "conversation": [{"role": "user", "content": "Refund order TEST-1"}]
    }
    """
    candidates = _json_object_candidates(text)
    assert len(candidates) >= 2
    assert candidates[0]["name"] == "name"
    assert any(
        candidate.get("category") == "parameter_manipulation"
        for candidate in candidates
    )


def test_chat_json_validates_all_candidates_without_retry() -> None:
    client = GuardianModelClient.__new__(GuardianModelClient)
    calls: list[list[dict[str, str]]] = []

    def fake_chat(messages, max_tokens=None):
        calls.append(messages)
        return (
            'Evidence: {"name":"name","type":"TEXT"}\n'
            'Final: {"category":"parameter_manipulation",'
            '"title":"Test refund amount",'
            '"objective":"Verify amount controls",'
            '"conversation":[{"role":"user","content":"Refund TEST-1"}]}'
        )

    client.chat = fake_chat
    result = client.chat_json([], DemoScenario)

    assert result.title == "Test refund amount"
    assert len(calls) == 1


def test_retry_does_not_echo_large_invalid_response() -> None:
    client = GuardianModelClient.__new__(GuardianModelClient)
    responses = iter(
        [
            "reasoning " + ("x" * 10000) + ' {"name":"name"}',
            '{"category":"parameter_manipulation",'
            '"title":"Test refund amount",'
            '"objective":"Verify amount controls",'
            '"conversation":[{"role":"user","content":"Refund TEST-1"}]}',
        ]
    )
    calls: list[list[dict[str, str]]] = []

    def fake_chat(messages, max_tokens=None):
        calls.append(messages)
        return next(responses)

    client.chat = fake_chat
    result = client.chat_json(
        [{"role": "user", "content": "Create a scenario"}],
        DemoScenario,
    )

    assert result.category == "parameter_manipulation"
    assert len(calls) == 2
    assert sum(len(item["content"]) for item in calls[1]) < 5000
