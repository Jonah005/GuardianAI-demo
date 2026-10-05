from guardian.clients.langflow import LangflowClient
from guardian.clients.llm import GuardianModelClient


def test_extract_langflow_output_text() -> None:
    payload = {
        "outputs": [
            {
                "outputs": [
                    {"results": {"message": {"text": "Final answer"}}}
                ]
            }
        ]
    }
    assert LangflowClient.extract_output_text(payload) == "Final answer"


def test_extract_openai_content() -> None:
    payload = {"choices": [{"message": {"content": "hello"}}]}
    assert GuardianModelClient._extract_content(payload) == "hello"


def test_extract_generic_content() -> None:
    assert GuardianModelClient._extract_content({"generated_text": "hello"}) == "hello"
