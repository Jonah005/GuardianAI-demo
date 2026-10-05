from guardian.schemas import Scenario


def test_scenario_accepts_string_conversation() -> None:
    scenario = Scenario.model_validate(
        {
            "category": "test",
            "title": "A valid scenario",
            "objective": "Test a workflow invariant",
            "conversation": ["Please process synthetic order ORD-TEST-1"],
        }
    )
    assert scenario.conversation[0].content.startswith("Please")
