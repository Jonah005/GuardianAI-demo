from guardian.flow_inventory import extract_flow_inventory


def test_extract_agents_tools_and_edges() -> None:
    flow = {
        "name": "Refund flow",
        "data": {
            "nodes": [
                {
                    "id": "Tool-1",
                    "data": {
                        "type": "CustomTool",
                        "node": {
                            "display_name": "Lookup Order",
                            "description": "Reads an order",
                            "base_classes": ["Tool"],
                            "template": {"api_key": {"value": "secret"}},
                        },
                    },
                },
                {
                    "id": "Agent-1",
                    "data": {
                        "type": "Agent",
                        "node": {
                            "display_name": "Intake Agent",
                            "base_classes": ["Agent"],
                            "template": {},
                        },
                    },
                },
            ],
            "edges": [
                {
                    "source": "Tool-1",
                    "target": "Agent-1",
                    "sourceHandle": "tool",
                    "targetHandle": "tools",
                }
            ],
        },
    }
    inventory = extract_flow_inventory(flow, "flow-1")
    assert inventory.flow_name == "Refund flow"
    assert inventory.agent_ids == ["Agent-1"]
    assert inventory.tool_ids == ["Tool-1"]
    tool = next(item for item in inventory.components if item.id == "Tool-1")
    agent = next(item for item in inventory.components if item.id == "Agent-1")
    assert tool.connected_agent_ids == ["Agent-1"]
    assert agent.connected_agent_ids == ["Tool-1"]
