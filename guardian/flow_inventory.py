from __future__ import annotations

from typing import Any

from guardian.schemas import ComponentInfo, EdgeInfo, FlowInventory, ToolActionInfo
from guardian.utils import normalize_name, redact_secrets


def _node_payload(node: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    data = node.get("data") if isinstance(node.get("data"), dict) else {}
    inner = data.get("node") if isinstance(data.get("node"), dict) else {}
    return data, inner


def _text(*values: Any) -> str:
    for value in values:
        if isinstance(value, str) and value.strip():
            return value.strip()
    return ""


def _template_value(template: dict[str, Any], *field_names: str) -> Any:
    """Read a Langflow template field, unwrapping its nested value object."""

    for field_name in field_names:
        raw = template.get(field_name)
        if isinstance(raw, dict) and "value" in raw:
            return raw.get("value")
        if raw is not None:
            return raw
    return None


def _as_string_list(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [str(item) for item in value]
    return []


def _is_agent_component(
    *,
    node_type: str,
    display_name: str,
    base_classes: list[str],
    metadata_module: str,
) -> bool:
    type_name = normalize_name(node_type)
    display = normalize_name(display_name)
    module = normalize_name(metadata_module)
    base = {normalize_name(item) for item in base_classes}

    return (
        type_name == "agent"
        or display.endswith("agent")
        or "agentcomponent" in module
        or "agent" in base
    )


def _is_tool_component(
    *,
    node_id: str,
    node_type: str,
    display_name: str,
    metadata_module: str,
    tool_connected_nodes: set[str],
    is_agent: bool,
) -> bool:
    if is_agent:
        return False

    identity = " ".join(
        [node_type, display_name, metadata_module]
    ).lower()

    return (
        node_id in tool_connected_nodes
        or normalize_name(node_type) in {"mcp", "tool", "tools"}
        or "mcp_component" in metadata_module.lower()
        or "toolcomponent" in normalize_name(identity)
    )


def _extract_tool_actions(
    component_id: str,
    template: dict[str, Any],
) -> list[ToolActionInfo]:
    raw_metadata = _template_value(template, "tools_metadata")
    if not isinstance(raw_metadata, list):
        return []

    actions: list[ToolActionInfo] = []
    for item in raw_metadata:
        if not isinstance(item, dict):
            continue

        name = _text(item.get("name"), item.get("display_name"))
        if not name:
            continue

        status = item.get("status", True)
        enabled = status is not False and str(status).lower() not in {"false", "0", "disabled"}
        if not enabled:
            continue

        parameters = item.get("args")
        if not isinstance(parameters, dict):
            parameters = {}

        actions.append(
            ToolActionInfo(
                component_id=component_id,
                name=name,
                description=_text(
                    item.get("description"),
                    item.get("display_description"),
                )[:2000],
                parameters=parameters,
                enabled=True,
            )
        )

    return actions


def extract_flow_inventory(flow: dict[str, Any], flow_id: str) -> FlowInventory:
    """Extract agents, concrete tool actions, prompts, and graph relationships.

    The extractor deliberately separates three concepts that Langflow represents
    with different edge types:

    * agent-to-agent workflow edges;
    * tool-component-to-agent capability edges; and
    * all other component wiring such as model and chat input/output edges.
    """

    clean_flow = redact_secrets(flow)
    graph = clean_flow.get("data") if isinstance(clean_flow.get("data"), dict) else clean_flow
    nodes = graph.get("nodes", []) if isinstance(graph, dict) else []
    edges = graph.get("edges", []) if isinstance(graph, dict) else []

    edge_items: list[EdgeInfo] = []
    tool_connected_nodes: set[str] = set()
    incoming_counts: dict[str, int] = {}
    outgoing_counts: dict[str, int] = {}

    for raw_edge in edges if isinstance(edges, list) else []:
        if not isinstance(raw_edge, dict):
            continue

        source = str(raw_edge.get("source", ""))
        target = str(raw_edge.get("target", ""))
        if not source or not target:
            continue

        source_handle = _text(
            raw_edge.get("sourceHandle"),
            raw_edge.get("source_handle"),
        ) or None
        target_handle = _text(
            raw_edge.get("targetHandle"),
            raw_edge.get("target_handle"),
        ) or None
        handle_text = f"{source_handle or ''} {target_handle or ''}".lower()

        if (
            "fieldname" in handle_text and "tools" in handle_text
        ) or "output_types" in handle_text and "tool" in handle_text:
            tool_connected_nodes.add(source)

        incoming_counts[target] = incoming_counts.get(target, 0) + 1
        outgoing_counts[source] = outgoing_counts.get(source, 0) + 1

        edge_items.append(
            EdgeInfo(
                source=source,
                target=target,
                source_handle=source_handle,
                target_handle=target_handle,
            )
        )

    components: list[ComponentInfo] = []
    by_id: dict[str, ComponentInfo] = {}
    actions_by_component: dict[str, list[ToolActionInfo]] = {}

    for raw_node in nodes if isinstance(nodes, list) else []:
        if not isinstance(raw_node, dict):
            continue

        data, inner = _node_payload(raw_node)
        node_id = str(raw_node.get("id") or data.get("id") or "")
        if not node_id:
            continue

        node_type = _text(
            data.get("type"),
            inner.get("type"),
            raw_node.get("type"),
            "unknown",
        )
        display_name = _text(
            inner.get("display_name"),
            inner.get("name"),
            data.get("display_name"),
            data.get("label"),
            node_type,
        )
        description = _text(inner.get("description"), data.get("description"))

        base_classes = _as_string_list(
            inner.get("base_classes") or data.get("base_classes") or []
        )
        template = inner.get("template") if isinstance(inner.get("template"), dict) else {}
        template_fields = sorted(str(key) for key in template.keys())
        metadata = inner.get("metadata") if isinstance(inner.get("metadata"), dict) else {}
        metadata_module = _text(metadata.get("module"))

        is_agent = _is_agent_component(
            node_type=node_type,
            display_name=display_name,
            base_classes=base_classes,
            metadata_module=metadata_module,
        )
        is_tool = _is_tool_component(
            node_id=node_id,
            node_type=node_type,
            display_name=display_name,
            metadata_module=metadata_module,
            tool_connected_nodes=tool_connected_nodes,
            is_agent=is_agent,
        )

        system_prompt = ""
        if is_agent:
            system_prompt = _text(
                _template_value(
                    template,
                    "system_prompt",
                    "agent_instructions",
                    "instructions",
                    "prompt",
                )
            )[:12000]

        component = ComponentInfo(
            id=node_id,
            name=display_name,
            node_type=node_type,
            description=description[:1200],
            base_classes=base_classes,
            template_fields=template_fields,
            is_agent=is_agent,
            is_tool=is_tool,
            system_prompt=system_prompt,
        )
        components.append(component)
        by_id[node_id] = component

        if is_tool:
            actions_by_component[node_id] = _extract_tool_actions(node_id, template)

    for edge in edge_items:
        source = by_id.get(edge.source)
        target = by_id.get(edge.target)
        if source is None or target is None:
            continue

        handle_text = f"{edge.source_handle or ''} {edge.target_handle or ''}".lower()
        is_tool_edge = (
            "fieldname" in handle_text and "tools" in handle_text
        ) or (
            "output_types" in handle_text and "tool" in handle_text
        )

        if source.is_tool and target.is_agent and is_tool_edge:
            if target.id not in source.connected_agent_ids:
                source.connected_agent_ids.append(target.id)
            for action in actions_by_component.get(source.id, []):
                if target.id not in action.connected_agent_ids:
                    action.connected_agent_ids.append(target.id)
                if action.name not in target.tool_action_names:
                    target.tool_action_names.append(action.name)
            continue

        if target.is_tool and source.is_agent and is_tool_edge:
            if source.id not in target.connected_agent_ids:
                target.connected_agent_ids.append(source.id)
            for action in actions_by_component.get(target.id, []):
                if source.id not in action.connected_agent_ids:
                    action.connected_agent_ids.append(source.id)
                if action.name not in source.tool_action_names:
                    source.tool_action_names.append(action.name)
            continue

        if source.is_agent and target.is_agent:
            if target.id not in source.downstream_agent_ids:
                source.downstream_agent_ids.append(target.id)
            if source.id not in target.upstream_agent_ids:
                target.upstream_agent_ids.append(source.id)

    for component in components:
        component.connected_agent_ids.sort()
        component.tool_action_names.sort()
        component.upstream_agent_ids.sort()
        component.downstream_agent_ids.sort()

    tool_actions = [
        action
        for component_id in sorted(actions_by_component)
        for action in actions_by_component[component_id]
    ]
    for action in tool_actions:
        action.connected_agent_ids.sort()

    unique_tool_names = sorted({action.name for action in tool_actions if action.enabled})

    entry_component_ids = [
        component.id
        for component in components
        if "chatinput" in normalize_name(component.node_type)
        or "chatinput" in normalize_name(component.name)
    ]
    exit_component_ids = [
        component.id
        for component in components
        if "chatoutput" in normalize_name(component.node_type)
        or "chatoutput" in normalize_name(component.name)
    ]

    if not entry_component_ids:
        entry_component_ids = [
            component.id
            for component in components
            if incoming_counts.get(component.id, 0) == 0
            and outgoing_counts.get(component.id, 0) > 0
        ]
    if not exit_component_ids:
        exit_component_ids = [
            component.id
            for component in components
            if outgoing_counts.get(component.id, 0) == 0
            and incoming_counts.get(component.id, 0) > 0
        ]

    return FlowInventory(
        flow_id=flow_id,
        flow_name=_text(clean_flow.get("name"), clean_flow.get("display_name")),
        flow_description=_text(clean_flow.get("description")),
        components=components,
        tool_actions=tool_actions,
        edges=edge_items,
        agent_ids=[item.id for item in components if item.is_agent],
        tool_ids=unique_tool_names,
        entry_component_ids=sorted(entry_component_ids),
        exit_component_ids=sorted(exit_component_ids),
    )
