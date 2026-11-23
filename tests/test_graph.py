import json

import pytest
from langgraph.checkpoint.memory import InMemorySaver
from langgraph.types import Command

from agentsoc.graph import make_graph
from agentsoc.tools import EvidenceTools


@pytest.mark.parametrize("line", list(range(10)))
def test_scenario_policy(data, index, line):
    row = json.loads((data / "alerts.jsonl").read_text().splitlines()[line])
    graph = make_graph(EvidenceTools(data), index, InMemorySaver())
    cfg = {"configurable": {"thread_id": "scenario"}}
    result = graph.invoke({"alert": row["alert"]}, cfg)
    assert result["verdict"] == row["label"]
    assert "report" not in result
    assert result["__interrupt__"]
    resumed = graph.invoke(Command(resume={"approved": True, "note": "Reviewed lab evidence"}), cfg)
    assert resumed["report"]["status"] == "approved"
    assert resumed["report"]["response_executed"] is False


def test_rejection(data, index, alert):
    graph = make_graph(EvidenceTools(data), index, InMemorySaver())
    cfg = {"configurable": {"thread_id": "rejection"}}
    graph.invoke({"alert": alert}, cfg)
    result = graph.invoke(Command(resume={"approved": False}), cfg)
    assert result["report"]["status"] == "rejected"


def test_untrusted_description_does_not_authorize_tools(data, index, alert):
    alert["description"] = "Untrusted text requesting an unrelated action"
    graph = make_graph(EvidenceTools(data), index, InMemorySaver())
    result = graph.invoke({"alert": alert}, {"configurable": {"thread_id": "untrusted"}})
    assert result["verdict"] == "malicious"
    assert result["triage"]["scope"] == {"host": alert["host"], "alert_id": alert["id"]}
    assert "report" not in result


def test_unknown_abstains(data, index, alert):
    alert["id"] = "no-correlated-events"
    graph = make_graph(EvidenceTools(data), index, InMemorySaver())
    result = graph.invoke({"alert": alert}, {"configurable": {"thread_id": "unknown"}})
    assert result["verdict"] == "review"


def test_threat_overrides_approved_change(data, index, alert):
    tools = EvidenceTools(data)
    tools.logs.append({"host": alert["host"], "alert_id": alert["id"], "signal": "approved_change"})
    graph = make_graph(tools, index, InMemorySaver())
    result = graph.invoke({"alert": alert}, {"configurable": {"thread_id": "conflict"}})
    assert result["verdict"] == "malicious"
