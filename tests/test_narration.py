from langgraph.checkpoint.memory import InMemorySaver
from langgraph.types import Command

from agentsoc.graph import make_graph
from agentsoc.tools import EvidenceTools


class StubNarrator:
    def summarize(self, state):
        assert state["citations"]
        return "Advisory test summary, no actions taken."


def test_optional_narration_does_not_skip_human_gate(data, index, alert):
    graph = make_graph(EvidenceTools(data), index, InMemorySaver(), narrator=StubNarrator())
    cfg = {"configurable": {"thread_id": "narrated"}}
    result = graph.invoke({"alert": alert}, cfg)
    assert result["narrative"].startswith("Advisory")
    assert result["verdict"] == "malicious"
    assert "report" not in result
    assert result["__interrupt__"]
    final = graph.invoke(Command(resume={"approved": False}), cfg)
    assert final["report"]["advisory_narrative"] == result["narrative"]
    assert final["report"]["response_executed"] is False
