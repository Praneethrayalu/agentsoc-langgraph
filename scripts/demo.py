"""Run a complete local investigation and a human review prompt."""

import json
import os
from pathlib import Path

from langgraph.checkpoint.memory import InMemorySaver
from langgraph.types import Command

from agentsoc.graph import make_graph
from agentsoc.llm import LocalNarrator
from agentsoc.retrieval import AttackIndex
from agentsoc.tools import EvidenceTools

if __name__ == "__main__":
    graph = make_graph(
        EvidenceTools(Path("data")),
        AttackIndex(".cache/chroma"),
        InMemorySaver(),
        narrator=LocalNarrator(os.environ["AGENTSOC_MODEL"]) if os.environ.get("AGENTSOC_MODEL") else None,
    )
    alert = json.loads(Path("data/alerts.jsonl").read_text().splitlines()[1])["alert"]
    config = {"configurable": {"thread_id": "interactive-demo"}}
    result = graph.invoke({"alert": alert}, config)
    print(json.dumps(result["__interrupt__"][0].value, indent=2))
    approved = input("Approve this report? Type yes to approve, anything else to reject: ").strip() == "yes"
    final = graph.invoke(Command(resume={"approved": approved, "note": "Interactive analyst review"}), config)
    print(json.dumps(final["report"], indent=2))
