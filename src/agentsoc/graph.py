"""Three nodes, evidence policy, and a real resumable human gate.

The default agents are deterministic specialist nodes, not three autonomous LLMs.
Untrusted alert text never selects tools or authorizes actions.
"""

from typing import TypedDict

from langgraph.graph import END, START, StateGraph
from langgraph.types import interrupt

from agentsoc.models import Alert, Review
from agentsoc.retrieval import AttackIndex
from agentsoc.tools import EvidenceTools


class State(TypedDict, total=False):
    alert: dict
    triage: dict
    evidence: dict
    verdict: str
    reasons: list[str]
    citations: list[dict]
    review: dict
    report: dict
    narrative: str


def make_graph(tools: EvidenceTools, index: AttackIndex, checkpointer, narrator=None):
    def triage(state: State):
        alert = Alert.model_validate(state["alert"])
        return {
            "triage": {
                "category": alert.category,
                "read_only": True,
                "scope": {"host": alert.host, "alert_id": alert.id},
            }
        }

    def investigate(state: State):
        a = state["alert"]
        reputation = tools.ip_reputation(a.get("source_ip"))
        logs = tools.log_search(a["host"], a["id"])
        confirmed = [
            r
            for r in logs
            if r.get("signal")
            in {"credential_dump", "ransomware", "c2_beacon", "malware_execution", "exfiltration"}
        ]
        approved = [r for r in logs if r.get("signal") == "approved_change"]
        suspicious = [
            r
            for r in logs
            if r.get("signal") in {"failed_logins", "encoded_command", "unusual_transfer", "unknown_binary"}
        ]
        # Deny evidence takes precedence over an allowlist/change record.
        if confirmed or reputation["status"] == "malicious":
            verdict = "malicious"
            reasons = ["High-confidence indicator in correlated fixture evidence"]
        elif suspicious:
            verdict = "review"
            reasons = ["Suspicious behavior without conclusive corroboration"]
        elif approved:
            verdict = "benign"
            reasons = ["Approved change record with no correlated threat signal"]
        else:
            verdict = "review"
            reasons = ["Insufficient independent evidence; abstain"]
        citations = index.search(a["title"] + " " + a["description"])
        findings = {
            "evidence": {"reputation": reputation, "logs": logs},
            "verdict": verdict,
            "reasons": reasons,
            "citations": citations,
        }
        if narrator is not None:
            findings["narrative"] = narrator.summarize({**state, **findings})
        return findings

    def report(state: State):
        # Every verdict requires a human review, including a benign recommendation.
        review = Review.model_validate(
            interrupt(
                {
                    "kind": "analyst_review",
                    "alert_id": state["alert"]["id"],
                    "proposed_verdict": state["verdict"],
                    "reasons": state["reasons"],
                    "evidence": state["evidence"],
                    "citations": state["citations"],
                    "advisory_narrative": state.get("narrative"),
                }
            )
        )
        return {
            "review": review.model_dump(),
            "report": {
                "alert_id": state["alert"]["id"],
                "verdict": state["verdict"],
                "status": "approved" if review.approved else "rejected",
                "reviewer_note": review.note,
                "reasons": state["reasons"],
                "evidence": state["evidence"],
                "attack_candidates": state["citations"],
                "advisory_narrative": state.get("narrative"),
                "response_executed": False,
            },
        }

    builder = StateGraph(State)
    builder.add_node("triage", triage)
    builder.add_node("investigation", investigate)
    builder.add_node("report", report)
    builder.add_edge(START, "triage")
    builder.add_edge("triage", "investigation")
    builder.add_edge("investigation", "report")
    builder.add_edge("report", END)
    return builder.compile(checkpointer=checkpointer)
