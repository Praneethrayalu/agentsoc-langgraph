"""Compare evidence graph with a genuine single-prompt local-LLM baseline."""

import argparse
import hashlib
import json
import platform
import statistics
import time
from collections import Counter
from pathlib import Path

from langgraph.checkpoint.memory import InMemorySaver

from agentsoc.graph import make_graph
from agentsoc.llm import SYSTEM, LocalClassifier
from agentsoc.retrieval import AttackIndex
from agentsoc.tools import EvidenceTools


def metrics(rows, key):
    times = sorted(r[key + "_seconds"] for r in rows)
    confusion = Counter((r["label"], r[key]) for r in rows)
    return {
        "accuracy": sum(r["label"] == r[key] for r in rows) / len(rows),
        "latency_mean_seconds": statistics.mean(times),
        "latency_median_seconds": statistics.median(times),
        "latency_p95_seconds": times[max(0, int(len(times) * 0.95) - 1)],
        "confusion_matrix": {f"{a}->{b}": count for (a, b), count in sorted(confusion.items())},
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--model", required=True)
    parser.add_argument("--limit", type=int, default=100)
    parser.add_argument("--output", default="reports/evaluation.json")
    args = parser.parse_args()
    rows = [json.loads(line) for line in Path("data/alerts.jsonl").read_text().splitlines()][: args.limit]
    graph = make_graph(EvidenceTools(Path("data")), AttackIndex(".cache/chroma"), InMemorySaver())
    llm = LocalClassifier(args.model)
    measured = []
    for row in rows:
        t = time.perf_counter()
        result = graph.invoke({"alert": row["alert"]}, {"configurable": {"thread_id": row["alert"]["id"]}})
        graph_time = time.perf_counter() - t
        t = time.perf_counter()
        baseline = llm.classify(row["alert"])
        baseline_time = time.perf_counter() - t
        measured.append(
            {
                "id": row["alert"]["id"],
                "label": row["label"],
                "graph": result["verdict"],
                "baseline": baseline,
                "graph_seconds": graph_time,
                "baseline_seconds": baseline_time,
            }
        )
        print(len(measured), row["label"], result["verdict"], baseline, round(baseline_time, 3), flush=True)
    report = {
        "n": len(rows),
        "dataset": "synthetic lab, ten scenario families x ten context variants",
        "dataset_sha256": hashlib.sha256(Path("data/alerts.jsonl").read_bytes()).hexdigest(),
        "model_filename": Path(args.model).name,
        "model_sha256": hashlib.sha256(Path(args.model).read_bytes()).hexdigest(),
        "platform": platform.platform(),
        "python": platform.python_version(),
        "threads": 2,
        "baseline_prompt": SYSTEM,
        "temperature": 0,
        "seed": 42,
        "graph": metrics(measured, "graph"),
        "baseline": metrics(measured, "baseline"),
        "caveats": [
            "Graph has privileged correlated fixture logs and reputation; baseline sees alert text only.",
            "Labels are constructed from the same explicit evidence policy as the graph.",
            "Not a fair model-quality comparison, not real attack detection accuracy.",
            "Model/index startup and human waiting time excluded; graph includes retrieval and pause.",
            "No training/test split; synthetic scenario variants are not independent samples.",
        ],
        "rows": measured,
    }
    Path(args.output).write_text(json.dumps(report, indent=2))
    print(json.dumps({key: report[key] for key in ("n", "graph", "baseline")}, indent=2))


if __name__ == "__main__":
    main()
