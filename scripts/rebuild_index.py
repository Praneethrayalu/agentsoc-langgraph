import json
from pathlib import Path

from agentsoc.retrieval import AttackIndex

if __name__ == "__main__":
    docs = json.loads(Path("data/attack_techniques.json").read_text())
    AttackIndex(".cache/chroma").load(docs)
    print(f"Indexed {len(docs)} vendored ATT&CK technique descriptions")
