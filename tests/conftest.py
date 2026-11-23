import json
from pathlib import Path

import pytest

from agentsoc.retrieval import AttackIndex


@pytest.fixture(scope="session")
def data():
    return Path(__file__).resolve().parents[1] / "data"


@pytest.fixture(scope="session")
def index(tmp_path_factory, data):
    path = str(tmp_path_factory.mktemp("index"))
    instance = AttackIndex(path)
    docs = json.loads((data / "attack_techniques.json").read_text())
    instance.load([d for d in docs if d["id"] in {"T1059.001", "T1003.001", "T1566.001"}])
    return instance


@pytest.fixture
def alert(data):
    return json.loads((data / "alerts.jsonl").read_text().splitlines()[1])["alert"]
