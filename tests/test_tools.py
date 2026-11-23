import pytest
from pydantic import ValidationError

from agentsoc.models import Alert
from agentsoc.tools import EvidenceTools


def test_join_requires_host_and_alert(data):
    tools = EvidenceTools(data)
    assert tools.log_search("wrong-host", "lab-00-01") == []
    assert tools.log_search("endpoint-01", "lab-00-01")[0]["signal"] == "credential_dump"


def test_ip_unknown_and_validation(data):
    tools = EvidenceTools(data)
    assert tools.ip_reputation(None)["status"] == "unknown"
    assert tools.ip_reputation("203.0.113.5")["status"] == "unknown"
    with pytest.raises(ValueError):
        tools.ip_reputation("not-an-ip")


def test_alert_schema(alert):
    Alert.model_validate(alert)
    with pytest.raises(ValidationError):
        Alert.model_validate({**alert, "shell_command": "disallowed"})
    with pytest.raises(ValidationError):
        Alert.model_validate({**alert, "description": "x" * 4001})


def test_log_bound(data):
    tools = EvidenceTools(data)
    tools.logs = [{"host": "a", "alert_id": "b"}] * 200
    assert len(tools.log_search("a", "b", 1000)) == 30
    assert tools.log_search("a", "b", -1) == []


def test_retrieval_has_real_citations(index):
    results = index.search("PowerShell command scripting interpreter")
    assert results[0]["technique_id"] == "T1059.001"
    assert results[0]["url"].startswith("https://attack.mitre.org/techniques/")
