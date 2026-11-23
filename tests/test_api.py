import pytest
from fastapi.testclient import TestClient

from agentsoc.api import create_app

KEY = "test-only-api-key-for-fixture-012345"


def app_for(monkeypatch, tmp_path, data, index):
    monkeypatch.setenv("AGENTSOC_API_KEY", KEY)
    return create_app(
        str(data), str(index.client.get_settings().persist_directory), str(tmp_path / "state.sqlite")
    )


def test_api_auth_flow(monkeypatch, tmp_path, data, index, alert):
    app = app_for(monkeypatch, tmp_path, data, index)
    headers = {"X-API-Key": KEY}
    with TestClient(app) as client:
        assert client.get("/health").status_code == 200
        assert client.post("/investigations", json=alert).status_code == 401
        response = client.post("/investigations", json=alert, headers=headers)
        assert response.status_code == 201
        ident = response.json()["investigation_id"]
        assert response.json()["pending_review"] is True
        assert (
            client.post(f"/investigations/{ident}/review", json={"approved": True}, headers=headers).json()[
                "report"
            ]["status"]
            == "approved"
        )
        assert (
            client.post(
                f"/investigations/{ident}/review", json={"approved": True}, headers=headers
            ).status_code
            == 409
        )
        assert (
            client.get("/investigations/00000000-0000-0000-0000-000000000000", headers=headers).status_code
            == 404
        )
        assert client.get("/investigations/not-uuid", headers=headers).status_code == 422


def test_api_requires_secret(monkeypatch):
    monkeypatch.delenv("AGENTSOC_API_KEY", raising=False)
    with pytest.raises(RuntimeError):
        create_app()


def test_resume_survives_restart(monkeypatch, tmp_path, data, index, alert):
    headers = {"X-API-Key": KEY}
    with TestClient(app_for(monkeypatch, tmp_path, data, index)) as client:
        ident = client.post("/investigations", json=alert, headers=headers).json()["investigation_id"]
    with TestClient(app_for(monkeypatch, tmp_path, data, index)) as client:
        assert client.get(f"/investigations/{ident}", headers=headers).json()["pending_review"]
        response = client.post(f"/investigations/{ident}/review", json={"approved": False}, headers=headers)
        assert response.status_code == 200
        assert response.json()["report"]["status"] == "rejected"
