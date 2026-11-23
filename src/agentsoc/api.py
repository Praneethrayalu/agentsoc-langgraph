"""Authenticated local API. SQLite checkpoints persist analyst review across restarts."""

import hmac
import os
import sqlite3
import uuid
from contextlib import asynccontextmanager
from pathlib import Path
from threading import RLock

from fastapi import Depends, FastAPI, Header, HTTPException
from langgraph.checkpoint.sqlite import SqliteSaver
from langgraph.types import Command

from agentsoc.graph import make_graph
from agentsoc.models import Alert, Review
from agentsoc.retrieval import AttackIndex
from agentsoc.tools import EvidenceTools


def create_app(
    data_dir: str = "data",
    index_dir: str = ".cache/chroma",
    checkpoint_path: str = ".cache/checkpoints.sqlite",
):
    key = os.environ.get("AGENTSOC_API_KEY", "")
    if len(key) < 24:
        raise RuntimeError("Set AGENTSOC_API_KEY to at least 24 random characters before starting the API")
    lock = RLock()

    @asynccontextmanager
    async def lifespan(app):
        Path(checkpoint_path).parent.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(checkpoint_path, check_same_thread=False)
        graph = make_graph(EvidenceTools(Path(data_dir)), AttackIndex(index_dir), SqliteSaver(connection))
        app.state.graph = graph
        yield
        connection.close()

    app = FastAPI(
        title="AgentSOC",
        version="0.1.0",
        lifespan=lifespan,
        description="Read-only alert lab. No containment or external response is executed.",
    )

    def auth(x_api_key: str = Header(default="")):
        if not hmac.compare_digest(x_api_key, key):
            raise HTTPException(401, "Invalid API key")

    def config(ident: uuid.UUID):
        return {"configurable": {"thread_id": str(ident)}}

    def snapshot(ident: uuid.UUID):
        state = app.state.graph.get_state(config(ident))
        if not state.values:
            raise HTTPException(404, "Investigation not found")
        return state

    def view(ident, state):
        return {
            "investigation_id": str(ident),
            "pending_review": bool(state.next),
            "verdict": state.values.get("verdict"),
            "evidence": state.values.get("evidence"),
            "citations": state.values.get("citations"),
            "report": state.values.get("report"),
        }

    @app.get("/health")
    def health():
        return {"status": "ok", "response_execution_enabled": False}

    @app.post("/investigations", status_code=201, dependencies=[Depends(auth)])
    def start(alert: Alert):
        ident = uuid.uuid4()
        with lock:
            app.state.graph.invoke({"alert": alert.model_dump(mode="json")}, config(ident))
            return view(ident, snapshot(ident))

    @app.get("/investigations/{ident}", dependencies=[Depends(auth)])
    def get(ident: uuid.UUID):
        with lock:
            return view(ident, snapshot(ident))

    @app.post("/investigations/{ident}/review", dependencies=[Depends(auth)])
    def review(ident: uuid.UUID, decision: Review):
        with lock:
            state = snapshot(ident)
            if not state.next:
                raise HTTPException(409, "Review already completed")
            app.state.graph.invoke(Command(resume=decision.model_dump()), config(ident))
            return view(ident, snapshot(ident))

    return app
