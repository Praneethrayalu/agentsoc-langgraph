# AgentSOC

An evidence-first security alert investigation lab. Three LangGraph specialist
nodes correlate an alert with read-only tools, retrieve relevant MITRE ATT&CK
techniques from Chroma, and pause for a human decision before releasing a report.
Runs locally on a CPU. No paid API key, cloud account, or GPU is required.

## What is real, and what is simulated

- Real LangGraph execution: `triage -> investigation -> report`, with `interrupt`
  and `Command(resume=...)`. SQLite checkpoints survive an API restart.
- Real Chroma retrieval over **706 official Enterprise ATT&CK technique and
  sub-technique descriptions**. These are STIX descriptions, not scraped web pages.
  Every candidate includes its official URL. Retrieval uses 2,048-dimensional
  hashing vectors, not a pretrained neural embedding model.
- IP reputation and log search are **offline synthetic fixtures**, not live threat
  intelligence or a SIEM integration. All sample IP addresses use documentation ranges.
- Default specialist nodes use explicit evidence rules. They are **not three LLM
  agents**. Optional local Qwen narration turns retrieved context and evidence into
  a short draft; it cannot change the verdict or invoke tools.
- A real local Qwen model is used for the single-prompt evaluation baseline.
- This is a portfolio lab, not production-ready detection, incident response,
  malware analysis, or a substitute for an analyst. It never contains or blocks a host.

## Architecture

```text
Alert (validated schema)
   |
   v
triage: scope by host + alert ID
   |
   v
investigation: offline IP lookup + exact-match log search + Chroma ATT&CK retrieval
   |           explicit evidence verdict + optional advisory local-LLM RAG summary
   v
report: LangGraph interrupt -> analyst approves / rejects -> immutable final report
```

All verdicts require review, including benign recommendations. A rejected report
remains rejected. Repeated API review attempts return 409. Candidate ATT&CK matches
are hypotheses, not proof of a technique being executed.

## Quick start: Windows PowerShell, 16 GB RAM, no GPU

Python 3.10-3.12 and Git are required. The normal path does not download a model.

```powershell
git clone https://github.com/Praneethrayalu/agentsoc-langgraph.git
cd agentsoc-langgraph
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e ".[dev]"
python scripts/rebuild_index.py
pytest -q
python scripts/demo.py
```

If script activation is restricted, invoke `.\.venv\Scripts\python.exe` directly.
On Linux/macOS use `python3 -m venv .venv` and `source .venv/bin/activate`.
The index is rebuilt from the versioned corpus, so no MITRE network request is
needed at runtime. First installation still needs internet for Python packages.
The 706-record index is small. The optional Qwen GGUF is about 469 MiB and works on
CPU; actual memory and speed vary. The reference run used a 2-core Linux machine.
Windows installation has been documented but not tested on a Windows host.

## API

Generate a local random API key; do not commit it:

```powershell
$env:AGENTSOC_API_KEY = python -c "import secrets; print(secrets.token_urlsafe(32))"
uvicorn agentsoc.api:create_app --factory --host 127.0.0.1 --port 8000
```

Open `http://127.0.0.1:8000/docs`. Use `X-API-Key` for protected routes.

| Route | Behavior |
|---|---|
| `GET /health` | Liveness only, no sensitive details |
| `POST /investigations` | Validate alert, run tools, pause for review; returns generated ID |
| `GET /investigations/{id}` | Read evidence, citations, review state and final report |
| `POST /investigations/{id}/review` | Body `{"approved": true, "note": "Reviewed evidence"}` |

A sample request is `data/example_alert.json`. It correlates with the fixture log
containing a credential-dump signal. A novel alert without corroborating fixture
evidence should return `review`, not a fabricated conclusion.

For a curl-capable shell:

```sh
curl -s http://127.0.0.1:8000/investigations \
  -H "Content-Type: application/json" -H "X-API-Key: $AGENTSOC_API_KEY" \
  --data-binary @data/example_alert.json
```

SQLite and Chroma state live in `.cache/`. Run one API worker. The shared key is
suitable for a local single-user lab, not multi-tenant authentication. Keep it on
localhost; do not expose it to the internet without TLS, identity, authorization,
audit retention, rate limits, and a deployment security review.

## Optional local LLM RAG narration

```powershell
python -m pip install llama-cpp-python --only-binary=:all: --extra-index-url https://abetlen.github.io/llama-cpp-python/whl/cpu
New-Item -ItemType Directory -Force models
Invoke-WebRequest "https://huggingface.co/Qwen/Qwen2.5-0.5B-Instruct-GGUF/resolve/main/qwen2.5-0.5b-instruct-q4_k_m.gguf" -OutFile models/qwen2.5-0.5b-instruct-q4_k_m.gguf
$env:AGENTSOC_MODEL = "$PWD/models/qwen2.5-0.5b-instruct-q4_k_m.gguf"
python scripts/demo.py
```

CPU wheels may not be available for every Python/Windows combination. If a wheel
cannot be found, use the no-model path or build llama-cpp-python with its documented
compiler prerequisites. There is no silent fallback to a paid provider. The 0.5B
model is deliberately small and can produce poor summaries. A real local narration
smoke run is saved in `reports/rag_narration_smoke.json`; it was rejected for
reference testing, not approved by a human analyst. That run includes broad or
imperfect retrieval matches and a summary without consistent technique-ID
citations. It demonstrates the wiring, not validated grounding quality. Its text is advisory
and must be checked against the displayed evidence and citations.

## Reproduce the benchmark

```powershell
python scripts/generate_fixtures.py
python scripts/rebuild_index.py
python scripts/evaluate.py --model models/qwen2.5-0.5b-instruct-q4_k_m.gguf
```

Committed raw results: [`reports/evaluation.json`](reports/evaluation.json), including
all 100 predictions, labels, per-alert times, hashes, prompt, model and platform.

| Measured on 100 synthetic alerts | Evidence graph | Single-prompt Qwen 0.5B Q4_K_M |
|---|---:|---:|
| Match to constructed label | 100/100 | 40/100 |
| Mean runtime per alert | 0.0091 s | 0.6409 s |
| p95 runtime per alert | 0.0080 s | 0.6710 s |

**Do not interpret this as 100% real-world detection accuracy.** The dataset has ten
scenario families repeated with ten context variants, not 100 independent real
incidents. Labels come from the same evidence policy the graph implements. The
graph gets correlated synthetic logs and reputation while the text-only baseline
does not. The baseline predicted `malicious` on every alert, matching a 40% majority
baseline. This comparison demonstrates context and policy mechanics, not that a
rule graph is a better language model. No training/test split or statistical
significance is claimed. Index/model startup and analyst wait time are excluded;
graph time includes retrieval and pausing before approval. p95 can be below mean
when startup overhead affects a small number of rows.

## Tests, packaging and CI

```sh
pytest -q
ruff check src scripts tests
ruff format --check src scripts tests
docker build -t agentsoc .
docker run --rm -p 127.0.0.1:8000:8000 -e AGENTSOC_API_KEY agentsoc
```

Tests cover all scenario families, gate behavior, rejection, exact evidence joins,
unknowns, conflicting evidence, schema bounds, citation retrieval, API auth, repeat
review rejection, and SQLite restart persistence. The Dockerfile uses a non-root
user. Docker is not installed on the reference test machine, so the container build
has **not** been verified. CI is supplied for Python 3.10/3.11/3.12; local tests were
run on 3.10, and remote CI results must be checked separately. `requirements-lock.txt`
records the Linux reference environment, including optional evaluator dependencies;
use `pyproject.toml` for cross-platform installation.

## Data provenance and licensing

- [Official ATT&CK STIX source](https://github.com/mitre-attack/attack-stix-data).
  `data/attack_manifest.json` records the full-source SHA-256, bundle ID, latest
  object timestamp, and embedding configuration. The vendored extract is limited
  to active, non-deprecated attack patterns. Refresh with
  `python scripts/ingest_attack.py`; the `master` URL moves, so future refreshes can
  change the count. Rebuild from committed data for an exact corpus replay.
- ATT&CK content: see [`data/ATTACK-LICENSE.txt`](data/ATTACK-LICENSE.txt).
  Copyright 2026 The MITRE Corporation. Reproduced with permission under its license.
- [Qwen model and model card](https://huggingface.co/Qwen/Qwen2.5-0.5B-Instruct-GGUF).
  Weights are not redistributed here. Review its license before use.
- Synthetic data: generated by `scripts/generate_fixtures.py`. No personal logs,
  customer data, live credentials, or real malicious payloads are included.
- Project code: MIT. AI-assisted implementation; review and understand the code
  before presenting it as a skill demonstration. No employment, deployment, or
  operational security experience is implied by this repository.

## Next steps

Add a real, authorized SIEM adapter with provenance and time bounds; build a blinded
human-labeled incident dataset; compare both systems with equal evidence; measure
retrieval relevance and grounding independently; add multi-user auth, audit trails,
retention policy, monitoring and deployment hardening before any production use.
