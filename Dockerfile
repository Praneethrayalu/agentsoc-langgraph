FROM python:3.11-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1
WORKDIR /app
COPY pyproject.toml ./
COPY src ./src
RUN pip install . && useradd --create-home app
COPY data ./data
COPY scripts/rebuild_index.py ./scripts/rebuild_index.py
RUN mkdir -p /app/.cache && chown -R app:app /app
USER app
RUN python scripts/rebuild_index.py
EXPOSE 8000
CMD ["uvicorn", "agentsoc.api:create_app", "--factory", "--host", "0.0.0.0", "--port", "8000"]
