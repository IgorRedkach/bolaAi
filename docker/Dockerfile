# BOLA AI — Ready-to-go container (RAG preload at first run to avoid build OOM)
FROM python:3.11-slim

WORKDIR /app

COPY pyproject.toml ./
COPY src/ ./src/
COPY data/ /app/data/

RUN pip install --no-cache-dir fastapi "uvicorn[standard]" httpx pydantic chromadb sentence-transformers python-multipart jinja2 pyyaml

ENV BOLA_AI_DATA=/data
ENV OLLAMA_HOST=http://ollama:11434
ENV OLLAMA_MODEL=bola-analyzer
ENV PYTHONPATH=/app/src
# Set to 0 to skip RAG preload on first start (if limited RAM)
ENV BOLA_AI_PRELOAD=1

COPY docker/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 8000
ENTRYPOINT ["/entrypoint.sh"]
