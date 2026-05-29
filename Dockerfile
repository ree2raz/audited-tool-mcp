# HF Space Docker deployment for auditguard-mcp
# Real MCP server + real Privacy Filter model (1.5B MoE, 50M active params)
# CPU-only: no CUDA deps (HF Spaces are CPU-only, saves ~400MB download)

FROM python:3.12-slim

WORKDIR /app

# Install uv via pip (fast, no apt-get needed)
RUN pip install --no-cache-dir uv

# === LAYER 1: Light dependencies (fast, rarely change) ===
# These install quickly, so we cache them separately
RUN uv pip install --system --no-cache \
    "pydantic>=2.0.0" \
    "fastapi>=0.110.0" \
    "uvicorn>=0.29.0" \
    "httpx>=0.27.0" \
    "python-dotenv>=1.0.0" \
    "sqlglot>=23.0.0" \
    "faker>=25.0.0" \
    "sqlalchemy>=2.0.0"

# === LAYER 2: CPU-only ML dependencies (no CUDA, ~100MB vs ~400MB) ===
# HF Spaces are CPU-only, so we skip CUDA deps entirely
RUN uv pip install --system --no-cache \
    --extra-index-url https://download.pytorch.org/whl/cpu \
    "torch" \
    "accelerate>=0.26.0" \
    "transformers>=4.40.0" \
    "mcp[cli]>=1.0.0"

# === LAYER 3: LangGraph orchestration backend ===
RUN uv pip install --system --no-cache \
    "langgraph>=0.2.0" \
    "langchain-core>=0.3.0"

# Copy application code (changes won't bust dep layers)
COPY auditguard_mcp/ ./auditguard_mcp/
COPY scripts/ ./scripts/
COPY web/ ./web/
COPY web_app.py ./

# Create data dir and seed DB at build time
RUN mkdir -p data && python scripts/seed_data.py

# HF Spaces uses port 7860
ENV PORT=7860
ENV HF_HOME=/data/huggingface
ENV TRANSFORMERS_CACHE=/data/huggingface
# Optional: Path to local Privacy Filter model. If set and exists, loads from disk.
# Otherwise downloads from HF Hub and caches to HF_HOME.
# Example: docker run -v /path/to/model:/app/model -e PRIVACY_FILTER_LOCAL_PATH=/app/model ...
ENV PRIVACY_FILTER_LOCAL_PATH=""

EXPOSE 7860

# The app will download openai/privacy-filter on first startup (~6GB, cached to /data)
CMD ["uvicorn", "web_app:app", "--host", "0.0.0.0", "--port", "7860", "--log-level", "info"]
