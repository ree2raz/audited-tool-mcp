"""HF Space entry point — FastAPI + MCP Streamable HTTP + real Privacy Filter.

Uses the documented FastMCP + FastAPI lifespan pattern:
  GET  /     → static frontend
  ALL  /mcp  → MCP Streamable HTTP (handled by mounted mcp_app)
"""

from __future__ import annotations

import logging
import os
import subprocess
import sys
import time
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import HTMLResponse, FileResponse

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(name)s] %(levelname)s: %(message)s")
logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Ensure database is seeded
# ---------------------------------------------------------------------------
DB_PATH = Path("data/synthetic_fs.sqlite")
if not DB_PATH.exists():
    logger.info("Seeding database...")
    subprocess.run([sys.executable, "scripts/seed_data.py"], check=True)

# ---------------------------------------------------------------------------
# Import MCP server
# ---------------------------------------------------------------------------
logger.info("Loading auditguard-mcp server...")
from auditguard_mcp.server import mcp  # noqa: E402

# Pre-warm Privacy Filter model
logger.info("Pre-warming Privacy Filter model (1.5B MoE, 50M active params)...")
_start = time.monotonic()
from auditguard_mcp.privacy import detect  # noqa: E402

detect("Warmup")
_elapsed = time.monotonic() - _start
logger.info("Privacy Filter loaded in %.1fs", _elapsed)

# ---------------------------------------------------------------------------
# FastAPI app with MCP lifespan
# ---------------------------------------------------------------------------
WEB_DIR = Path(__file__).parent / "web"


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Start MCP session manager on app startup, shut down on teardown."""
    async with mcp._session_manager.run():
        logger.info("MCP Streamable HTTP session manager started")
        yield
    logger.info("MCP Streamable HTTP session manager stopped")


app = FastAPI(title="auditguard-mcp", docs_url=None, redoc_url=None, lifespan=lifespan)


@app.get("/")
async def index():
    """Serve the single-page demo frontend."""
    return HTMLResponse((WEB_DIR / "index.html").read_text())


@app.get("/favicon.svg")
async def favicon():
    """Serve the favicon."""
    return FileResponse(WEB_DIR / "favicon.svg", media_type="image/svg+xml")


# Mount MCP at root — mcp_app internally handles /mcp route.
# Must come after @app.get("/") so the landing page takes priority.
app.mount("/", mcp.streamable_http_app())

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import uvicorn

    port = int(os.environ.get("PORT", "7860"))
    logger.info("Starting auditguard-mcp web demo on port %d", port)
    uvicorn.run("web_app:app", host="0.0.0.0", port=port, log_level="info")
