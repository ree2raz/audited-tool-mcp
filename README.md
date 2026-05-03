---
title: AuditGuard MCP
emoji: 🔒
colorFrom: blue
colorTo: gray
sdk: docker
pinned: false
license: apache-2.0
---

# auditguard-mcp

A compliance-aware AI tool gateway. When an LLM calls a tool, that call passes through a 7-stage audit pipeline before execution and again before returning. Every stage is pluggable. Every decision is logged. No raw PII leaves the system.

Built on OpenAI's Privacy Filter (1.5B params, April 2026), running locally on CPU. This is not a library you install. It is a complete system that demonstrates how to build production-grade AI safety infrastructure for regulated workflows.

[![Live Demo](https://img.shields.io/badge/Live-Demo-blue)](https://auditguard.rituraj.info)

<details>
<summary><strong>Watch the demo</strong></summary>
<br>

<em>Async backend</em> — analyst query with PII hashing, RBAC denial for intern, audit log:

<video src="https://github.com/ree2raz/auditguard-mcp/releases/download/v1.0/async_demo.mp4" controls="controls" style="max-width:100%;"></video>

<em>Temporal backend</em> — same pipeline with durable workflow, Temporal UI link:

<video src="https://github.com/ree2raz/auditguard-mcp/releases/download/v1.0/temporal_demo.mp4" controls="controls" style="max-width:100%;"></video>

</details>

## The problem

Most MCP servers treat tool calls as transparent passthroughs. The LLM asks for SQL. The server runs SQL. The LLM gets results. This is fast. It is also unauditable. If a query returned customer SSNs to an intern, there is no record of who saw what, under which policy, with which PII redactions applied. The tool executed. Nothing else happened.

The fix is not a bolt-on. The fix is a pipeline that gates every tool call through four primitives before execution and two more after. RBAC, PII detection, policy enforcement, structured audit logging. If a request cannot pass all four, the tool never runs.

## Architecture: ports and adapters

The pipeline uses a ports-and-adapters (hexagonal) pattern. Stage logic lives in `pipeline/stages.py` as pure functions. No IO, no framework dependencies, easy to test. Each orchestration backend (`async_runner.py`, `temporal_runner.py`) is a thin adapter that calls those functions in sequence. Adding a third backend (AWS Step Functions, Celery) is roughly 100 lines of adapter code, not a rewrite.

The design is **fail-closed**. Unparseable SQL always triggers `RBACDenied`. Missing policy categories default to `ALLOW` explicitly. Audit records never contain raw PII.

See [`docs/architecture.md`](docs/architecture.md) for the full design rationale.

## PII detection: a local 1.5B model, not regex

Most production PII detection is regex-based. Regex catches SSN patterns and email addresses. It misses contextual PII. A sentence like "the Henderson trust's primary contact" contains no syntactic PII pattern, but a token classifier identifies "Henderson" as a `private_person` span. Regex does not.

The project integrates [OpenAI's Privacy Filter](https://huggingface.co/openai/privacy-filter), a 1.5B-parameter sparse mixture-of-experts with 128 experts and top-4 routing (50M active parameters per inference). Runs locally on CPU. No data sent to any API. Supports 8 PII categories using constrained Viterbi decoding over a BIOES tagging scheme. We built robust BIOES span decoding (`privacy.py`) to map token predictions back to exact character offsets. This is the unglamorous part most integrations skip and the part that determines whether detections are correct or off-by-several-characters.

**Honest limitation.** The model occasionally over-redacts public entities and flags numeric financial values (e.g., `496959.67`) as phone numbers. We handle this with a post-detection numeric guard in `policy.py` rather than trying to force the model to behave differently. Detection is a primitive, not a pipeline. The model detects. The policy layer decides.

## Security: RBAC, policy engine, audit trails

**RBAC** uses `sqlglot` to parse SQL into an AST, extracting tables and columns for access validation. Handles subqueries, JOINs, `SELECT *`, and table-prefixed columns. Column filtering uses union logic across JOINs, not intersection. The check is O(1) set membership for tool names, AST-walked for column access.

**The policy engine** supports six actions: `ALLOW`, `REDACT`, `HASH`, `VAULT`, `REVIEW`, `BLOCK`. Per-category, per-direction, per-role mappings. `HASH` replaces PII with `[category:sha256-first-8]`, preserving identity consistency so analysts can `GROUP BY` pseudonymized data without seeing real names.

Two bundled policies demonstrate opposite compliance philosophies:

1. **permissive_analyst**: hashes names and emails so analysts can correlate records across tables
2. **strict_financial**: replaces all PII with generic `[category]` tags, preventing even statistical correlation

Same detection pipeline. Same engine. Same audit logger. Only the config differs.

**Audit records** never store raw PII. Original queries and outputs are SHA-256 hashed. Detection text is replaced with `[category]` placeholders. One JSONL record per request, containing the full decision trace. A regulator can verify that the pipeline ran, inspect every decision, and confirm the policy version in effect at the time. They cannot reconstruct the customer's SSN from the audit log. That is the point.

## Infrastructure: Temporal, Docker, async

Two orchestration backends for the same 7-stage pipeline:

| | Async (default) | Temporal |
|---|---|---|
| Latency overhead | None | ~50-100ms per stage |
| Durability | Lost on crash | Resumes from last completed stage |
| Human-in-the-loop | No | 24-hour signal timeout |
| Retry per stage | No | Independent policies (RBAC: 3 attempts, Audit: 20) |
| Operational cost | Zero | Temporal cluster + worker process |

The Temporal workflow (`temporal_runner.py`) handles `ActivityError` unwrapping for RBAC denial, heartbeating for long model inference, and human review signals. Temporal tests use an in-memory server. No Docker needed for CI.

## The 7-stage pipeline

Every tool call flows through seven stages. Cheapest checks first, most expensive last.

```
    User Query
       |
       v
[1] RBAC Gate           fail-closed set membership check (O(1))
       |
       v
[2] Inbound PII Scan    1.5B Privacy Filter detects 8 categories
       |
       v
[3] Inbound Policy      ALLOW | REDACT | HASH | VAULT | REVIEW | BLOCK
       |
       v
[4] Tool Execution      bounded, with timeouts
       |
       v
[5] Outbound PII Scan   canonical JSON scan (sort_keys=True)
       |
       v
[6] Outbound Policy     redact/hash/vault results before returning
       |
       v
[7] Audit Logging       append-only JSONL (SHA-256, no raw PII)
       |
       v
    LLM Response
```

RBAC denies without touching the PII model. The PII model runs before the tool, so a blocked secret never reaches execution. The audit logger fires last, in a `finally`-equivalent path, so it captures timeouts, errors, and blocked requests in addition to successful ones. A failed request that RBAC-denied an intern produces the same audit record shape as a successful request that ran SQL and redacted three account numbers.

## Quality: tests, eval, benchmarks

- **108 tests** across unit, integration, and pipeline stages (`tests/`)
- **Golden-set eval harness** with 15 test cases measuring RBAC accuracy, PII detection accuracy, and audit completeness (`eval/`)
- **Latency benchmarks** reporting p50/p90/p95/p99 for the 1.5B model on CPU (`benchmarks/`)

## Full-stack demo

- **Interactive web demo** (`web/index.html`): single-page app with real-time pipeline visualization, MCP Streamable HTTP client, and animated 7-step status indicators. Shows backend type (async/temporal) and links to Temporal UI for workflow inspection.
- **LangGraph ReAct agent** (`examples/agent/`): 3-node agent consuming the MCP server via stdio transport.
- **Synthetic financial dataset** (`scripts/seed_data.py`): realistic data with deliberate PII edge cases (aliases, compound identifiers, one-hop references).

## What this is not

This is a reference implementation, not a production-hardened service. Three gaps are documented explicitly:

1. The `REVIEW` action is synchronous. In production, hold the request, return a pending status, and wait for an out-of-band human approval webhook.
2. The vault is a local JSONL file. In production, replace it with [AWS KMS](https://aws.amazon.com/kms/) or [HashiCorp Vault](https://www.vaultproject.io/).
3. The stdio transport assumes a trusted local client. For SSE transport, add mTLS client certificate validation.

The repo does not include async review queues, streaming architecture, or multi-node scaling. It is the minimum viable pipeline that proves the four primitives compose correctly.

## Running it

```bash
# Prerequisites: Python 3.11+, uv

git clone https://github.com/ree2raz/auditguard-mcp.git
cd auditguard-mcp
make install
make seed
MOCK_PII=1 make demo
# -> http://localhost:7860
```

For Temporal backend:

```bash
docker compose -f docker/docker-compose.temporal.yml up -d   # Temporal cluster
AUDITGUARD_BACKEND=temporal python -m auditguard_mcp.pipeline.temporal_worker  # Worker
AUDITGUARD_BACKEND=temporal uv run uvicorn web_app:app --port 7860             # Server
# -> http://localhost:8080 for Temporal UI
```

## Tech stack

| Component | Technology |
|-----------|-----------|
| Language | Python 3.14 |
| MCP Server | FastMCP (stdio + Streamable HTTP) |
| PII Detection | OpenAI Privacy Filter 1.5B (local CPU) |
| SQL Parsing | sqlglot |
| Orchestration | asyncio / Temporal |
| Web Framework | FastAPI + Uvicorn |
| Database | SQLite (synthetic) |
| Container | Docker (multi-layer, CPU-only ML deps) |

## The verifiability stack

auditguard-mcp is one piece of a three-repo compliance verification stack. The other two solve adjacent problems.

[rubric-grader-eval](https://github.com/ree2raz/rubric-grader-eval) handles deterministic evaluation. It compiles unstructured rubrics into machine-readable schemas, then evaluates documents against them with golden-set ground truth. If auditguard-mcp answers "did the pipeline run correctly?", rubric-grader-eval answers "did the LLM produce correct verdicts?"

[RegTriage](https://github.com/ree2raz/RegTriage-OpenEnv) handles agentic auditing. It is an RL environment that trains agents to audit contact center transcripts under a compute budget, forcing triage strategy over brute-force. If rubric-grader-eval measures accuracy, RegTriage measures whether an agent can prioritize high-risk sections under resource constraints.

Together: auditguard-mcp proves the tool call was compliant. rubric-grader-eval proves the evaluation was accurate. RegTriage proves the agent can scale. Scrutiny proves the pattern works as a vertical product. Four repos. One problem class. Verifiability from tool call to final report.

## License

[Apache License 2.0](LICENSE)