# audited-tool-mcp

A production-grade, compliance-aware Model Context Protocol (MCP) server that wraps LLM tool use with four primitives: PII safety, role-based access control (RBAC), configurable policy enforcement, and structured audit logging.

This project serves as a reference implementation for agentic systems in highly regulated industries.

## Try it in 60 seconds

Prerequisites: Python 3.11+, `uv`

```bash
# Set your OpenAI API key for the demo's LangGraph agent
export OPENAI_API_KEY="sk-..."

git clone https://github.com/ree2raz/audited-tool-mcp.git
cd audited-tool-mcp
make install
make seed
MOCK_PII=1 make demo
```

## 1. What this is

When an LLM (the client) calls a tool (e.g., `sql_query`), that call passes through a strict compliance pipeline before execution, and the result passes through the pipeline again before returning to the LLM.

1. **RBAC Gate**: Fails fast if the user's role lacks access to the tool or specific data fields.
2. **Inbound PII Scan**: Detects sensitive data in the query using OpenAI's 1.5B parameter Privacy Filter.
3. **Inbound Policy**: Applies role-specific rules (Allow, Redact, Hash, Vault, Review, Block).
4. **Tool Execution**: Executes the bounded tool (with timeouts).
5. **Outbound PII Scan**: Scans the canonical JSON output.
6. **Outbound Policy**: Applies redaction/hashing rules to the results.
7. **Audit Logging**: Writes a structured JSONL record of the entire trace.

## 2. Architecture

Every tool call flows through a 7-step pipeline. Cheapest checks first, most expensive last.

```
    User Query
       │
       ▼
[1] RBAC Gate ────── fail-closed set membership check (O(1))
       │
       ▼
[2] Inbound PII Scan ── 1.5B Privacy Filter detects 8 categories
       │
       ▼
[3] Inbound Policy ──── ALLOW | REDACT | HASH | VAULT | REVIEW | BLOCK
       │
       ▼
[4] Tool Execution ──── bounded, with timeouts
       │
       ▼
[5] Outbound PII Scan ── canonical JSON scan (sort_keys=True)
       │
       ▼
[6] Outbound Policy ──── redact/hash/vault results before returning
       │
       ▼
[7] Audit Logging ───── append-only JSONL (SHA-256, no raw PII)
       │
       ▼
    LLM Response
```

The server uses `FastMCP` with `stdio` transport. The core pipeline is in `audited_tool_mcp/server.py:process_request()`.

## 3. The Privacy Filter

We use `openai/privacy-filter`, a 1.5B parameter bidirectional token classifier that supports 8 PII categories (e.g., `private_person`, `account_number`, `secret`). 

- It runs **locally on CPU** by default. No data is sent to OpenAI APIs.
- We implemented robust BIOES span decoding to accurately map token predictions back to character offsets in the original text.
- For fast local testing, setting `MOCK_PII=1` bypasses the model and uses a regex stub.
  - *Note: The mock is a fast stub for local iteration and CI. Real Privacy Filter detection is qualitatively different and handles complex semantics. See the benchmarks in `benchmarks/` for latency comparisons.*

### What Privacy Filter gets wrong
Because Privacy Filter was trained to aggressively protect personal data, it occasionally over-redacts public entities. For example, if a query returns a transaction counterparty named "Bennett Group", the model may tag it as three separate `private_person` spans.

We leave this behavior intact in the demo to illustrate a core design philosophy: **detection is a primitive, not a pipeline.** If your use case requires suppressing company name false-positives, the correct place to do so is in a post-detection filter (e.g., dropping spans that match known company suffixes), rather than trying to force the model to behave differently.

## 4. RBAC and Policy Engine

Policies are defined as strict Pydantic models, not loose YAML files. This ensures type safety and IDE autocomplete.

There are six policy actions:
- `ALLOW`: Pass through unchanged.
- `REDACT`: Replace with `[category]`.
- `HASH`: Replace with `[category:sha256-first-8]`. Preserves identity consistency.
- `VAULT`: Store raw text in `vault.jsonl` and replace with a UUID reference.
- `REVIEW`: Leave intact but flag for human review (writes to `review_queue.jsonl`).
- `BLOCK`: Halt the request immediately and raise a `PolicyViolation`.

**Policy Philosophies:**
The repo includes two bundled policies that demonstrate different compliance philosophies:
- `permissive_analyst`: Prioritizes data usability. Replaces names and emails with a `HASH` so analysts can still correlate records (e.g., `GROUP BY`) belonging to the same entity across tables without knowing the entity's true identity.
- `strict_financial`: Prioritizes absolute privacy. Replaces names and emails with a generic `REDACT` (e.g., `[private_person]`), preventing even statistical correlation.

> **What's happening here?** `permissive_analyst_v1` keeps redacted text **inline** as `[private_person:sha256-first-8]`. An analyst can still `GROUP BY` that hash to correlate records belonging to the same person — without ever seeing the person's name. `strict_financial_v1` replaces all PII with a generic `[private_person]` tag, making even statistical correlation impossible. Same detection pipeline, opposite compliance philosophies. The policy is a config object, not a code change.

## 5. Audit Trail

The audit log (`audit.jsonl`) is the ultimate source of truth. A single request produces a single JSONL record containing:
- The actor (role, user_id, session_id)
- SHA-256 hashes of the raw input and raw output
- Inbound and outbound detections (with raw text stripped)
- The exact policy config version and model version used
- Latency and terminal status

## 6. The Synthetic Dataset

The `scripts/seed_data.py` script generates a realistic SQLite database with customers, accounts, transactions, and advisors. Crucially, the transaction descriptions include deliberate edge cases for the PII scanner, such as compound identifiers ("account ending in 4821") and aliases.

## 7. Evaluation Harness

Run `make eval` to execute the evaluation harness against a golden set of 15 test cases. It measures:
- RBAC accuracy (did it correctly allow/deny?)
- Status accuracy (did the request end in the expected state?)
- Inbound PII detection (were the expected categories caught?)
- Audit completeness (are all required fields present?)

## 8. Included Tools

- `sql_query`: Read-only SQLite execution with RBAC-enforced column filtering.
- `customer_api`: A separate FastAPI process simulating a REST backend, demonstrating how the pipeline handles internal service boundaries.

## 9. Extending this

To take this from a reference implementation to production:
1. **Async Review Queue**: Currently, the `REVIEW` action is synchronous (the request completes but is flagged). In production, `REVIEW` should hold the request, return a "pending" status to the LLM, and wait for an out-of-band human approval webhook.
2. **KMS Vaulting**: Replace the local `vault.jsonl` writer with a call to AWS KMS or HashiCorp Vault.
3. **Client-side TLS**: The `stdio` transport assumes a trusted local client. If moving to SSE transport, add mTLS client certificate validation to strictly identify the actor.
