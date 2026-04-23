# audited-tool-mcp

A production-grade, compliance-aware Model Context Protocol (MCP) server that wraps LLM tool use with four primitives: PII safety, role-based access control (RBAC), configurable policy enforcement, and structured audit logging.

This project serves as a reference implementation for agentic systems in highly regulated industries.

## 1. What this is

When an LLM (the client) calls a tool (e.g., `sql_query`), that call passes through a strict compliance pipeline before execution, and the result passes through the pipeline again before returning to the LLM.

1. **RBAC Gate**: Fails fast if the user's role lacks access to the tool or specific data fields.
2. **Inbound PII Scan**: Detects sensitive data in the query using OpenAI's 1.5B parameter Privacy Filter.
3. **Inbound Policy**: Applies role-specific rules (Allow, Redact, Hash, Vault, Review, Block).
4. **Tool Execution**: Executes the bounded tool (with timeouts).
5. **Outbound PII Scan**: Scans the canonical JSON output.
6. **Outbound Policy**: Applies redaction/hashing rules to the results.
7. **Audit Logging**: Writes a structured JSONL record of the entire trace.

## 2. Quickstart

Prerequisites: Python 3.11+, `uv`

```bash
git clone https://github.com/yourusername/audited-tool-mcp.git
cd audited-tool-mcp

# Install dependencies and download the 1.5B Privacy Filter model
make install

# Generate the synthetic financial services dataset (~500 rows)
make seed

# Run the end-to-end demo (uses a mock PII detector for speed)
export OPENAI_API_KEY=sk-...  # For the LangGraph agent
MOCK_PII=1 make demo
```

## 3. Architecture

The server uses `FastMCP` with `stdio` transport. The core pipeline is located in `audited_tool_mcp/server.py:process_request()`.

Every tool call triggers a 7-step pipeline. The cheapest checks happen first (O(1) RBAC set membership), and the most expensive checks happen last (1.5B param PII inference). The audit logger is append-only JSONL, explicitly avoiding raw PII storage by replacing matched text with `[category]` placeholders or hashes.

## 4. The Privacy Filter

We use `openai/privacy-filter`, a 1.5B parameter bidirectional token classifier that supports 8 PII categories (e.g., `private_person`, `account_number`, `secret`). 

- It runs **locally on CPU** by default. No data is sent to OpenAI APIs.
- We implemented robust BIOES span decoding to accurately map token predictions back to character offsets in the original text.
- For fast local testing, setting `MOCK_PII=1` bypasses the model and uses a regex stub.

## 5. RBAC and Policy Engine

Policies are defined as strict Pydantic models, not loose YAML files. This ensures type safety and IDE autocomplete.

There are six policy actions:
- `ALLOW`: Pass through unchanged.
- `REDACT`: Replace with `[category]`.
- `HASH`: Replace with `[category:sha256-first-8]`. Preserves identity consistency.
- `VAULT`: Store raw text in `vault.jsonl` and replace with a UUID reference.
- `REVIEW`: Leave intact but flag for human review (writes to `review_queue.jsonl`).
- `BLOCK`: Halt the request immediately and raise a `PolicyViolation`.

## 6. Audit Trail

The audit log (`audit.jsonl`) is the ultimate source of truth. A single request produces a single JSONL record containing:
- The actor (role, user_id, session_id)
- SHA-256 hashes of the raw input and raw output
- Inbound and outbound detections (with raw text stripped)
- The exact policy config version and model version used
- Latency and terminal status

## 7. The Synthetic Dataset

The `scripts/seed_data.py` script generates a realistic SQLite database with customers, accounts, transactions, and advisors. Crucially, the transaction descriptions include deliberate edge cases for the PII scanner, such as compound identifiers ("account ending in 4821") and aliases.

## 8. Evaluation Harness

Run `make eval` to execute the evaluation harness against a golden set of 15 test cases. It measures:
- RBAC accuracy (did it correctly allow/deny?)
- Status accuracy (did the request end in the expected state?)
- Inbound PII detection (were the expected categories caught?)
- Audit completeness (are all required fields present?)

## 9. Included Tools

- `sql_query`: Read-only SQLite execution with RBAC-enforced column filtering.
- `customer_api`: A separate FastAPI process simulating a REST backend, demonstrating how the pipeline handles internal service boundaries.

## 10. Extending this

To take this from a reference implementation to production:
1. **Async Review Queue**: Currently, the `REVIEW` action is synchronous (the request completes but is flagged). In production, `REVIEW` should hold the request, return a "pending" status to the LLM, and wait for an out-of-band human approval webhook.
2. **KMS Vaulting**: Replace the local `vault.jsonl` writer with a call to AWS KMS or HashiCorp Vault.
3. **Client-side TLS**: The `stdio` transport assumes a trusted local client. If moving to SSE transport, add mTLS client certificate validation to strictly identify the actor.
