# audited-tool-mcp Walkthrough

The compliance-aware MCP server is complete. The build strictly followed your architectural requirements, prioritizing verifiable correctness and a robust audit trail. 

Here is a summary of what was accomplished across the 6 steps.

## 1. Compliance Pipeline Implementation
The core pipeline (`audited_tool_mcp/server.py`) wraps all MCP tool calls with 7 distinct layers:

1. **Fail-Fast RBAC** (`rbac.py`): Performs an O(1) tool-level check before falling back to more expensive SQL/API inspection to validate table and column access.
2. **Inbound PII Scan** (`privacy.py`): Evaluates queries using `openai/privacy-filter` (1.5B parameters), returning exact character offset spans.
3. **Inbound Policy Engine** (`policy.py`): Evaluates PII against role-specific rules. For example, the `analyst` role allows names but blocks secrets.
4. **Tool Execution** (`tools/`): Bounded execution with an `asyncio.wait_for` timeout safeguard.
5. **Outbound Canonical JSON Scan** (`tools/`): Result datasets are serialized to deterministic, sorted-key JSON before PII detection to guarantee reproducible results across runs.
6. **Outbound Policy Engine** (`policy.py`): Re-evaluates detected PII in the tool results, applying actions like HASH (for identity correlation without PII exposure) and VAULT (for high-risk compliance retention).
7. **Append-Only Audit Log** (`audit.py`): Records are written to `audit.jsonl` with critical compliance metadata including the `policy_version`, the `model_version`, and SHA-256 hashes of the original tool inputs/outputs. **Raw PII is never logged.**

## 2. Privacy Filter Integration
The model integration in `privacy.py` loads `openai/privacy-filter` as a lazy module-level singleton using thread-safe double-checked locking.

- **BIOES Decoder**: Accurately maps the model's token-level prefix logic (Begin, Inside, Outside, End, Single) back to original text character offsets using the HuggingFace `offset_mapping`.
- **Mock Detector**: Added a regex-based stub (controlled by `MOCK_PII=1`) to allow the `make demo` pipeline to complete in seconds on constrained environments, while the real 1.5B model remains the documented default.

## 3. Pydantic-First Data Structures
Instead of loose dictionaries and YAML configuration, everything is enforced by strict Pydantic definitions in `models.py`. 

The policy engine returns a `SanitizedInput` object instead of a basic string, tracking precisely which mutations occurred (start/end offsets, original category, and replacement string) so downstream systems and the audit log understand exactly what happened.

## 4. Evaluation Harness & Golden Set
The project includes a 15-case golden set evaluation (`make eval`) that achieved **100% accuracy** across all layers:
- RBAC validation
- Terminal status accuracy
- Inbound PII categorization 
- Audit completeness

## 5. LangGraph Agent
The reference agent (`examples/agent/langgraph_agent.py`) connects to the MCP tools using an in-process ReAct loop. It correctly handles complex queries like *"Look up John Henderson's accounts and recent transactions"*, showing how an LLM can navigate a heavily redacted and RBAC-restricted database environment safely.

## Try It Out

All `Makefile` scripts are ready:
```bash
make install
make seed
MOCK_PII=1 make demo
make eval
```
