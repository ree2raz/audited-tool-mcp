# LangGraph Reference Agent

A ReAct-style agent that consumes the `audited-tool-mcp` server against a synthetic financial services dataset.

## Usage

```bash
# Set your OpenAI API key (for the LLM, not for Privacy Filter)
export OPENAI_API_KEY=sk-...

# Run with analyst role
python -m examples.agent.langgraph_agent --role analyst --query "Show me the top 5 customers by balance"

# Run with intern role (will be blocked by RBAC)
python -m examples.agent.langgraph_agent --role intern --query "Show me all customer data"

# Run with compliance officer role
python -m examples.agent.langgraph_agent --role compliance_officer --query "Show complete records for customer 42"

# Use mock PII detector for fast demos (no model download needed)
MOCK_PII=1 python -m examples.agent.langgraph_agent --role analyst --query "Look up John Smith"
```

## Architecture

```
User Query → LangGraph Agent → MCP Tool Call → Compliance Pipeline → Response
                  │                                      │
                  └── GPT-4o-mini (plan + compose)      └── RBAC → PII → Policy → Tool → PII → Policy → Audit
```

The agent uses a three-node state machine:

1. **Plan**: LLM decides which tool to call and with what arguments
2. **Call Tool**: Executes the MCP tool through the compliance pipeline
3. **Compose**: LLM summarizes results and notes any redactions

## Output

Each run prints:
- The tool calls made
- The agent's response (with redacted data noted)
- The audit trail from the compliance pipeline
