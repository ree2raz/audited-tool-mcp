"""Reference LangGraph agent that consumes the audited-tool-mcp server.

Connects via stdio transport, sends natural-language queries through
the MCP compliance pipeline, and prints results with audit trail.

Usage:
    python -m examples.agent.langgraph_agent --role analyst --query "Show me John's accounts"
    python -m examples.agent.langgraph_agent --role intern --query "Show me all data"
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
from pathlib import Path
from typing import Any, TypedDict

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from langchain_core.messages import AIMessage, HumanMessage, SystemMessage, ToolMessage
from langchain_openai import ChatOpenAI
from langgraph.graph import END, StateGraph


# ---------------------------------------------------------------------------
# State
# ---------------------------------------------------------------------------


class AgentState(TypedDict):
    """State for the ReAct agent."""
    role: str
    user_id: str
    query: str
    messages: list
    tool_results: list[dict]
    final_response: str
    steps: int


# ---------------------------------------------------------------------------
# MCP Client (direct tool call, no transport for simplicity in demo)
# ---------------------------------------------------------------------------

async def call_mcp_tool(tool_name: str, arguments: dict) -> str:
    """Call an MCP tool directly (in-process for demo purposes).

    In production, this would use stdio_client to connect to the MCP server
    as a subprocess. For the demo, we call the pipeline directly to avoid
    requiring a separate server process.
    """
    from audited_tool_mcp.privacy import use_mock_detector

    # Use mock PII detector if MOCK_PII is set
    if os.environ.get("MOCK_PII", "0") == "1":
        use_mock_detector(True)

    if tool_name == "sql_query":
        from audited_tool_mcp.server import sql_query
        return await sql_query(**arguments)
    elif tool_name == "customer_lookup":
        from audited_tool_mcp.server import customer_lookup
        return await customer_lookup(**arguments)
    elif tool_name == "customer_search":
        from audited_tool_mcp.server import customer_search
        return await customer_search(**arguments)
    else:
        return json.dumps({"error": f"Unknown tool: {tool_name}"})


# ---------------------------------------------------------------------------
# Agent nodes
# ---------------------------------------------------------------------------

SYSTEM_PROMPT = """You are a financial services assistant with access to a compliance-aware database system.
You can query customer data and account information, but all queries pass through a compliance pipeline
that enforces role-based access control and PII protection.

Available tools:
1. sql_query - Execute SQL queries against the financial database
   Tables: customers (id, first_name, last_name, email, phone, address, date_of_birth),
           accounts (id, customer_id, account_type, balance, opened_date),
           transactions (id, account_id, amount, description, timestamp, counterparty),
           advisors (id, name, email, phone, region)

2. customer_lookup - Look up a customer by their ID number
3. customer_search - Search for customers by name or email

Your role determines what data you can access. Results may be redacted based on compliance policies.
Always explain to the user what data was returned and note any redactions."""

TOOLS_SCHEMA = [
    {
        "type": "function",
        "function": {
            "name": "sql_query",
            "description": "Execute a SQL SELECT query against the financial services database",
            "parameters": {
                "type": "object",
                "properties": {
                    "query": {"type": "string", "description": "SQL SELECT query to execute"},
                },
                "required": ["query"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "customer_lookup",
            "description": "Look up a customer by their database ID",
            "parameters": {
                "type": "object",
                "properties": {
                    "customer_id": {"type": "integer", "description": "Customer ID"},
                },
                "required": ["customer_id"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "customer_search",
            "description": "Search for customers by name or email",
            "parameters": {
                "type": "object",
                "properties": {
                    "name": {"type": "string", "description": "Customer name to search for"},
                    "email": {"type": "string", "description": "Customer email to search for"},
                },
            },
        },
    },
]


def plan_node(state: AgentState) -> AgentState:
    """LLM plans which tool to call based on the user query."""
    llm = ChatOpenAI(model="gpt-4o-mini", temperature=0)

    messages = [
        SystemMessage(content=SYSTEM_PROMPT),
        HumanMessage(content=f"[Role: {state['role']}] {state['query']}"),
    ]

    # Add previous messages if any
    messages.extend(state.get("messages", []))

    response = llm.invoke(messages, tools=TOOLS_SCHEMA)
    state["messages"] = messages + [response]
    return state


async def tool_node(state: AgentState) -> AgentState:
    """Execute the tool call planned by the LLM."""
    messages = state["messages"]
    last_message = messages[-1]

    if not hasattr(last_message, "tool_calls") or not last_message.tool_calls:
        # No tool call — LLM gave a direct response
        state["final_response"] = last_message.content
        return state

    tool_results = []
    for tool_call in last_message.tool_calls:
        tool_name = tool_call["name"]
        arguments = tool_call["args"]

        # Inject role and user_id into tool arguments
        arguments["role"] = state["role"]
        arguments["user_id"] = state["user_id"]

        print(f"\n  📋 Calling tool: {tool_name}")
        print(f"     Arguments: {json.dumps(arguments, indent=2)}")

        result = await call_mcp_tool(tool_name, arguments)
        tool_results.append({
            "tool_name": tool_name,
            "arguments": arguments,
            "result": result,
        })

        # Add tool result as a message
        messages.append(ToolMessage(content=result, tool_call_id=tool_call["id"]))

        print(f"     Result preview: {result[:200]}...")

    state["messages"] = messages
    state["tool_results"] = state.get("tool_results", []) + tool_results
    state["steps"] = state.get("steps", 0) + 1
    return state


def compose_node(state: AgentState) -> AgentState:
    """LLM composes a final response from the tool results."""
    llm = ChatOpenAI(model="gpt-4o-mini", temperature=0)

    messages = state["messages"] + [
        HumanMessage(content="Please summarize the results. Note any redacted or restricted data.")
    ]

    response = llm.invoke(messages)
    state["final_response"] = response.content
    state["messages"] = messages + [response]
    return state


def should_continue(state: AgentState) -> str:
    """Decide whether to continue the loop or compose final response."""
    messages = state["messages"]
    last_message = messages[-1]

    # If last message has tool calls, execute them
    if hasattr(last_message, "tool_calls") and last_message.tool_calls:
        return "call_tool"

    # If we already have a final response, end
    if state.get("final_response"):
        return "end"

    # Otherwise compose response
    return "compose"


# ---------------------------------------------------------------------------
# Graph
# ---------------------------------------------------------------------------


def build_graph() -> StateGraph:
    """Build the LangGraph agent graph."""
    graph = StateGraph(AgentState)

    graph.add_node("plan", plan_node)
    graph.add_node("call_tool", tool_node)
    graph.add_node("compose", compose_node)

    graph.set_entry_point("plan")

    graph.add_conditional_edges(
        "plan",
        should_continue,
        {
            "call_tool": "call_tool",
            "compose": "compose",
            "end": END,
        },
    )

    graph.add_edge("call_tool", "compose")
    graph.add_edge("compose", END)

    return graph.compile()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


async def run_agent(role: str, query: str, user_id: str = "demo-user") -> None:
    """Run the agent with the given role and query."""
    print("=" * 70)
    print(f"  🔐 Role: {role}")
    print(f"  💬 Query: {query}")
    print(f"  👤 User: {user_id}")
    print("=" * 70)

    graph = build_graph()

    initial_state: AgentState = {
        "role": role,
        "user_id": user_id,
        "query": query,
        "messages": [],
        "tool_results": [],
        "final_response": "",
        "steps": 0,
    }

    result = await graph.ainvoke(initial_state)

    print("\n" + "=" * 70)
    print("  📝 Agent Response:")
    print("=" * 70)
    print(result.get("final_response", "(no response)"))

    # Print audit trail
    print("\n" + "=" * 70)
    print("  📊 Audit Trail:")
    print("=" * 70)

    from audited_tool_mcp.audit import AuditLogger
    logger = AuditLogger()
    records = logger.read_all()
    if records:
        latest = records[-1]
        print(f"  Request ID: {latest.request_id}")
        print(f"  Status: {latest.status.value}")
        print(f"  Tool: {latest.tool_name}")
        print(f"  Latency: {latest.latency_ms:.1f}ms")
        print(f"  Policy: {latest.policy_version}")
        print(f"  Model: {latest.model_version}")
        print(f"  Inbound detections: {len(latest.inbound_detections)}")
        print(f"  Outbound detections: {len(latest.outbound_detections)}")
        if latest.review_queue_id:
            print(f"  ⚠️  Review queue ID: {latest.review_queue_id}")
    else:
        print("  (no audit records found)")


def main():
    parser = argparse.ArgumentParser(description="Reference LangGraph agent for audited-tool-mcp")
    parser.add_argument(
        "--role",
        choices=["intern", "analyst", "compliance_officer"],
        default="analyst",
        help="Role to assume (default: analyst)",
    )
    parser.add_argument(
        "--query",
        default="Show me the top 5 customers by account balance",
        help="Natural language query",
    )
    parser.add_argument(
        "--user-id",
        default="demo-user",
        help="User identifier",
    )
    args = parser.parse_args()

    asyncio.run(run_agent(args.role, args.query, args.user_id))


if __name__ == "__main__":
    main()
