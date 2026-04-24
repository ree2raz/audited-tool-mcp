"""Run the audited-tool-mcp demo scenarios.

Orchestrates the entire demo:
1. Seeds the database
2. Starts the customer API subprocess
3. Runs the LangGraph agent against several scenarios
4. Prints the final audit trail

Usage:
    python scripts/run_demo.py
    MOCK_PII=1 python scripts/run_demo.py  # Use mock detector for speed
"""

import asyncio
import os
import subprocess
import sys
import time
from pathlib import Path

from dotenv import load_dotenv
load_dotenv()

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from examples.agent.langgraph_agent import run_agent

# Use colors for clean console output
BLUE = "\033[94m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
RESET = "\033[0m"


async def main():
    print(f"{BLUE}======================================================================{RESET}")
    print(f"{BLUE}  audited-tool-mcp: Compliance-Aware MCP Server Demo{RESET}")
    print(f"{BLUE}======================================================================{RESET}\n")

    # 1. Seed the database
    print(f"{YELLOW}[1/4] Seeding synthetic database...{RESET}")
    subprocess.run([sys.executable, "scripts/seed_data.py"], check=True)

    # 2. Start Customer API
    print(f"\n{YELLOW}[2/4] Starting Customer API...{RESET}")
    api_process = subprocess.Popen(
        [sys.executable, "-m", "audited_tool_mcp.tools.customer_api"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    time.sleep(2)  # Wait for API to start

    try:
        # 3. Run scenarios
        print(f"\n{YELLOW}[3/4] Running Scenarios...{RESET}\n")

        scenarios = [
            {
                "title": "Scenario 1: Analyst Query (PII Redaction)",
                "role": "analyst",
                "query": "Look up John Henderson's accounts and recent transactions",
            },
            {
                "title": "Scenario 2: Intern RBAC Denial",
                "role": "intern",
                "query": "Show me all customer data including SSNs",
            },
            {
                "title": "Scenario 3: Compliance Officer (Review Queue)",
                "role": "compliance_officer",
                "query": "Show recent transactions with wire transfer descriptions",
            },
        ]

        for s in scenarios:
            print(f"{GREEN}▶ {s['title']}{RESET}")
            await run_agent(role=s["role"], query=s["query"])
            print("\n")
            time.sleep(1)

        # 4. Print final review queue
        print(f"{YELLOW}[4/4] Checking Review Queue...{RESET}")
        review_path = os.environ.get("REVIEW_QUEUE_PATH", "./review_queue.jsonl")
        if os.path.exists(review_path):
            with open(review_path) as f:
                lines = f.readlines()
                print(f"Found {len(lines)} items in the review queue:")
                for i, line in enumerate(lines, 1):
                    # Print shortened preview
                    print(f"  {i}. {line[:100]}...")
        else:
            print("Review queue is empty.")

        print(f"\n{BLUE}Demo complete! The full audit trail is available in audit.jsonl{RESET}")

    finally:
        # Cleanup
        api_process.terminate()
        api_process.wait()


if __name__ == "__main__":
    if not os.environ.get("OPENAI_API_KEY"):
        print(f"{YELLOW}Warning: OPENAI_API_KEY is not set. The LangGraph agent may fail if it tries to call OpenAI APIs.{RESET}")
    
    asyncio.run(main())
