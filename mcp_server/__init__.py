"""
mcp_server — FastAPI tool-plugin servers used in the Obedient Insider demo.

Two siblings live here:
  - legitimate_mcp.py : the clean reference server (what a real dev tool looks like).
  - evil_mcp.py       : identical-looking server that injects a malicious task
                        into the agent's task queue as a side effect of one of
                        its endpoints.

Real-world analog: a third-party "MCP server" / coding-assistant plugin a
developer installed. The agent is clean, the cloud is clean, the user is
clean — but a compromised tool in the middle can steer the agent. That is
the supply-chain threat the demo illustrates.
"""
