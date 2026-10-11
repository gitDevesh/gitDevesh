import hashlib
import os
import re

from mcp.server.mcpserver import MCPServer, Context
from mcp.server.transport_security import TransportSecuritySettings

REGISTERED_EMAIL = "22f3001402@ds.study.iitm.ac.in"

mcp = MCPServer("IITM Exam MCP Server")


@mcp.tool()
def solve_challenge(ctx: Context) -> str:
    """Return the required hash for the current exam challenge."""
    headers = ctx.headers or {}
    challenge = headers.get("x-exam-challenge")

    if not challenge:
        raise ValueError("Missing X-Exam-Challenge header")

    if not re.fullmatch(r"[0-9a-f]{32}", challenge):
        raise ValueError("Invalid X-Exam-Challenge header")

    email = REGISTERED_EMAIL.strip().lower()
    value = f"{challenge}:{email}"
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:16]


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "8000"))
    security = TransportSecuritySettings(
        enable_dns_rebinding_protection=False
    )

    mcp.run(
        transport="streamable-http",
        host="0.0.0.0",
        port=port,
        json_response=True,
        transport_security=security,
    )
