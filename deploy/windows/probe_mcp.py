"""Metadata-only installed MCP check. Never opens an intake or reads targets."""
import asyncio
import sys

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


async def probe():
    args = [
        "-I",
        "-m", "openagent_secretbox.mcp_server", "--workspace", sys.argv[1],
        "--only-target", ".env.local",
    ]
    async with stdio_client(StdioServerParameters(command=sys.executable, args=args)) as streams:
        async with ClientSession(*streams) as session:
            await session.initialize()
            names = {tool.name for tool in (await session.list_tools()).tools}
            assert names == {
                "open_secret_intake", "get_secret_intake_status", "cancel_secret_intake",
            }
    print("PASS: intake MCP handshake and all three tools; no secrets accessed")


if __name__ == "__main__":
    try:
        asyncio.run(asyncio.wait_for(probe(), timeout=25))
    except Exception:
        print("FAIL: MCP startup/handshake failed; check runtime and workspace metadata")
        sys.exit(1)
