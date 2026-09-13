"""Real stdio MCP -> local bridge -> mTLS -> Linux worker -> PostgreSQL smoke."""

import asyncio
import json
import sys
import uuid
from pathlib import Path

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


async def main():
    root = Path(__file__).resolve().parents[2]
    server = StdioServerParameters(
        command=sys.executable,
        cwd=str(root.parent),
        args=[
            "-m",
            "openagent_secretbox.linux_worker.mcp_bridge",
            "--compose",
            str(root / "deploy/linux-worker/compose.yaml"),
        ],
    )
    async with stdio_client(server) as (read, write), ClientSession(read, write) as session:
        await session.initialize()
        tools = await session.list_tools()
        assert {tool.name for tool in tools.tools} == {
            "create_remote_task",
            "get_remote_task_status",
            "cancel_remote_task",
        }
        request = {
            "request_id": "mcp-" + uuid.uuid4().hex,
            "operation": "rds.connectivity_check",
            "target_id": "isolated-local",
            "parameters": {},
            "ttl_seconds": 60,
        }
        created = await session.call_tool("create_remote_task", {"request": request})
        result = created.structuredContent or json.loads(created.content[0].text)
        assert "task_id" in result, json.dumps(result)
        task_id = result["task_id"]
        for _ in range(30):
            answer = await session.call_tool("get_remote_task_status", {"task_id": task_id})
            result = answer.structuredContent or json.loads(answer.content[0].text)
            if result["status"] == "succeeded":
                break
            assert result["status"] not in {"failed", "timed_out", "cancelled"}
            await asyncio.sleep(0.2)
        assert result["summary"] == {"connected": True, "server_major": 17}
        cancelled = await session.call_tool("cancel_remote_task", {"task_id": task_id})
        terminal = cancelled.structuredContent or json.loads(cancelled.content[0].text)
        assert terminal["status"] == "succeeded"
        print("PASS stdio MCP tools discovered and real TLS PostgreSQL task completed")
        print(json.dumps(result, ensure_ascii=True))


if __name__ == "__main__":
    asyncio.run(main())
