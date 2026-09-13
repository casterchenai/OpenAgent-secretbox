"""Separate stdio MCP adapter; never offers the owner's confirmation capability."""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
from pathlib import Path
from typing import TYPE_CHECKING, Any

from .common import TASK_ID, Rejected, decode, public_result

if TYPE_CHECKING:
    from mcp.server.fastmcp import FastMCP


class WorkerBridge:
    def __init__(self, compose: Path) -> None:
        self.compose = compose.resolve(strict=True)

    def invoke(
        self,
        action: str,
        task_id: str | None = None,
        request: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        if action not in ("create", "status", "cancel"):
            return {"error_code": "SBX-003"}
        if task_id is not None and not TASK_ID.fullmatch(task_id):
            return {"error_code": "SBX-001"}
        # Some MCP hosts omit ProgramData/ProgramFiles, breaking Docker's plugin discovery
        # on Windows. The bundled standalone Compose executable does not require it.
        standalone = shutil.which("docker-compose")
        argv = ([standalone] if standalone else ["docker", "compose"]) + [
            "-f",
            str(self.compose),
            "exec",
            "-T",
            "--user",
            "10003:10003",
            "agent",
            "python3",
            "-m",
            "openagent_secretbox.linux_worker.client",
            action,
        ]
        if task_id:
            argv.append(task_id)
        try:
            raw = json.dumps(request).encode() if request is not None else None
            if raw is not None and len(raw) > 4096:
                return {"error_code": "SBX-001"}
            result = subprocess.run(
                argv,
                input=raw,
                capture_output=True,
                timeout=15,
                check=False,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
            if len(result.stdout) > 16384:
                return {"error_code": "SBX-011"}
            if result.returncode and not result.stdout.strip():
                return {"error_code": "SBX-008"}
            return public_result(decode(result.stdout))
        except Rejected as exc:
            return {"error_code": exc.code}
        except Exception:
            return {"error_code": "SBX-008"}


def create_server(bridge: WorkerBridge) -> FastMCP:
    from mcp.server.fastmcp import FastMCP
    from mcp.types import ToolAnnotations

    app = FastMCP("secretbox-linux-worker")

    @app.tool(annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=True))
    def create_remote_task(request: dict[str, Any]) -> dict[str, Any]:
        """Submit fixed target/operation metadata only. Never include secrets or shell commands."""
        return bridge.invoke("create", request=request)

    @app.tool(annotations=ToolAnnotations(readOnlyHint=True))
    def get_remote_task_status(task_id: str) -> dict[str, Any]:
        """Return closed public status and counts, never raw process output."""
        return bridge.invoke("status", task_id)

    @app.tool(annotations=ToolAnnotations(readOnlyHint=False, destructiveHint=True))
    def cancel_remote_task(task_id: str) -> dict[str, Any]:
        """Request termination; cancellation does not undo a committed database restore."""
        return bridge.invoke("cancel", task_id)

    return app


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--compose", type=Path, required=True)
    args = parser.parse_args()
    create_server(WorkerBridge(args.compose)).run(transport="stdio")


if __name__ == "__main__":
    main()
