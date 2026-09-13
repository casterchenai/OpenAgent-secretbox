import asyncio
import json
import subprocess
from pathlib import Path

import pytest

from openagent_secretbox.linux_worker.common import Rejected, public_result
from openagent_secretbox.linux_worker.mcp_bridge import WorkerBridge, create_server


def result():
    return {
        "task_id": "task_" + "a" * 32,
        "operation": "rds.connectivity_check",
        "target_id": "isolated-local",
        "status": "succeeded",
        "error_code": None,
        "exit_code": 0,
        "summary": {"connected": True, "server_major": 17},
        "events": ["created", "validated", "queued", "running", "succeeded"],
        "preflight_id": None,
        "created_at": 1780000000.0,
        "finished_at": 1780000001.0,
    }


def test_public_result():
    assert public_result(result()) == result()
    assert public_result({"error_code": "SBX-011"}) == {"error_code": "SBX-011"}


@pytest.mark.parametrize(
    "field,value",
    [
        ("summary", {"password": "synthetic"}),
        ("summary", {"rows": "synthetic"}),
        ("summary", {"server_major": True}),
        ("events", ["raw exception synthetic"]),
        ("events", ["created"] * 21),
        ("preflight_id", "synthetic"),
        ("task_id", "not-a-task"),
        ("target_id", "postgres://synthetic"),
        ("created_at", float("nan")),
        ("exit_code", 42),
    ],
)
def test_closed_public_result(field, value):
    with pytest.raises(Rejected, match="SBX-011"):
        public_result({**result(), field: value})


def test_extra_output():
    with pytest.raises(Rejected, match="SBX-011"):
        public_result({**result(), "stderr": "synthetic"})


def test_bridge_does_not_expose_exception(tmp_path, monkeypatch):
    source = tmp_path / "compose.yaml"
    source.touch()
    bridge = WorkerBridge(source)

    def fail(*args, **kwargs):
        raise RuntimeError("synthetic-secret-in-exception")

    monkeypatch.setattr(subprocess, "run", fail)
    assert bridge.invoke("status", "task_" + "a" * 32) == {"error_code": "SBX-008"}


def test_bridge_rejects_raw_output(tmp_path, monkeypatch):
    source = tmp_path / "compose.yaml"
    source.touch()
    bridge = WorkerBridge(source)
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *a, **kw: subprocess.CompletedProcess(
            [], 0, b'{"password":"synthetic"}', b"synthetic"
        ),
    )
    assert bridge.invoke("status", "task_" + "a" * 32) == {"error_code": "SBX-011"}


def test_mcp_tools_no_owner_approval(tmp_path: Path):
    pytest.importorskip("mcp")
    source = tmp_path / "compose.yaml"
    source.touch()
    app = create_server(WorkerBridge(source))
    tools = asyncio.run(app.list_tools())
    by_name = {tool.name: tool for tool in tools}
    assert set(by_name) == {
        "create_remote_task",
        "get_remote_task_status",
        "cancel_remote_task",
    }
    assert set(by_name["create_remote_task"].inputSchema["properties"]) == {"request"}
    assert "compose" not in json.dumps([tool.inputSchema for tool in tools])
    assert by_name["get_remote_task_status"].annotations.readOnlyHint
