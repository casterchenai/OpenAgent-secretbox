from __future__ import annotations

import json
import threading
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlencode, urlsplit
from urllib.request import Request, urlopen

from openagent_secretbox.mcp_server import IntakeManager
from openagent_secretbox.ui_handoff import serve_handoff


def _request(workspace: Path, request_id: str = "handoff-test") -> dict[str, Any]:
    return {
        "schema_version": 1,
        "request_id": request_id,
        "title": "Handoff test",
        "workspace_root": str(workspace),
        "needs": [
            {
                "type": "env",
                "name": "OPENAI_API_KEY",
                "required": True,
                "description": "Test API key",
            }
        ],
        "write_policy": {
            "env_file": ".env.local",
            "mode": "merge_only",
            "no_overwrite": True,
            "backup": False,
        },
    }


def test_handoff_form_proxy_submit_writes_env(tmp_path: Path) -> None:
    token = "x" * 24
    server = serve_handoff(host="127.0.0.1", port=0, token=token)
    port = int(server.server_address[1])
    thread = threading.Thread(
        target=server.serve_forever, kwargs={"poll_interval": 0.1}, daemon=True
    )
    thread.start()
    publish_url = f"http://127.0.0.1:{port}/internal/publish"
    manager = IntakeManager(
        tmp_path,
        browser_open=lambda _url: False,
        ui_handoff_url=publish_url,
        ui_handoff_token=token,
    )
    try:
        created = manager.open_intake(_request(tmp_path), ttl_seconds=60)
        assert created["status"] == "awaiting_input"
        assert created["browser_opened"] is True
        encoded = json.dumps(created)
        assert "/intake/" not in encoded
        assert "token=" not in encoded

        with urlopen(f"http://127.0.0.1:{port}/api/active", timeout=2) as response:
            active = json.loads(response.read().decode("utf-8"))
        assert len(active["items"]) == 1
        page_path = active["items"][0]["page_path"]

        with urlopen(f"http://127.0.0.1:{port}{page_path}", timeout=2) as response:
            html = response.read().decode("utf-8")
        assert "OPENAI_API_KEY" in html
        assert "安全提交" in html
        # Must NOT redirect remote users to loopback.
        assert "location.replace" not in html
        assert "#token=" not in html

        body = urlencode({"OPENAI_API_KEY": "sk-test-handoff-value"}).encode()
        req = Request(
            f"http://127.0.0.1:{port}{page_path}",
            data=body,
            method="POST",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        with urlopen(req, timeout=5) as response:
            done = response.read().decode("utf-8")
        assert "提交成功" in done

        env_path = tmp_path / ".env.local"
        assert env_path.is_file()
        content = env_path.read_text(encoding="utf-8")
        assert "OPENAI_API_KEY=sk-test-handoff-value" in content

        status = manager.get_status(created["intake_id"])
        assert status["status"] == "applied"
    finally:
        manager.close()
        server.shutdown()
        server.server_close()


def test_browser_failure_without_handoff_still_errors(tmp_path: Path) -> None:
    manager = IntakeManager(tmp_path, browser_open=lambda _url: False)
    try:
        result = manager.open_intake(_request(tmp_path))
        assert result["status"] == "error"
        assert result["error"]["code"] == "browser_open_failed"
    finally:
        manager.close()


def test_handoff_rejects_non_loopback_publish_url(tmp_path: Path) -> None:
    raised = False
    try:
        IntakeManager(
            tmp_path,
            browser_open=lambda _url: False,
            ui_handoff_url="http://example.com/internal/publish",
            ui_handoff_token="x" * 24,
        )
    except Exception:
        raised = True
    assert raised
