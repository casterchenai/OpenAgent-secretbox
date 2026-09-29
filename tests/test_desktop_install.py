from pathlib import Path

import pytest

from openagent_secretbox import mcp_server
from openagent_secretbox.writers import apply_request


def test_restricted_startup_replaces_default_allowlist(tmp_path, monkeypatch):
    captured = {}

    class Server:
        def run(self, *, transport):
            assert transport == "stdio"

    def server(manager):
        captured["targets"] = manager.allowed_targets
        captured["workspace"] = manager.workspace
        return Server()

    monkeypatch.setattr(mcp_server, "create_mcp_server", server)
    assert mcp_server.main([
        "--workspace", str(tmp_path), "--only-target", ".env.local",
    ]) == 0
    assert captured == {"targets": (".env.local",), "workspace": tmp_path.resolve()}
    with pytest.raises(SystemExit):
        mcp_server._build_parser().parse_args([
            "--workspace", str(tmp_path), "--only-target", ".env.local",
            "--allow-target", "secrets/*",
        ])


def test_bad_env_reports_safe_category_without_modification(tmp_path: Path):
    target = tmp_path / ".env.local"
    original = "private-invalid-heading\nEXISTING=private-test-value\n"
    target.write_text(original, encoding="utf-8")
    result = apply_request({
        "schema_version": 1, "request_id": "syntax-test", "title": "Syntax test",
        "needs": [{"type": "env", "name": "NEW_KEY", "required": True}],
        "write_policy": {
            "env_file": ".env.local", "mode": "merge_only",
            "no_overwrite": True, "backup": False,
        },
    }, {"NEW_KEY": "synthetic-submitted-value"}, workspace_root=tmp_path)
    assert result["blocked"] == [{"code": "env_syntax_invalid"}]
    assert result["written"] == []
    assert target.read_text(encoding="utf-8") == original
    assert "private" not in str(result)
    assert "synthetic-submitted-value" not in str(result)
