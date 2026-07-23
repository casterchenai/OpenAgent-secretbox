from __future__ import annotations

import base64
import json
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator

from openagent_secretbox import cli
from openagent_secretbox import server as server_module

ROOT = Path(__file__).resolve().parents[1]
EXAMPLES = sorted((ROOT / "examples").glob("*.request.json"))
REQUEST_SCHEMA = json.loads((ROOT / "schemas" / "request-v1.json").read_text(encoding="utf-8"))
SCHEMA_VALIDATOR = Draft202012Validator(REQUEST_SCHEMA)


def _request_file(path: Path, workspace: Path) -> Path:
    path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "request_id": "cli-test",
                "title": "CLI test",
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
        ),
        encoding="utf-8",
    )
    return path


@pytest.mark.parametrize("example", EXAMPLES, ids=lambda path: path.name)
def test_validate_examples_as_json(example: Path, capsys: pytest.CaptureFixture[str]) -> None:
    SCHEMA_VALIDATOR.validate(json.loads(example.read_text(encoding="utf-8")))
    assert cli.main(["--json", "validate", str(example)]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["status"] == "valid"
    assert payload["schema_version"] == 1


def test_validation_error_is_json_and_does_not_echo_values(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    request = _request_file(tmp_path / "request.json", tmp_path)
    document = json.loads(request.read_text(encoding="utf-8"))
    document["unknown"] = "sk-test-must-not-appear"
    request.write_text(json.dumps(document), encoding="utf-8")

    assert cli.main(["--json", "validate", str(request)]) == cli.EXIT_USAGE
    output = capsys.readouterr().out
    payload = json.loads(output)
    assert payload["status"] == "error"
    assert payload["error"]["code"] == "invalid_request"
    assert "sk-test-must-not-appear" not in output


def test_published_schema_matches_runtime_name_and_path_rules(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    request = _request_file(tmp_path / "request.json", tmp_path)
    document = json.loads(request.read_text(encoding="utf-8"))
    document["needs"][0]["name"] = "_PRIVATE_KEY"
    SCHEMA_VALIDATOR.validate(document)
    request.write_text(json.dumps(document), encoding="utf-8")
    assert cli.main(["--json", "validate", str(request)]) == 0
    assert json.loads(capsys.readouterr().out)["status"] == "valid"

    for unsafe_name in ("API-KEY", "API.KEY"):
        document["needs"][0]["name"] = unsafe_name
        assert not SCHEMA_VALIDATOR.is_valid(document)
        request.write_text(json.dumps(document), encoding="utf-8")
        assert cli.main(["--json", "validate", str(request)]) == cli.EXIT_USAGE
        assert json.loads(capsys.readouterr().out)["status"] == "error"

    document["needs"] = [
        {
            "type": "file",
            "name": "private.pem",
            "required": True,
            "target": "secrets/NUL.txt",
        }
    ]
    assert not SCHEMA_VALIDATOR.is_valid(document)
    request.write_text(json.dumps(document), encoding="utf-8")
    assert cli.main(["--json", "validate", str(request)]) == cli.EXIT_USAGE
    assert json.loads(capsys.readouterr().out)["status"] == "error"

    document = json.loads(_request_file(request, tmp_path).read_text(encoding="utf-8"))
    document["title"] = "unsafe\ncontrol"
    assert not SCHEMA_VALIDATOR.is_valid(document)
    request.write_text(json.dumps(document), encoding="utf-8")
    assert cli.main(["--json", "validate", str(request)]) == cli.EXIT_USAGE
    assert json.loads(capsys.readouterr().out)["status"] == "error"


def test_create_and_status_use_metadata_only_registry(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    request = _request_file(tmp_path / "request.json", tmp_path)
    document = json.loads(request.read_text(encoding="utf-8"))
    document["needs"][0]["default_value"] = "sk-test-default-must-not-persist"
    request.write_text(json.dumps(document), encoding="utf-8")
    state_dir = tmp_path / "state"

    assert (
        cli.main(
            [
                "--json",
                "create",
                str(request),
                "--state-dir",
                str(state_dir),
                "--ttl",
                "60",
            ]
        )
        == 0
    )
    created = json.loads(capsys.readouterr().out)
    request_id = created["request_id"]
    assert created["status"] == "proposed"
    assert request_id.startswith("req_")
    registry_file = state_dir / "requests" / f"{request_id}.json"
    assert "sk-test-default-must-not-persist" not in registry_file.read_text(encoding="utf-8")

    assert cli.main(["--json", "status", request_id, "--state-dir", str(state_dir)]) == 0
    status = json.loads(capsys.readouterr().out)
    assert status["request_id"] == request_id
    assert status["status"] == "proposed"


def test_unknown_command_returns_machine_readable_usage_error(
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert cli.main(["--json", "not-a-command"]) == cli.EXIT_USAGE
    payload = json.loads(capsys.readouterr().out)
    assert payload["status"] == "error"
    assert payload["error"]["code"] == "usage_error"


class _FakeThread:
    def join(self) -> None:
        return

    def is_alive(self) -> bool:
        return False


class _FakeHandle:
    session_id = "ses_test"


class _FakeStore:
    def __init__(self, result: Mapping[str, Any] | None = None) -> None:
        self.result = result or {"status": "applied"}

    def get(self, _session_id: str) -> dict[str, Any]:
        return {"status": "applied", "result": dict(self.result)}


class _FakeServing:
    def __init__(self, url: str, result: Mapping[str, Any] | None = None) -> None:
        self.url = url
        self.thread = _FakeThread()
        self.handle = _FakeHandle()
        self.store = _FakeStore(result)
        self.closed = False

    def close(self) -> None:
        self.closed = True


def test_serve_opens_browser_without_printing_bearer_url(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    request = _request_file(tmp_path / "request.json", tmp_path)
    bearer_url = "http://127.0.0.1:17321/intake/ses_test#token=test-bearer-token"
    seen: dict[str, Any] = {}

    def fake_serve_once(
        request: Mapping[str, Any],
        apply_fn: Callable[[Mapping[str, Any], Mapping[str, Any]], dict[str, Any]],
        **_: Any,
    ) -> _FakeServing:
        seen["served_request"] = request
        seen["result"] = apply_fn(
            request,
            {
                "env": {"OPENAI_API_KEY": "sk-test-cli-secret"},
                "files": {},
            },
        )
        return _FakeServing(bearer_url, seen["result"])

    def fake_open(url: str, new: int = 0) -> bool:
        seen["url"] = url
        seen["new"] = new
        return True

    monkeypatch.setattr(server_module, "serve_once", fake_serve_once)
    monkeypatch.setattr(cli.webbrowser, "open", fake_open)

    assert (
        cli.main(
            [
                "--json",
                "serve",
                "--workspace",
                str(tmp_path),
                "--request",
                str(request),
            ]
        )
        == 0
    )
    output = capsys.readouterr().out
    payload = json.loads(output)
    assert payload["status"] == "applied"
    assert bearer_url not in output
    assert "test-bearer-token" not in output
    assert "sk-test-cli-secret" not in output
    assert seen["url"] == bearer_url
    assert seen["served_request"]["workspace_root"] == str(tmp_path.resolve())
    assert seen["served_request"]["write_policy"]["no_overwrite"] is True
    assert seen["served_request"]["write_policy"]["backup"] is False
    assert seen["result"]["status"] == "applied"
    assert "sk-test-cli-secret" in (tmp_path / ".env.local").read_text(encoding="utf-8")


def test_serve_no_open_marks_url_as_sensitive(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    request = _request_file(tmp_path / "request.json", tmp_path)
    bearer_url = "http://127.0.0.1:17321/intake/ses_test#token=test-bearer-token"

    def fake_serve_once(**_: Any) -> _FakeServing:
        return _FakeServing(bearer_url)

    monkeypatch.setattr(server_module, "serve_once", fake_serve_once)
    assert (
        cli.main(
            [
                "--json",
                "serve",
                "--workspace",
                str(tmp_path),
                "--request",
                str(request),
                "--no-open",
            ]
        )
        == 0
    )
    lines = capsys.readouterr().out.splitlines()
    assert len(lines) == 2
    initial = json.loads(lines[0])
    final = json.loads(lines[1])
    assert initial["status"] == "awaiting_input"
    assert initial["sensitive_intake_url"] == bearer_url
    assert "bearer secret" in initial["warning"]
    assert final["status"] == "applied"
    assert "sensitive_intake_url" not in final
    assert "test-bearer-token" not in lines[1]


def test_flatten_submission_decodes_declared_files_only(tmp_path: Path) -> None:
    request_path = tmp_path / "file-request.json"
    request_path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "request_id": "file-test",
                "title": "File test",
                "workspace_root": str(tmp_path),
                "needs": [
                    {
                        "type": "file",
                        "name": "PRIVATE_KEY",
                        "required": True,
                        "target": "secrets/private-key.pem",
                        "max_bytes": 32,
                    }
                ],
                "write_policy": {
                    "env_file": ".env.local",
                    "mode": "merge_only",
                    "no_overwrite": True,
                    "backup": False,
                },
            }
        ),
        encoding="utf-8",
    )
    request = cli._load_request_model(request_path, tmp_path)
    content = b"test-private-key"
    flattened = cli._flatten_submission(
        request,
        {
            "env": {},
            "files": {
                "PRIVATE_KEY": {
                    "filename": "ignored-name.pem",
                    "content_base64": base64.b64encode(content).decode("ascii"),
                }
            },
        },
    )
    assert flattened == {"PRIVATE_KEY": content}

    with pytest.raises(ValueError, match="file encoding"):
        cli._flatten_submission(
            request,
            {
                "env": {},
                "files": {
                    "PRIVATE_KEY": {
                        "filename": "ignored-name.pem",
                        "content_base64": "not base64",
                    }
                },
            },
        )


def test_serve_rejects_agent_target_outside_host_policy(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    request = _request_file(tmp_path / "request.json", tmp_path)
    document = json.loads(request.read_text(encoding="utf-8"))
    document["needs"] = [
        {
            "type": "file",
            "name": "APP_SOURCE",
            "required": True,
            "target": "src/app.py",
        }
    ]
    request.write_text(json.dumps(document), encoding="utf-8")

    assert (
        cli.main(
            [
                "--json",
                "serve",
                "--workspace",
                str(tmp_path),
                "--request",
                str(request),
                "--no-open",
            ]
        )
        == cli.EXIT_USAGE
    )
    payload = json.loads(capsys.readouterr().out)
    assert payload["error"]["code"] == "policy_rejected"


def test_serve_honours_request_allowlist_as_a_narrowing_constraint(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    request = _request_file(tmp_path / "request.json", tmp_path)
    document = json.loads(request.read_text(encoding="utf-8"))
    document["allowed_targets"] = ["secrets/*"]
    request.write_text(json.dumps(document), encoding="utf-8")

    assert (
        cli.main(
            [
                "--json",
                "serve",
                "--workspace",
                str(tmp_path),
                "--request",
                str(request),
                "--no-open",
            ]
        )
        == cli.EXIT_USAGE
    )
    payload = json.loads(capsys.readouterr().out)
    assert payload["error"]["code"] == "policy_rejected"
