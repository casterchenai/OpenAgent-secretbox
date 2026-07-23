"""Install the built wheel in a fresh venv and smoke-test published surfaces."""

from __future__ import annotations

import os
import subprocess
import tempfile
import venv
from pathlib import Path

PACKAGE_SMOKE = r"""
import json
import sys
from importlib import resources
from pathlib import Path

import openagent_secretbox
from openagent_secretbox.mcp_server import IntakeManager, create_mcp_server

venv_root = Path(sys.argv[1]).resolve()
module_path = Path(openagent_secretbox.__file__).resolve()
module_path.relative_to(venv_root)

schema_root = resources.files("openagent_secretbox").joinpath("schemas")
expected_ids = {
    "request-v1.json": "/schemas/request-v1.json",
    "result-v1.json": "/schemas/result-v1.json",
}
for name, expected_id_suffix in expected_ids.items():
    document = json.loads(schema_root.joinpath(name).read_text(encoding="utf-8"))
    assert document["$schema"] == "https://json-schema.org/draft/2020-12/schema"
    assert document["$id"].endswith(expected_id_suffix)

manager = IntakeManager(Path.cwd())
try:
    create_mcp_server(manager)
finally:
    manager.close()
"""


def _run(command: list[str], *, cwd: Path, environment: dict[str, str]) -> None:
    subprocess.run(command, cwd=cwd, env=environment, check=True)


def main() -> int:
    repository = Path(__file__).resolve().parents[2]
    wheels = sorted((repository / "dist").glob("*.whl"))
    if len(wheels) != 1:
        raise SystemExit(f"expected exactly one wheel in dist, found {len(wheels)}")

    environment = os.environ.copy()
    environment.pop("PYTHONHOME", None)
    environment.pop("PYTHONPATH", None)

    with tempfile.TemporaryDirectory(prefix="secretbox-wheel-smoke-") as temporary:
        root = Path(temporary)
        environment_root = root / "venv"
        run_directory = root / "work"
        run_directory.mkdir()
        venv.EnvBuilder(with_pip=True).create(environment_root)

        scripts = environment_root / ("Scripts" if os.name == "nt" else "bin")
        python = scripts / ("python.exe" if os.name == "nt" else "python")
        executable_suffix = ".exe" if os.name == "nt" else ""
        wheel_requirement = f"openagent-secretbox[mcp] @ {wheels[0].resolve().as_uri()}"

        _run(
            [str(python), "-m", "pip", "install", wheel_requirement],
            cwd=run_directory,
            environment=environment,
        )
        _run(
            [str(scripts / f"secretbox{executable_suffix}"), "--version"],
            cwd=run_directory,
            environment=environment,
        )
        _run(
            [str(scripts / f"secretbox-mcp{executable_suffix}"), "--help"],
            cwd=run_directory,
            environment=environment,
        )
        _run(
            [str(python), "-c", PACKAGE_SMOKE, str(environment_root)],
            cwd=run_directory,
            environment=environment,
        )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
