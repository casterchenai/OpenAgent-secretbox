import json
from concurrent.futures import ThreadPoolExecutor

import pytest

from openagent_secretbox.remote_worker import MockScenario, MockTarget, MockWorker, WorkerError


def request(operation: str = "rds.connectivity_check") -> dict:
    params = {}
    if operation == "rds.restore_public_business":
        params = {
            "backup_id": "reviewed-backup", "scope": "public_business_only",
            "allow_existing_data": False,
        }
    return {
        "request_id": "test-request", "operation": operation,
        "target_id": "isolated-test", "parameters": params,
    }


def worker(clock=None):
    return MockWorker((MockTarget("isolated-test"),), **({"clock": clock} if clock else {}))


def start(w, scenario=None, operation="rds.connectivity_check"):
    task = w.create(request(operation))["task_id"]
    token = w.issue_internal_token(task)
    return task, token, w.dispatch(task, token, scenario=scenario)


def test_success_and_snapshot():
    w = worker()
    task, _, result = start(w)
    assert result["status"] == "succeeded"
    assert result["redacted_logs"] == ["created", "validated", "queued", "running", "succeeded"]
    result["summary"]["simulation"] = False
    assert w.status(task)["summary"]["simulation"] is True


@pytest.mark.parametrize("field,value,code", [
    ("target_id", "production", "SBX-002"),
    ("operation", "shell", "SBX-003"),
    ("parameters", {"host": "elsewhere"}, "SBX-001"),
    ("parameters", {"command": "anything"}, "SBX-001"),
    ("request_id", "../invalid", "SBX-001"),
])
def test_policy(field, value, code):
    req = request()
    req[field] = value
    with pytest.raises(WorkerError, match=code):
        worker().create(req)


def test_production_target_rejected():
    w = MockWorker((MockTarget("isolated-test", environment="production"),))
    with pytest.raises(WorkerError, match="SBX-002"):
        w.create(request())


def test_duplicate_and_replay():
    w = worker()
    task, token, _ = start(w)
    with pytest.raises(WorkerError, match="SBX-006"):
        w.create(request())
    with pytest.raises(WorkerError, match="SBX-006"):
        w.dispatch(task, token)


@pytest.mark.parametrize("field,value", [
    ("target_id", "other"), ("operation", "rds.verify_restore"),
    ("parameters", {"host": "bad"}),
])
def test_signature_binds_all_metadata(field, value):
    w = worker()
    task = w.create(request())["task_id"]
    token = w.issue_internal_token(task)
    w._tasks[task].request[field] = value  # Simulate a tampered transport envelope.
    with pytest.raises(WorkerError, match="SBX-007"):
        w.dispatch(task, token)


def test_untrusted_worker_and_restart():
    w = worker()
    task = w.create(request())["task_id"]
    token = w.issue_internal_token(task)
    other = worker()
    other_task = other.create(request())["task_id"]
    with pytest.raises(WorkerError, match="SBX-007"):
        other.dispatch(other_task, token)


def test_expiry_and_timeout():
    now = [1.0]
    w = worker(lambda: now[0])
    task = w.create(request(), ttl=1)["task_id"]
    token = w.issue_internal_token(task)
    now[0] = 2
    with pytest.raises(WorkerError, match="SBX-005"):
        w.dispatch(task, token)
    w = worker(lambda: now[0])
    task, _, _ = start(w, MockScenario(duration=2000))
    now[0] += 1800
    assert w.status(task)["error_code"] == "SBX-012"
    assert w.status(task)["summary"]["cleanup_completed"]


@pytest.mark.parametrize("scenario,code", [
    (MockScenario(crash=True), "SBX-008"),
    (MockScenario(cleanup_fails=True), "SBX-014"),
    (MockScenario(verification_fails=True), "RDS-008"),
])
def test_failures_never_success(scenario, code):
    _, _, result = start(worker(), scenario)
    assert result["status"] == "failed"
    assert result["error_code"] == code


@pytest.mark.parametrize("payload", [
    "password=not-a-real-secret", "postgresql://user:fake@host/db",
    "Traceback: fake-secret", "connection failed PGPASSWORD=fake",
    "-----BEGIN PRIVATE KEY----- fake -----END PRIVATE KEY-----",
    "business row data", "ZmFrZS1zZWNyZXQ=",
])
def test_raw_outputs_are_never_released(payload):
    _, _, result = start(worker(), MockScenario(stdout=payload, stderr=payload))
    assert payload not in json.dumps(result)


def test_cancel_and_no_late_success():
    w = worker()
    task, _, _ = start(w, MockScenario(duration=100))
    assert w.cancel(task)["status"] == "cancelled"
    assert w.status(task)["status"] == "cancelled"


def test_restore_requires_owner_confirmation():
    w = worker()
    task, _, result = start(w, operation="rds.restore_public_business")
    assert result["status"] == "awaiting_confirmation"
    with pytest.raises(WorkerError, match="SBX-004"):
        w.confirm_from_trusted_ui(task, "wrong")
    assert w.confirm_from_trusted_ui(task, result["preflight_id"])["status"] == "succeeded"
    with pytest.raises(WorkerError, match="SBX-004"):
        w.confirm_from_trusted_ui(task, result["preflight_id"])


def test_preflight_and_confirmation_timeout():
    _, _, result = start(
        worker(), MockScenario(preflight_fails=True), "rds.restore_public_business",
    )
    assert result["error_code"] == "RDS-010"
    now = [1.0]
    w = worker(lambda: now[0])
    task, _, result = start(w, operation="rds.restore_public_business")
    now[0] += 300
    with pytest.raises(WorkerError, match="SBX-004"):
        w.confirm_from_trusted_ui(task, result["preflight_id"])
    assert w.status(task)["status"] == "timed_out"


def test_parallel_replay_only_runs_once():
    w = worker()
    task = w.create(request())["task_id"]
    token = w.issue_internal_token(task)

    def dispatch(_):
        try:
            return w.dispatch(task, token)["status"]
        except WorkerError as exc:
            return exc.code

    with ThreadPoolExecutor(max_workers=4) as pool:
        results = list(pool.map(dispatch, range(4)))
    assert results.count("succeeded") == 1
    assert results.count("SBX-006") == 3


@pytest.mark.parametrize("token", ["", "密钥", "x" * 64, None, 42])
def test_malformed_token(token):
    w = worker()
    task = w.create(request())["task_id"]
    with pytest.raises(WorkerError, match="SBX-007"):
        w.dispatch(task, token)


def test_narrow_operations_and_capacity():
    w = MockWorker((MockTarget("isolated-test", operations=frozenset()),))
    with pytest.raises(WorkerError, match="SBX-003"):
        w.create(request())
    w = MockWorker((MockTarget("isolated-test"),), capacity=1)
    w.create(request())
    req = request()
    req["request_id"] = "second"
    with pytest.raises(WorkerError, match="SBX-008"):
        w.create(req)


@pytest.mark.parametrize("ttl", [0, -1, 601, True, "600"])
def test_invalid_ttl(ttl):
    with pytest.raises(WorkerError, match="SBX-001"):
        worker().create(request(), ttl=ttl)


def test_no_overwrite_restore():
    req = request("rds.restore_public_business")
    req["parameters"]["allow_existing_data"] = True
    with pytest.raises(WorkerError, match="SBX-001"):
        worker().create(req)


def test_cancel_cleanup_failure():
    w = worker()
    task, _, _ = start(w, MockScenario(duration=100, cleanup_fails=True))
    assert w.cancel(task)["error_code"] == "SBX-014"
    assert w.status(task)["status"] == "failed"
