"""Unattended api_server runs with a registered-but-unanswered approval bridge resolve fast (IST-129).

The gateway sets HERMES_EXEC_ASK=1 and ``api_server_runs.py`` registers a notify callback for every
/v1/runs run, so the gate used to park on the full ``approvals.timeout`` even though no client ever
POSTs ``/v1/runs/{id}/approval``. Ten flagged commands then exhausted the 600s run budget. The gate now
gives an attached client a short grace window and then resolves from ``approvals.unattended_mode``:
deny stays fail-closed, approve grants once. Headless ask-mode WITHOUT a platform marker keeps the
pending fallback (``test_cli_approval_exec_ask_leak``).
"""

import threading
import time

import pytest

from tools import approval as mod
from tools import approval_context

SESSION_KEY = "ist129-unattended"
COMMAND = "rm -rf /tmp/probe"


@pytest.fixture(autouse=True)
def _unattended_api_server(monkeypatch):
    for key in ("HERMES_INTERACTIVE", "HERMES_CRON_SESSION", "HERMES_YOLO_MODE", "HERMES_SINGLE_QUERY"):
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setenv("HERMES_SESSION_PLATFORM", "api_server")
    monkeypatch.setenv("HERMES_EXEC_ASK", "1")
    monkeypatch.setenv("HERMES_GATEWAY_SESSION", "1")
    monkeypatch.setenv("HERMES_SESSION_KEY", SESSION_KEY)
    monkeypatch.setattr(mod, "_YOLO_MODE_FROZEN", False)
    # A long approval window: the test proves the gate does NOT wait for it.
    monkeypatch.setattr(approval_context, "_get_approval_config", lambda: {"mode": "manual", "timeout": 120})
    monkeypatch.setattr("tools.tirith_security.check_command_security",
                        lambda _c: {"action": "allow", "findings": [], "summary": ""})
    mod._gateway_queues.clear(); mod._gateway_notify_cbs.clear()
    mod._session_approved.clear(); mod._permanent_approved.clear(); mod._pending.clear()
    yield
    mod._gateway_queues.clear(); mod._gateway_notify_cbs.clear()


def _run(mode, monkeypatch):
    monkeypatch.setattr(approval_context, "_get_unattended_approval_mode", lambda: mode)
    notified = []
    mod.register_gateway_notify(SESSION_KEY, lambda d: notified.append(d))
    started = time.monotonic()
    result = mod.check_all_command_guards(COMMAND, "local")
    return result, time.monotonic() - started, notified


def test_deny_mode_blocks_fast_without_consuming_the_approval_window(monkeypatch):
    result, elapsed, notified = _run("deny", monkeypatch)
    assert len(notified) == 1  # the bridge WAS offered the card
    assert result["approved"] is False
    assert result.get("status") != "pending_approval"
    assert "approvals.unattended_mode" in result["message"]
    assert elapsed < 10, f"deny waited {elapsed:.1f}s (approvals.timeout=120)"


def test_approve_mode_grants_fast_when_nobody_answers(monkeypatch):
    result, elapsed, notified = _run("approve", monkeypatch)
    assert len(notified) == 1
    assert result["approved"] is True
    assert elapsed < 10, f"approve waited {elapsed:.1f}s (approvals.timeout=120)"


def test_attached_client_answer_inside_grace_window_still_wins(monkeypatch):
    """The /v1/runs bridge keeps working: a client that answers is honoured, even under deny."""
    monkeypatch.setattr(approval_context, "_get_unattended_approval_mode", lambda: "deny")

    def _answer(data):
        threading.Timer(0.2, lambda: mod.resolve_gateway_approval(SESSION_KEY, "deny", reason="nope")).start()

    mod.register_gateway_notify(SESSION_KEY, _answer)
    result = mod.check_all_command_guards(COMMAND, "local")
    assert result["approved"] is False
    assert result.get("deny_reason") == "nope"


def test_headless_ask_mode_without_platform_marker_keeps_pending_fallback(monkeypatch):
    monkeypatch.delenv("HERMES_SESSION_PLATFORM", raising=False)
    monkeypatch.delenv("HERMES_GATEWAY_SESSION", raising=False)
    result = mod.check_all_command_guards(COMMAND, "local")
    assert result.get("status") == "pending_approval"
