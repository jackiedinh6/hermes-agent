"""Non-quiet ``chat -q`` must exit non-zero when the turn never reaches the model.

The kanban dispatcher books a worker that exits 0 with its task still running as a protocol
violation, so a missing provider used to look like the agent skipping ``kanban_complete``.
"""

from types import SimpleNamespace

import pytest


def _fake_cli(setup_failed):
    queries = []

    def chat(query, images=None):
        queries.append(query)
        fake._last_turn_setup_failed = setup_failed

    fake = SimpleNamespace(
        _claim_active_session=lambda *a, **k: True,
        console=SimpleNamespace(print=lambda *a, **k: None),
        _show_security_advisories=lambda: None,
        chat=chat,
        _print_exit_summary=lambda **k: None,
    )
    return fake, queries


@pytest.fixture
def cli_mod(monkeypatch):
    import cli
    monkeypatch.setenv("HERMES_SINGLE_QUERY_SESSION", "0")
    monkeypatch.setattr(cli, "_should_seed_interactive", lambda *a: False)
    monkeypatch.setattr(cli, "_collect_query_images", lambda q, i: (q, []))
    monkeypatch.setattr(cli, "_collect_kanban_task_images", lambda imgs: [])
    monkeypatch.setattr(cli, "_finalize_single_query", lambda c: None)
    return cli


def test_setup_failure_exits_nonzero(cli_mod):
    fake, queries = _fake_cli(setup_failed=True)
    with pytest.raises(SystemExit) as ei:
        cli_mod._run_single_query_mode(fake, "work kanban task t_1", None, False, False)
    assert ei.value.code == 1
    assert queries == ["work kanban task t_1"]


def test_completed_turn_does_not_exit(cli_mod):
    fake, queries = _fake_cli(setup_failed=False)
    cli_mod._run_single_query_mode(fake, "hi", None, False, False)
    assert queries == ["hi"]


def test_chat_flags_credential_failure():
    from hermes_cli.cli_chat_turn_mixin import CLIChatTurnMixin
    stub = SimpleNamespace(_secret_capture_callback=None, _ensure_runtime_credentials=lambda: False)
    assert CLIChatTurnMixin.chat(stub, "hi") is None
    assert stub._last_turn_setup_failed is True
