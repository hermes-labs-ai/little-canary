"""CLI discovery and explicit demo-mode dispatch tests."""

from unittest.mock import patch

import pytest

from little_canary import __version__
from little_canary.cli import DEFAULT_CANARY_TIMEOUT, TIMEOUT_ENV_VAR, main


def test_version_is_discoverable(capsys):
    with pytest.raises(SystemExit) as exc_info:
        main(["--version"])

    assert exc_info.value.code == 0
    assert capsys.readouterr().out.strip() == f"little-canary {__version__}"


def test_bare_demo_defaults_to_offline_replay():
    with (
        patch("little_canary.demo.run_replay", return_value=0) as replay,
        patch("little_canary.demo.run_live") as live,
    ):
        exit_code = main(["demo"])

    assert exit_code == 0
    replay.assert_called_once_with(output_json=False)
    live.assert_not_called()


def test_bare_demo_replay_honors_json_flag():
    with (
        patch("little_canary.demo.run_replay", return_value=0) as replay,
        patch("little_canary.demo.run_live") as live,
    ):
        exit_code = main(["demo", "--json"])

    assert exit_code == 0
    replay.assert_called_once_with(output_json=True)
    live.assert_not_called()


def test_demo_replay_flag_still_selects_replay():
    with (
        patch("little_canary.demo.run_replay", return_value=7) as replay,
        patch("little_canary.demo.run_live") as live,
    ):
        exit_code = main(["demo", "--replay", "--json"])

    assert exit_code == 7
    replay.assert_called_once_with(output_json=True)
    live.assert_not_called()


def test_demo_live_dispatches_explicit_backend_model_and_endpoint():
    with (
        patch("little_canary.demo.run_live", return_value=1) as live,
        patch("little_canary.demo.run_replay") as replay,
    ):
        exit_code = main(
            [
                "demo",
                "--live",
                "--backend",
                "ollama",
                "--model",
                "model:tag",
                "--endpoint",
                "http://127.0.0.1:9999",
                "--json",
            ]
        )

    assert exit_code == 1
    live.assert_called_once_with(
        endpoint="http://127.0.0.1:9999",
        backend="ollama",
        model="model:tag",
        output_json=True,
        timeout=DEFAULT_CANARY_TIMEOUT,
    )
    replay.assert_not_called()


def test_demo_live_timeout_flag_overrides_default():
    with patch("little_canary.demo.run_live", return_value=0) as live:
        exit_code = main(["demo", "--live", "--timeout", "45"])

    assert exit_code == 0
    assert live.call_args.kwargs["timeout"] == 45.0


def test_demo_live_timeout_rejects_non_positive():
    with pytest.raises(SystemExit) as exc_info:
        main(["demo", "--live", "--timeout", "0"])
    assert exc_info.value.code == 2


def test_demo_live_timeout_from_env(monkeypatch):
    monkeypatch.setenv(TIMEOUT_ENV_VAR, "30")
    with patch("little_canary.demo.run_live", return_value=0) as live:
        exit_code = main(["demo", "--live"])

    assert exit_code == 0
    assert live.call_args.kwargs["timeout"] == 30.0


def test_demo_live_timeout_flag_beats_env(monkeypatch):
    monkeypatch.setenv(TIMEOUT_ENV_VAR, "30")
    with patch("little_canary.demo.run_live", return_value=0) as live:
        main(["demo", "--live", "--timeout", "90"])

    assert live.call_args.kwargs["timeout"] == 90.0


def test_demo_live_invalid_env_timeout_errors(monkeypatch):
    monkeypatch.setenv(TIMEOUT_ENV_VAR, "soon")
    with pytest.raises(SystemExit) as exc_info:
        main(["demo", "--live"])
    assert exc_info.value.code != 0


def test_demo_modes_are_mutually_exclusive():
    with pytest.raises(SystemExit) as exc_info:
        main(["demo", "--replay", "--live"])

    assert exc_info.value.code == 2


def test_serve_passes_explicit_ollama_origin():
    with patch("little_canary.server.run_server") as run_server:
        exit_code = main(
            [
                "serve",
                "--port",
                "19000",
                "--mode",
                "full",
                "--canary-model",
                "model:tag",
                "--ollama-url",
                "http://127.0.0.1:9999",
            ]
        )

    assert exit_code == 0
    run_server.assert_called_once_with(
        port=19000,
        mode="full",
        canary_model="model:tag",
        ollama_url="http://127.0.0.1:9999",
        canary_timeout=DEFAULT_CANARY_TIMEOUT,
    )


def test_serve_timeout_flag_overrides_default():
    with patch("little_canary.server.run_server") as run_server:
        exit_code = main(["serve", "--timeout", "75"])

    assert exit_code == 0
    assert run_server.call_args.kwargs["canary_timeout"] == 75.0


def test_serve_timeout_from_env(monkeypatch):
    monkeypatch.setenv(TIMEOUT_ENV_VAR, "33")
    with patch("little_canary.server.run_server") as run_server:
        exit_code = main(["serve"])

    assert exit_code == 0
    assert run_server.call_args.kwargs["canary_timeout"] == 33.0


@pytest.mark.parametrize("port", ["-1", "65536"])
def test_serve_rejects_out_of_range_port_before_dispatch(port, capsys):
    with (
        patch("little_canary.server.run_server") as run_server,
        pytest.raises(SystemExit) as exc_info,
    ):
        main(["serve", "--port", port])

    assert exc_info.value.code == 2
    run_server.assert_not_called()
    error = capsys.readouterr().err
    assert "invalid port" in error
    assert "0..65535" in error


def test_serve_accepts_port_zero_for_ephemeral_bind():
    with patch("little_canary.server.run_server") as run_server:
        exit_code = main(["serve", "--port", "0"])

    assert exit_code == 0
    assert run_server.call_args.kwargs["port"] == 0


def test_bare_command_prints_help_and_returns_one(capsys):
    assert main([]) == 1
    assert "demo" in capsys.readouterr().out
