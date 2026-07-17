"""CLI discovery and explicit demo-mode dispatch tests."""

from unittest.mock import patch

import pytest

from little_canary import __version__
from little_canary.cli import main


def test_version_is_discoverable(capsys):
    with pytest.raises(SystemExit) as exc_info:
        main(["--version"])

    assert exc_info.value.code == 0
    assert capsys.readouterr().out.strip() == f"little-canary {__version__}"


def test_bare_demo_requires_explicit_run_kind(capsys):
    with (
        patch("little_canary.demo.run_replay") as replay,
        patch("little_canary.demo.run_live") as live,
    ):
        exit_code = main(["demo"])

    assert exit_code == 2
    replay.assert_not_called()
    live.assert_not_called()
    error = capsys.readouterr().err
    assert "--replay or --live" in error
    assert "No mode is inferred" in error


def test_demo_replay_dispatches_without_live_arguments():
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
    )
    replay.assert_not_called()


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
    )


def test_bare_command_prints_help_and_returns_one(capsys):
    assert main([]) == 1
    assert "demo" in capsys.readouterr().out
