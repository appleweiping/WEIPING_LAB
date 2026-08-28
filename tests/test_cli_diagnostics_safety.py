from __future__ import annotations

import json

import typer
from typer.testing import CliRunner


def test_typer_command_exception_emits_only_safe_error():
    import cli.main as main
    from lab.runtime import safe_error

    fixture_value = "QX7V2K9M" + "-private-R4T8"
    private_path = "C:" + "\\Users\\operator\\research\\draft.txt"
    failure = RuntimeError("Authorization: Bearer " + fixture_value + " failed at " + private_path)
    unsafe_app = typer.Typer(
        cls=main._SafeTyperGroup,
        pretty_exceptions_enable=False,
    )

    @unsafe_app.command()
    def fail():
        raise failure

    @unsafe_app.command()
    def noop():
        return None

    result = CliRunner().invoke(unsafe_app, ["fail"])

    assert result.exit_code == 1
    assert result.output.strip() == safe_error(failure)
    assert fixture_value not in result.output
    assert private_path not in result.output
    assert "Traceback" not in result.output


def test_model_diagnostics_redact_dynamic_strings_and_preserve_normal_names(tmp_path):
    from lab.core.config import LabConfig, ModelProfile
    from lab.diagnostics import build_diagnostics

    fixture_value = "JN6C3W8P" + "-private-H5Y2"
    private_path = "C:" + "\\Users\\operator\\private\\model.bin"
    config = LabConfig(
        models=[
            ModelProfile(
                id="token=" + fixture_value,
                name="Authorization: Bearer " + fixture_value,
                role="architect at " + private_path,
                provider=private_path,
                api_key_env="UNSET_DIAGNOSTICS_TEST_KEY",
            ),
            ModelProfile(
                id="claude-sonnet-4-6",
                name="Sonnet",
                role="executor",
                provider="anthropic",
                api_key_env="UNSET_DIAGNOSTICS_TEST_KEY",
            ),
        ],
        workspace_root=str(tmp_path),
    )

    diagnostics = build_diagnostics(config)
    rendered = json.dumps(diagnostics, ensure_ascii=False)
    unsafe_model, normal_model = diagnostics["models"]

    assert fixture_value not in rendered
    assert private_path not in rendered
    assert unsafe_model["model"] == "token=...redacted"
    assert unsafe_model["name"] == "...redacted"
    assert "Authorization" not in unsafe_model["name"]
    assert "Bearer" not in unsafe_model["name"]
    assert "...redacted-path" in unsafe_model["role"]
    assert unsafe_model["provider"] == "...redacted-path"
    assert normal_model["model"] == "claude-sonnet-4-6"
    assert normal_model["name"] == "Sonnet"
    assert normal_model["provider"] == "anthropic"


def test_configured_secret_is_scrubbed_from_unshaped_cli_and_model_labels(monkeypatch, tmp_path):
    import cli.main as main
    from lab.core.config import LabConfig, ModelProfile
    from lab.diagnostics import build_diagnostics

    fixture_value = "UNSHAPED-CONFIGURED-VALUE-Q7Z9L4N2"
    monkeypatch.setenv("ANTHROPIC_API_KEY", fixture_value)
    config = LabConfig(
        models=[
            ModelProfile(
                id=fixture_value,
                name="model-" + fixture_value,
                role="architect",
                provider="anthropic",
                api_key_env="ANTHROPIC_API_KEY",
            )
        ],
        workspace_root=str(tmp_path),
    )

    rendered = json.dumps(build_diagnostics(config), ensure_ascii=False)
    assert fixture_value not in rendered
    assert fixture_value[:12] not in rendered
    assert fixture_value[-12:] not in rendered

    unsafe_app = typer.Typer(cls=main._SafeTyperGroup, pretty_exceptions_enable=False)

    @unsafe_app.command()
    def fail():
        raise RuntimeError("unexpected model " + fixture_value)

    @unsafe_app.command()
    def noop():
        return None

    result = CliRunner().invoke(unsafe_app, ["fail"])
    assert result.exit_code == 1
    assert fixture_value not in result.output
    assert fixture_value[:12] not in result.output
    assert fixture_value[-12:] not in result.output
