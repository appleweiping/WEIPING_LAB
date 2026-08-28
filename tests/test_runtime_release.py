"""Runtime and release-safety regression tests."""

from __future__ import annotations

import asyncio
import base64
import json
import os
import shutil
import subprocess
import sys
import time
import tomllib
from pathlib import Path

import pytest


def _runtime_text(*parts: str) -> str:
    """Build hostile fixtures without making the test source itself a release-scan finding."""
    return "".join(parts)


class _StrictAsciiStream:
    encoding = "ascii"

    def __init__(self):
        self.value = ""

    def write(self, text: str) -> int:
        text.encode(self.encoding)
        self.value += text
        return len(text)


def test_cli_encoding_fallback_escapes_unsupported_glyphs():
    from cli.main import _safe_terminal_stream

    target = _StrictAsciiStream()
    safe_stream = _safe_terminal_stream(target)
    safe_stream.write("result 🧪")

    assert target.value == r"result \U0001f9ea"


def test_cli_and_monitor_public_renderers_never_echo_runtime_material(monkeypatch, capsys):
    import time
    from types import SimpleNamespace

    from cli import main, monitor, repl, todo

    fixture_value = "CliSecret_" + "Z9v-7319"
    path_marker = "CLI-PATH-MARKER"
    monkeypatch.setenv("SYNTH_API_KEY", fixture_value)
    main.print_idea(
        {
            "title": "Finding " + fixture_value,
            "status": "generated",
            "origin": "phenomenon",
            "phenomenon": "failed at /srv/private/" + path_marker,
            "hypothesis": "Token economy research",
        }
    )
    repl.print_session_result(
        SimpleNamespace(
            id="session-safe",
            phenomena=[SimpleNamespace(severity=0.5, description="Finding " + fixture_value)],
            analogies=[SimpleNamespace(confidence=0.5, target_problem="Finding " + fixture_value)],
            ideas=[],
        )
    )
    monitor._print_event(
        "m1",
        monitor.MonitorEvent(
            ts=time.time(),
            stream="stderr",
            text=(
                "Authorization: Bearer "
                + fixture_value
                + " at /srv/private/"
                + path_marker
                + "\x1b]0;x"
            ),
        ),
    )
    poisoned = monitor.MonitorInstance(
        id="mtest",
        command="run --value " + fixture_value,
        started_at=time.time(),
        process=SimpleNamespace(),
        events=[
            monitor.MonitorEvent(
                ts=time.time(),
                stream="stderr",
                text="Authorization: Bearer " + fixture_value,
            )
        ],
    )
    monitor._monitors[poisoned.id] = poisoned
    try:
        rendered_sinks = monitor.monitor_logs(poisoned.id) + monitor.monitor_list()
    finally:
        monitor._monitors.clear()
    monkeypatch.setattr(todo, "_load", lambda: [])
    identifier_sinks = (
        todo.format_todo_list(
            [
                {
                    "id": fixture_value,
                    "text": "protein",
                    "status": "pending",
                    "priority": "normal",
                }
            ]
        )
        + todo.handle_todo_command("done " + fixture_value)
        + monitor.monitor_stop(fixture_value)
        + monitor.monitor_logs(fixture_value)
    )

    rendered = capsys.readouterr().out
    assert fixture_value not in rendered
    assert fixture_value not in rendered_sinks
    assert fixture_value not in identifier_sinks
    assert path_marker not in rendered
    assert "\x1b]0;x" not in rendered


def test_diagnostics_redacts_key_sources(monkeypatch, tmp_path):
    fixture_value = _runtime_text("sk-", "testsecret-1234567890")
    monkeypatch.setenv("ANTHROPIC_API_KEY", fixture_value)
    monkeypatch.setenv("WEIPING_LAB_WORKSPACE_ROOT", str(tmp_path))

    from lab.core.config import LabConfig
    from lab.diagnostics import build_diagnostics

    diagnostics = build_diagnostics(LabConfig())
    text = json.dumps(diagnostics)
    assert diagnostics["ok"] is True
    assert fixture_value not in text
    assert diagnostics["models"][0]["api_key"] == "configured"
    assert diagnostics["agentmemory"]["legacy_markdown_fallback"] is False
    assert diagnostics["agentmemory"]["legacy_agent_hub_mailbox"] is False


def test_runtime_redacts_url_userinfo_and_endpoint_credentials():
    from lab.runtime import endpoint_host, redact, safe_error

    url = "".join(
        (
            "https://",
            "account-marker:credential-marker@",
            "example.test:8443/path?token=query-marker",
        )
    )
    message = safe_error(RuntimeError(f"request failed for {url}"))

    for marker in ["account-marker", "credential-marker", "query-marker"]:
        assert marker not in message
    assert "".join(("https://", "...redacted@", "example.test:8443/path")) in message
    assert endpoint_host(url) == "example.test:8443"
    assert endpoint_host("example.test:8443") == "example.test:8443"
    assert endpoint_host("".join(("https://", "user:pass@", "example.test:not-a-port"))) == ""
    structured = redact(
        "".join(('{"to', 'ken": "value with spaces", "author', 'ization": "Bearer abc+/="}'))
    )
    assert "value with spaces" not in structured
    assert "abc+/=" not in structured
    network_path = safe_error("failure at //network-user:network-pass@network.example/path")
    assert "network-user" not in network_path
    assert "network-pass" not in network_path


@pytest.mark.parametrize(
    ("message", "markers"),
    [
        (
            "request failed at account-no-scheme:password-no-scheme@host.example/path",
            ["account-no-scheme", "password-no-scheme"],
        ),
        (
            "request failed at malformed-user:malformed-pass@[broken?token=malformed-query",
            ["malformed-user", "malformed-pass", "malformed-query"],
        ),
        ('request failed with Bearer "quoted-bearer marker"', ["quoted-bearer marker"]),
        (
            "".join(("request failed with Author", "ization: Basic basic-auth-marker")),
            ["basic-auth-marker"],
        ),
        ("request failed with Basic 'quoted-basic marker'", ["quoted-basic marker"]),
    ],
)
def test_safe_error_redacts_dynamic_authorization_forms(message, markers):
    from lab.runtime import safe_error

    rendered = safe_error(RuntimeError(message))

    assert "...redacted" in rendered
    for marker in markers:
        assert marker not in rendered


@pytest.mark.parametrize(
    "message",
    [
        "".join(("Author", "ization: Token arbitrary-token-marker")),
        "".join(("Author", "ization: Digest arbitrary-digest-marker")),
        "".join(("Author", "ization: ApiKey arbitrary-api-key-marker")),
        "".join(("pass", "word=correct password-tail-marker")),
        _runtime_text('{"to', 'ken":["json-first-marker","json-second-marker"]}'),
        _runtime_text('{"to', 'ken":{"primary":"json-object-one","backup":"json-object-two"}}'),
        '{"to\\u006ben":"json-escaped-key-marker"}',
        "https://example.test/path?to%6ben=encoded-query-marker",
        _runtime_text("https://example.test/path?api.k", "ey=dot-query-marker"),
        _runtime_text('failure payload={"to', 'ken":["prefixed-json-one","prefixed-json-two"]}'),
        _runtime_text(
            'failure payload={"to',
            'ken":{"primary":"prefixed-object-one","backup":"prefixed-object-two"}}',
        ),
        'failure payload={"to\\u006ben":"prefixed-escaped-key-marker"}',
        _runtime_text("failure payload={'to", "ken':['repr-list-one','repr-list-two']}"),
        "".join(("Author", 'ization: Token "quoted-auth-one,quoted-auth-two"')),
        "".join(("Author", 'ization: Basic "quoted-basic-one,quoted-basic-two"')),
        "".join(("Author", "ization: Token folded-auth-one\r\n folded-auth-two")),
        "https://example.test/path?token%3Dencoded-equals-marker",
        "https://example.test/path?safe=1%26token%3Dnested-query-marker",
        '{"message":"Bearer \\"json-bearer-one,json-bearer-two\\""}',
        "".join(
            (
                '{"message":"Author',
                'ization: Digest username=\\"digest-user-marker\\", ',
                'response=\\"digest-response-marker\\", nonce=\\"digest-nonce-marker\\""}',
            )
        ),
        _runtime_text('failure={"to', 'ken":["suffix-one-marker","suffix-two-marker"]} trailing'),
        "https://example.test/?safe=1%3Btoken%3Dsemicolon-query-marker",
        _runtime_text(
            "https://example.test/?payload=%7B%22to",
            "ken%22%3A%22json-query-marker%22%7D",
        ),
        _runtime_text(
            "https://example.test/callback#access_t",
            "oken%3Dfragment-token-marker",
        ),
        "".join(("https://example.test/?next=to", "ken%3Dnested-token-marker")),
        "https://example.test/?next=https%3A%2F%2Fnested.test%2F%3Ftoken%3Dnested-url-marker",
        "https://encoded-user%" + "3Aencoded-pass%40example.test/path",
        "https%3A"
        + "%2F%2Fencoded-user%3Aencoded-pass%40example.test%2Fpath".join(
            ("%3Fto", "ken%3Dfully-encoded-query-marker")
        ),
        "".join(('{"ｔｏ', 'ｋｅｎ":"fullwidth-key-marker"}')),
        'Digest username="digest-bare-user", response="digest-bare-response-marker"',
        "Token bare-token-marker",
        "ApiKey bare-api-key-marker",
        "Authorization%3A" + "%20Bearer%20folded-encoded-one%0D%0A%20folded-encoded-two",
        "Digest%20" + "username%3Dencoded-digest-user%0D%0A%20encoded-digest-tail",
        "Token%20" + "encoded-token-one%0D%0A%20encoded-token-two",
    ],
)
def test_safe_error_redacts_structured_and_encoded_credentials(message):
    from lab.runtime import safe_error

    rendered = safe_error(RuntimeError(message))

    for marker in (
        "arbitrary-token-marker",
        "arbitrary-digest-marker",
        "arbitrary-api-key-marker",
        "password-tail-marker",
        "json-first-marker",
        "json-second-marker",
        "json-object-one",
        "json-object-two",
        "json-escaped-key-marker",
        "encoded-query-marker",
        "dot-query-marker",
        "prefixed-json-one",
        "prefixed-json-two",
        "prefixed-object-one",
        "prefixed-object-two",
        "prefixed-escaped-key-marker",
        "repr-list-one",
        "repr-list-two",
        "quoted-auth-one",
        "quoted-auth-two",
        "quoted-basic-one",
        "quoted-basic-two",
        "folded-auth-one",
        "folded-auth-two",
        "encoded-equals-marker",
        "nested-query-marker",
        "json-bearer-one",
        "json-bearer-two",
        "digest-user-marker",
        "digest-response-marker",
        "digest-nonce-marker",
        "suffix-one-marker",
        "suffix-two-marker",
        "semicolon-query-marker",
        "json-query-marker",
        "fragment-token-marker",
        "nested-token-marker",
        "nested-url-marker",
        "encoded-user",
        "encoded-pass",
        "digest-bare-response-marker",
        "bare-token-marker",
        "bare-api-key-marker",
        "fully-encoded-query-marker",
        "fullwidth-key-marker",
        "folded-encoded-one",
        "folded-encoded-two",
        "encoded-digest-user",
        "encoded-digest-tail",
        "encoded-token-one",
        "encoded-token-two",
    ):
        assert marker not in rendered


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("", ""),
        ("https://[broken", ""),
        ("//u:p@[bad", ""),
        ("https://", ""),
        ("https:/broken.example", ""),
        ("https:example.test", ""),
        ("http:localhost", ""),
        ("data:text/plain,secret", ""),
        ("mailto:user@example.test", ""),
        ("D:relative", ""),
        ("https://example.test:", ""),
        ("//example.test:", ""),
        ("not a url", ""),
        ("D:" + "\\private\\endpoint", ""),
        ("".join(("https://", "user:pass@", "example.test:bad/path?token=marker")), ""),
        ("http://[::1]:8080/path", "[::1]:8080"),
    ],
)
def test_endpoint_host_is_total_and_returns_only_safe_authority(value, expected):
    from lab.runtime import endpoint_host

    assert endpoint_host(value) == expected


def test_endpoint_host_handles_objects_with_broken_string_conversion():
    from lab.runtime import endpoint_host

    class BrokenString:
        def __str__(self):
            raise RuntimeError("must not escape")

    assert endpoint_host(BrokenString()) == ""


@pytest.mark.parametrize(
    "message",
    [
        "failure at " + "D:" + r"\Temp\private-error-marker",
        "failure at " + "C:" + r"\Users\operator\private-user-marker",
        "failure at /" + "home/operator/private-home-marker",
        "failure at " + "E:" + r"\Projects\private-project-marker",
        "failure at " + "D:" + r"\WEIPING_SUITE_UPGRADE\private-suite-marker",
        "failure at /" + "root/private-root-marker",
        "failure at /" + "tmp/private-temp-marker",
        "failure at " + r"\\" + r"server\share\private-unc-marker",
        "failure at /" + "workspace/private-workspace-marker",
        "failure at /" + "data/private-data-marker",
        "failure at /" + "usr/local/private-usr-marker",
        "failure at /" + "run/secrets/private-run-marker",
        "failure at /" + ".config/private-config-marker",
        "failure at file://" + "/workspace/private-file-uri-marker",
        "failure at %" + "2Fworkspace%2Fprivate-encoded-path-marker",
    ],
)
def test_safe_error_redacts_operator_private_paths(message):
    from lab.runtime import safe_error

    rendered = safe_error(message)

    assert "...redacted-path" in rendered
    assert "private-" not in rendered


@pytest.mark.parametrize(
    "message",
    [
        "failed at /" + "code/private-code-marker",
        "failed at /" + "project/private-project-root-marker",
        "failed at /" + "secrets/private-secrets-marker",
        "failed at /" + "nix/store/private-nix-marker",
        "failed at /" + "github/workspace/private-github-marker",
        "failed at /" + "u01/app/private-u01-marker",
    ],
)
def test_safe_error_redacts_arbitrary_absolute_roots(message):
    from lab.runtime import safe_error

    rendered = safe_error(message)

    assert "...redacted-path" in rendered
    assert "private-" not in rendered


@pytest.mark.parametrize(
    "message",
    [
        'failed at "C:' + '\\Users\\John Doe\\Private\\AUTHORITY-FUZZ-MARKER\\x.txt"',
        'failed at "/' + 'home/John Doe/private/AUTHORITY-FUZZ-MARKER/x"',
        "".join(("failed at ", "https://", "AUTHORITY-FUZZ-MARKER%20user:pass@", "example.test/x")),
        "".join(("failed at ", "https://", "user:AUTHORITY-FUZZ-MARKER%2Ftail@", "example.test/x")),
        "".join(("failed at ", "https://", "user:AUTHORITY-FUZZ-MARKER%3Ftail@", "example.test/x")),
        "Bearer prefix%0A" + "AUTHORITY-FUZZ-MARKER",
        "pass" + "word=prefix%0A" + "AUTHORITY-FUZZ-MARKER",
        "https://example.test/?token=prefix%0A" + "AUTHORITY-FUZZ-MARKER",
        "failed file://" + "/home/private%20dir/AUTHORITY-FUZZ-MARKER/x",
        "failed file://" + "server/share/AUTHORITY-FUZZ-MARKER/x",
        "failed " + r"\\" + "server\\Private Dir\\AUTHORITY-FUZZ-MARKER\\x",
    ],
)
def test_safe_error_fails_closed_on_ambiguous_encoded_authorities_and_spaced_paths(message):
    from lab.runtime import safe_error

    assert "AUTHORITY-FUZZ-MARKER" not in safe_error(message, limit=2_000)


def test_private_path_projection_preserves_benign_percent_text_and_public_urls():
    from lab.runtime import redact_private_paths, redact_public_text, safe_error

    benign = "accuracy%20improved%20by%2010%25"
    public_url = "https://example.test/public/path"

    assert redact_private_paths(benign) == benign
    assert redact_private_paths(public_url) == public_url
    encoded_fixture = "https%3A" + "%2F%2Fuser%3Apass%40example.test%2Fpath"
    assert "user" not in redact_private_paths(encoded_fixture)
    assert redact_public_text("Token economy research") == "Token economy research"
    assert redact_public_text("Basic research methodology") == "Basic research methodology"
    assert redact_public_text("Digest this paper") == "Digest this paper"
    assert redact_public_text("Call /api/v1/models") == "Call /api/v1/models"
    assert (
        redact_public_text("Read [guide](/docs/setup/install)")
        == "Read [guide](/docs/setup/install)"
    )
    assert redact_public_text("Study /protein/folding") == "Study /protein/folding"
    assert redact_public_text("precision / recall") == "precision / recall"
    assert redact_public_text("Use /help for commands") == "Use /help for commands"
    prose = "Visit https://example.test/public/path and email contact@example.org"
    assert redact_public_text(prose) == prose
    assert redact_public_text("//arxiv.org/abs/1234.5678") == "//arxiv.org/abs/1234.5678"
    assert redact_public_text("/privateer/public") == "/privateer/public"
    assert redact_public_text("/secretary/public") == "/secretary/public"
    markdown = "[paper](https://example.org/view?q=research) trailing finding"
    assert redact_public_text(markdown) == markdown
    sensitive_markdown = _runtime_text(
        "[paper](https://example.org/view?to",
        "ken=QUERYMARK7319) trailing finding",
    )
    projected_markdown = redact_public_text(sensitive_markdown)
    assert "QUERYMARK7319" not in projected_markdown
    assert projected_markdown.endswith(") trailing finding")
    authorization_fixture = "".join(("Author", "ization: Bearer credential-marker"))
    assert "credential-marker" not in redact_public_text(authorization_fixture)
    assert "credential-marker" not in redact_public_text("Bearer credential-marker")
    assert "CURRENT_MARKER_302716" not in redact_public_text(
        "Token SYNTHETIC_CURRENT_MARKER_302716"
    )
    assert "abcdefgh" not in redact_public_text("Bearer abcdefgh")
    assert redact_public_text("Token bucket") == "Token bucket"
    assert "abcdefgh" not in redact_public_text("Token abcdefgh")
    assert redact_public_text("ApiKey rotation") == "ApiKey rotation"
    assert "abc12345" not in redact_public_text("Token abc12345")
    assert "abc12345" not in redact_public_text("ApiKey abc12345")
    basic = base64.b64encode(b"user:basic-credential-marker").decode("ascii")
    assert basic not in redact_public_text("Basic " + basic)
    assert "digest-credential-marker" not in redact_public_text(
        'Digest username="user", response="digest-credential-marker"'
    )
    json_fixture = _runtime_text('{"secret_k', 'ey":"json-secret-marker"}')
    assert "json-secret-marker" not in redact_public_text(json_fixture)
    for private_path in (
        "/srv/private/PATHMARK77/data.json",
        "/srv/private workspace/PATHMARK77/data.json",
        "/opt/weiping/PATHMARK77/data.json",
        "/workspace/PATHMARK77/data.json",
        "/run/secrets/PATHMARK77/value",
        "/u01/app/PATHMARK77/data.json",
        "/var/lib/weiping/PATHMARK77/data.json",
        "/etc/weiping/PATHMARK77/config.json",
        "/usr/local/weiping/PATHMARK77/data.json",
        "/data/private/PATHMARK77/data.json",
        "/github/workspace/PATHMARK77/data.json",
        "/nix/store/PATHMARK77/data.json",
        "/private/var/PATHMARK77/data.json",
        "//server/private share/PATHMARK77/data.json",
        r"\\" + r"server\private share\PATHMARK77\data.json",
        r"\\wsl$\Ubuntu\home\private\PATHMARK77\data.json",
        r"\\.\pipe\PATHMARK77",
    ):
        assert "PATHMARK77" not in redact_public_text("failed at " + private_path)
    assert "single-root-marker" not in safe_error("failed /" + "single-root-marker")
    assert safe_error("ordinary failure", limit=float("inf")) == "ordinary failure"


def test_public_projection_preserves_research_credential_homonyms_and_path_tails():
    from lab.runtime import redact_public_artifact, redact_public_text

    prose_samples = [
        "".join(("to", "ken = embedding vector")),
        "".join(("to", "ken: classification label")),
        "".join(("To", "ken: economy and governance")),
        "".join(("au", "th = OAuth method")),
        "".join(("The sec", "ret: protein folding dynamics")),
        "Bearer plants reproduce seeds",
        "bearer bonds and yields",
    ]
    for sample in prose_samples:
        assert redact_public_text(sample) == sample
        assert redact_public_artifact(sample) == sample

    for unsafe_sample in (
        _runtime_text("to", 'ken: "classification label"'),
        _runtime_text("to", "ken: opaquecredentialvalue"),
    ):
        assert redact_public_text(unsafe_sample) == "...redacted"
        assert redact_public_artifact(unsafe_sample) == "...redacted"

    path_samples = {
        "[file](/"
        + "home/alice/private.txt) tail preserved": "[file](...redacted-path) tail preserved",
        "(/" + "Users/Jane/data) after": "(...redacted-path) after",
        "See /srv/project/private.txt for details": "See ...redacted-path for details",
    }
    for source, expected in path_samples.items():
        assert redact_public_text(source) == expected
        assert redact_public_artifact(source) == expected


def test_security_shadows_close_invisible_and_control_structure_bypasses():
    from lab.runtime import (
        public_executable_artifact_is_safe,
        redact,
        redact_public_artifact,
        redact_public_text,
    )

    separators = [
        "\u200b",
        "\ufe0f",
        "\u034f",
        "\u180b",
        "\u2065",
        "\ufff0",
        "\x00",
        "\x01",
        "\x07",
        "\t",
        "\x0b",
        "\x1f",
        "\x7f",
        "\x80",
        "\x9f",
    ]
    for separator in separators:
        probes = [
            f"Author{separator}ization: Bea{separator}rer AUTHMARK7319",
            f"-----BEGIN PRI{separator}VATE KEY-----\nPRIVATEKEYMARK7319",
            f"/ho{separator}me/alice/PATHMARK7319",
        ]
        for probe in probes:
            for sanitizer in (redact, redact_public_text, redact_public_artifact):
                rendered = sanitizer(probe)
                assert "AUTHMARK7319" not in rendered
                assert "PRIVATEKEYMARK7319" not in rendered
                assert "PATHMARK7319" not in rendered
            assert public_executable_artifact_is_safe(probe) is False


def test_url_session_and_multi_parameter_credentials_are_never_public():
    from lab.runtime import (
        public_executable_artifact_is_safe,
        redact,
        redact_public_artifact,
        redact_public_text,
        safe_error,
    )

    probes = [
        "https://e/x?token%00=CTRLMARK7319",
        "https://example.org/x;jsessionid=QUERYMARK7319",
        _runtime_text("https://e/x?q=research;to", "ken=QUERYMARK7319"),
        _runtime_text("https://e/x?ok=1;access_t", "oken=QUERYMARK7319"),
    ]
    for probe in probes:
        for sanitizer in (redact, redact_public_text, redact_public_artifact, safe_error):
            rendered = sanitizer(probe)
            assert "CTRLMARK7319" not in rendered
            assert "QUERYMARK7319" not in rendered
        assert public_executable_artifact_is_safe(probe) is False


@pytest.mark.parametrize(
    "private_path",
    [
        "/home/Alice Smith/PRIVATE-MARK/file",
        "/Users/Jane Doe/PRIVATE-MARK/file",
        "/tmp/my dir/PRIVATE-MARK/file",
        "/mnt/c/Users/Jane Doe/PRIVATE-MARK/file",
    ],
)
def test_public_projection_fails_closed_on_ambiguous_spaced_private_paths(private_path):
    from lab.runtime import redact_public_artifact, redact_public_text

    assert "PRIVATE-MARK" not in redact_public_text(private_path)
    assert "PRIVATE-MARK" not in redact_public_artifact(private_path)


def test_redaction_scrubs_raw_and_normalized_configured_secret_variants(monkeypatch):
    from lab.runtime import redact, redact_public_text, safe_error

    fixture_value = "OPAQUE%41CONFIGVALUE_923741"
    normalized = "OPAQUEACONFIGVALUE_923741"
    monkeypatch.setenv("ANTHROPIC_API_KEY", fixture_value)

    for sanitizer in (redact, redact_public_text, safe_error):
        rendered = sanitizer("provider " + fixture_value + " normalized " + normalized)
        assert fixture_value not in rendered
        assert normalized not in rendered


def test_redaction_scrubs_reconstructable_encodings_of_configured_secrets(monkeypatch):
    from lab.runtime import redact, redact_public_artifact, redact_public_text, safe_error

    fixture_value = "Base64KnownSecret-ZXCV-7319"
    monkeypatch.setenv("SYNTH_API_KEY", fixture_value)
    encoded = {
        base64.b64encode(fixture_value.encode()).decode(),
        base64.urlsafe_b64encode(fixture_value.encode()).decode().rstrip("="),
        fixture_value.encode().hex(),
        fixture_value.encode().hex().upper(),
    }
    for probe in encoded:
        for sanitizer in (redact, redact_public_text, redact_public_artifact, safe_error):
            assert probe not in sanitizer("encoded=" + probe)


@pytest.mark.parametrize(
    "token",
    [
        "glpat-" + "A" * 32,
        "xoxb-" + "1" * 32,
        "hf_" + "a" * 32,
        "sk_live_" + "a" * 32,
        "npm_" + "a" * 32,
        "pypi-" + "A" * 32,
        "AIza" + "A" * 35,
        "hvs." + "A" * 32,
    ],
)
def test_public_projection_masks_known_high_risk_provider_token_shapes(token):
    from lab.runtime import redact, redact_public_artifact, redact_public_text

    for sanitizer in (redact, redact_public_text, redact_public_artifact):
        assert token not in sanitizer("credential " + token)


def test_configured_secret_fragments_and_invisible_separator_variants_fail_closed(monkeypatch):
    from lab.memory.store import _redact_jsonish
    from lab.runtime import redact, redact_public_text, safe_error

    fixture_value = "Z9vExact" + "Secret_" + "Marker-73"
    monkeypatch.setenv("SYNTH_API_KEY", fixture_value)
    probes = [
        fixture_value[:12],
        fixture_value[-12:],
        fixture_value[5:17],
        fixture_value[:5] + "\u200b" + fixture_value[5:],
        fixture_value[:8] + "\u2060" + fixture_value[8:],
        fixture_value[:10] + "\u00ad" + fixture_value[10:],
        fixture_value[:6] + "\ufe0f" + fixture_value[6:],
        fixture_value[:9] + "\u034f" + fixture_value[9:],
        fixture_value[:11] + "\u180b" + fixture_value[11:],
        fixture_value[:6] + "\u2065" + fixture_value[6:],
        fixture_value[:9] + "\ufff0" + fixture_value[9:],
        fixture_value[:11] + "\ud800" + fixture_value[11:],
        fixture_value[:7] + "\n" + fixture_value[7:],
    ]

    for probe in probes:
        for sanitizer in (redact, redact_public_text, safe_error):
            rendered = sanitizer("provider " + probe)
            assert probe not in rendered
            assert fixture_value[:12] not in rendered
            assert fixture_value[-12:] not in rendered
        rendered_json = json.dumps(_redact_jsonish({"value": probe}))
        assert probe not in rendered_json

    short_fixture = "Ab!2345"
    monkeypatch.setenv("SYNTH_DB_PASSWORD", short_fixture)
    assert short_fixture not in redact_public_text("value=" + short_fixture)
    assert short_fixture not in json.dumps(_redact_jsonish({"value": short_fixture}))


def test_public_embedded_json_and_memory_preserve_normal_research_semantics():
    from lab.memory.store import _redact_jsonish
    from lab.runtime import redact_public_text

    normal = {
        "domain": "Token economy research",
        "method": "Basic protein structure research",
        "digest": "Digest protein folding literature",
        "metric": "precision / recall",
        "kill_argument": "Token bucket lacks causal identification",
        "kill_rebuttal": "ApiKey rotation is outside the study scope",
    }
    embedded = "prefix " + json.dumps(normal) + " suffix"
    rendered = redact_public_text(embedded)
    inner = json.loads(rendered[rendered.index("{") : rendered.rindex("}") + 1])

    assert inner == normal
    assert _redact_jsonish(normal) == normal


def test_public_artifact_projection_preserves_layout_and_fails_closed_on_encoded_forms(
    monkeypatch,
):
    from lab.runtime import redact_public_artifact

    fixture_value = "ArtifactSecret_" + "Z9v-7319"
    monkeypatch.setenv("SYNTH_API_KEY", fixture_value)
    normal = "# Finding\n\nToken economy research\n[paper](https://example.org/view?q=research)\n"
    assert redact_public_artifact(normal) == normal

    probes = [
        "".join(("Author", "ization%3A%20Bearer%20ENCODEDMARK7319\nnormal\n")),
        "".join(("Ａｕｔｈｏｒ", "ｉｚａｔｉｏｎ：　Ｂｅａｒｅｒ　FULLWIDTHMARK7319\nnormal\n")),
        "C%3A" + "%5CUsers%5Cresearcher%5CENCODEDPATH7319\nnormal\n",
        "prefix " + fixture_value + " suffix\n",
        "-----BEGIN%20" + "PRIVATE%20KEY-----\nPRIVATEKEYMARK7319\n",
    ]
    for probe in probes:
        rendered = redact_public_artifact(probe)
        for marker in (
            "ENCODEDMARK7319",
            "FULLWIDTHMARK7319",
            "ENCODEDPATH7319",
            "PRIVATEKEYMARK7319",
            fixture_value,
        ):
            assert marker not in rendered


def test_executable_artifact_policy_preserves_syntax_and_rejects_material(monkeypatch, tmp_path):
    from lab.runtime import public_executable_artifact_is_safe
    from lab.storage import atomic_write_executable_text

    safe_samples = {
        "runner.py": "".join(
            ("def f(text):\n    to", "ken = text.split()[0]\n    auth = token\n    return auth\n")
        ),
        "script.sh": "#!/usr/bin/env bash\nprintf '%s\\n' research\n",
        "config.yaml": "token_count: 128\nmethod: research\n",
        "client.py": (
            'url = "https://example.org/api?q=research"\ninterpreter = "/usr/bin/python3"\n'
        ),
    }
    for filename, source in safe_samples.items():
        assert public_executable_artifact_is_safe(source) is True
        destination = tmp_path / filename
        atomic_write_executable_text(destination, source)
        assert destination.read_text(encoding="utf-8") == source
    compile(safe_samples["runner.py"], "runner.py", "exec")
    compile(safe_samples["client.py"], "client.py", "exec")

    fixture_value = "ExecutableSecret_Z9v-7319"
    monkeypatch.setenv("SYNTH_API_KEY", fixture_value)
    unsafe_samples = [
        'value = "' + fixture_value + '"\n',
        "".join(('url = "https://', 'user:pass@example.org/api"\n')),
        _runtime_text('url = "https://example.org/api?to', 'ken=QUERYMARK7319"\n'),
        'path = "/' + 'home/researcher/private/data"\n',
        "".join(("Author", "ization: Bearer AUTHMARK7319\n")),
        _runtime_text("-----BEGIN ", "PRIVATE KEY-----\nPRIVATEKEYMARK7319\n"),
        "".join(("to", 'ken = get_secret("abc123")\n')),
        "".join(("to", 'ken = bytes.fromhex("616263313233")\n')),
    ]
    assert all(not public_executable_artifact_is_safe(source) for source in unsafe_samples)
    assert public_executable_artifact_is_safe(
        "".join(("to", 'ken = os.getenv("API_KEY")\n')), artifact_path="safe.py"
    )
    assert not public_executable_artifact_is_safe(
        "".join(("[auth]\nto", "ken = abc123\n")), artifact_path="config.ini"
    )
    assert not public_executable_artifact_is_safe(
        _runtime_text("export API_K", "EY=abc123\n"), artifact_path="script.sh"
    )


def test_safe_error_is_total_on_deeply_nested_json():
    from lab.runtime import redact, safe_error

    nested = "[" * 5_000 + '"ok"' + "]" * 5_000
    assert "ok" not in redact(nested)
    rendered = safe_error(nested, limit=2_000)
    assert "ok" not in rendered
    assert len(rendered) <= 2_000


def test_cli_json_status_handles_malformed_agentmemory_url(tmp_path):
    env = {
        **os.environ,
        "AGENTMEMORY_URL": "https://[",
        "ANTHROPIC_API_KEY": "".join(("configured-", "test-value")),
        "WEIPING_LAB_WORKSPACE_ROOT": str(tmp_path),
    }
    result = subprocess.run(
        [sys.executable, "-m", "cli.main", "status", "--json"],
        cwd=Path.cwd(),
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0
    payload = json.loads(result.stdout)
    assert payload["agentmemory"]["endpoint"] == ""


def test_diagnostics_strip_userinfo_from_all_endpoints(monkeypatch, tmp_path):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "configured-test-value")
    monkeypatch.setenv(
        "ANTHROPIC_BASE_URL",
        "".join(("https://", "provider-user:provider-pass@", "provider.example:9443/v1")),
    )
    monkeypatch.setenv(
        "AGENTMEMORY_URL",
        "".join(("https://", "memory-user:memory-pass@", "memory.example:3111/observations")),
    )
    monkeypatch.setenv("WEIPING_LAB_WORKSPACE_ROOT", str(tmp_path))

    from lab.core.config import LabConfig
    from lab.diagnostics import build_diagnostics

    diagnostics = build_diagnostics(LabConfig())
    rendered = json.dumps(diagnostics)
    for marker in ["provider-user", "provider-pass", "memory-user", "memory-pass"]:
        assert marker not in rendered
    assert diagnostics["models"][0]["endpoint_host"] == "provider.example:9443"
    assert diagnostics["agentmemory"]["endpoint"] == "memory.example:3111"


def test_missing_key_is_reported_without_old_fallbacks(monkeypatch, tmp_path):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.setenv("WEIPING_LAB_WORKSPACE_ROOT", str(tmp_path))

    from lab.core.config import LabConfig
    from lab.diagnostics import build_diagnostics

    diagnostics = build_diagnostics(LabConfig())
    assert diagnostics["ok"] is False
    assert any(check["name"] == "anthropic_api_key" for check in diagnostics["checks"])


def test_placeholder_key_is_not_configured(monkeypatch, tmp_path):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "<anthropic-api-key>")
    monkeypatch.setenv("WEIPING_LAB_WORKSPACE_ROOT", str(tmp_path))

    from lab.core.config import LabConfig
    from lab.diagnostics import build_diagnostics

    config = LabConfig()
    diagnostics = build_diagnostics(config)
    assert config.anthropic_key == ""
    assert diagnostics["ok"] is False
    assert diagnostics["models"][0]["api_key"] == "missing"


def test_weiping_lab_env_names_take_precedence(monkeypatch, tmp_path):
    legacy_root = tmp_path / "legacy"
    primary_root = tmp_path / "primary"
    monkeypatch.setenv("VIPIN_LAB_WORKSPACE_ROOT", str(legacy_root))
    monkeypatch.setenv("WEIPING_LAB_WORKSPACE_ROOT", str(primary_root))
    monkeypatch.setenv("VIPIN_LAB_ARCHITECT_MODEL", "legacy-architect")
    monkeypatch.setenv("WEIPING_LAB_ARCHITECT_MODEL", "primary-architect")

    from lab.core.config import LabConfig

    config = LabConfig()
    assert config.workspace_path() == primary_root.resolve()
    assert config.architect().id == "primary-architect"


def test_vipin_lab_env_names_remain_legacy_fallback(monkeypatch, tmp_path):
    monkeypatch.delenv("WEIPING_LAB_WORKSPACE_ROOT", raising=False)
    monkeypatch.delenv("WEIPING_LAB_ARCHITECT_MODEL", raising=False)
    monkeypatch.setenv("VIPIN_LAB_WORKSPACE_ROOT", str(tmp_path))
    monkeypatch.setenv("VIPIN_LAB_ARCHITECT_MODEL", "legacy-architect")

    from lab.core.config import LabConfig

    config = LabConfig()
    assert config.workspace_path() == tmp_path.resolve()
    assert config.architect().id == "legacy-architect"


def test_api_status_and_id_validation(monkeypatch, tmp_path):
    monkeypatch.setenv("ANTHROPIC_API_KEY", _runtime_text("sk-", "testsecret-1234567890"))
    monkeypatch.setenv("WEIPING_LAB_WORKSPACE_ROOT", str(tmp_path))

    from fastapi.testclient import TestClient

    import api.server as server
    from lab.core.config import LabConfig

    server._config = LabConfig()
    server._orchestrator = None
    client = TestClient(server.app)

    status = client.get("/api/status")
    assert status.status_code == 200
    assert status.json()["version"] == "1.6.0"
    health = client.get("/api/health")
    rendered_status = json.dumps({"status": status.json(), "health": health.json()})
    assert str(tmp_path) not in rendered_status
    assert "project_root" not in rendered_status
    assert "workspace_root" not in rendered_status
    assert "workspace_available" in health.json()

    bad = client.get("/api/sessions/bad!")
    assert bad.status_code == 400

    bad_pipeline = client.post("/api/pipeline/bad!")
    assert bad_pipeline.status_code == 400

    bad_resume = client.post("/api/resume/bad!")
    assert bad_resume.status_code == 400


def test_api_request_validation_never_echoes_rejected_input(monkeypatch, tmp_path):
    from fastapi.testclient import TestClient

    import api.server as server
    from lab.core.config import LabConfig

    marker = "REQUEST-VALIDATION-CREDENTIAL-MARKER"
    monkeypatch.setenv("WEIPING_LAB_WORKSPACE_ROOT", str(tmp_path))
    server._config = LabConfig()
    client = TestClient(server.app)
    responses = [
        client.post(
            "/api/discover",
            json={"domain": "Authorization: Bearer " + marker + "X" * 250},
        ),
        client.post(
            "/api/extend",
            json={"domain": "testing", "method": "Token " + marker + "X" * 20_100},
        ),
        client.post("/api/discover", json={"domain": {"secret_key": marker}}),
    ]

    assert all(response.status_code == 422 for response in responses)
    rendered = json.dumps([response.json() for response in responses])
    assert marker not in rendered
    assert "Authorization" not in rendered
    assert '"input"' not in rendered
    assert '"ctx"' not in rendered


def test_sse_projection_is_json_only_cycle_safe_and_never_stringifies_unknowns(monkeypatch):
    import api.server as server

    configured = "OPAQUE%41SSECONFIG_923741"
    normalized = "OPAQUEASSECONFIG_923741"
    marker = "SSE-GENERIC-MARKER-83071"
    monkeypatch.setenv("ANTHROPIC_API_KEY", configured)

    class SecretObject:
        stringified = False

        def __str__(self):
            self.stringified = True
            return marker

    secret_object = SecretObject()
    cycle = []
    cycle.append(cycle)
    payload = {
        "title": "normal research title",
        "configured": configured,
        "normalized": normalized,
        "tuple_value": (marker,),
        "set_value": {marker},
        "path_value": Path("D:" + "/Private") / marker,
        "object_value": secret_object,
        "bytes_value": marker.encode(),
        "infinite": float("inf"),
        "cycle": cycle,
        "Authorization: Bearer " + marker: "value",
        "token=" + marker: "value",
        "D:" + "\\Private\\" + marker: "value",
    }

    rendered = server.sse("done", payload)
    data = json.loads(
        next(
            line.removeprefix("data: ")
            for line in rendered.splitlines()
            if line.startswith("data: ")
        )
    )

    assert configured not in rendered
    assert normalized not in rendered
    assert marker not in rendered
    assert "NaN" not in rendered
    assert "Infinity" not in rendered
    assert secret_object.stringified is False
    assert data["title"] == "normal research title"
    assert data["infinite"] is None
    assert data["cycle"] == ["...redacted"]


def test_api_projection_preserves_research_kill_text_and_token_metrics():
    import api.server as server

    payload = {
        "kill_argument": "Token economy lacks causal identification",
        "kill_rebuttal": "Basic protein evidence addresses precision / recall",
        "token_count": 128,
        "input_tokens": 64,
        "token_entropy": 0.42,
    }

    assert server._public_payload(payload) == payload


def test_not_found_responses_do_not_echo_public_identifier(monkeypatch, tmp_path):
    from types import SimpleNamespace

    from fastapi.testclient import TestClient

    import api.server as server
    from lab.core.config import LabConfig
    from lab.workspace.manager import WorkspaceManager

    marker = "SYNTHETIC404MARKER83071"
    config = LabConfig(workspace_root=str(tmp_path))
    manager = WorkspaceManager(config)
    manager.setup()
    server._config = config
    server._orchestrator = SimpleNamespace(workspace=manager)
    client = TestClient(server.app)

    responses = [
        client.get(f"/api/ideas/{marker}"),
        client.get(f"/api/sessions/{marker}"),
    ]

    assert all(response.status_code == 404 for response in responses)
    assert marker not in json.dumps([response.json() for response in responses])


def test_api_idea_and_session_dtos_never_expose_absolute_workspace_paths(monkeypatch, tmp_path):
    from types import SimpleNamespace

    from fastapi.testclient import TestClient

    import api.server as server
    from lab.core.config import LabConfig
    from lab.core.models import Idea, IdeaOrigin
    from lab.workspace.manager import WorkspaceManager

    config = LabConfig()
    config.workspace_root = str(tmp_path)
    manager = WorkspaceManager(config)
    manager.setup()
    idea = Idea(
        id="publicidea",
        title="Public DTO",
        domain="testing",
        origin=IdeaOrigin.PHENOMENON,
        phenomenon="p",
        hypothesis="h",
        proposed_method="m",
        expected_contribution="c",
    )
    credential_marker = "PUBLIC-API-CREDENTIAL-MARKER"
    idea.metadata["provider_error"] = "Authorization: Bearer " + credential_marker
    manager.create_idea_workspace(idea)
    manager.save_idea(idea)
    session_dir = tmp_path / "publicsession"
    session_dir.mkdir()
    private_marker = str(tmp_path / "private-session-marker")
    (session_dir / "session.json").write_text(
        json.dumps(
            {
                "id": "publicsession",
                "mode": "discover",
                "domain": "Authorization: Bearer " + credential_marker,
                "ideas": [
                    {
                        "id": idea.id,
                        "workspace": idea.workspace_dir,
                        "title": idea.title,
                        "metadata": {"provider_message": credential_marker},
                    }
                ],
                "audit_trail": [
                    {
                        "step": "saved",
                        "message": "Authorization: Bearer " + credential_marker,
                        "detail": private_marker,
                    }
                ],
                "diag": "Authorization: Bearer " + credential_marker,
                "note": "Authorization: Bearer " + credential_marker,
                "details": "Authorization: Bearer " + credential_marker,
                "failure": "Authorization: Bearer " + credential_marker,
                "provider_message": "Authorization: Bearer " + credential_marker,
                "x": "Authorization: Bearer " + credential_marker,
            }
        ),
        encoding="utf-8",
    )

    server._config = config
    server._orchestrator = SimpleNamespace(workspace=manager)
    client = TestClient(server.app)
    responses = [
        client.get("/api/ideas"),
        client.get(f"/api/ideas/{idea.id}"),
        client.get("/api/sessions/publicsession"),
    ]
    rendered = json.dumps([response.json() for response in responses])

    assert all(response.status_code == 200 for response in responses)
    assert str(tmp_path) not in rendered
    assert private_marker not in rendered
    assert credential_marker not in rendered
    assert "workspace_dir" not in rendered
    assert '"workspace"' not in rendered
    assert "workspace_ref" in rendered
    for private_field in ("diag", "note", "details", "failure", "provider_message", "x"):
        assert f'"{private_field}"' not in rendered

    streamed = server._session_to_dict(
        SimpleNamespace(
            id="streamed",
            mode="discover",
            domain="testing",
            created_at="2026-01-01T00:00:00Z",
            phenomena=[],
            analogies=[],
            ideas=[],
            audit_trail=[{"error": "Authorization: Bearer " + credential_marker}],
        )
    )
    assert credential_marker not in json.dumps(streamed)

    public_sse = server.sse_done(
        {
            "title": "Authorization: Bearer " + credential_marker,
            "nested": [{"detail": "https://example.test/?token=" + credential_marker}],
        }
    )
    assert credential_marker not in public_sse


def test_cli_invalid_pipeline_ids_do_not_initialize_orchestrator(monkeypatch):
    from typer.testing import CliRunner

    import cli.main as main

    def fail_orchestrator():
        raise AssertionError("orchestrator should not be initialized for invalid IDs")

    monkeypatch.setattr(main, "get_orchestrator", fail_orchestrator)
    runner = CliRunner()

    pipeline = runner.invoke(main.app, ["pipeline", "bad!"])
    resume = runner.invoke(main.app, ["resume", "bad!"])

    assert pipeline.exit_code == 1
    assert resume.exit_code == 1
    assert "Invalid idea id" in pipeline.output
    assert "Invalid idea id" in resume.output


def test_cli_text_status_treats_placeholder_as_missing(monkeypatch, tmp_path):
    from typer.testing import CliRunner

    import cli.main as main

    monkeypatch.setenv("ANTHROPIC_API_KEY", "<anthropic-api-key>")
    monkeypatch.setenv("OPENAI_API_KEY", "")
    monkeypatch.setenv("SEMANTIC_SCHOLAR_API_KEY", "")
    monkeypatch.setenv("WEIPING_LAB_WORKSPACE_ROOT", str(tmp_path))

    result = CliRunner().invoke(main.app, ["status"])

    assert result.exit_code == 0
    assert "not set" in result.output
    assert "configured" not in result.output


def test_cli_text_status_never_prints_api_key_fragments(tmp_path):
    markers = {
        "ANTHROPIC_API_KEY": "".join(("QX7V2K9M-", "middle-R4T8")),
        "OPENAI_API_KEY": "".join(("JN6C3W8P-", "middle-H5Y2")),
        "SEMANTIC_SCHOLAR_API_KEY": "".join(("LK4D7S2F-", "middle-B9U6")),
    }
    env = {
        **os.environ,
        **markers,
        "WEIPING_LAB_WORKSPACE_ROOT": str(tmp_path),
    }

    result = subprocess.run(
        [sys.executable, "-m", "cli.main", "status"],
        cwd=Path.cwd(),
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0
    rendered = result.stdout + result.stderr
    assert "configured" in rendered
    for marker in markers.values():
        assert marker not in rendered
        assert marker[:8] not in rendered
        assert marker[-4:] not in rendered


def test_repl_invalid_pipeline_ids_do_not_initialize_orchestrator(monkeypatch, capsys):
    import asyncio

    from cli.repl import VlabREPL

    repl = VlabREPL()

    def fail_orchestrator():
        raise AssertionError("orchestrator should not be initialized for invalid IDs")

    monkeypatch.setattr(repl, "_get_orchestrator", fail_orchestrator)
    asyncio.run(repl._handle_pipeline({"arg1": "bad!"}))
    asyncio.run(repl._handle_resume({"arg1": "bad!"}))

    output = capsys.readouterr().out
    assert output.count("Invalid idea id") == 2


def test_repl_status_treats_placeholder_as_missing(monkeypatch, tmp_path, capsys):
    from cli.repl import VlabREPL

    monkeypatch.setenv("ANTHROPIC_API_KEY", "<anthropic-api-key>")
    monkeypatch.setenv("WEIPING_LAB_WORKSPACE_ROOT", str(tmp_path))

    VlabREPL()._handle_status()

    output = capsys.readouterr().out
    assert "not set" in output
    assert "anthropic-" not in output.lower()


def test_repl_status_never_prints_api_key_fragments(monkeypatch, tmp_path, capsys):
    from cli.repl import VlabREPL

    markers = {
        "ANTHROPIC_API_KEY": "".join(("PD8K3M7Q-", "middle-V4X9")),
        "OPENAI_API_KEY": "".join(("RC5T2N8J-", "middle-W6Z3")),
        "SEMANTIC_SCHOLAR_API_KEY": "".join(("HF9B4L6S-", "middle-Y7G2")),
    }
    for name, marker in markers.items():
        monkeypatch.setenv(name, marker)
    monkeypatch.setenv("WEIPING_LAB_WORKSPACE_ROOT", str(tmp_path))

    VlabREPL()._handle_status()

    captured = capsys.readouterr()
    rendered = captured.out + captured.err
    assert "configured" in rendered
    for marker in markers.values():
        assert marker not in rendered
        assert marker[:8] not in rendered
        assert marker[-4:] not in rendered


def test_agentmemory_outbox_is_local_and_safe(monkeypatch, tmp_path):
    monkeypatch.setenv("AGENTMEMORY_URL", "http://127.0.0.1:1")

    from lab.memory.store import LabMemory

    memory = LabMemory(str(tmp_path))
    fixture_value = _runtime_text("sk-", "testsecret-1234567890")
    assert memory.save_to_agentmemory({"session": "abc", "token": fixture_value})

    outbox = tmp_path / "agentmemory-outbox.jsonl"
    text = outbox.read_text(encoding="utf-8")
    assert fixture_value not in text
    assert "memory" + "\\sessions" not in text
    assert "memory" + "/sessions" not in text


def test_local_memory_records_are_sanitized_at_the_persistence_boundary(tmp_path):
    from lab.memory.store import IdeaRecord, LabMemory, PhenomenonRecord

    memory = LabMemory(str(tmp_path))
    credential_marker = "MEMORY-CREDENTIAL-MARKER"
    path_marker = "MEMORY-PATH-MARKER"
    query_marker = "MEMORY-QUERY-MARKER"
    memory.record_idea(
        IdeaRecord(
            idea_id="idea-safe",
            title="Authorization: Bearer " + credential_marker,
            domain="testing",
            origin="phenomenon",
            phenomenon="p",
            hypothesis="https://example.test/?token=" + query_marker,
            novelty_score=1.0,
            feasibility_score=1.0,
            final_status="killed",
            killed_at_phase="test",
            kill_reason="failed at D:" + "\\Temp\\" + path_marker,
        )
    )
    memory.record_phenomenon(
        PhenomenonRecord(
            phenomenon_id="phenomenon-safe",
            domain="testing",
            description="Authorization: Bearer " + credential_marker,
            severity=1.0,
            led_to_ideas=[],
            successful_ideas=[],
        )
    )
    memory.add_lesson(
        "testing",
        "Authorization: Bearer " + credential_marker,
        "failed at /" + "private-root/" + path_marker,
    )

    rendered = "\n".join(
        (tmp_path / name).read_text(encoding="utf-8")
        for name in ("ideas.json", "phenomena.json", "lessons.json")
    )
    for marker in (credential_marker, path_marker, query_marker):
        assert marker not in rendered


def test_agentmemory_5xx_writes_safe_outbox(monkeypatch, tmp_path):
    monkeypatch.setenv("AGENTMEMORY_URL", "http://agentmemory.test")

    class FakeResponse:
        status_code = 503

    class FakeClient:
        def __init__(self, *args, **kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return False

        async def post(self, *args, **kwargs):
            return FakeResponse()

    import httpx
    from lab.memory.store import LabMemory

    monkeypatch.setattr(httpx, "AsyncClient", FakeClient)
    memory = LabMemory(str(tmp_path))
    fixture_value = _runtime_text("sk-", "testsecret-1234567890")
    assert memory.save_to_agentmemory({"token": fixture_value})

    text = (tmp_path / "agentmemory-outbox.jsonl").read_text(encoding="utf-8")
    assert "HTTP 503" in text
    assert fixture_value not in text


def test_agentmemory_transport_and_outbox_scrub_configured_secret_variants(monkeypatch, tmp_path):
    configured = "OPAQUE%41MEMORYCONFIG_923741"
    normalized = "OPAQUEAMEMORYCONFIG_923741"
    captured = {}
    monkeypatch.setenv("ANTHROPIC_API_KEY", configured)
    monkeypatch.setenv("AGENTMEMORY_URL", "http://agentmemory.test")

    class FakeResponse:
        status_code = 201

    class FakeClient:
        def __init__(self, *args, **kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return False

        async def post(self, *args, **kwargs):
            captured.update(kwargs)
            return FakeResponse()

    import httpx
    from lab.memory.store import LabMemory

    monkeypatch.setattr(httpx, "AsyncClient", FakeClient)
    memory = LabMemory(str(tmp_path))
    summary = {"raw": configured, "normalized": normalized}

    assert memory.save_to_agentmemory(summary)
    rendered_transport = json.dumps(captured)
    assert configured not in rendered_transport
    assert normalized not in rendered_transport

    assert memory._write_agentmemory_outbox("http://agentmemory.test", "failure", summary)
    rendered_outbox = (tmp_path / "agentmemory-outbox.jsonl").read_text(encoding="utf-8")
    assert configured not in rendered_outbox
    assert normalized not in rendered_outbox


def test_agentmemory_outbox_strips_endpoint_credentials_and_redacts_all_fields(tmp_path):
    from lab.memory.store import LabMemory

    memory = LabMemory(str(tmp_path))
    url = "".join(
        (
            "https://",
            "memory-user:memory-pass@",
            "memory.example:3111/observations?token=query-marker",
        )
    )
    error = "".join((f"post failed at {url}; pass", "word=error-marker"))
    summary = {
        "authorization": "".join(("summary", "-marker")),
        "nested": {"token": "".join(("nested", "-marker"))},
    }

    assert memory._write_agentmemory_outbox(url, error, summary)
    payload = json.loads(
        (tmp_path / "agentmemory-outbox.jsonl").read_text(encoding="utf-8").splitlines()[0]
    )

    assert payload["agentmemory_endpoint"] == "memory.example:3111"
    rendered = json.dumps(payload)
    for marker in [
        "memory-user",
        "memory-pass",
        "query-marker",
        "error-marker",
        "summary-marker",
        "nested-marker",
    ]:
        assert marker not in rendered


def test_agentmemory_redaction_is_recursive_cycle_safe_and_fail_closed():
    from lab.memory.store import _redact_jsonish

    class PasswordObject:
        stringified = False

        def __str__(self):
            self.stringified = True
            return "password-object-marker"

    password_object = PasswordObject()
    cycle = {}
    cycle["self"] = cycle
    source = {
        "safe": (
            {"token": ["token-list-marker", {"nested": "token-nested-marker"}]},
            {
                "profile": [{"PASSWORD": password_object}],
                "auth_token": {
                    "primary": "token-object-primary-marker",
                    "backup": "token-object-backup-marker",
                },
            },
        ),
        "cycle": cycle,
        "message": 'Bearer "nested-bearer-marker"',
    }

    redacted = _redact_jsonish(source)
    rendered = json.dumps(redacted)

    assert password_object.stringified is False
    assert redacted["safe"][0]["token"] == "...redacted"
    assert redacted["safe"][1]["profile"][0]["PASSWORD"] == "...redacted"
    assert redacted["cycle"]["self"] == "...redacted"
    for marker in [
        "token-list-marker",
        "token-nested-marker",
        "token-object-primary-marker",
        "token-object-backup-marker",
        "password-object-marker",
        "nested-bearer-marker",
    ]:
        assert marker not in rendered


def test_agentmemory_redaction_rejects_unknown_sensitive_key_objects():
    from lab.memory.store import _redact_jsonish

    class SecretKey:
        def __str__(self):
            return "safe-looking-key"

    rendered = json.dumps(_redact_jsonish({SecretKey(): "object-key-marker"}))

    assert "object-key-marker" not in rendered


@pytest.mark.parametrize(
    "key",
    [
        "auth",
        "authentication",
        "auth_header",
        "authorization_header",
        "bearer",
        "cookie",
        "set-cookie",
        "passphrase",
        "pwd",
        "accessKeyId",
        "session_id",
        "secret_key",
        "secretKey",
        "session_key",
        "signing_key",
        "encryption_key",
        "ssh_key",
        "jwt",
        "ｔｏｋｅｎ",
    ],
)
def test_agentmemory_redaction_uses_complete_sensitive_key_vocabulary(key):
    from lab.memory.store import _redact_jsonish

    rendered = json.dumps(_redact_jsonish({key: "sensitive-key-marker"}))

    assert "sensitive-key-marker" not in rendered


def test_agentmemory_outbox_recursively_redacts_composite_summary(tmp_path):
    from lab.memory.store import LabMemory

    memory = LabMemory(str(tmp_path))
    cycle = {
        "token": [
            "".join(("cycle-token-one", "-marker")),
            "".join(("cycle-token-two", "-marker")),
        ],
    }
    cycle["self"] = cycle
    summary = {
        "token": [
            "".join(("outbox-token-one", "-marker")),
            "".join(("outbox-token-two", "-marker")),
        ],
        "password": {
            "primary": "outbox-password-one-marker",
            "backup": "outbox-password-two-marker",
        },
        "authorization": "".join(('Bearer "outbox-authorization', '-marker"')),
        "nested": {"api_key": "".join(("outbox-api-key", "-marker"))},
        "source": "free-user:free-pass@free.example/a?token=free-query-marker",
        "cycle": cycle,
    }

    assert memory._write_agentmemory_outbox("http://localhost:3111", "failure", summary)
    rendered = (tmp_path / "agentmemory-outbox.jsonl").read_text(encoding="utf-8")

    json.loads(rendered)
    for marker in [
        "outbox-token-one-marker",
        "outbox-token-two-marker",
        "outbox-password-one-marker",
        "outbox-password-two-marker",
        "outbox-authorization-marker",
        "outbox-api-key-marker",
        "free-user",
        "free-pass",
        "free-query-marker",
        "cycle-token-one-marker",
        "cycle-token-two-marker",
    ]:
        assert marker not in rendered


def test_agentmemory_outbox_redacts_private_paths_in_every_persisted_field(tmp_path):
    from lab.memory.store import LabMemory

    memory = LabMemory(str(tmp_path))
    error_path = "D:" + r"\Temp\outbox-error-marker"
    content_path = "C:" + r"\Users\operator\outbox-content-marker"
    path_value = Path("/" + "home/operator/outbox-path-marker")

    assert memory._write_agentmemory_outbox(
        "http://localhost:3111",
        f"failure at {error_path}",
        {"content_path": content_path, "path_value": path_value},
    )
    rendered = (tmp_path / "agentmemory-outbox.jsonl").read_text(encoding="utf-8")

    for marker in ("outbox-error-marker", "outbox-content-marker", "outbox-path-marker"):
        assert marker not in rendered
    assert rendered.count("...redacted-path") >= 3


def test_agentmemory_outbox_redacts_folded_authorization_fields(tmp_path):
    from lab.memory.store import LabMemory

    memory = LabMemory(str(tmp_path))
    summary = {
        "message": "".join(("Author", "ization: Bearer folded-one-marker\r\n folded-two-marker")),
        "digest": (
            "".join(("Author", 'ization: Digest username="user", response="digest-one-marker"'))
            + "\r\n "
            'nonce="digest-two-marker"'
        ),
    }

    assert memory._write_agentmemory_outbox("http://localhost:3111", "failure", summary)
    rendered = (tmp_path / "agentmemory-outbox.jsonl").read_text(encoding="utf-8")

    for marker in (
        "folded-one-marker",
        "folded-two-marker",
        "digest-one-marker",
        "digest-two-marker",
    ):
        assert marker not in rendered


def test_tool_registry_redacts_unhandled_tool_errors(tmp_path):
    from lab.tools.registry import ToolRegistry

    registry = ToolRegistry(workspace_dir=str(tmp_path))

    async def explode(_args):
        raise RuntimeError(
            "".join(
                (
                    "failure at ",
                    "https://",
                    "tool-user:tool-pass@",
                    "tool.example/v1?to",
                    "ken=tool-marker",
                )
            )
        )

    registry.register("explode", explode)
    result = asyncio.run(registry.call("explode", {}))

    assert result.success is False
    for marker in ["tool-user", "tool-pass", "tool-marker"]:
        assert marker not in result.error


def test_tool_registry_denies_secret_files_and_sanitizes_success_outputs(monkeypatch, tmp_path):
    from lab.tools.registry import ToolRegistry, ToolResult

    fixture_value = "ToolSecret_Z9v-7319"
    monkeypatch.setenv("SYNTH_API_KEY", fixture_value)
    (tmp_path / ".env").write_text("SYNTH_API_KEY=" + fixture_value, encoding="utf-8")
    (tmp_path / "research.txt").write_text(
        "Token economy research\nsecret=" + fixture_value,
        encoding="utf-8",
    )
    fixture_material = _runtime_text(
        "-----BEGIN ",
        "OPENSSH PRIVATE KEY-----\nPRIVATE-MATERIAL-MARKER\n-----END ",
        "OPENSSH PRIVATE KEY-----",
    )
    for filename in (
        "id_rsa.bak",
        "credentials.backup",
        "private.pem.txt",
        ".pgpass",
        ".htpasswd",
        ".vault-token",
        ".envrc",
    ):
        (tmp_path / filename).write_text(fixture_material, encoding="utf-8")
    (tmp_path / "ordinary-research.txt").write_text(fixture_material, encoding="utf-8")
    private_variants = [
        "-----BEGIN " + label + "-----\nPRIVATE-MATERIAL-MARKER\n-----END " + label + "-----"
        for label in (
            "ENCRYPTED " + "PRIVATE KEY",
            "DSA " + "PRIVATE KEY",
            "PGP " + "PRIVATE KEY BLOCK",
        )
    ]
    private_variants.append(
        "PuTTY-"
        + "User-Key-File-2: ssh-rsa\nEncryption: none\nPrivate-Lines: 1\nPRIVATE-MATERIAL-MARKER"
    )
    for index, material in enumerate(private_variants):
        (tmp_path / f"key_backup_{index}.txt").write_text(material, encoding="utf-8")
    registry = ToolRegistry(workspace_dir=str(tmp_path))

    async def custom(_args):
        return ToolResult(tool="custom", success=True, output="result=" + fixture_value)

    registry.register("custom", custom)
    denied = asyncio.run(registry.call("file_read", {"path": ".env"}))
    research = asyncio.run(registry.call("file_read", {"path": "research.txt"}))
    custom_result = asyncio.run(registry.call("custom", {}))
    private_results = [
        asyncio.run(registry.call("file_read", {"path": filename}))
        for filename in (
            "id_rsa.bak",
            "credentials.backup",
            "private.pem.txt",
            ".pgpass",
            ".htpasswd",
            ".vault-token",
            ".envrc",
            "ordinary-research.txt",
            *(f"key_backup_{index}.txt" for index in range(len(private_variants))),
        )
    ]

    assert denied.success is False
    assert denied.output == ""
    assert "Token economy research" in research.output
    assert fixture_value not in research.output
    assert fixture_value not in custom_result.output
    assert all(not result.success and result.output == "" for result in private_results)
    assert all("PRIVATE-MATERIAL-MARKER" not in result.error for result in private_results)

    code = "".join(
        ("def f(text):\n    to", "ken = text.split()[0]\n    auth = token\n    return auth\n")
    )
    code_result = asyncio.run(registry.call("file_write", {"path": "runner.py", "content": code}))
    rejected_code = asyncio.run(
        registry.call(
            "file_write",
            {"path": "unsafe.py", "content": 'value = "' + fixture_value + '"\n'},
        )
    )
    assert code_result.success is True
    assert (tmp_path / "runner.py").read_text(encoding="utf-8") == code
    assert rejected_code.success is False
    assert not (tmp_path / "unsafe.py").exists()


def test_tool_registry_never_rewrites_extensionless_or_named_executable_artifacts(tmp_path):
    from lab.tools.registry import ToolRegistry

    registry = ToolRegistry(workspace_dir=str(tmp_path))
    samples = {
        "Dockerfile": "FROM python:3.12\nRUN /usr/bin/python3 -V\n",
        "CMakeLists.txt": 'set(PYTHON "/usr/bin/python3")\n',
        "run": "#!/usr/bin/env bash\nexec /usr/bin/python3 app.py\n",
    }
    for path, content in samples.items():
        result = asyncio.run(registry.call("file_write", {"path": path, "content": content}))
        assert result.success is True
        assert (tmp_path / path).read_text(encoding="utf-8") == content

    rejected = {
        "config.ini": "".join(("[auth]\nto", "ken = abc123\n")),
        "script.sh": _runtime_text("export API_K", "EY=abc123\n"),
        "unsafe.py": "".join(("to", 'ken = get_secret("abc123")\n')),
    }
    for path, content in rejected.items():
        result = asyncio.run(registry.call("file_write", {"path": path, "content": content}))
        assert result.success is False
        assert not (tmp_path / path).exists()


def test_tool_registry_does_not_echo_unknown_tool_or_file_path_inputs(tmp_path):
    from lab.tools.registry import ToolRegistry, ToolResult

    registry = ToolRegistry(workspace_dir=str(tmp_path))
    unknown = asyncio.run(registry.call('Bearer "unknown-tool-marker"', {}))
    escaped = asyncio.run(
        registry.call(
            "file_read", {"path": _runtime_text("../passw", "ord=escaped-path-marker.txt")}
        )
    )
    missing = asyncio.run(
        registry.call("file_read", {"path": _runtime_text("to", "ken=missing-path-marker.txt")})
    )
    malformed = asyncio.run(
        registry.call(
            "file_read",
            {"path": _runtime_text("passw", "ord=malformed-path-marker", "\x00.txt")},
        )
    )

    async def returned_error(_args):
        return ToolResult(
            tool="returned_error",
            success=False,
            output="",
            error="".join(("to", "ken=returned-tool-error-marker")),
        )

    registry.register("returned_error", returned_error)
    returned = asyncio.run(registry.call("returned_error", {}))

    async def returned_unsafe_fields(_args):
        return ToolResult(
            tool="".join(("to", "ken=returned-tool-name-marker")),
            success=False,
            output="".join(("to", "ken=returned-tool-output-marker")),
            error="safe failure",
        )

    registry.register("unsafe_fields", returned_unsafe_fields)
    unsafe_fields = asyncio.run(registry.call("unsafe_fields", {}))

    assert unknown.tool == "unknown"
    assert "unknown-tool-marker" not in unknown.error
    assert "escaped-path-marker" not in escaped.error
    assert "missing-path-marker" not in missing.error
    assert "malformed-path-marker" not in malformed.error
    assert "returned-tool-error-marker" not in returned.error
    assert unsafe_fields.tool == "unsafe_fields"
    assert unsafe_fields.output == ""
    assert "returned-tool-name-marker" not in json.dumps(vars(unsafe_fields))
    assert "returned-tool-output-marker" not in json.dumps(vars(unsafe_fields))


def test_tool_registry_rejects_non_public_names_and_result_subclasses(tmp_path):
    from lab.tools.registry import ToolRegistry, ToolResult

    registry = ToolRegistry(workspace_dir=str(tmp_path))

    async def valid(_args):
        return ToolResult(tool="ignored", success=True, output="ok")

    with pytest.raises(ValueError, match="public identifier"):
        registry.register('Bearer "registered-name-marker"', valid)

    class DerivedResult(ToolResult):
        pass

    async def derived(_args):
        return DerivedResult(tool="derived", success=True, output="subclass-marker")

    registry.register("derived", derived)
    result = asyncio.run(registry.call("derived", {}))

    assert result.success is False
    assert result.output == ""
    assert result.tool == "derived"


def test_tool_registry_redacts_dynamic_descriptions(tmp_path):
    from lab.tools.registry import ToolRegistry, ToolResult

    registry = ToolRegistry(workspace_dir=str(tmp_path))

    async def described(_args):
        """Bearer description-secret-marker"""
        return ToolResult(tool="described", success=True, output="ok")

    registry.register("described", described)
    rendered = json.dumps(registry.list_tools())

    assert "description-secret-marker" not in rendered


def test_cli_and_persisted_pipeline_errors_use_the_shared_safe_formatter():
    repl_source = (Path.cwd() / "cli" / "repl.py").read_text(encoding="utf-8")
    main_source = (Path.cwd() / "cli" / "main.py").read_text(encoding="utf-8")
    orchestrator_source = (Path.cwd() / "lab" / "core" / "orchestrator.py").read_text(
        encoding="utf-8"
    )

    assert "safe_error(e)" in repl_source
    assert "safe_error(e)" in main_source
    assert 'idea.metadata["killed_reason"] = safe_error(e)' in orchestrator_source


def test_sensitive_key_decoding_fails_closed_after_nested_percent_encoding():
    from lab.runtime import is_sensitive_key

    assert is_sensitive_key("%25252574oken") is True


@pytest.mark.parametrize(
    "name",
    [
        "AZURE_OPENAI_KEY",
        "OPENAI_KEY",
        "GITHUB_PAT",
        "GITLAB_PAT",
        "KAGGLE_KEY",
        "STRIPE_KEY",
        "SLACK_WEBHOOK_URL",
        "SENTRY_DSN",
    ],
)
def test_environment_secret_classifier_covers_common_credential_names(name, monkeypatch):
    from lab.runtime import is_sensitive_env_key, redact_public_text

    value = "EnvSecret_Z9v-7319_" + name
    monkeypatch.setenv(name, value)

    assert is_sensitive_env_key(name) is True
    assert value not in redact_public_text("probe " + value)


@pytest.mark.parametrize(
    "name",
    [
        "OPENAI_API_KEY",
        "WEIPING_LAB_ARCHITECT_API_KEY",
        "DB_PASSWORD",
        "AWS_SECRET_ACCESS_KEY",
        "SLACK_WEBHOOK_URL",
        "SENTRY_DSN",
        "REDIS_URL",
        "DATABASE_URL",
        "SESSION_TOKEN",
        "GITHUB_PAT",
        "webhookUrl",
        "connectionString",
        "slackWebhookUrl",
        "dbConnectionString",
        "sentryDsn",
        "serviceDsn",
        "myGithubPat",
        "serviceCookieValue",
        "providerAuthorizationValue",
        "SECRET_KEY_BASE",
        "DOCKER_AUTH_CONFIG",
        "AUTH_CONFIG",
        "TOKEN_FILE",
        "SECRET_KEY_FILE",
    ],
)
def test_prefixed_sensitive_assignments_are_sanitized_and_rejected(name):
    from lab.runtime import (
        public_executable_artifact_is_safe,
        redact,
        redact_public_text,
        safe_error,
    )

    marker = "RUNTIME-CREDENTIAL-" + "MARKER-7319"
    probes = [
        name + "=" + marker,
        '"' + name + '" = "' + marker + '"',
        "'" + name + "': '" + marker + "'",
        r"{\"" + name + r"\":\"" + marker + r"\"}",
        name + "%3" + "\u200b" + "D" + marker,
        name + "\\u003d" + marker,
        name + "\\075" + marker,
    ]

    for probe in probes:
        assert marker not in redact(probe)
        assert marker not in redact_public_text(probe)
        assert marker not in safe_error(probe)
        assert not public_executable_artifact_is_safe(probe, artifact_path="config.ini")

    python_probe = 'payload = "{\\"' + name + '\\":\\"' + marker + '\\"}"'
    compile(python_probe, "probe.py", "exec")
    assert not public_executable_artifact_is_safe(python_probe, artifact_path="probe.py")

    octal_python_probe = 'payload = "' + name + "\\075" + marker + '"'
    compile(octal_python_probe, "probe.py", "exec")
    assert not public_executable_artifact_is_safe(octal_python_probe, artifact_path="probe.py")


def test_python_static_credentials_include_subscript_and_concatenated_assignments():
    from lab.runtime import public_executable_artifact_is_safe, redact_public_artifact

    fixture_name = "OPENAI_API_K" + "EY"
    database_name = "DB_PASS" + "WORD"
    header_name = "X-API-" + "Key"
    fixture_value = "opaque_F9k3Lm7Q2xW8v6N4p2Q7"
    sources = [
        f'{fixture_name} = "opaque_" + "F9k3Lm7Q2xW8v6N4p2Q7"',
        f'os.environ["{fixture_name}"] = "{fixture_value}"',
        f'headers["{header_name}"] = "{fixture_value}"',
        f'config["{database_name}"] = "{fixture_value}"',
        f'settings = {{"{fixture_name}": "{fixture_value}"}}',
        f'header = "Author" + "ization: Bearer {fixture_value}"',
        f'os.putenv("{fixture_name}", "{fixture_value}")',
        f'os.environ.setdefault("{fixture_name}", "{fixture_value}")',
        f'config.set("{database_name}", "{fixture_value}")',
        f'set_key(".env", "{fixture_name}", "{fixture_value}")',
        "putenv(k" + f'ey="{fixture_name}", value="{fixture_value}")',
        f'config.set(option="{database_name}", value="{fixture_value}")',
        f'dotenv.set_key(dotenv_path=".env", key_to_set="{fixture_name}", '
        f'value_to_set="{fixture_value}")',
        f"import os\nwriter = os.putenv\ndef shadow():\n    writer = print\n"
        f'writer("{fixture_name}", "{fixture_value}")',
        f"import os\nwriter = os.putenv\nif False:\n    writer = print\n"
        f'writer("{fixture_name}", "{fixture_value}")',
        f'import os\nwriter = helper = os.putenv\nwriter("{fixture_name}", "{fixture_value}")',
    ]

    for source in sources:
        compile(source, "probe.py", "exec")
        assert not public_executable_artifact_is_safe(source, artifact_path="probe.py")
        assert fixture_value not in redact_public_artifact(source)


def test_python_static_high_risk_tokens_fail_closed_in_public_artifacts():
    from lab.runtime import public_executable_artifact_is_safe, redact_public_artifact

    prefixes = ("g" + "hp_", "h" + "f_", "n" + "pm_", "s" + "k-")
    tail = "A" * 32
    for prefix in prefixes:
        sources = [
            f'message = "{prefix}" + "{tail}"\n',
            f'def reveal():\n    return "{prefix}" + "{tail}"\n',
            f'matched = candidate == "{prefix}" + "{tail}"\n',
            f'def f(value="{prefix}" + "{tail}"):\n    return value\n',
            f'message = "".join(("{prefix[:2]}", "{prefix[2:]}", "{tail}"))\n',
            f"message = f'{prefix}{{\"{tail}\"}}'\n",
        ]
        for source in sources:
            assert not public_executable_artifact_is_safe(source, artifact_path="probe.py")
            assert tail not in redact_public_artifact(source)


def test_python_generic_key_semantics_avoid_false_positives_without_allowing_credentials():
    from lab.runtime import public_executable_artifact_is_safe

    safe_sources = [
        "".join(("lookup(k", 'ey="customer_id")')),
        "".join(('metadata = {"k', 'ey": "display_name"}')),
        "".join(("k", 'ey = "primary_label"')),
        "".join(("k", 'ey = "name"')),
        "".join(("lookup(k", 'ey="type")')),
        "".join(("k", 'ey = "customer-id"')),
        "".join(("k", 'ey = "customerId"')),
    ]
    unsafe_names = ("pass" + "word", "sec" + "ret", "to" + "ken", "k" + "ey", "au" + "th")
    unsafe_sources = [f'{name}="abcd1234"' for name in unsafe_names]
    alphabetic_entropy = "qmvxcpzrtnshdfwkabeg"
    generic_name = "k" + "ey"
    unsafe_sources.extend(
        (
            f'{generic_name}="{alphabetic_entropy}_id"',
            f'data={{"{generic_name}": "{alphabetic_entropy}_label"}}',
        )
    )

    assert all(
        public_executable_artifact_is_safe(source, artifact_path="probe.py")
        for source in safe_sources
    )
    assert all(
        not public_executable_artifact_is_safe(source, artifact_path="probe.py")
        for source in unsafe_sources
    )


def test_private_network_endpoints_are_rejected_and_sanitized_from_public_surfaces():
    from lab.runtime import (
        public_executable_artifact_is_safe,
        redact_public_artifact,
        redact_public_text,
        safe_error,
    )

    endpoints = [
        "".join(("http://", "192.", "168.10.25:8080/private")),
        "".join(("https://", "service.", "internal:8443/path")),
        "".join(("https://[", "fd", "12:3456::1]:8443/path")),
        "".join(("https://[", "fe", "80::1]:8443/path")),
    ]
    for endpoint in endpoints:
        source = f'endpoint = "{endpoint}"'
        assert not public_executable_artifact_is_safe(source, artifact_path="probe.py")
        for sanitizer in (redact_public_artifact, redact_public_text, safe_error):
            assert endpoint not in sanitizer(endpoint)


def test_multiline_configured_credentials_fail_closed_in_public_artifacts():
    from lab.runtime import (
        public_executable_artifact_is_safe,
        redact,
        redact_public_artifact,
        redact_public_text,
        safe_error,
    )

    marker = "MULTILINE-CREDENTIAL-MARKER-7319"
    probes = [
        "".join(("OPENAI_API_", "KEY=\n", marker)),
        "".join(("OPENAI_API_", "KEY=\n  ", marker)),
        "".join(("OPENAI_API_", "KEY: |\n  ", marker)),
        "".join(("OPENAI_API_", 'KEY="abc\n', marker, '"')),
    ]

    for probe in probes:
        for sanitizer in (redact, redact_public_text, redact_public_artifact, safe_error):
            assert marker not in sanitizer(probe)
        assert not public_executable_artifact_is_safe(probe, artifact_path="config.ini")


def test_generated_structured_credentials_fail_closed_across_public_surfaces():
    from lab.runtime import (
        public_executable_artifact_is_safe,
        redact,
        redact_public_artifact,
        redact_public_text,
        safe_error,
    )

    fixture_name = "OPENAI_API_K" + "EY"
    header_name = "x-api-" + "key"
    fixture_value = "opaque_" + "F9k3Lm7Q2xW8v6N4p2Q7"
    tick = chr(96)
    generic_field = _runtime_text("to", "ken")
    generated = [
        (f'Set-Item -Path Env:{fixture_name} -Value "{fixture_value}"', "probe.ps1"),
        (
            f'Set-Item -LiteralPath Env:{fixture_name} -Value "{fixture_value}"',
            "probe.ps1",
        ),
        (f'Set-Item -Value "{fixture_value}" -Path Env:{fixture_name}', "probe.ps1"),
        (
            f'Set-Item -Path Env:{fixture_name} {tick}\n  -Value "{fixture_value}"',
            "probe.ps1",
        ),
        (
            f'[Environment]::SetEnvironmentVariable(\n  "{fixture_name}",\n'
            f'  "{fixture_value}",\n  "Process"\n)',
            "probe.ps1",
        ),
        (f"$env:{fixture_name} = @'\n{fixture_value}\n'@", "probe.ps1"),
        (f'$env:{fixture_name} = @"\n{fixture_value}\n"@', "probe.ps1"),
        (f"${{env:{fixture_name}}} = @'\n{fixture_value}\n'@", "probe.ps1"),
        (
            f"[Environment]::SetEnvironmentVariable('{fixture_name}', "
            f"@'\n{fixture_value}\n'@, 'Process')",
            "probe.ps1",
        ),
        (
            f'[Environment]::SetEnvironmentVariable("{fixture_name}", '
            f'"{fixture_value[:2]}" + "{fixture_value[2:]}", "Process")',
            "probe.ps1",
        ),
        (f"ENV {fixture_name} {fixture_value}", "Dockerfile"),
        (f'process.env["{fixture_name}"] = "{fixture_value}";', "probe.js"),
        (f'headers["{header_name}"] = "{fixture_value}";', "probe.js"),
        (f"headers.authorization = {tick}{fixture_value}{tick};", "probe.js"),
        (f'os.Setenv("{fixture_name}", {tick}{fixture_value}{tick})', "probe.go"),
        (f'- name: "{fixture_name}"\n  value: "{fixture_value}"', "probe.yaml"),
        (
            f"- name: {fixture_name}\n  # fixture comment\n\n  value: {fixture_value}",
            "probe.yaml",
        ),
        (
            f"- value: {fixture_value}\n  # fixture comment\n\n  name: {fixture_name}",
            "probe.yaml",
        ),
        (f"- {{name: {fixture_name}, value: {fixture_value}}}", "probe.yaml"),
        (f"- {{value: {fixture_value}, name: {fixture_name}}}", "probe.yaml"),
        (f'- "name": {fixture_name}\n  "value": {fixture_value}', "probe.yaml"),
        (f"- 'value': {fixture_value}\n  'name': {fixture_name}", "probe.yaml"),
        (f'{{"safe":"x","{generic_field}":"{fixture_value}"}}', "probe.json"),
        (f'config: {{ {generic_field}: "{fixture_value}" }}', "probe.yaml"),
        (f"export {fixture_name}={fixture_value}", "probe.sh"),
        (f'<add name="{fixture_name}" value="{fixture_value}" />', "probe.config"),
        ("<add value=" + f'"{fixture_value}" k' + f'ey="{fixture_name}" />', "probe.config"),
    ]
    for source, artifact_path in generated:
        assert not public_executable_artifact_is_safe(source, artifact_path=artifact_path)
        for sanitizer in (redact, redact_public_text, redact_public_artifact, safe_error):
            assert fixture_value not in sanitizer(source)


def test_python_static_setter_aliases_fail_closed_across_public_surfaces():
    from lab.runtime import (
        public_executable_artifact_is_safe,
        redact,
        redact_public_artifact,
        redact_public_text,
        safe_error,
    )

    fixture_name = "OPENAI_API_K" + "EY"
    fixture_value = "opaque_" + "F9k3Lm7Q2xW8v6N4p2Q7"
    sources = [
        f'import os as runtime_os\nsetter = runtime_os.putenv\nsetter("{fixture_name}", "{fixture_value}")',
        f'import os\nsetter = os.putenv\nsetter("{fixture_name}", '
        f'"{fixture_value}")\nsetter = print',
        f"import os\nsetter = os.putenv\ndef shadow():\n    setter = print\n"
        f'setter("{fixture_name}", "{fixture_value}")',
        f"import os\nsetter = os.putenv\nif False:\n    setter = print\n"
        f'setter("{fixture_name}", "{fixture_value}")',
        f'import os\nsetter = helper = os.putenv\nsetter("{fixture_name}", "{fixture_value}")',
        f'from os import putenv as setter\nsetter("{fixture_name}", "{fixture_value}")',
        f'from dotenv import set_key as setter\nsetter(".env", "{fixture_name}", "{fixture_value}")',
        f'setter = config.set\nsetter("{fixture_name}", "{fixture_value}")',
    ]
    for source in sources:
        compile(source, "probe.py", "exec")
        assert not public_executable_artifact_is_safe(source, artifact_path="probe.py")
        for sanitizer in (redact, redact_public_text, redact_public_artifact, safe_error):
            assert fixture_value not in sanitizer(source)


def test_dynamic_docker_and_k8s_secret_references_remain_public_safe():
    from lab.runtime import (
        public_executable_artifact_is_safe,
        redact_public_artifact,
        redact_public_text,
    )

    fixture_name = "OPENAI_API_K" + "EY"
    source_name = "SOURCE_K" + "EY"
    docker_sources = [
        f"ENV {fixture_name} ${{{source_name}:-fallback}}",
        f"ENV {fixture_name} ${{{source_name}:-}}",
    ]
    for source in docker_sources:
        assert public_executable_artifact_is_safe(source, artifact_path="Dockerfile")
        assert redact_public_text(source) == source
        assert redact_public_artifact(source) == source

    powershell_references = [
        f"${{env:{fixture_name}}} = ${{env:{source_name}}}",
        f"Set-Item -Path Env:{fixture_name} -Value ${{env:{source_name}}}",
        f'[Environment]::SetEnvironmentVariable("{fixture_name}",'
        f' "${{env:{source_name}}}", "Process")',
    ]
    for source in powershell_references:
        assert public_executable_artifact_is_safe(source, artifact_path="probe.ps1")
        assert redact_public_text(source) == source
        assert redact_public_artifact(source) == source

    yaml_references = [
        f"- {{name: {fixture_name}, value: ${{{source_name}}}}}",
        f'- "name": {fixture_name}\n  "value": ${{{source_name}}}',
    ]
    for source in yaml_references:
        assert public_executable_artifact_is_safe(source, artifact_path="probe.yaml")
        rendered = redact_public_text(source)
        assert f"${{{source_name}}}" in rendered
        assert "...redacted" not in rendered
        assert redact_public_artifact(source) == source

    k8s_reference = _runtime_text(
        f"- name: {fixture_name}\n  valueFrom:\n    secretKeyRef:\n      name: provider\n",
        "      k",
        "ey: provider\n",
    )
    assert public_executable_artifact_is_safe(k8s_reference, artifact_path="probe.yaml")
    assert "...redacted" not in redact_public_text(k8s_reference)
    assert redact_public_artifact(k8s_reference) == k8s_reference


def test_query_redaction_preserves_markdown_closing_delimiter_and_trailing_finding():
    from lab.runtime import redact, redact_public_artifact, redact_public_text, safe_error

    marker = "QUERY-CREDENTIAL-" + "MARKER-7319"
    source = f"[details](https://example.test/path?token={marker}) trailing finding"
    for sanitizer in (redact, redact_public_text, redact_public_artifact, safe_error):
        rendered = sanitizer(source)
        assert marker not in rendered
        assert rendered.endswith(") trailing finding")


@pytest.mark.parametrize(
    "key",
    [
        "token_count",
        "token_budget",
        "token_length",
        "tokenization_method",
        "tokenomics_score",
        "tokens_per_second",
        "num_tokens",
        "input_tokens",
        "output_tokens",
        "prompt_tokens",
        "completion_tokens",
        "token_accuracy",
        "token_entropy",
        "tokenizer",
        "token_pruning_rate",
        "passwordless_auth_method",
        "credentialing_strategy",
        "api_key_rotation",
    ],
)
def test_sensitive_key_classifier_preserves_research_and_governance_metrics(key):
    from lab.runtime import is_sensitive_key

    assert is_sensitive_key(key) is False


@pytest.mark.parametrize(
    "key",
    [
        "token",
        "access_token",
        "refresh_token",
        "access_tokens",
        "refresh_tokens",
        "api_tokens",
        "token_value",
        "client_secret_value",
        "secret_value",
        "password",
        "credential",
        "api_key",
        "session_cookie",
        "auth_cookie",
        "csrf_cookie",
        "cookie_value",
        "authorization_code",
        "authorization_value",
        "code_verifier",
        "jwt_value",
        "bearer_value",
        "github_pat",
        "gitlab_pat",
        "client_key",
        "consumer_key",
        "subscription_key",
        "app_key",
        "jsessionid",
    ],
)
def test_sensitive_key_classifier_still_masks_credential_fields(key):
    from lab.runtime import is_sensitive_key

    assert is_sensitive_key(key) is True


def test_cli_missing_key_error_is_safe_under_strict_gbk(tmp_path):
    env = {
        **os.environ,
        "ANTHROPIC_API_KEY": "",
        "PYTHONIOENCODING": "gbk:strict",
        "WEIPING_LAB_WORKSPACE_ROOT": str(tmp_path),
    }
    result = subprocess.run(
        [sys.executable, "-m", "cli.main", "ideas"],
        cwd=Path.cwd(),
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=False,
        check=False,
    )
    output = result.stdout.decode("gbk", errors="strict")

    assert result.returncode == 1
    assert "ANTHROPIC_API_KEY not set" in output
    assert "UnicodeEncodeError" not in output
    assert "Traceback" not in output


def test_release_scan_includes_lab_workspace_source():
    from scripts.release_scan import _iter_text_files

    files = {path.as_posix() for path in _iter_text_files()}
    assert any(path.endswith("lab/workspace/manager.py") for path in files)


@pytest.mark.parametrize(
    "payload",
    [
        ("sk-" + "or-v1-" + "A" * 32).encode(),
        ("gh" + "p_" + "B" * 24).encode("utf-16-le"),
        ("github_" + "pat_11" + "C" * 76).encode(),
        ("D:" + r"\Temp\operator-private").encode("utf-16-le"),
    ],
)
def test_release_scan_rejects_secret_and_path_mutations_without_echoing_values(
    payload, monkeypatch
):
    import scripts.release_scan as release_scan

    monkeypatch.setattr(
        release_scan,
        "_read_release_snapshots",
        lambda: {
            "index": {Path("leak.txt"): payload},
            "worktree": {Path("leak.txt"): payload},
        },
    )
    monkeypatch.setattr(release_scan, "_working_tree_matches_index", lambda: True)
    failures = []

    release_scan._check_forbidden_text(failures)

    assert failures
    rendered = "\n".join(failures)
    assert "AAAA" not in rendered
    assert "BBBB" not in rendered
    assert "CCCC" not in rendered
    assert "operator-private" not in rendered


def test_release_scan_rejects_force_tracked_generated_paths(monkeypatch):
    import scripts.release_scan as release_scan

    monkeypatch.setattr(
        release_scan,
        "_read_release_snapshots",
        lambda: {
            "index": {Path("Dist/leak.txt"): b"public"},
            "worktree": {Path("Dist/leak.txt"): b"public"},
        },
    )
    monkeypatch.setattr(release_scan, "_working_tree_matches_index", lambda: True)
    failures = []

    release_scan._check_forbidden_text(failures)

    assert any("tracked generated/private path" in item for item in failures)


def test_release_scan_fails_if_tracked_sources_change_mid_scan(monkeypatch):
    import scripts.release_scan as release_scan

    snapshots = iter(
        [
            {
                "index": {Path("public.txt"): b"public"},
                "worktree": {Path("public.txt"): b"public"},
            },
            {
                "index": {Path("public.txt"): b"changed"},
                "worktree": {Path("public.txt"): b"changed"},
            },
        ]
    )
    monkeypatch.setattr(
        release_scan,
        "_read_release_snapshots",
        lambda: next(snapshots),
    )
    monkeypatch.setattr(release_scan, "_working_tree_matches_index", lambda: True)
    failures = []

    release_scan._check_forbidden_text(failures)

    assert "tracked sources changed during release scan" in failures


def test_release_scan_main_rechecks_sources_after_every_gate(monkeypatch, capsys):
    import scripts.release_scan as release_scan

    snapshots = iter(
        [
            {
                "index": {Path("public.txt"): b"before"},
                "worktree": {Path("public.txt"): b"before"},
            },
            {
                "index": {Path("public.txt"): b"after"},
                "worktree": {Path("public.txt"): b"after"},
            },
        ]
    )
    monkeypatch.setattr(release_scan, "_read_release_snapshots", lambda: next(snapshots))
    monkeypatch.setattr(release_scan, "_working_tree_matches_index", lambda: True)
    monkeypatch.setattr(release_scan, "_index_flags_are_safe", lambda: True)
    for name in (
        "_check_forbidden_text",
        "_check_version_consistency",
        "_check_workspace_source_tracked",
        "_check_env_example",
        "_check_package_lock",
        "_check_ruff_policy",
        "_check_evidence_contract",
        "_check_windows_gate",
        "_check_critical_gate_files",
        "_check_ci_contract",
    ):
        monkeypatch.setattr(release_scan, name, lambda failures: None)

    assert release_scan.main() == 1
    assert "changed during the complete release gate" in capsys.readouterr().out


def test_release_scan_reads_staged_index_even_when_worktree_is_safe(tmp_path, monkeypatch):
    import scripts.release_scan as release_scan

    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    candidate = tmp_path / ".env.example"
    candidate.write_text("SAFE=value\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(tmp_path), "add", ".env.example"], check=True)
    candidate.write_text("TOKEN=" + "sk-" + "or-v1-" + "Z" * 32, encoding="utf-8")
    subprocess.run(["git", "-C", str(tmp_path), "add", ".env.example"], check=True)
    candidate.write_text("SAFE=value\n", encoding="utf-8")
    monkeypatch.setattr(release_scan, "ROOT", tmp_path)
    failures = []

    release_scan._check_forbidden_text(failures)

    assert any("index:.env.example: blocked pattern secret-api-key" in item for item in failures)
    assert any("index and worktree differ" in item for item in failures)


def test_release_scan_compares_snapshots_even_if_git_diff_is_hidden(monkeypatch):
    import scripts.release_scan as release_scan

    snapshots = {
        "index": {Path("public.txt"): b"index"},
        "worktree": {Path("public.txt"): b"worktree"},
    }
    monkeypatch.setattr(release_scan, "_read_release_snapshots", lambda: snapshots)
    monkeypatch.setattr(release_scan, "_working_tree_matches_index", lambda: True)
    monkeypatch.setattr(release_scan, "_index_flags_are_safe", lambda: True)
    failures = []

    release_scan._check_forbidden_text(failures)

    assert "tracked index and worktree differ; stage or revert changes before release" in failures


@pytest.mark.parametrize("flag", ["--assume-unchanged", "--skip-worktree"])
def test_release_scan_rejects_git_index_visibility_flags(tmp_path, monkeypatch, flag):
    import scripts.release_scan as release_scan

    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    candidate = tmp_path / "public.txt"
    candidate.write_text("public", encoding="utf-8")
    subprocess.run(["git", "-C", str(tmp_path), "add", "public.txt"], check=True)
    subprocess.run(["git", "-C", str(tmp_path), "update-index", flag, "public.txt"], check=True)
    monkeypatch.setattr(release_scan, "ROOT", tmp_path)
    failures = []

    release_scan._check_forbidden_text(failures)

    assert any("assume-unchanged or skip-worktree" in item for item in failures)


@pytest.mark.parametrize("path", ["Dist/app.js", "Data/Sessions/x.json"])
def test_release_scan_generated_path_matching_is_case_insensitive(path, monkeypatch):
    import scripts.release_scan as release_scan

    snapshots = {
        "index": {Path(path): b"public"},
        "worktree": {Path(path): b"public"},
    }
    monkeypatch.setattr(release_scan, "_read_release_snapshots", lambda: snapshots)
    monkeypatch.setattr(release_scan, "_working_tree_matches_index", lambda: True)
    failures = []

    release_scan._check_forbidden_text(failures)

    assert any("tracked generated/private path" in item for item in failures)


@pytest.mark.parametrize("path", ["Data/private.json", "Sessions/private.json"])
def test_release_scan_rejects_top_level_private_state_directories(path, monkeypatch):
    import scripts.release_scan as release_scan

    snapshots = {
        "index": {Path(path): b"public"},
        "worktree": {Path(path): b"public"},
    }
    monkeypatch.setattr(release_scan, "_read_release_snapshots", lambda: snapshots)
    monkeypatch.setattr(release_scan, "_working_tree_matches_index", lambda: True)
    failures = []

    release_scan._check_forbidden_text(failures)

    assert any("tracked generated/private path" in item for item in failures)


@pytest.mark.parametrize(
    "path",
    [
        ".env.local",
        ".envrc",
        ".htpasswd",
        ".netrc",
        ".pgpass",
        ".vault-token",
        ".git-credentials",
        "_netrc",
        "auth.json",
        ".docker/config.json",
        ".config/gh/hosts.yml",
        ".kube/config",
        ".ssh/config",
        "Credentials.json",
        "id_rsa",
        "keys/secret.pem",
        "ui/.NPMRC",
    ],
)
def test_release_scan_rejects_sensitive_configuration_paths(path, monkeypatch):
    import scripts.release_scan as release_scan

    snapshots = {
        "index": {Path(path): b"benign"},
        "worktree": {Path(path): b"benign"},
    }
    monkeypatch.setattr(release_scan, "_read_release_snapshots", lambda: snapshots)
    monkeypatch.setattr(release_scan, "_working_tree_matches_index", lambda: True)
    monkeypatch.setattr(release_scan, "_index_flags_are_safe", lambda: True)
    failures = []

    release_scan._check_forbidden_text(failures)

    assert any("tracked generated/private path" in item for item in failures)


def test_release_scan_rejects_and_does_not_echo_secret_shaped_filename(tmp_path, monkeypatch):
    import scripts.release_scan as release_scan

    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    secret_tail = "Z" * 32
    filename = "sk-" + "or-v1-" + secret_tail + ".txt"
    (tmp_path / filename).write_text("public", encoding="utf-8")
    subprocess.run(["git", "-C", str(tmp_path), "add", "--", filename], check=True)
    monkeypatch.setattr(release_scan, "ROOT", tmp_path)
    failures = []

    release_scan._check_forbidden_text(failures)

    rendered = "\n".join(failures)
    assert "tracked path contains blocked pattern secret-api-key" in rendered
    assert secret_tail not in rendered


@pytest.mark.parametrize(
    "value",
    [
        "".join(("http://", "192.", "168.10.25:8080")),
        "".join(("http://", "169.", "254.10.25:8080")),
        "".join(("https://[", "fd", "12:3456::1]:8443")),
        "".join(("https://[", "fe", "80::1]:8443")),
        "".join(("https://service.", "internal:8443/path")),
        "".join(("https://service.", "local/path")),
        "".join(("https://", "user:pass@", "public.example/path")),
        "".join(("postgresql", "://", "user:pass@", "public-db.example/db")),
        "".join(("redis", "://", ":pass@", "cache.example/0")),
        "".join(("mongodb+srv", "://", "user:pass@", "cluster.example/db")),
        "".join(("db.", "internal:5432")),
    ],
)
def test_release_scan_rejects_private_endpoint_fragments(value, tmp_path, monkeypatch):
    import scripts.release_scan as release_scan

    snapshots = {
        "index": {Path("public.txt"): value.encode("utf-8")},
        "worktree": {Path("public.txt"): value.encode("utf-8")},
    }
    monkeypatch.setattr(release_scan, "_read_release_snapshots", lambda: snapshots)
    monkeypatch.setattr(release_scan, "_working_tree_matches_index", lambda: True)
    monkeypatch.setattr(release_scan, "_index_flags_are_safe", lambda: True)
    failures = []

    release_scan._check_forbidden_text(failures)

    assert any("blocked pattern" in item for item in failures)


@pytest.mark.parametrize(
    "value",
    [
        '{"' + "WEIPING_LAB_ARCHITECT_API_KEY" + '":"' + "opaque_" + "A" * 40 + '"}',
        '{"' + "OPENAI_API_KEY" + '":"' + "opaque_" + "B" * 40 + '"}',
        '{"' + "Authorization" + '":"' + "Bearer " + "opaque_" + "C" * 40 + '"}',
        '{"' + "Authorization" + '":"' + "Basic " + "Q" * 24 + '=="}',
        '{"' + "OPENAI_API_KEY" + '":\n"' + "opaque_" + "D" * 40 + '"}',
        '{"' + "Authorization" + '":\n"' + "Bearer " + "opaque_" + "E" * 40 + '"}',
        r"{\"" + "OPENAI_API_KEY" + r"\":\"" + "opaque_" + "F" * 40 + r"\"}",
        r"{\"" + "Authorization" + r"\":\"" + "Bearer " + "opaque_" + "G" * 40 + r"\"}",
        "COHERE_API_KEY=" + "opaque_" + "H" * 40,
        "GOOGLE_API_KEY=" + "opaque_" + "I" * 40,
        "AWS_SECRET_ACCESS_KEY=" + "opaque_" + "J" * 40,
        "DB_PASSWORD=" + "opaque_" + "K" * 40,
        "DB_PASS" + "WORD=1.2.3",
        _runtime_text("SESSION_CO", "OKIE=^1.2.3"),
        _runtime_text("API_K", "EY=2.0.0-beta"),
        "SLACK_WEBHOOK_URL=" + "https://hooks.example/" + "L" * 40,
        "SENTRY_DSN=" + "https://dsn.example/" + "M" * 40,
        "ACME_API_KEY=" + "\\\n" + "opaque_" + "N" * 40,
        "ACME_API_KEY: |\n  " + "opaque_" + "O" * 40,
        'DB_PASSWORD="' + "opaque!_" + "P" * 40 + '"',
        "DB_PASS" + 'WORD="' + "correct horse battery staple" + '"',
        "_ACME_API_KEY=" + "opaque_" + "Q" * 40,
        "SERVICE_CREDENTIALS=" + "opaque_" + "R" * 40,
        'OPENAI_API_KEY="' + "sk" + "\\x2d" + "S" * 32 + '"',
        "SECRET_KEY_BASE=" + "opaque_" + "T" * 40,
        "GOOGLE_APPLICATION_CREDENTIALS=" + "opaque_" + "U" * 40,
        "DOCKER_AUTH_CONFIG=" + "opaque_" + "V" * 40,
        "TOKEN_VALUE=" + "opaque_" + "W" * 40,
        "OPENAI_API_KEY_FILE=" + "opaque_" + "X" * 40,
        'DB_PASSWORD="' + "P@ssw0rd123!" + '"',
        'SESSION_COOKIE="' + "abc12345" + '"',
        "apiKey=" + "opaque_" + "Y" * 40,
        "apikey=" + "opaque_" + "Z" * 40,
        "accessToken=" + "opaque_" + "A" * 40,
        "refreshToken=" + "opaque_" + "B" * 40,
        "clientSecret=" + "opaque_" + "C" * 40,
        "privateKey=" + "opaque_" + "D" * 40,
        "databaseUrl=" + "https://db.example/" + "E" * 40,
        "webhookUrl=" + "https://hooks.example/" + "F" * 40,
        "githubPat=" + "opaque_" + "G" * 40,
        "connectionString=" + "opaque_" + "H" * 40,
        "serviceCookieValue=" + "opaque_" + "I" * 40,
        "providerAuthorizationValue=" + "opaque_" + "J" * 40,
        'DB_PASSWORD="' + "don't_share_" + "H" * 24 + '"',
        "DB_PASSWORD='" + 'say"no_' + "I" * 24 + "'",
        "".join(("DB_PASS", 'WORD="', 'abc\\"def_', "J" * 24, '"')),
        "ACME_API_" + "K" + "EY: |2-\n  " + "opaque_" + "K" * 40,
        "DB_PASS" + "WORD=" + '"""' + "opaque_" + "O" * 40 + '"""',
        "DB_PASS" + 'WORD="' + "abc\n" + "def_" + "P" * 32 + '"',
        "".join(("DB_PASS", "WORD=letmein")),
        "".join(("DB_PASS", 'WORD="letmein"')),
        "".join(("SESSION_", "COO", "KIE=abc1234")),
        "".join(("API_", "K", "EY=abcdefg")),
        "".join(("Author", "ization: Bearer abcdefghijkl")),
        "".join(("Author", "ization: Token abcdefghijkl")),
        "".join(("Author", "ization: ApiKey abcdefghijkl")),
        'settings:\n  "' + "OPENAI_API_KEY" + '": "' + "opaque_" + "Q" * 40 + '"',
        "headers:\n  x-api-key: " + "opaque_" + "R" * 40,
        "config:\n  db-pass" + "word: letmein",
        "headers:\n  x.api.key: " + "opaque_" + "S" * 40,
        "ACME_API_KEY=" + "test_live_" + "L" * 32,
        "ACME_API_KEY=" + "your_live_" + "M" * 32,
        "OPENAI_API_KEY" + "\\075" + "opaque_" + "N" * 40,
        "glpat-" + "A" * 32,
        "hvs." + "A" * 32,
        "hf_" + "A" * 32,
        "npm_" + "A" * 32,
    ],
)
def test_release_scan_rejects_role_and_common_provider_credentials_without_echo(value, monkeypatch):
    import scripts.release_scan as release_scan

    snapshots = {
        "index": {Path("public.txt"): value.encode("utf-8")},
        "worktree": {Path("public.txt"): value.encode("utf-8")},
    }
    monkeypatch.setattr(release_scan, "_read_release_snapshots", lambda: snapshots)
    monkeypatch.setattr(release_scan, "_working_tree_matches_index", lambda: True)
    monkeypatch.setattr(release_scan, "_index_flags_are_safe", lambda: True)
    failures = []

    release_scan._check_forbidden_text(failures)

    rendered = "\n".join(failures)
    assert "blocked pattern" in rendered
    assert value not in rendered


@pytest.mark.parametrize(
    "value",
    [
        "OPENAI_API_KEY=replace_with_your_api_key",
        "TOKEN_COUNT=" + "1" * 40,
        "API_KEY_ROTATION=automatic_rotation_policy_enabled",
        "OPENAI_API_KEY=replace_me_with_your_api_key",
    ],
)
def test_release_scan_preserves_explicit_placeholders_and_benign_metrics(value, monkeypatch):
    import scripts.release_scan as release_scan

    snapshots = {
        "index": {Path("public.txt"): value.encode("utf-8")},
        "worktree": {Path("public.txt"): value.encode("utf-8")},
    }
    monkeypatch.setattr(release_scan, "_read_release_snapshots", lambda: snapshots)
    monkeypatch.setattr(release_scan, "_working_tree_matches_index", lambda: True)
    monkeypatch.setattr(release_scan, "_index_flags_are_safe", lambda: True)
    failures = []

    release_scan._check_forbidden_text(failures)

    assert failures == []


def test_python_reference_exemption_is_limited_to_the_assignment_prefix():
    import scripts.release_scan as release_scan

    fixture_name = "OPENAI_API_K" + "EY"
    marker = "OPAQUECREDENTIALVALUE7319"
    safe_reference = "api_" + "ke" + f'y = source_env["{fixture_name}"]'
    unsafe_values = [
        f'payload = wrapper("{fixture_name}={marker}")',
        f'payload = wrapper(value="{fixture_name}={marker}")',
        f'payload = ["{fixture_name}={marker}"]',
        f'payload = "{fixture_name}={marker}"',
        f"# {fixture_name}={marker}",
    ]

    assert not release_scan._contains_configured_credential(
        safe_reference, source_path=Path("probe.py")
    )
    assert all(
        release_scan._contains_configured_credential(value, source_path=Path("probe.py"))
        for value in unsafe_values
    )


def test_python_ast_reconstructs_static_credentials_and_subscript_targets():
    import scripts.release_scan as release_scan

    fixture_name = "OPENAI_API_K" + "EY"
    fixture_value = "opaque_F9k3Lm7Q2xW8v6N4p2Q7"
    sources = [
        f'{fixture_name} = "opaque_" + "F9k3Lm7Q2xW8v6N4p2Q7"',
        f'os.environ["{fixture_name}"] = "{fixture_value}"',
        f'settings = {{"{fixture_name}": "{fixture_value}"}}',
        f'header = "Author" + "ization: Bearer {fixture_value}"',
        f'def configured({fixture_name.lower()}="{fixture_value}"):\n    return None',
    ]

    for source in sources:
        raw = source.encode("utf-8")
        views = release_scan._configured_credential_views(
            raw, Path("probe.py"), release_scan._scan_views(raw)
        )
        assert any(
            release_scan._contains_configured_credential(view, source_path=path)
            for view, path in views
        )


def test_python_untrusted_token_views_never_join_unrelated_literals():
    import scripts.release_scan as release_scan

    benign_source = _runtime_text(
        'first = "Author',
        'ization: Bearer "\n',
        'second = u"benign metadata"\n',
    )
    raw = benign_source.encode("utf-8")
    views = release_scan._configured_credential_views(
        raw, Path("probe.py"), release_scan._scan_views(raw)
    )
    assert not any(
        release_scan._contains_configured_credential(view, source_path=path) for view, path in views
    )

    fixture_value = _runtime_text("opaque_", "F9k3Lm7Q2xW8v6N4p2Q7")
    unsafe_source = _runtime_text(
        'message = "Author',
        "ization: Bearer ",
        fixture_value,
        '"\n',
    )
    raw = unsafe_source.encode("utf-8")
    views = release_scan._configured_credential_views(
        raw, Path("probe.py"), release_scan._scan_views(raw)
    )
    assert any(
        release_scan._contains_configured_credential(view, source_path=path) for view, path in views
    )


def test_structured_and_python_setter_credentials_fail_closed():
    import scripts.release_scan as release_scan

    fixture_name = "OPENAI_API_K" + "EY"
    database_name = "DB_PASS" + "WORD"
    fixture_value = "opaque_F9k3Lm7Q2xW8v6N4p2Q7"
    punctuation = "!abcDEF7"
    tick = chr(96)
    header_name = "x-api-" + "key"
    structured = [
        f'$env:{fixture_name} = "{fixture_value}"',
        f"ENV {fixture_name} {fixture_value}",
        f'process.env["{fixture_name}"]="{fixture_value}"',
        f'headers["{header_name}"]="{fixture_value}"',
        f'- name: "{fixture_name}"\n  value: "{fixture_value}"',
        f'os.Setenv("{fixture_name}", "{fixture_value}")',
        f'<add name="{fixture_name}" value="{fixture_value}" />',
        f'Set-Item -Path Env:{fixture_name} -Value "{fixture_value}"',
        f'Set-Item -LiteralPath Env:{fixture_name} -Value "{fixture_value}"',
        f'Set-Item -Value "{fixture_value}" -Path Env:{fixture_name}',
        f'Set-Item -Path Env:{fixture_name} {tick}\n  -Value "{fixture_value}"',
        f'[Environment]::SetEnvironmentVariable(\n  "{fixture_name}",\n'
        f'  "{fixture_value}",\n  "Process"\n)',
        f"$env:{fixture_name} = @'\n{fixture_value}\n'@",
        f'$env:{fixture_name} = @"\n{fixture_value}\n"@',
        f"${{env:{fixture_name}}} = @'\n{fixture_value}\n'@",
        f"[Environment]::SetEnvironmentVariable('{fixture_name}', "
        f"@'\n{fixture_value}\n'@, 'Process')",
        f'[Environment]::SetEnvironmentVariable("{fixture_name}", '
        f'"{fixture_value[:2]}" + "{fixture_value[2:]}", "Process")',
        f"- name: {fixture_name}\n  # fixture comment\n\n  value: {fixture_value}",
        f"- value: {fixture_value}\n  # fixture comment\n\n  name: {fixture_name}",
        f"- {{name: {fixture_name}, value: {fixture_value}}}",
        f"- {{value: {fixture_value}, name: {fixture_name}}}",
        f'- "name": {fixture_name}\n  "value": {fixture_value}',
        f"- 'value': {fixture_value}\n  'name': {fixture_name}",
        f'{{"safe":"x","{header_name}":"{fixture_value}"}}',
        f'config: {{ {header_name}: "{fixture_value}" }}',
        f"export {fixture_name}={fixture_value}",
        f'process.env["{fixture_name}"]={tick}{fixture_value}{tick}',
        f'os.Setenv("{fixture_name}", {tick}{fixture_value}{tick})',
        f'<add value="{fixture_value}" name="{fixture_name}" />',
        "<add value=" + f'"{fixture_value}" k' + f'ey="{fixture_name}" />',
        "".join(("Author", f"ization: Token {punctuation}")),
        "".join(("Author", f"ization: ApiKey {punctuation}")),
        "".join(("Author", "ization: Token tok:abc123")),
        "".join(("Author", "ization: ApiKey abc,def")),
        "".join(("Author", "ization: Token ]abcDEF7")),
        "".join(("Author", "ization: Token }abcDEF7")),
        "".join(("Author", 'ization: Digest response="abcDEF7"')),
    ]
    assert all(release_scan._contains_configured_credential(value) for value in structured)
    assert not release_scan._contains_configured_credential("Authorization: Digest")

    setters = [
        f'os.putenv("{fixture_name}", "{fixture_value}")',
        f'os.environ.setdefault("{fixture_name}", "{fixture_value}")',
        f'config.set("{database_name}", "{fixture_value}")',
        f'set_key(".env", "{fixture_name}", "{fixture_value}")',
        "putenv(k" + f'ey="{fixture_name}", value="{fixture_value}")',
        f'config.set(option="{database_name}", value="{fixture_value}")',
        f'dotenv.set_key(dotenv_path=".env", key_to_set="{fixture_name}", '
        f'value_to_set="{fixture_value}")',
    ]
    for source in setters:
        raw = source.encode("utf-8")
        views = release_scan._configured_credential_views(
            raw, Path("probe.py"), release_scan._scan_views(raw)
        )
        assert any(
            release_scan._contains_configured_credential(view, source_path=path)
            for view, path in views
        )

    source_reference = "SOURCE_" + "KEY"
    references = [
        f"$env:{fixture_name} = $env:SOURCE_KEY",
        f"ENV {fixture_name} ${{{source_reference}}}",
        f"ENV {fixture_name} ${{{source_reference}:-fallback}}",
        f"${{env:{fixture_name}}} = ${{env:{source_reference}}}",
        f"Set-Item -Path Env:{fixture_name} -Value ${{env:{source_reference}}}",
        f'[Environment]::SetEnvironmentVariable("{fixture_name}",'
        f' "${{env:{source_reference}}}", "Process")',
        f"- {{name: {fixture_name}, value: ${{{source_reference}}}}}",
        f'- "name": {fixture_name}\n  "value": ${{{source_reference}}}',
        f"- name: {fixture_name}\n  valueFrom:\n    secretKeyRef:\n"
        "      name: provider\n      key: provider",
    ]
    assert all(not release_scan._contains_configured_credential(value) for value in references)

    safe_python = [
        "".join(("lookup(k", 'ey="customer_id")')),
        "".join(('metadata = {"k', 'ey": "display_name"}')),
        "".join(("k", 'ey = "primary_label"')),
    ]
    unsafe_names = ("pass" + "word", "sec" + "ret", "to" + "ken", "k" + "ey", "au" + "th")
    unsafe_python = [f'{name}="abcd1234"' for name in unsafe_names]
    alphabetic_entropy = "qmvxcpzrtnshdfwkabeg"
    generic_name = "k" + "ey"
    unsafe_python.extend(
        (
            f'{generic_name}="{alphabetic_entropy}_id"',
            f'data={{"{generic_name}": "{alphabetic_entropy}_label"}}',
        )
    )

    def configured_hit(source: str) -> bool:
        raw = source.encode()
        return any(
            release_scan._contains_configured_credential(view, source_path=path)
            for view, path in release_scan._configured_credential_views(
                raw, Path("probe.py"), release_scan._scan_views(raw)
            )
        )

    assert all(not configured_hit(source) for source in safe_python)
    assert all(configured_hit(source) for source in unsafe_python)


def test_structured_scanner_patterns_are_bounded_on_ci_yaml():
    import scripts.release_scan as release_scan

    workflow = (Path(__file__).resolve().parents[1] / ".github/workflows/ci.yml").read_text(
        encoding="utf-8"
    )
    started = time.perf_counter()

    for pattern in release_scan.STRUCTURED_CREDENTIAL_ASSIGNMENTS:
        tuple(pattern.finditer(workflow))

    assert time.perf_counter() - started < 2.0


def test_python_static_high_risk_tokens_are_reconstructed(monkeypatch):
    import scripts.release_scan as release_scan

    prefixes = ("g" + "hp_", "h" + "f_", "n" + "pm_", "s" + "k-")
    tail = "A" * 32
    for prefix in prefixes:
        sources = [
            f'message = "{prefix}" + "{tail}"\n',
            f'def reveal():\n    return "{prefix}" + "{tail}"\n',
            f'matched = candidate == "{prefix}" + "{tail}"\n',
            f'def f(value="{prefix}" + "{tail}"):\n    return value\n',
            f'message = "".join(("{prefix[:2]}", "{prefix[2:]}", "{tail}"))\n',
            f"message = f'{prefix}{{\"{tail}\"}}'\n",
        ]
        for source in sources:
            snapshots = {
                "index": {Path("probe.py"): source.encode()},
                "worktree": {Path("probe.py"): source.encode()},
            }
            monkeypatch.setattr(release_scan, "_read_release_snapshots", lambda: snapshots)
            monkeypatch.setattr(release_scan, "_working_tree_matches_index", lambda: True)
            monkeypatch.setattr(release_scan, "_index_flags_are_safe", lambda: True)
            failures = []

            release_scan._check_forbidden_text(failures)

            assert any("blocked pattern" in item for item in failures)


def test_package_lock_path_key_semver_is_the_only_semver_exemption():
    import scripts.release_scan as release_scan

    value = "".join(('"path-', "k", 'ey": "^3.1.1"'))
    non_semver = _runtime_text("opaque_", "F9k3Lm7Q2xW8v6N4p2Q7")
    assert not release_scan._contains_configured_credential(
        value, source_path=Path("ui/package-lock.json")
    )
    assert release_scan._contains_configured_credential(value, source_path=Path("config.json"))
    assert release_scan._contains_configured_credential(
        _runtime_text('"api-k', 'ey": "^3.1.1"'),
        source_path=Path("ui/package-lock.json"),
    )
    assert release_scan._contains_configured_credential(
        _runtime_text('"path-', 'key": "', non_semver, '"'),
        source_path=Path("ui/package-lock.json"),
    )
    assert not release_scan._contains_configured_credential(
        _runtime_text('{"k', 'ey":"value"}'), source_path=Path("schema.json")
    )
    assert release_scan._contains_configured_credential(
        _runtime_text("OPENAI_API_", "KEY=value"), source_path=Path("config.yaml")
    )


@pytest.mark.parametrize(
    "path",
    [
        "ui/index.html",
        "ui/public/favicon.svg",
        "config.ini",
        "script.sh",
        "notes.xml",
        "asset.bin",
    ],
)
def test_release_scan_scans_every_tracked_file_type(path, monkeypatch):
    import scripts.release_scan as release_scan

    marker = bytes((115, 107, 45)) + b"Z" * 32
    snapshots = {"index": {Path(path): marker}, "worktree": {Path(path): marker}}
    monkeypatch.setattr(release_scan, "_read_release_snapshots", lambda: snapshots)
    monkeypatch.setattr(release_scan, "_working_tree_matches_index", lambda: True)
    monkeypatch.setattr(release_scan, "_index_flags_are_safe", lambda: True)
    failures = []

    release_scan._check_forbidden_text(failures)

    assert any("blocked pattern secret-api-key" in item for item in failures)


def test_release_scan_binary_fast_path_still_blocks_plaintext_token(monkeypatch):
    import scripts.release_scan as release_scan

    marker = bytes((115, 107, 45)) + b"Z" * 32
    payload = bytes(range(256)) * 256 + b"\0" + marker + b"\0"
    assert not release_scan._is_probably_text(payload)
    snapshots = {"index": {Path("asset.bin"): payload}, "worktree": {Path("asset.bin"): payload}}
    monkeypatch.setattr(release_scan, "_read_release_snapshots", lambda: snapshots)
    monkeypatch.setattr(release_scan, "_working_tree_matches_index", lambda: True)
    monkeypatch.setattr(release_scan, "_index_flags_are_safe", lambda: True)

    def reject_text_semantics(*args, **kwargs):
        raise AssertionError("binary payload reached text-only semantic scanning")

    monkeypatch.setattr(release_scan, "_configured_credential_views", reject_text_semantics)
    monkeypatch.setattr(release_scan, "_unicode_escape_views", reject_text_semantics)
    monkeypatch.setattr(release_scan, "_fixed_point_security_view", reject_text_semantics)
    failures = []

    release_scan._check_forbidden_text(failures)

    assert any("blocked pattern secret-api-key" in item for item in failures)


def test_release_scan_binary_metadata_still_blocks_semantic_and_endpoint_leaks(monkeypatch):
    import scripts.release_scan as release_scan

    sensitive_name = "_".join(("OPENAI", "API", "KEY"))
    private_host = b".".join((b"10", b"23", b"45", b"67"))
    userinfo = b":".join((b"operator", b"opaque-credential@example.test"))
    cases = [
        (f"{sensitive_name}=opaque_F9k3Lm7Q2xW8v6N4p2Q7".encode(), "configured-api-key"),
        (b"endpoint=https://" + private_host + b":8443/v1", "private-ipv4-endpoint"),
        (b"https://" + userinfo + b"/v1", "url-userinfo"),
    ]
    monkeypatch.setattr(release_scan, "_working_tree_matches_index", lambda: True)
    monkeypatch.setattr(release_scan, "_index_flags_are_safe", lambda: True)

    for metadata, expected_code in cases:
        payload = bytes(range(256)) * 64 + b"\0" + metadata + b"\0"
        assert not release_scan._is_probably_text(payload)
        snapshots = {
            "index": {Path("asset.bin"): payload},
            "worktree": {Path("asset.bin"): payload},
        }
        monkeypatch.setattr(release_scan, "_read_release_snapshots", lambda: snapshots)
        failures = []

        release_scan._check_forbidden_text(failures)

        assert any(expected_code in item for item in failures)


@pytest.mark.parametrize("encoding", ["utf-16-le", "utf-16-be"])
def test_release_scan_binary_metadata_decodes_mixed_utf16_credentials(encoding, monkeypatch):
    import scripts.release_scan as release_scan

    sensitive_name = "_".join(("OPENAI", "API", "KEY"))
    metadata = f"{sensitive_name}=opaque_F9k3Lm7Q2xW8v6N4p2Q7".encode(encoding)
    payload = bytes(range(256)) * 64 + b"\x01\x02\x03" + metadata + b"\x04\x05\x06"
    assert not release_scan._is_probably_text(payload)
    snapshots = {"index": {Path("asset.bin"): payload}, "worktree": {Path("asset.bin"): payload}}
    monkeypatch.setattr(release_scan, "_read_release_snapshots", lambda: snapshots)
    monkeypatch.setattr(release_scan, "_working_tree_matches_index", lambda: True)
    monkeypatch.setattr(release_scan, "_index_flags_are_safe", lambda: True)
    failures = []

    release_scan._check_forbidden_text(failures)

    assert any("configured-api-key" in item for item in failures)


def test_release_scan_binary_fast_path_is_bounded(monkeypatch):
    import scripts.release_scan as release_scan

    payload = bytes(range(256)) * ((3 * 1024 * 1024) // 256)
    assert len(payload) == 3 * 1024 * 1024
    assert not release_scan._is_probably_text(payload)
    snapshots = {"index": {Path("banner.png"): payload}, "worktree": {Path("banner.png"): payload}}
    monkeypatch.setattr(release_scan, "_read_release_snapshots", lambda: snapshots)
    monkeypatch.setattr(release_scan, "_working_tree_matches_index", lambda: True)
    monkeypatch.setattr(release_scan, "_index_flags_are_safe", lambda: True)
    failures = []
    started = time.perf_counter()

    release_scan._check_forbidden_text(failures)

    assert failures == []
    assert time.perf_counter() - started < 2.0


@pytest.mark.parametrize(
    "payload",
    [
        ("sk" + "\\u002d" + "Z" * 32).encode(),
        ("SEMANTIC_SCHOLAR_API_KEY=" + "".join("\\u0041" for _ in range(24))).encode(),
        ("Authorization" + "\\u003a Basic " + "Q" * 24).encode(),
    ],
)
def test_release_scan_decodes_unicode_escapes_before_secret_matching(payload, monkeypatch):
    import scripts.release_scan as release_scan

    snapshots = {"index": {Path("public.txt"): payload}, "worktree": {Path("public.txt"): payload}}
    monkeypatch.setattr(release_scan, "_read_release_snapshots", lambda: snapshots)
    monkeypatch.setattr(release_scan, "_working_tree_matches_index", lambda: True)
    monkeypatch.setattr(release_scan, "_index_flags_are_safe", lambda: True)
    failures = []

    release_scan._check_forbidden_text(failures)

    assert any("blocked pattern" in item for item in failures)


@pytest.mark.parametrize(
    "payload",
    [
        ("sk" + "-" + "ABCD" + "\u200b" + "Z" * 28).encode(),
        ("OPENAI_API" + "\u200b" + "_KEY=" + "opaque_" + "A" * 40).encode(),
        ("Authorization: Bearer " + "opaque_" + "ABCD" + "\u2060" + "B" * 32).encode(),
        ("gh" + "p_" + "ABCD" + "\ufe0f" + "C" * 24).encode(),
    ],
)
def test_release_scan_compacts_default_ignorables_before_secret_matching(payload, monkeypatch):
    import scripts.release_scan as release_scan

    snapshots = {"index": {Path("public.txt"): payload}, "worktree": {Path("public.txt"): payload}}
    monkeypatch.setattr(release_scan, "_read_release_snapshots", lambda: snapshots)
    monkeypatch.setattr(release_scan, "_working_tree_matches_index", lambda: True)
    monkeypatch.setattr(release_scan, "_index_flags_are_safe", lambda: True)
    failures = []

    release_scan._check_forbidden_text(failures)

    assert any("blocked pattern" in item for item in failures)


def test_release_scan_repeats_security_transforms_for_combined_encoding(monkeypatch):
    import scripts.release_scan as release_scan

    payload = ("OPENAI_API_KEY%3" + "\u200b" + "A" + "opaque_" + "Z" * 40).encode()
    snapshots = {"index": {Path("public.txt"): payload}, "worktree": {Path("public.txt"): payload}}
    monkeypatch.setattr(release_scan, "_read_release_snapshots", lambda: snapshots)
    monkeypatch.setattr(release_scan, "_working_tree_matches_index", lambda: True)
    monkeypatch.setattr(release_scan, "_index_flags_are_safe", lambda: True)
    failures = []

    release_scan._check_forbidden_text(failures)

    assert any("blocked pattern" in item for item in failures)


def test_release_scan_rejects_untrusted_or_unpinned_lockfile_entries(tmp_path, monkeypatch):
    import scripts.release_scan as release_scan

    ui = tmp_path / "ui"
    ui.mkdir()
    package = {
        "name": "ui",
        "version": "0.0.0",
        "dependencies": {},
        "devDependencies": {},
        "engines": {"node": ">=22.18.0"},
    }
    lock = {
        "name": "ui",
        "version": "0.0.0",
        "lockfileVersion": 3,
        "requires": True,
        "packages": {
            "": package,
            "node_modules/example": {
                "version": "1.0.0",
                "resolved": "https://attacker.example/example.tgz",
            },
        },
    }
    (ui / "package.json").write_text(json.dumps(package), encoding="utf-8")
    (ui / "package-lock.json").write_text(json.dumps(lock), encoding="utf-8")
    monkeypatch.setattr(release_scan, "ROOT", tmp_path)
    failures = []

    release_scan._check_package_lock(failures)

    assert any("non-official resolved package URL" in item for item in failures)
    assert any("missing a SHA-512 integrity pin" in item for item in failures)


def test_release_scan_rejects_official_tarball_for_a_different_package(tmp_path, monkeypatch):
    import scripts.release_scan as release_scan

    ui = tmp_path / "ui"
    ui.mkdir()
    package = {
        "name": "ui",
        "version": "0.0.0",
        "scripts": release_scan.EXPECTED_UI_SCRIPTS,
        "dependencies": {},
        "devDependencies": {},
        "engines": {"node": ">=22.18.0"},
    }
    lock = {
        "name": "ui",
        "version": "0.0.0",
        "lockfileVersion": 3,
        "requires": True,
        "packages": {
            "": {
                field_name: field_value
                for field_name, field_value in package.items()
                if field_name != "scripts"
            },
            "node_modules/@types/react": {
                "version": "19.2.18",
                "resolved": "https://registry.npmjs.org/picocolors/-/picocolors-1.1.1.tgz",
                "integrity": "sha512-" + base64.b64encode(b"A" * 64).decode("ascii"),
            },
        },
    }
    (ui / "package.json").write_text(json.dumps(package), encoding="utf-8")
    (ui / "package-lock.json").write_text(json.dumps(lock), encoding="utf-8")
    monkeypatch.setattr(release_scan, "ROOT", tmp_path)
    failures = []

    release_scan._check_package_lock(failures)

    assert any("resolved package name/version" in item for item in failures)


def test_release_scan_rejects_noop_or_redirected_ui_scripts(tmp_path, monkeypatch):
    import scripts.release_scan as release_scan

    ui = tmp_path / "ui"
    ui.mkdir()
    package = {
        "name": "ui",
        "version": "0.0.0",
        "scripts": {**release_scan.EXPECTED_UI_SCRIPTS, "build": "true"},
        "dependencies": {},
        "devDependencies": {},
        "engines": {"node": ">=22.18.0"},
    }
    lock = {
        "name": "ui",
        "version": "0.0.0",
        "lockfileVersion": 3,
        "requires": True,
        "packages": {
            "": {
                field_name: field_value
                for field_name, field_value in package.items()
                if field_name != "scripts"
            },
        },
    }
    (ui / "package.json").write_text(json.dumps(package), encoding="utf-8")
    (ui / "package-lock.json").write_text(json.dumps(lock), encoding="utf-8")
    monkeypatch.setattr(release_scan, "ROOT", tmp_path)
    failures = []

    release_scan._check_package_lock(failures)

    assert any("audited executable gates" in item for item in failures)


@pytest.mark.parametrize("value", ["sha512-A=", "sha512-AAAA", "sha256-" + "A" * 88])
def test_release_scan_rejects_malformed_or_short_integrity_pins(value):
    from scripts.release_scan import _valid_sha512_integrity

    assert _valid_sha512_integrity(value) is False


def test_release_scan_accepts_exact_512_bit_integrity_pin():
    from scripts.release_scan import _valid_sha512_integrity

    value = "sha512-" + base64.b64encode(b"A" * 64).decode("ascii")

    assert _valid_sha512_integrity(value) is True


def test_release_scan_ci_validation_ignores_comment_decoys_and_rejects_unsafe_yaml():
    from scripts.release_scan import _validate_ci_workflow

    workflow = """
permissions: write-all
jobs:
  verify:
    steps:
      - name: Untrusted
        uses: attacker/action@latest
# actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1
# actions/setup-python@5fda3b95a4ea91299a34e894583c3862153e4b97
# actions/setup-node@820762786026740c76f36085b0efc47a31fe5020
# persist-credentials: false
# node-version: "22.18.0"
# pip>=26.2.1 setuptools>=84.0.0
"""

    errors = _validate_ci_workflow(workflow)

    assert any("permissions" in item for item in errors)
    assert any("official action allowlist" in item for item in errors)


@pytest.mark.parametrize(
    ("input_name", "input_value"),
    [
        ("persist-credentials", "false"),
        ("python-version", '"3.11"'),
        ("node-version", '"22.18.0"'),
    ],
)
def test_release_scan_ci_requires_action_inputs_under_with(input_name, input_value):
    from scripts.release_scan import _validate_ci_workflow

    workflow = (Path.cwd() / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    original = f"        with:\n          {input_name}: {input_value}"
    mutated = f"        env:\n          {input_name}: {input_value}"
    assert original in workflow

    errors = _validate_ci_workflow(workflow.replace(original, mutated, 1))

    assert any("with mapping" in item for item in errors)


def test_release_scan_ci_rejects_quoted_job_permissions_key():
    from scripts.release_scan import _validate_ci_workflow

    workflow = (Path.cwd() / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    mutated = workflow.replace(
        "    runs-on: ubuntu-latest",
        '    "permissions": write-all\n    runs-on: ubuntu-latest',
        1,
    )

    errors = _validate_ci_workflow(mutated)

    assert any("privilege-bearing keys" in item for item in errors)


@pytest.mark.parametrize(
    ("original", "mutated"),
    [
        (
            "          persist-credentials: false",
            "          persist-credentials: false\n          repository: attacker/example",
        ),
        (
            "        run: make -f Makefile verify",
            "        continue-on-error: true\n        run: make -f Makefile verify",
        ),
        (
            "        run: make -f Makefile verify",
            "        if: false\n        run: make -f Makefile verify",
        ),
        (
            "        run: make -f Makefile verify",
            '        shell: "cmd /c echo {0}"\n        run: make -f Makefile verify',
        ),
        (
            "        run: make -f Makefile verify",
            "        run: |\n          cat <<'EOF'\n          make -f Makefile verify\n          EOF",
        ),
    ],
)
def test_release_scan_ci_rejects_step_execution_bypasses(original, mutated):
    from scripts.release_scan import _validate_ci_workflow

    workflow = (Path.cwd() / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    assert original in workflow

    errors = _validate_ci_workflow(workflow.replace(original, mutated, 1))

    assert any("exactly match the audited step structure" in item for item in errors)


def test_release_scan_ci_rejects_unaudited_root_defaults():
    from scripts.release_scan import _validate_ci_workflow

    workflow = (Path.cwd() / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    mutated = workflow.replace(
        "permissions:\n", "defaults:\n  run:\n    shell: false\n\npermissions:\n", 1
    )

    errors = _validate_ci_workflow(mutated)

    assert any("audited root fields" in item for item in errors)


@pytest.mark.parametrize("alias", ["true", "yes", "TRUE", "True", "On", "ON"])
def test_release_scan_ci_requires_exact_lowercase_on_key(alias):
    from scripts.release_scan import _validate_ci_workflow

    workflow = (Path.cwd() / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    mutated = workflow.replace("on:", f"{alias}:", 1)

    errors = _validate_ci_workflow(mutated)

    assert any("audited root fields" in item for item in errors)


@pytest.mark.parametrize(
    "mutated",
    [
        "permissions:\n  contents: write\npermissions:\n  contents: read\n",
        (
            "jobs:\n  verify:\n    runs-on: ubuntu-latest\n    timeout-minutes: 30\n"
            "    steps:\n      - uses: attacker/action@latest\n"
            "        uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1\n"
        ),
    ],
)
def test_release_scan_ci_rejects_duplicate_yaml_keys(mutated):
    from scripts.release_scan import _validate_ci_workflow

    errors = _validate_ci_workflow("name: CI\n" + mutated)

    assert errors == ["CI workflow must be valid safe YAML"]


def test_release_scan_rejects_additional_tracked_workflow(monkeypatch):
    import scripts.release_scan as release_scan

    monkeypatch.setattr(
        release_scan,
        "_tracked_paths",
        lambda: [Path(".github/workflows/ci.yml"), Path(".github/workflows/extra.yaml")],
    )
    failures = []

    release_scan._check_ci_contract(failures)

    assert any("inventory must contain exactly ci.yml" in item for item in failures)


def test_release_scan_pins_executable_gate_files_and_make_precedence(tmp_path, monkeypatch):
    import scripts.release_scan as release_scan

    (tmp_path / "scripts").mkdir()
    (tmp_path / "Makefile").write_bytes((Path.cwd() / "Makefile").read_bytes())
    (tmp_path / "scripts" / "verify.ps1").write_bytes(
        (Path.cwd() / "scripts" / "verify.ps1").read_bytes()
    )
    (tmp_path / "scripts" / "run_ruff.py").write_bytes(
        (Path.cwd() / "scripts" / "run_ruff.py").read_bytes()
    )
    monkeypatch.setattr(release_scan, "ROOT", tmp_path)
    monkeypatch.setattr(release_scan, "_tracked_paths", lambda: [Path("Makefile")])
    failures = []

    release_scan._check_critical_gate_files(failures)
    assert failures == []

    (tmp_path / "Makefile").write_text("verify:\n\t@true\n", encoding="utf-8")
    monkeypatch.setattr(
        release_scan,
        "_tracked_paths",
        lambda: [Path("Makefile"), Path("GNUmakefile"), Path("makefile")],
    )
    release_scan._check_critical_gate_files(failures)

    assert any("audited contract" in item for item in failures)
    assert any("override Makefile" in item for item in failures)


@pytest.mark.parametrize(
    "value",
    [
        "D:" + r"\Research\WEIPING_LAB",
        "C:" + r"\Users\operator\source",
        "/" + "home/operator/source",
    ],
)
def test_release_scan_rejects_operator_specific_absolute_paths(value):
    from scripts.release_scan import PRIVATE_PATH

    assert PRIVATE_PATH.search(value)


def test_release_version_consistency():
    from lab.runtime import VERSION

    pyproject = tomllib.loads(Path("pyproject.toml").read_text(encoding="utf-8"))
    assert pyproject["project"]["version"] == VERSION


def test_ui_declares_and_locks_supported_node_floor():
    package = json.loads(Path("ui/package.json").read_text(encoding="utf-8"))
    lock = json.loads(Path("ui/package-lock.json").read_text(encoding="utf-8"))

    assert package["engines"]["node"] == ">=22.18.0"
    assert lock["packages"][""]["engines"]["node"] == ">=22.18.0"


def test_release_ruff_policy_is_explicit():
    pyproject = tomllib.loads(Path("pyproject.toml").read_text(encoding="utf-8"))
    assert pyproject["tool"]["ruff"]["lint"]["select"] == ["E4", "E7", "E9", "F"]


def test_release_scan_rejects_pytest_addopts_and_nested_lint_config(tmp_path, monkeypatch):
    import scripts.release_scan as release_scan

    pyproject = """
[tool.ruff]
line-length = 100
[tool.ruff.lint]
select = ["E4", "E7", "E9", "F"]
[tool.pytest.ini_options]
testpaths = ["tests"]
addopts = "--collect-only"
"""
    (tmp_path / "pyproject.toml").write_text(pyproject, encoding="utf-8")
    monkeypatch.setattr(release_scan, "ROOT", tmp_path)
    monkeypatch.setattr(
        release_scan,
        "_tracked_paths",
        lambda: (Path("pyproject.toml"), Path("tests/.ruff.toml")),
    )
    failures = []

    release_scan._check_ruff_policy(failures)

    assert any("audited pytest policy" in item for item in failures)
    assert any("override configuration" in item for item in failures)


@pytest.mark.parametrize(
    ("gate_kind", "gate_index"),
    [
        ("python", 1),
        ("python", 2),
        ("python", 3),
        ("python", 4),
        ("python", 5),
        ("python", 6),
        ("npm", 1),
        ("npm", 2),
        ("npm", 3),
    ],
)
def test_windows_verify_propagates_every_external_gate_failure(gate_kind, gate_index):
    shell = shutil.which("powershell") or shutil.which("pwsh")
    if not shell:
        pytest.skip("PowerShell is not available on this platform")

    verify = (Path.cwd() / "scripts" / "verify.ps1").resolve()
    harness = rf"""
$script:PythonCalls = 0
$script:NpmCalls = 0
function global:python {{
    $script:PythonCalls++
    if ($env:WEIPING_TEST_FAIL_KIND -eq 'python' -and
        $script:PythonCalls -eq [int]$env:WEIPING_TEST_FAIL_INDEX) {{
        $global:LASTEXITCODE = 23
    }} else {{
        $global:LASTEXITCODE = 0
    }}
}}
function global:npm {{
    $script:NpmCalls++
    if ($env:WEIPING_TEST_FAIL_KIND -eq 'npm' -and
        $script:NpmCalls -eq [int]$env:WEIPING_TEST_FAIL_INDEX) {{
        $global:LASTEXITCODE = 23
    }} else {{
        $global:LASTEXITCODE = 0
    }}
}}
& '{verify}'
"""
    env = {
        **os.environ,
        "WEIPING_TEST_FAIL_KIND": gate_kind,
        "WEIPING_TEST_FAIL_INDEX": str(gate_index),
        "WEIPING_LAB_VERIFY_PYTHON": "python",
    }
    result = subprocess.run(
        [shell, "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", harness],
        cwd=Path.cwd(),
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode != 0
    assert "failed with exit code 23" in (result.stdout + result.stderr)
