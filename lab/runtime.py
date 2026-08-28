"""Shared runtime constants and safe diagnostics helpers."""

from __future__ import annotations

import base64
import binascii
import ast
import ipaddress
import json
import math
import os
import re
import unicodedata
from pathlib import Path
from urllib.parse import unquote, unquote_plus, urlsplit

VERSION = "1.6.0"
SAFE_SK_PLACEHOLDER = "sk" + "-...redacted"
EMPTY_CONFIG_VALUES = {
    "",
    "...",
    "changeme",
    "change-me",
    "none",
    "null",
    "todo",
    "unset",
}
URL_USERINFO = re.compile(
    r"(?P<prefix>(?:\b[A-Za-z][A-Za-z0-9+.-]*:)?//)[^\s/@?#]+@",
    flags=re.I,
)
SCHEMELESS_URL_USERINFO = re.compile(
    r"(?<![A-Za-z0-9._%+-])[^\s/@?#]+@(?P<host>[^\s/?#]+)",
    flags=re.I,
)
PUBLIC_SCHEMELESS_URL_USERINFO = re.compile(
    r"(?<![A-Za-z0-9._%+-])[^\s/@?#:]+:[^\s/@?#]+@(?P<host>[^\s/?#]+)",
    flags=re.I,
)
URL_AUTHORITY = re.compile(
    r"(?P<prefix>(?:\b[A-Za-z][A-Za-z0-9+.-]*:)?//)(?P<authority>[^\s/?#]+)",
    flags=re.I,
)
URL_CREDENTIAL_SPAN = re.compile(
    r"(?P<prefix>\b[A-Za-z][A-Za-z0-9+.-]*://|(?<!:)/{2})"
    r"(?P<userinfo>[^\s/?#\"'<>]{1,2048}?)@",
    flags=re.I,
)
PRIVATE_NETWORK_ENDPOINT = re.compile(
    r"(?<![A-Za-z0-9])(?:"
    r"10(?:\.\d{1,3}){3}|192\.168(?:\.\d{1,3}){2}|"
    r"169\.254(?:\.\d{1,3}){2}|172\.(?:1[6-9]|2\d|3[01])(?:\.\d{1,3}){2}"
    r")(?:\:\d{1,5})?(?![A-Za-z0-9])"
    r"|(?:\[)?(?:f[cd][0-9a-f]{2}|fe[89ab][0-9a-f]):[0-9a-f:]+(?:\])?(?::\d{1,5})?"
    r"|(?<![A-Za-z0-9.-])(?:[A-Za-z0-9-]+\.)+(?:internal|local)"
    r"(?::\d{1,5})?(?![A-Za-z0-9.-])",
    flags=re.I,
)
AUTH_CREDENTIAL = re.compile(
    r"(?P<scheme>\b(?:Bearer|Basic|Token|ApiKey)\b)(?P<space>\s+)"
    r"(?P<value>\"(?:\\.|[^\"\\])*\"|'(?:\\.|[^'\\])*'|[^\s,;}\]]+)"
    r"(?P<continuation>[^\r\n]*)",
    flags=re.I,
)
PUBLIC_AUTH_CREDENTIAL = re.compile(
    r"(?P<scheme>\b(?:Bearer|Basic|Token|ApiKey)\b)(?P<space>[ \t]+)"
    r"(?P<value>\"(?:\\.|[^\"\\])*\"|'(?:\\.|[^'\\])*'|[^\s,;}\]]+)"
    r"(?P<continuation>)",
    flags=re.I,
)
DIGEST_CREDENTIAL = re.compile(
    r"\bDigest\b[^\r\n]*(?:\r?\n[ \t]+[^\r\n]*)*",
    flags=re.I,
)
PUBLIC_DIGEST_CREDENTIAL = re.compile(
    r"\bDigest\b(?=[^\r\n]{0,512}\b(?:username|realm|nonce|uri|response|opaque|cnonce)\s*=)"
    r"[^\r\n]*",
    flags=re.I,
)
PRIVATE_KEY_MATERIAL = re.compile(
    r"(?:-{2,}BEGIN (?P<pem_label>(?:[A-Z0-9][A-Z0-9 -]{0,62} )?PRIVATE KEY(?: BLOCK)?)-{2,}"
    r".*?(?:-{2,}END (?P=pem_label)-{2,}|$)"
    r"|PuTTY-User-Key-File-[23]:[^\r\n]*(?:\r?\n[^\r\n]*)*)",
    flags=re.I | re.S,
)
AUTHORIZATION_HEADER = re.compile(
    r"(?P<key>\bAuthorization\s*[:=]\s*)"
    r"(?P<value>[^\r\n]+(?:\r?\n[ \t]+[^\r\n]*)*)",
    flags=re.I,
)
URL_QUERY_SEGMENT = re.compile(
    r"(?P<prefix>[?&#;])(?P<segment>[^\s&;?#\r\n]+)",
    flags=re.I,
)
SENSITIVE_ASSIGNMENT = re.compile(
    r"(?=(?P<assignment>(?<![A-Za-z0-9_?&#])(?P<key>(?P<quote>['\"]?)(?P<name>"
    r"[A-Za-z_][A-Za-z0-9_.-]{0,127}|"
    r"api[ \t_.-]?key|authorization|auth|cookie|set[ \t_.-]?cookie|"
    r"(?:access|refresh|id|auth)[ \t_-]?token|token|client[ \t_-]?secret|secret|"
    r"pass(?:word|wd|phrase)|pwd|credential|private[ \t_.-]?key|"
    r"access[ \t_.-]?key(?:[ \t_.-]?id)?|session(?:[ \t_.-]?id)?"
    r")(?P=quote)\s*[:=]\s*)(?P<value>[^\r\n]+)))",
    flags=re.I,
)
MULTILINE_SENSITIVE_ASSIGNMENT = re.compile(
    r"(?<![A-Za-z0-9_])(?P<name>[A-Za-z_][A-Za-z0-9_.-]{0,127})[ \t]*[:=][ \t]*"
    r"(?:"
    r"(?P<quote>['\"])(?P<quoted>[^\r\n]*\r?\n[\s\S]*?)(?P=quote)"
    r"|[|>][^\r\n]*\r?\n[ \t]+(?P<block>[^\r\n]+)"
    r"|\r?\n[ \t]*(?![A-Za-z_][A-Za-z0-9_.-]*[ \t]*[:=])(?P<plain>[^\r\n]+)"
    r")",
    flags=re.I,
)
STRUCTURED_SENSITIVE_ASSIGNMENTS = (
    re.compile(
        r"(?im)\$env:(?P<name>[A-Za-z_][A-Za-z0-9_.-]{1,127})[ \t]*=[ \t]*"
        r"(?P<value>[^\r\n;#]{4,})"
    ),
    re.compile(
        r"(?im)\$\{env:(?P<name>[A-Za-z_][A-Za-z0-9_.-]{1,127})\}[ \t]*=[ \t]*"
        r"(?P<value>[^\r\n;#]{4,})"
    ),
    re.compile(
        r"(?im)\$env:(?P<name>[A-Za-z_][A-Za-z0-9_.-]{1,127})[ \t]*=[ \t]*"
        r"(?P<value>@(?P<here_quote>['\"])[ \t]*\r?\n[\s\S]*?\r?\n"
        r"(?P=here_quote)@)"
    ),
    re.compile(
        r"(?im)\$\{env:(?P<name>[A-Za-z_][A-Za-z0-9_.-]{1,127})\}[ \t]*=[ \t]*"
        r"(?P<value>@(?P<here_quote>['\"])[ \t]*\r?\n[\s\S]*?\r?\n"
        r"(?P=here_quote)@)"
    ),
    re.compile(
        r"(?im)^[ \t]*ENV[ \t]+(?P<name>[A-Za-z_][A-Za-z0-9_.-]{1,127})[ \t]+"
        r"(?P<value>[^\r\n]{4,})"
    ),
    re.compile(
        r"(?im)^[ \t]*export[ \t]+(?P<name>[A-Za-z_][A-Za-z0-9_.-]{1,127})"
        r"[ \t]*=[ \t]*(?P<value>[^\r\n;#]{4,})"
    ),
    re.compile(
        r"(?im)(?=(?<!\$)(?:^|[,{][ \t]*)(?P<name_quote>['\"]?)"
        r"(?P<name>[A-Za-z_][A-Za-z0-9_.-]{1,127})(?P=name_quote)[ \t]*:[ \t]*"
        r"(?P<value>(?P<value_quote>['\"])(?:\\.|(?!(?P=value_quote)).){4,}?"
        r"(?P=value_quote)|\$\{[^}\r\n]+\}|[^,}\]\r\n]{4,}))"
    ),
    re.compile(
        r"(?i)(?:process\.env|headers?|config|settings|os\.environ)[ \t]*\[[ \t]*"
        r"(?P<name_quote>['\"])(?P<name>[A-Za-z_][A-Za-z0-9_.-]{1,127})"
        r"(?P=name_quote)[ \t]*\][ \t]*=[ \t]*(?P<value_quote>['\"`])"
        r"(?P<value>(?:\\.|(?!(?P=value_quote)).){4,}?)(?P=value_quote)"
    ),
    re.compile(
        r"(?i)(?:process\.env|headers?|config|settings)\."
        r"(?P<name>[A-Za-z_][A-Za-z0-9_]{1,127})[ \t]*=[ \t]*"
        r"(?P<value_quote>['\"`])(?P<value>(?:\\.|(?!(?P=value_quote)).){4,}?)"
        r"(?P=value_quote)"
    ),
    re.compile(
        r"(?i)\b(?:os\.)?Setenv[ \t]*\([ \t]*(?P<name_quote>['\"`])"
        r"(?P<name>[A-Za-z_][A-Za-z0-9_.-]{1,127})(?P=name_quote)[ \t]*,[ \t]*"
        r"(?P<value_quote>['\"`])(?P<value>(?:\\.|(?!(?P=value_quote)).){4,}?)"
        r"(?P=value_quote)"
    ),
    re.compile(
        r"(?im)^[ \t]*-[ \t]*(?:['\"]name['\"]|name):[ \t]*"
        r"(?P<name_quote>['\"]?)"
        r"(?P<name>[A-Za-z_][A-Za-z0-9_.-]{1,127})(?P=name_quote)[ \t]*\r?\n"
        r"(?:(?:[ \t]*+(?:#[^\r\n]*)?\r?\n)|"
        r"(?:[ \t]++(?!-[ \t]|['\"]?(?:name|value)['\"]?[ \t]*:)"
        r"[^\r\n]++\r?\n)){0,12}"
        r"[ \t]+(?:['\"]value['\"]|value):[ \t]*(?P<value>[^\r\n]{4,})"
    ),
    re.compile(
        r"(?im)^[ \t]*-[ \t]*(?:['\"]value['\"]|value):[ \t]*"
        r"(?P<value>[^\r\n]{4,})\r?\n"
        r"(?:(?:[ \t]*+(?:#[^\r\n]*)?\r?\n)|"
        r"(?:[ \t]++(?!-[ \t]|['\"]?(?:name|value)['\"]?[ \t]*:)"
        r"[^\r\n]++\r?\n)){0,12}"
        r"[ \t]+(?:['\"]name['\"]|name):[ \t]*(?P<name_quote>['\"]?)"
        r"(?P<name>[A-Za-z_][A-Za-z0-9_.-]{1,127})(?P=name_quote)"
    ),
    re.compile(
        r"(?im)^[ \t]*-[ \t]*\{[^}\r\n]*\b(?:['\"]name['\"]|name)[ \t]*:[ \t]*"
        r"(?P<name_quote>['\"]?)(?P<name>[A-Za-z_][A-Za-z0-9_.-]{1,127})"
        r"(?P=name_quote)[^}\r\n]*,[^}\r\n]*\b(?:['\"]value['\"]|value)"
        r"[ \t]*:[ \t]*(?P<value>\$\{[^}\r\n]+\}|[^,}\r\n]{4,})[^}\r\n]*\}"
    ),
    re.compile(
        r"(?im)^[ \t]*-[ \t]*\{[^}\r\n]*\b(?:['\"]value['\"]|value)[ \t]*:[ \t]*"
        r"(?P<value>\$\{[^}\r\n]+\}|[^,}\r\n]{4,}),[^}\r\n]*"
        r"\b(?:['\"]name['\"]|name)"
        r"[ \t]*:[ \t]*(?P<name_quote>['\"]?)(?P<name>"
        r"[A-Za-z_][A-Za-z0-9_.-]{1,127})(?P=name_quote)[^}\r\n]*\}"
    ),
    re.compile(
        r"(?i)<(?:add|environmentVariable)\b[^>]*\b(?:name|key)[ \t]*=[ \t]*"
        r"(?P<name_quote>['\"])"
        r"(?P<name>[A-Za-z_][A-Za-z0-9_.-]{1,127})(?P=name_quote)[^>]*"
        r"\bvalue[ \t]*=[ \t]*(?P<value_quote>['\"])(?P<value>.{4,}?)"
        r"(?P=value_quote)"
    ),
    re.compile(
        r"(?i)<(?:add|environmentVariable)\b[^>]*\bvalue[ \t]*=[ \t]*"
        r"(?P<value_quote>['\"])"
        r"(?P<value>.{4,}?)(?P=value_quote)[^>]*\b(?:name|key)[ \t]*=[ \t]*"
        r"(?P<name_quote>['\"])(?P<name>[A-Za-z_][A-Za-z0-9_.-]{1,127})"
        r"(?P=name_quote)"
    ),
    re.compile(
        r"(?is)\bSet-Item[\s`]+(?:-(?:Literal)?Path[\s`]+)?(?P<name_quote>['\"]?)"
        r"Env:[\\/]?(?P<name>[A-Za-z_][A-Za-z0-9_.-]{1,127})(?P=name_quote)[\s`]+"
        r"(?:-Value[\s`]+)?(?P<value>(?P<value_quote>['\"])"
        r"(?:`.|(?!(?P=value_quote)).){4,}?(?P=value_quote)|[^\s;#]{4,})"
    ),
    re.compile(
        r"(?is)\bSet-Item[\s`]+-Value[\s`]+(?P<value>(?P<value_quote>['\"])"
        r"(?:`.|(?!(?P=value_quote)).){4,}?(?P=value_quote)|[^\s;#]{4,})[\s`]+"
        r"-(?:Literal)?Path[\s`]+(?P<name_quote>['\"]?)Env:[\\/]?"
        r"(?P<name>[A-Za-z_][A-Za-z0-9_.-]{1,127})(?P=name_quote)"
    ),
    re.compile(
        r"(?is)\[(?:System\.)?Environment\]::SetEnvironmentVariable[\s`]*\([\s`]*"
        r"(?P<name_quote>['\"])(?P<name>[A-Za-z_][A-Za-z0-9_.-]{1,127})"
        r"(?P=name_quote)[\s`]*,[\s`]*(?P<value_quote>['\"])"
        r"(?P<value>(?:`.|(?!(?P=value_quote)).){4,}?)(?P=value_quote)"
    ),
    re.compile(
        r"(?is)\[(?:System\.)?Environment\]::SetEnvironmentVariable[\s`]*\([\s`]*"
        r"(?P<name_quote>['\"])(?P<name>[A-Za-z_][A-Za-z0-9_.-]{1,127})"
        r"(?P=name_quote)[\s`]*,[\s`]*(?P<value>@(?P<here_quote>['\"])"
        r"[ \t]*\r?\n[\s\S]*?\r?\n(?P=here_quote)@)"
    ),
    re.compile(
        r"(?is)\[(?:System\.)?Environment\]::SetEnvironmentVariable[\s`]*\([\s`]*"
        r"(?P<name_quote>['\"])(?P<name>[A-Za-z_][A-Za-z0-9_.-]{1,127})"
        r"(?P=name_quote)[\s`]*,[\s`]*(?P<value>(?P<piece_quote>['\"])"
        r"(?:`.|(?!(?P=piece_quote)).)+?(?P=piece_quote)(?:[\s`]*\+[\s`]*"
        r"(?P<next_quote>['\"])(?:`.|(?!(?P=next_quote)).)+?"
        r"(?P=next_quote))+)"
    ),
)
PRIVATE_PATH = re.compile(
    r"(?i)(?:"
    r"(?<![A-Za-z0-9])[A-Z]:[\\/][^\r\n\"']*"
    r"|\x5c\x5c[A-Z0-9][A-Z0-9._-]{0,62}[\\/]"
    r"[A-Z0-9][^\r\n\"']*"
    r"|\bfile:(?:/{2,3}|\x5c{2,3})[^\r\n\"']+"
    r"|(?<![A-Za-z0-9:/\x5c])[\\/](?![\\/])"
    r"[^\\/\r\n\"']+(?:[\\/][^\\/\r\n\"']*)*"
    r")"
)
NETWORK_SHARE_PATH = re.compile(
    r"(?i)(?<!:)(?:\x5c{2}[A-Z0-9.$_-]+[\\/]|/{2}[A-Z0-9$_-]+/)[^\r\n\"']+"
)
PUBLIC_PRIVATE_PATH = re.compile(
    r"(?i)(?:"
    r"(?<![A-Za-z0-9])[A-Z]:[\\/][^\s\"'`)\]}>;,?#&]*"
    r"|\x5c\x5c[A-Z0-9][A-Z0-9._-]{0,62}[\\/][A-Z0-9][^\s\"'`)\]}>;,?#&]*"
    r"|\bfile:(?:/{2,3}|\x5c{2,3})[^\s\"'`)\]}>;,?#&]+"
    r"|(?<![A-Za-z0-9])/(?:home|Users)/[A-Z0-9._-]+(?:/[^\s\"'`)\]}>;,?#&]*)?"
    r"|(?<![A-Za-z0-9])/(?:root|tmp/[A-Z0-9._-]+)(?:/[^\s\"'`)\]}>;,?#&]*)?"
    r"|(?<![A-Za-z0-9])/(?:private(?:[._-][A-Z0-9._-]+)?|secrets?(?:[._-][A-Z0-9._-]+)?)(?=/|[^A-Z0-9._-]|$)(?:/[^\s\"'`)\]}>;,?#&]*)?"
    r"|(?<![A-Za-z0-9])/(?:var|etc|usr|data|github|nix|Volumes|dev|proc)(?:/[^\s\"'`)\]}>;,?#&]*)?"
    r"|(?<![A-Za-z0-9])/mnt/[A-Z]/Users/[A-Z0-9._-]+(?:/[^\s\"'`)\]}>;,?#&]*)?"
    r"|(?<![A-Za-z0-9:/\x5c])/(?:srv|opt|workspace|run|u01)(?:/[^\s\"'`)\]}>;,?#&]*)?"
    r")"
)
PERCENT_ESCAPE = re.compile(r"%[0-9a-f]{2}", flags=re.I)
UNICODE_ESCAPE = re.compile(r"\\u([0-9a-fA-F]{4})")
HEX_ESCAPE = re.compile(r"\\x([0-9a-fA-F]{2})")
OCTAL_ESCAPE = re.compile(r"\\([0-7]{1,3})")
HIGH_RISK_TOKEN = re.compile(
    r"(?<![A-Za-z0-9])(?:"
    r"github_pat_[A-Za-z0-9_]{20,}|gh[pousr]_[A-Za-z0-9]{20,}|"
    r"glpat-[A-Za-z0-9_-]{20,}|xox[baprs]-[A-Za-z0-9-]{20,}|"
    r"hf_[A-Za-z0-9]{20,}|sk_(?:live|test)_[A-Za-z0-9]{16,}|"
    r"npm_[A-Za-z0-9]{20,}|pypi-[A-Za-z0-9_-]{20,}|"
    r"AIza[0-9A-Za-z_-]{30,}|hvs\.[A-Za-z0-9_-]{20,}|"
    r"AKIA[A-Z0-9]{16}"
    r")(?![A-Za-z0-9])",
    flags=re.I,
)
# Empty is the public status contract for an absent or unparseable endpoint.
UNCONFIGURED_ENDPOINT = ""


def project_root() -> Path:
    return Path(__file__).resolve().parents[1]


def redact(value: object) -> str:
    try:
        text = str(value)
    except Exception:
        return "...redacted"
    if (
        _python_has_static_sensitive_assignment(text)
        or _has_multiline_sensitive_assignment(text)
        or _has_structured_sensitive_assignment(text)
    ):
        return "...redacted"
    text, restorations = _protect_structured_references(text)
    text = text.replace("\r", " ").replace("\n", " ")
    text = _scrub_configured_env_secrets(text)
    text = _redact_embedded_json(text)
    return _restore_structured_references(_redact_scalar_text(text), restorations)


def redact_private_paths(value: object) -> str:
    """Remove operator-specific absolute paths while preserving multiline content."""
    try:
        text = str(value)
    except Exception:
        return "...redacted-path"
    text = _scrub_configured_env_secrets(text)
    shadows = _untrusted_text_shadows(text)
    if shadows[0] == "...redacted":
        return shadows[0]
    if any(shadow != text and _redact_scalar_text(shadow) != shadow for shadow in shadows):
        return "...redacted"
    return PRIVATE_PATH.sub("...redacted-path", text)


def redact_public_text(value: object) -> str:
    """Sanitize public prose without treating ordinary uses of words such as token as credentials."""
    try:
        text = str(value)
    except Exception:
        return "...redacted"
    if (
        _python_has_static_sensitive_assignment(text)
        or _has_multiline_sensitive_assignment(text)
        or _has_structured_sensitive_assignment(text, public=True)
    ):
        return "...redacted"
    text, restorations = _protect_structured_references(text)
    text = _scrub_configured_env_secrets(text)
    return _restore_structured_references(_redact_embedded_json(text, public=True), restorations)


def redact_public_artifact(value: object) -> str:
    """Sanitize a human-readable artifact while preserving its line layout."""
    try:
        text = str(value)
    except Exception:
        return "...redacted"
    if (
        _python_has_static_sensitive_assignment(text)
        or _has_multiline_sensitive_assignment(text)
        or _has_structured_sensitive_assignment(text, public=True)
    ):
        return "...redacted"
    text, restorations = _protect_structured_references(text)
    text = _scrub_configured_env_secrets(text)
    document_shadows = _untrusted_text_shadows(text)
    if document_shadows[0] == "...redacted":
        return document_shadows[0]
    if any(
        shadow != text and _redact_public_scalar(shadow, preserve_newlines=True) != shadow
        for shadow in document_shadows
    ):
        return "...redacted"
    if any(PRIVATE_KEY_MATERIAL.search(shadow) for shadow in document_shadows):
        return "...redacted-private-key"
    text = PRIVATE_KEY_MATERIAL.sub("...redacted-private-key", text)
    rendered: list[str] = []
    for line in text.splitlines(keepends=True):
        content = line.rstrip("\r\n")
        ending = line[len(content) :]
        if _has_ambiguous_spaced_private_path(content):
            rendered.append("...redacted" + ending)
            continue
        shadows = _untrusted_text_shadows(content)
        if shadows[0] == "...redacted" or any(
            shadow != content and _redact_public_scalar(shadow) != shadow for shadow in shadows
        ):
            rendered.append("...redacted" + ending)
        else:
            rendered.append(_redact_public_scalar(content) + ending)
    if not rendered and text:
        return _restore_structured_references(_redact_public_segment(text), restorations)
    return _restore_structured_references("".join(rendered), restorations)


def public_executable_artifact_is_safe(
    value: object,
    *,
    artifact_path: str | Path | None = None,
) -> bool:
    """Validate generated code/config without rewriting syntax-bearing content."""
    if not isinstance(value, str):
        return False
    scrubbed = _scrub_configured_env_secrets(value)
    if scrubbed != value:
        return False
    shadows = _untrusted_text_shadows(value)
    if shadows[0] == "...redacted":
        return False
    python_like = _is_python_artifact(value, artifact_path)
    return all(
        _public_executable_shadow_is_safe(shadow, python_like=python_like) for shadow in shadows
    )


def _is_python_artifact(value: str, artifact_path: str | Path | None) -> bool:
    if artifact_path is not None and Path(artifact_path).suffix.casefold() != ".py":
        return False
    try:
        ast.parse(value)
    except (SyntaxError, TypeError, ValueError):
        return False
    return True


def _python_static_text_views(text: str) -> tuple[str, ...]:
    """Recover static Python string expressions without conflating dict syntax with config."""
    try:
        tree = ast.parse(text)
    except (SyntaxError, TypeError, ValueError):
        return ()
    views = []
    for node in ast.walk(tree):
        literal = _static_python_text_value(node)
        if literal is not None and len(literal) >= 4:
            views.append(literal)
    return tuple(dict.fromkeys(views))


def _public_executable_shadow_is_safe(shadow: str, *, python_like: bool) -> bool:
    """Evaluate one decoded security shadow without mutating executable text."""
    if python_like and _python_has_static_sensitive_assignment(shadow):
        return False
    if _has_multiline_sensitive_assignment(shadow):
        return False
    structured_views = _python_static_text_views(shadow) if python_like else (shadow,)
    if any(_has_structured_sensitive_assignment(view) for view in structured_views):
        return False
    shadow, _ = _protect_structured_references(shadow)
    path_shadow = re.sub(
        r"(?m)^#![ \t]*/usr/bin/(?:env[^\r\n]*|python[0-9.]*)$",
        "",
        shadow,
    )
    path_shadow = re.sub(
        r"(?P<quote>[\"'])/usr/bin/(?:bash|env|python(?:3(?:\.[0-9]+)?)?|sh)(?P=quote)",
        "",
        path_shadow,
    )
    path_shadow = re.sub(
        r"(?<![A-Za-z0-9._-])/usr/bin/(?:bash|env|python(?:3(?:\.[0-9]+)?)?|sh)"
        r"(?=$|[\s;|&)])",
        "",
        path_shadow,
    )
    if (
        PRIVATE_KEY_MATERIAL.search(shadow)
        or NETWORK_SHARE_PATH.search(path_shadow)
        or PUBLIC_PRIVATE_PATH.search(path_shadow)
        or PRIVATE_NETWORK_ENDPOINT.search(shadow)
        or URL_CREDENTIAL_SPAN.search(shadow)
        or URL_USERINFO.search(shadow)
        or AUTHORIZATION_HEADER.search(shadow)
        or PUBLIC_DIGEST_CREDENTIAL.search(shadow)
        or HIGH_RISK_TOKEN.search(shadow)
        or re.search(r"sk" r"-[A-Za-z0-9_-]{8,}", shadow)
    ):
        return False
    for match in PUBLIC_AUTH_CREDENTIAL.finditer(shadow):
        if match.group("value") in {"=", "==", ":="}:
            continue
        if _redact_public_auth_credential(match) != match.group(0):
            return False
    for match in URL_QUERY_SEGMENT.finditer(shadow):
        if match.group("prefix") in {"#", "&", ";"}:
            token_start = max(
                shadow.rfind(separator, 0, match.start()) for separator in " \t\r\n\"'"
            )
            prefix_text = shadow[token_start + 1 : match.start()]
            if "?" not in prefix_text and "://" not in prefix_text:
                continue
        key, separator, _ = match.group("segment").partition("=")
        if not separator or is_sensitive_key(key):
            return False
    for match in SENSITIVE_ASSIGNMENT.finditer(shadow):
        if not is_sensitive_env_key(match.group("name").strip()):
            continue
        if _is_k8s_reference_key(match, shadow) or _is_protected_reference_value(
            match.group("value")
        ):
            continue
        assigned = match.group("value").strip().rstrip(",;")
        unquoted = assigned[1:-1] if assigned[:1] in {'"', "'"} else assigned
        if python_like:
            literal_prefix = re.match(
                r"(?P<quote>['\"])(?:\\.|(?!(?P=quote)).)*(?P=quote)", assigned
            )
            if literal_prefix is not None:
                try:
                    parsed_literal = ast.literal_eval(literal_prefix.group(0))
                except (SyntaxError, ValueError):
                    parsed_literal = unquoted.strip()
                if isinstance(parsed_literal, str):
                    unquoted = parsed_literal
        if python_like and _generic_python_key_value_is_semantic(
            match.group("name").strip(), unquoted.strip()
        ):
            continue
        if unquoted.strip().casefold() in EMPTY_CONFIG_VALUES:
            continue
        if python_like and "=" in match.group("key") and _safe_python_reference(assigned):
            continue
        return False
    return True


def _safe_python_reference(value: str) -> bool:
    """Allow references/computation, but never literals that can embed credentials."""
    if any(quote in value for quote in ('"', "'")):
        return (
            re.fullmatch(
                r"(?:os\.(?:getenv|environ\.get))\(\s*['\"][A-Za-z_][A-Za-z0-9_]*['\"]\s*\)",
                value,
            )
            is not None
        )
    return (
        re.fullmatch(
            r"[A-Za-z_][A-Za-z0-9_.]*(?:\([^\r\n]*\))?(?:\[[0-9]+\])?",
            value,
        )
        is not None
    )


def _static_python_text_value(node: ast.AST) -> str | None:
    if isinstance(node, ast.Constant):
        if isinstance(node.value, str):
            return node.value
        if isinstance(node.value, bytes):
            return node.value.decode("utf-8", errors="replace")
        return None
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left = _static_python_text_value(node.left)
        right = _static_python_text_value(node.right)
        if left is not None and right is not None and len(left) + len(right) <= 1_000_000:
            return left + right
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mult):
        if isinstance(node.right, ast.Constant) and isinstance(node.right.value, int):
            value = _static_python_text_value(node.left)
            count = node.right.value
        elif isinstance(node.left, ast.Constant) and isinstance(node.left.value, int):
            value = _static_python_text_value(node.right)
            count = node.left.value
        else:
            return None
        if value is not None and 0 <= count <= 1_000_000 and len(value) * count <= 1_000_000:
            return value * count
    if isinstance(node, ast.JoinedStr):
        parts = []
        for value in node.values:
            if isinstance(value, ast.FormattedValue):
                if value.conversion != -1 or value.format_spec is not None:
                    return None
                part = _static_python_text_value(value.value)
            else:
                part = _static_python_text_value(value)
            if part is None:
                return None
            parts.append(part)
        candidate = "".join(parts)
        return candidate if len(candidate) <= 1_000_000 else None
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "join"
        and len(node.args) == 1
        and not node.keywords
        and isinstance(node.args[0], (ast.List, ast.Tuple))
    ):
        separator = _static_python_text_value(node.func.value)
        parts = [_static_python_text_value(item) for item in node.args[0].elts]
        if separator is not None and all(part is not None for part in parts):
            candidate = separator.join(part for part in parts if part is not None)
            return candidate if len(candidate) <= 1_000_000 else None
    return None


def _python_sensitive_target_names(target: ast.AST) -> tuple[str, ...]:
    if isinstance(target, ast.Name):
        return (target.id,)
    if isinstance(target, ast.Attribute):
        return (target.attr,)
    if isinstance(target, ast.Subscript):
        key = _static_python_text_value(target.slice)
        return (key,) if key is not None else ()
    if isinstance(target, ast.Starred):
        return _python_sensitive_target_names(target.value)
    if isinstance(target, (ast.List, ast.Tuple)):
        return tuple(name for item in target.elts for name in _python_sensitive_target_names(item))
    return ()


def _python_call_path(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        prefix = _python_call_path(node.value)
        return f"{prefix}.{node.attr}" if prefix else node.attr
    return ""


def _python_target_has_config_context(target: ast.AST) -> bool:
    if not isinstance(target, (ast.Attribute, ast.Subscript)):
        return False
    path = _python_call_path(target.value).casefold()
    return any(
        part
        in {
            "config",
            "configuration",
            "credentials",
            "env",
            "environ",
            "headers",
            "secrets",
            "settings",
        }
        for part in path.split(".")
    )


def _is_generic_sensitive_name(value: str) -> bool:
    return re.sub(r"[^a-z0-9]", "", value.casefold()) in {
        "auth",
        "authorization",
        "cookie",
        "key",
        "password",
        "secret",
        "token",
    }


def _generic_python_key_value_is_semantic(name: str, literal: str) -> bool:
    if re.sub(r"[^a-z0-9]", "", name.casefold()) != "key":
        return False
    semantic_suffixes = {
        "attribute",
        "column",
        "description",
        "field",
        "format",
        "id",
        "index",
        "kind",
        "label",
        "method",
        "metric",
        "name",
        "path",
        "policy",
        "property",
        "role",
        "status",
        "strategy",
        "title",
        "type",
    }
    if literal.casefold() in semantic_suffixes:
        return True
    if any(character.isdigit() for character in literal) or len(literal) > 64:
        return False
    separated = re.sub(r"(?<=[a-z])(?=[A-Z])", "_", literal)
    words = [word.casefold() for word in re.split(r"[_-]+", separated) if word]
    semantic_components = semantic_suffixes | {
        "account",
        "agent",
        "analysis",
        "artifact",
        "claim",
        "client",
        "customer",
        "dataset",
        "display",
        "document",
        "event",
        "experiment",
        "feature",
        "finding",
        "group",
        "job",
        "model",
        "object",
        "organization",
        "output",
        "project",
        "provider",
        "primary",
        "record",
        "request",
        "research",
        "result",
        "run",
        "schema",
        "session",
        "source",
        "stage",
        "task",
        "team",
        "tenant",
        "tool",
        "trace",
        "user",
        "version",
        "workspace",
    }
    return (
        2 <= len(words) <= 4
        and all(word in semantic_components for word in words)
        and words[-1] in semantic_suffixes
    )


def _python_call_aliases(tree: ast.AST) -> dict[str, str]:
    aliases: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for item in node.names:
                aliases[item.asname or item.name] = item.name
        elif isinstance(node, ast.ImportFrom) and node.module:
            for item in node.names:
                if item.name != "*":
                    aliases[item.asname or item.name] = f"{node.module}.{item.name}"

    for _ in range(8):
        changed = False
        for node in ast.walk(tree):
            if not isinstance(node, ast.Assign) or len(node.targets) != 1:
                continue
            target = node.targets[0]
            if not isinstance(target, ast.Name):
                continue
            resolved = _resolve_python_call_path(node.value, aliases)
            if not resolved or aliases.get(target.id) == resolved:
                continue
            aliases[target.id] = resolved
            changed = True
        if not changed:
            break
    return aliases


def _python_call_alias_snapshots(tree: ast.AST) -> dict[int, dict[str, str]]:
    """Resolve aliases at each call site so later rebindings cannot hide an earlier sink."""
    events: list[tuple[int, int, int, ast.AST]] = []
    for node in ast.walk(tree):
        position = (getattr(node, "lineno", 0), getattr(node, "col_offset", 0))
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            events.append((*position, 0, node))
        elif isinstance(node, ast.Assign) and any(
            isinstance(target, ast.Name) for target in node.targets
        ):
            events.append((*position, 1, node))
        elif isinstance(node, ast.Call):
            events.append((*position, 2, node))

    aliases: dict[str, str] = {}
    snapshots: dict[int, dict[str, str]] = {}
    for _, _, _, node in sorted(events, key=lambda event: event[:3]):
        if isinstance(node, ast.Import):
            for item in node.names:
                aliases[item.asname or item.name.split(".", 1)[0]] = item.name
        elif isinstance(node, ast.ImportFrom) and node.module:
            for item in node.names:
                if item.name != "*":
                    aliases[item.asname or item.name] = f"{node.module}.{item.name}"
        elif isinstance(node, ast.Assign):
            resolved = _resolve_python_call_path(node.value, aliases)
            for target in node.targets:
                if not isinstance(target, ast.Name):
                    continue
                existing = aliases.get(target.id, "")
                if _python_path_is_sensitive_setter(
                    existing
                ) and not _python_path_is_sensitive_setter(resolved):
                    continue
                if resolved:
                    aliases[target.id] = resolved
                else:
                    aliases.pop(target.id, None)
        elif isinstance(node, ast.Call):
            snapshots[id(node)] = dict(aliases)
    return snapshots


def _python_path_is_sensitive_setter(path: str) -> bool:
    folded = path.casefold()
    if folded in {"os.putenv", "putenv", "os.setenv", "setenv", "set_key"}:
        return True
    if folded.endswith((".putenv", ".setenv", ".set_key")):
        return True
    if folded.endswith(".setdefault"):
        return folded.rsplit(".", 2)[-2] in {
            "config",
            "env",
            "environ",
            "headers",
            "settings",
        }
    if folded.endswith(".set"):
        return folded.rsplit(".", 2)[-2] in {
            "config",
            "configuration",
            "env",
            "headers",
            "options",
            "settings",
        }
    return False


def _resolve_python_call_path(node: ast.AST, aliases: dict[str, str]) -> str:
    path = _python_call_path(node)
    if not path:
        return ""
    first, separator, remainder = path.partition(".")
    resolved = aliases.get(first, first)
    return f"{resolved}.{remainder}" if separator else resolved


def _python_call_static_credentials(
    node: ast.Call, aliases: dict[str, str] | None = None
) -> tuple[tuple[str, str], ...]:
    path = _resolve_python_call_path(node.func, aliases or {}).casefold()
    pairs: list[tuple[ast.AST, ast.AST]] = []
    keywords = {item.arg.casefold(): item.value for item in node.keywords if item.arg is not None}
    if path in {"os.putenv", "putenv", "os.setenv", "setenv"} and len(node.args) >= 2:
        pairs.append((node.args[0], node.args[1]))
    elif (
        path in {"os.putenv", "putenv", "os.setenv", "setenv"}
        and {
            "key",
            "value",
        }
        <= keywords.keys()
    ):
        pairs.append((keywords["key"], keywords["value"]))
    elif path.endswith(".setdefault"):
        receiver = path.rsplit(".", 1)[0].rsplit(".", 1)[-1]
        if receiver in {"config", "env", "environ", "headers", "settings"}:
            if len(node.args) >= 2:
                pairs.append((node.args[0], node.args[1]))
            elif {"key", "default"} <= keywords.keys():
                pairs.append((keywords["key"], keywords["default"]))
    elif path == "set_key" or path.endswith(".set_key"):
        if len(node.args) >= 3:
            pairs.append((node.args[1], node.args[2]))
        else:
            name_node = keywords.get("key_to_set") or keywords.get("key") or keywords.get("name")
            value_node = keywords.get("value_to_set") or keywords.get("value")
            if name_node is not None and value_node is not None:
                pairs.append((name_node, value_node))
    elif path.endswith(".set"):
        receiver = path.rsplit(".", 1)[0].rsplit(".", 1)[-1]
        if receiver in {"config", "configuration", "env", "headers", "options", "settings"}:
            if len(node.args) >= 2:
                pairs.append((node.args[0], node.args[1]))
            if len(node.args) >= 3:
                pairs.append((node.args[-2], node.args[-1]))
            name_node = keywords.get("option") or keywords.get("key") or keywords.get("name")
            value_node = keywords.get("value")
            if name_node is not None and value_node is not None:
                pairs.append((name_node, value_node))

    recovered: list[tuple[str, str]] = []
    for name_node, value_node in pairs:
        name = _static_python_text_value(name_node)
        literal = _static_python_text_value(value_node)
        if name is not None and literal is not None:
            recovered.append((name, literal))
    return tuple(dict.fromkeys(recovered))


def _literal_is_configured_credential(
    name: str, literal: str, *, allow_generic: bool = False
) -> bool:
    return (
        is_sensitive_env_key(name)
        and (
            allow_generic
            or not _is_generic_sensitive_name(name)
            or not _generic_python_key_value_is_semantic(name, literal)
        )
        and len(literal.strip()) >= 4
        and literal.strip().casefold() not in EMPTY_CONFIG_VALUES
    )


def _python_has_static_sensitive_assignment(text: str) -> bool:
    try:
        tree = ast.parse(text)
    except (SyntaxError, TypeError, ValueError):
        return False
    alias_snapshots = _python_call_alias_snapshots(tree)
    for node in ast.walk(tree):
        folded = _static_python_text_value(node)
        if folded is not None and (
            AUTHORIZATION_HEADER.search(folded) is not None
            or AUTH_CREDENTIAL.search(folded) is not None
            or HIGH_RISK_TOKEN.search(folded) is not None
            or re.search(r"sk-[A-Za-z0-9_-]{8,}", folded, re.I) is not None
            or URL_CREDENTIAL_SPAN.search(folded) is not None
            or URL_USERINFO.search(folded) is not None
            or PRIVATE_NETWORK_ENDPOINT.search(folded) is not None
        ):
            return True

        value: ast.AST | None = None
        targets: tuple[ast.AST, ...] = ()
        if isinstance(node, ast.Assign):
            value = node.value
            targets = tuple(node.targets)
        elif isinstance(node, (ast.AnnAssign, ast.NamedExpr)):
            value = node.value
            targets = (node.target,)
        elif isinstance(node, ast.keyword) and node.arg is not None:
            value = node.value
            targets = (node,)
        if value is not None:
            literal = _static_python_text_value(value)
            if literal is not None:
                for target in targets:
                    names = (
                        (node.arg,)
                        if isinstance(node, ast.keyword) and node.arg is not None
                        else _python_sensitive_target_names(target)
                    )
                    if any(
                        _literal_is_configured_credential(
                            name,
                            literal,
                            allow_generic=_python_target_has_config_context(target),
                        )
                        for name in names
                    ):
                        return True

        if isinstance(node, ast.Call) and any(
            _literal_is_configured_credential(name, literal, allow_generic=True)
            for name, literal in _python_call_static_credentials(
                node, alias_snapshots.get(id(node), {})
            )
        ):
            return True

        if isinstance(node, ast.Dict):
            for key, item_value in zip(node.keys, node.values, strict=True):
                if key is None:
                    continue
                name = _static_python_text_value(key)
                literal = _static_python_text_value(item_value)
                if (
                    name is not None
                    and literal is not None
                    and _literal_is_configured_credential(name, literal)
                ):
                    return True
    return False


def _has_multiline_sensitive_assignment(text: str) -> bool:
    for match in MULTILINE_SENSITIVE_ASSIGNMENT.finditer(text):
        if not is_sensitive_env_key(match.group("name")):
            continue
        value = match.group("quoted") or match.group("block") or match.group("plain") or ""
        if len(value.strip()) >= 4 and value.strip().casefold() not in EMPTY_CONFIG_VALUES:
            return True
    return False


def _structured_value_is_reference(value: str) -> bool:
    candidate = value.strip().rstrip(",/>").strip()
    if candidate[:1] in {'"', "'", "`"} and candidate[-1:] == candidate[:1]:
        candidate = candidate[1:-1].strip()
    if re.fullmatch(
        r"(?:\$(?:env:)?[A-Za-z_][A-Za-z0-9_]*|\$\{env:[A-Za-z_][A-Za-z0-9_]*\}|"
        r"%[A-Za-z_][A-Za-z0-9_]*%|"
        r"\$\([^)]+\)|(?:process\.env|os\.environ)"
        r"(?:\.[A-Za-z_][A-Za-z0-9_]*|\[['\"][A-Za-z_][A-Za-z0-9_]*['\"]\]))",
        candidate,
        flags=re.I,
    ):
        return True
    expansion = re.fullmatch(
        r"\$\{[A-Za-z_][A-Za-z0-9_]*(?::[-+?=](?P<fallback>[^}]*))?\}",
        candidate,
    )
    if expansion is None:
        return False
    fallback = expansion.group("fallback")
    return fallback is None or fallback.casefold() in {
        "",
        "change_me",
        "changeme",
        "default",
        "fallback",
        "placeholder",
        "redacted",
        "unset",
    }


def _structured_sensitive_assignment_spans(
    text: str,
    *,
    public: bool = False,
) -> tuple[tuple[int, int, bool], ...]:
    findings: list[tuple[int, int, bool]] = []
    for pattern in STRUCTURED_SENSITIVE_ASSIGNMENTS:
        for match in pattern.finditer(text):
            if not is_sensitive_env_key(match.group("name")):
                continue
            raw_value = match.group("value").strip().rstrip(",/>").strip()
            if public and _public_sensitive_assignment_is_benign(match.group("name"), raw_value):
                continue
            value = raw_value
            if value[:1] in {'"', "'", "`"} and value[-1:] == value[:1]:
                value = value[1:-1].strip()
            is_reference = _structured_value_is_reference(value)
            bare_authorization_scheme = re.sub(
                r"[^a-z0-9]", "", match.group("name").casefold()
            ) == "authorization" and re.sub(r"[^a-z0-9]", "", value.casefold()) in {
                "apikey",
                "basic",
                "bearer",
                "digest",
                "token",
            }
            if is_reference or (
                len(value) >= 4
                and value.casefold() not in EMPTY_CONFIG_VALUES
                and not bare_authorization_scheme
            ):
                findings.append((match.start("value"), match.end("value"), is_reference))
    return tuple(dict.fromkeys(findings))


def _protect_structured_references(text: str) -> tuple[str, tuple[tuple[str, str], ...]]:
    references = [item for item in _structured_sensitive_assignment_spans(text) if item[2]]
    references.extend(
        (match.start("value"), match.end("value"), True)
        for match in SENSITIVE_ASSIGNMENT.finditer(text)
        if _is_k8s_reference_key(match, text)
    )
    if not references:
        return text, ()
    output: list[str] = []
    restorations: list[tuple[str, str]] = []
    cursor = 0
    for index, (start, end, _) in enumerate(sorted(references)):
        if start < cursor:
            continue
        marker = f"__WEIPING_DYNAMIC_REFERENCE_{index}__"
        output.extend((text[cursor:start], marker))
        restorations.append((marker, text[start:end]))
        cursor = end
    output.append(text[cursor:])
    return "".join(output), tuple(restorations)


def _restore_structured_references(text: str, restorations: tuple[tuple[str, str], ...]) -> str:
    for marker, reference in restorations:
        text = text.replace(marker, reference)
    return text


def _has_structured_sensitive_assignment(text: str, *, public: bool = False) -> bool:
    return any(
        not is_reference
        for _, _, is_reference in _structured_sensitive_assignment_spans(text, public=public)
    )


def _redact_public_segment(text: str) -> str:
    if _has_ambiguous_spaced_private_path(text):
        return "...redacted"
    shadows = _untrusted_text_shadows(text)
    if shadows[0] == "...redacted":
        return shadows[0]
    if any(shadow != text and _redact_public_scalar(shadow) != shadow for shadow in shadows):
        return "...redacted"
    return _redact_public_scalar(text)


def _redact_scalar_text(text: str) -> str:
    text = _scrub_configured_env_secrets(text)
    text = URL_CREDENTIAL_SPAN.sub(r"\g<prefix>...redacted@", text)
    shadows = _untrusted_text_shadows(text)
    normalized = shadows[0]
    if normalized == "...redacted":
        return normalized
    if normalized != text and any(character in normalized for character in "\r\n"):
        return "...redacted"
    for shadow in shadows[1:]:
        candidate = _flatten_controls(shadow)
        if _redact_scalar_core(candidate) != candidate:
            return "...redacted"
    return _redact_scalar_core(_flatten_controls(normalized))


def _redact_scalar_core(text: str) -> str:
    text = PRIVATE_KEY_MATERIAL.sub("...redacted-private-key", text)
    text = NETWORK_SHARE_PATH.sub("...redacted-path", text)
    text = PRIVATE_PATH.sub("...redacted-path", text)
    text = PRIVATE_NETWORK_ENDPOINT.sub("...redacted-endpoint", text)
    text = URL_CREDENTIAL_SPAN.sub(r"\g<prefix>...redacted@", text)
    text = URL_USERINFO.sub(r"\g<prefix>...redacted@", text)
    text = SCHEMELESS_URL_USERINFO.sub(r"...redacted@\g<host>", text)
    text = URL_AUTHORITY.sub(_redact_encoded_url_authority, text)
    text = URL_QUERY_SEGMENT.sub(_redact_query_segment, text)
    text = re.sub(r"sk" r"-[A-Za-z0-9_-]{8,}", SAFE_SK_PLACEHOLDER, text)
    text = HIGH_RISK_TOKEN.sub("...redacted-token", text)
    text = AUTHORIZATION_HEADER.sub(r"\g<key>...redacted", text)
    text = DIGEST_CREDENTIAL.sub("Digest ...redacted", text)
    text = AUTH_CREDENTIAL.sub(_redact_auth_credential, text)
    text = _redact_sensitive_assignments(text)
    text = text.replace("\r", " ").replace("\n", " ")
    return _scrub_configured_env_secrets(text)


def _redact_public_scalar(text: str, *, preserve_newlines: bool = False) -> str:
    text = _scrub_configured_env_secrets(text)
    text = URL_CREDENTIAL_SPAN.sub(r"\g<prefix>...redacted@", text)
    text = _flatten_controls(text, preserve_newlines=preserve_newlines)
    text = PRIVATE_KEY_MATERIAL.sub("...redacted-private-key", text)
    text = NETWORK_SHARE_PATH.sub("...redacted-path", text)
    text = PUBLIC_PRIVATE_PATH.sub("...redacted-path", text)
    text = PRIVATE_NETWORK_ENDPOINT.sub("...redacted-endpoint", text)
    text = URL_CREDENTIAL_SPAN.sub(r"\g<prefix>...redacted@", text)
    text = URL_USERINFO.sub(r"\g<prefix>...redacted@", text)
    text = PUBLIC_SCHEMELESS_URL_USERINFO.sub(r"...redacted@\g<host>", text)
    text = URL_AUTHORITY.sub(_redact_encoded_url_authority, text)
    text = URL_QUERY_SEGMENT.sub(_redact_public_query_segment, text)
    text = re.sub(r"sk" r"-[A-Za-z0-9_-]{8,}", SAFE_SK_PLACEHOLDER, text)
    text = HIGH_RISK_TOKEN.sub("...redacted-token", text)
    text = AUTHORIZATION_HEADER.sub(r"\g<key>...redacted", text)
    text = PUBLIC_DIGEST_CREDENTIAL.sub("Digest ...redacted", text)
    text = PUBLIC_AUTH_CREDENTIAL.sub(_redact_public_auth_credential, text)
    text = _redact_sensitive_assignments(text, public=True)
    if not preserve_newlines:
        text = text.replace("\r", " ").replace("\n", " ")
    return _scrub_configured_env_secrets(text)


def _flatten_controls(text: str, *, preserve_newlines: bool = False) -> str:
    return "".join(
        character
        if preserve_newlines and character in {"\r", "\n"}
        else " "
        if unicodedata.category(character) in {"Cc", "Cs", "Zl", "Zp"}
        else character
        for character in text
    )


def is_sensitive_key(value: object) -> bool:
    """Classify untrusted mapping/query keys using one fail-closed vocabulary."""
    if not isinstance(value, str):
        return True
    decoded = unicodedata.normalize("NFKC", value)
    for _ in range(8):
        candidate = unquote_plus(decoded)
        if candidate == decoded:
            break
        decoded = unicodedata.normalize("NFKC", candidate)
    if PERCENT_ESCAPE.search(decoded):
        return True
    normalized = re.sub(r"[^a-z0-9]", "", decoded.casefold())
    if not normalized:
        return False
    exact = {
        "auth",
        "authentication",
        "authheader",
        "authorization",
        "authorizationheader",
        "bearer",
        "cookie",
        "setcookie",
        "session",
        "sessionid",
        "token",
        "apikey",
        "accesskey",
        "accesskeyid",
        "clientsecret",
        "secret",
        "password",
        "passwd",
        "passphrase",
        "pwd",
        "credential",
        "privatekey",
        "secretkey",
        "sessionkey",
        "signingkey",
        "encryptionkey",
        "sshkey",
        "jwt",
    }
    benign_key_management = normalized.endswith(
        ("algorithm", "format", "method", "policy", "rotation", "strategy", "type")
    )
    plural_credential_token = normalized.endswith("tokens") and normalized[
        : -len("tokens")
    ].endswith(
        ("access", "api", "auth", "bearer", "client", "csrf", "id", "oauth", "refresh", "session")
    )
    credential_value = normalized.endswith("value") and normalized[: -len("value")].endswith(
        (
            "accesskey",
            "apikey",
            "authorization",
            "clientsecret",
            "cookie",
            "credential",
            "password",
            "passphrase",
            "privatekey",
            "secret",
            "token",
        )
    )
    credential_composite = normalized in {
        "appkey",
        "authcookie",
        "authorizationcode",
        "authorizationvalue",
        "bearervalue",
        "clientkey",
        "codeverifier",
        "consumerkey",
        "cookievalue",
        "csrfcookie",
        "githubpat",
        "gitlabpat",
        "jwtvalue",
        "jsessionid",
        "sessioncookie",
        "subscriptionkey",
    }
    return (
        normalized in exact
        or normalized.endswith("token")
        or plural_credential_token
        or credential_value
        or credential_composite
        or normalized.endswith("secret")
        or ("apikey" in normalized and not benign_key_management)
        or ("accesskey" in normalized and not benign_key_management)
        or ("privatekey" in normalized and not benign_key_management)
        or normalized.endswith(("secretkey", "sessionkey", "signingkey", "encryptionkey", "sshkey"))
        or ("credential" in normalized and not normalized.startswith("credentialing"))
        or ("password" in normalized and not normalized.startswith("passwordless"))
        or "passphrase" in normalized
    )


def is_sensitive_env_key(value: object) -> bool:
    """Use a stricter suffix policy for configured process environment names."""
    if is_sensitive_key(value):
        return True
    if not isinstance(value, str):
        return True
    decoded = unicodedata.normalize("NFKC", value)
    for _ in range(8):
        candidate = unquote_plus(decoded)
        if candidate == decoded:
            break
        decoded = unicodedata.normalize("NFKC", candidate)
    if PERCENT_ESCAPE.search(decoded):
        return True
    words = [word for word in re.split(r"[^a-z0-9]+", decoded.casefold()) if word]
    normalized = re.sub(r"[^a-z0-9]", "", decoded.casefold())
    return (
        (
            bool(words)
            and (
                words[-1] in {"dsn", "key", "pat"}
                or words[-2:] in (["connection", "string"], ["webhook", "url"])
            )
        )
        or normalized.endswith(
            (
                "apikey",
                "accesskey",
                "clientsecret",
                "connectionstring",
                "credential",
                "dsn",
                "githubpat",
                "gitlabpat",
                "password",
                "passphrase",
                "privatekey",
                "secret",
                "token",
                "webhookurl",
            )
        )
        or normalized.endswith(
            ("databaseurl", "dburl", "mongodburl", "mysqlurl", "postgresurl", "redisurl")
        )
        or normalized.endswith(
            (
                "apikeybase",
                "apikeyconfig",
                "apikeyfile",
                "apikeyvalue",
                "authconfig",
                "secretkeybase",
                "secretkeyconfig",
                "secretkeyfile",
                "secretkeyvalue",
                "tokenbase",
                "tokenconfig",
                "tokenfile",
                "tokenvalue",
            )
        )
        or (
            bool(words)
            and words[-1] in {"base", "config", "file", "value"}
            and (
                words[-2:-1] in (["auth"], ["credential"], ["credentials"], ["secret"], ["token"])
                or words[-3:-1] in (["api", "key"], ["secret", "key"])
            )
        )
    )


def _normalize_untrusted_text(text: str) -> str:
    """Normalize confusables and bounded percent encoding before redaction."""
    normalized = unicodedata.normalize("NFKC", text)
    for _ in range(8):
        candidate = unicodedata.normalize("NFKC", unquote(normalized))
        if candidate == normalized:
            break
        normalized = candidate
    if any(unicodedata.category(character) == "Cs" for character in normalized):
        return "...redacted"
    if PERCENT_ESCAPE.search(normalized):
        return "...redacted"
    return normalized


def _untrusted_text_shadows(text: str) -> tuple[str, ...]:
    """Return normal and compact forms so separators cannot hide credential syntax."""
    normalized = _normalize_untrusted_text(text)
    if normalized == "...redacted":
        return (normalized,)
    views = [normalized]
    security_view = _fixed_point_security_view(normalized)
    if security_view == "...redacted":
        return (security_view,)
    if security_view != normalized:
        views.append(security_view)
    for view in tuple(views):
        decoded = view
        for _ in range(4):
            candidate = re.sub(r"\\(['\"])", r"\1", decoded)
            if candidate == decoded:
                break
            decoded = candidate
            views.append(decoded)
    return tuple(dict.fromkeys(views))


def _fixed_point_security_view(text: str) -> str:
    """Compose bounded text decoders so transform order cannot hide credential syntax."""
    decoded = text
    for _ in range(12):
        candidate = UNICODE_ESCAPE.sub(lambda match: chr(int(match.group(1), 16)), decoded)
        candidate = HEX_ESCAPE.sub(lambda match: chr(int(match.group(1), 16)), candidate)
        candidate = OCTAL_ESCAPE.sub(lambda match: chr(int(match.group(1), 8)), candidate)
        candidate = unicodedata.normalize("NFKC", candidate)
        candidate = re.sub(r"\\\r?\n[ \t]*", "", candidate)
        candidate = "".join(
            character
            for character in candidate
            if character in {"\r", "\n"} or not _is_default_ignorable(character)
        )
        candidate = unicodedata.normalize("NFKC", unquote(candidate))
        if candidate == decoded:
            break
        decoded = candidate
    if PERCENT_ESCAPE.search(decoded):
        return "...redacted"
    return decoded


def _has_ambiguous_spaced_private_path(text: str) -> bool:
    """Fail closed when a private absolute path clearly continues after whitespace."""
    return (
        re.search(
            r"(?i)(?:"
            r"(?<![A-Za-z0-9])[A-Z]:[\\/]"
            r"|\\\\[A-Z0-9.$_-]+[\\/]"
            r"|(?<![A-Za-z0-9])/(?:home|Users|tmp|mnt|srv|opt|workspace|run|u01|"
            r"root|private|secrets?|var|etc|usr|data|github|nix|Volumes|dev|proc)/"
            r")[^\r\n\"'`)\]}>;,?#&]*\s+[^\r\n\"'`)\]}>;,?#&]*[\\/]",
            text,
        )
        is not None
    )


def _sanitize_json_value(item: object, depth: int = 0, *, public: bool = False) -> object:
    if depth > 64:
        return "...redacted"
    if isinstance(item, dict):
        safe = {}
        for index, (key, child) in enumerate(item.items()):
            raw_key = str(key)
            safe_key = _redact_public_segment(raw_key) if public else raw_key
            if safe_key != raw_key:
                safe_key = f"masked_field_{index}"
            safe[safe_key] = (
                "...redacted"
                if is_sensitive_key(key)
                else _sanitize_json_value(child, depth + 1, public=public)
            )
        return safe
    if isinstance(item, list):
        return [_sanitize_json_value(child, depth + 1, public=public) for child in item]
    if isinstance(item, str):
        return _redact_public_segment(item) if public else _redact_scalar_text(item)
    if isinstance(item, float) and not math.isfinite(item):
        return None
    return item


def _redact_embedded_json(text: str, *, public: bool = False) -> str:
    decoder = json.JSONDecoder()
    output: list[str] = []
    cursor = 0
    search_from = 0
    while search_from < len(text):
        starts = [
            position for token in ("{", "[") if (position := text.find(token, search_from)) >= 0
        ]
        if not starts:
            break
        start = min(starts)
        try:
            value, consumed = decoder.raw_decode(text[start:])
        except RecursionError:
            return "...redacted"
        except (json.JSONDecodeError, TypeError, ValueError):
            search_from = start + 1
            continue
        if not isinstance(value, (dict, list)):
            search_from = start + max(consumed, 1)
            continue
        outside = text[cursor:start]
        output.append(_redact_public_segment(outside) if public else outside)
        try:
            output.append(
                json.dumps(
                    _sanitize_json_value(value, public=public),
                    ensure_ascii=True,
                    separators=(",", ":"),
                )
            )
        except (TypeError, ValueError):
            output.append("...redacted")
        cursor = start + consumed
        search_from = cursor
    remainder = text[cursor:]
    output.append(_redact_public_segment(remainder) if public else remainder)
    return "".join(output)


def _redact_query_segment(match: re.Match[str]) -> str:
    if not _query_segment_has_url_context(match):
        return match.group(0)
    segment, suffix = _split_query_markup_suffix(match.group("segment"))
    original_key, original_separator, _ = segment.partition("=")
    if not original_separator:
        return f"{match.group('prefix')}...redacted{suffix}"
    return f"{match.group('prefix')}{original_key}=...redacted{suffix}"


def _redact_public_query_segment(match: re.Match[str]) -> str:
    if not _query_segment_has_url_context(match):
        return match.group(0)
    segment, _ = _split_query_markup_suffix(match.group("segment"))
    original_key, original_separator, _ = segment.partition("=")
    if not original_separator or is_sensitive_key(original_key):
        return _redact_query_segment(match)
    return match.group(0)


def _split_query_markup_suffix(segment: str) -> tuple[str, str]:
    """Keep Markdown/quoted URL delimiters outside a redacted query value."""
    boundary = re.search(r"[)\]}>\"']+$", segment)
    if boundary is None:
        return segment, ""
    return segment[: boundary.start()], boundary.group(0)


def _query_segment_has_url_context(match: re.Match[str]) -> bool:
    if match.group("prefix") == "?":
        return True
    token_start = max(match.string.rfind(separator, 0, match.start()) for separator in " \t\r\n\"'")
    prefix_text = match.string[token_start + 1 : match.start()]
    return "?" in prefix_text or "://" in prefix_text


def _redact_encoded_url_authority(match: re.Match[str]) -> str:
    authority = match.group("authority")
    if "@" in authority:
        return match.group(0)
    decoded = authority
    for _ in range(8):
        candidate = unquote_plus(decoded)
        if candidate == decoded:
            break
        decoded = candidate
    if "@" in decoded or re.search(r"%[0-9a-f]{2}", decoded, flags=re.IGNORECASE):
        return f"{match.group('prefix')}...redacted"
    return match.group(0)


def _redact_complete_json(text: str) -> str:
    """Backward-compatible wrapper for callers that expect complete-JSON redaction."""
    try:
        value = json.loads(text)
    except (json.JSONDecodeError, RecursionError, TypeError, ValueError):
        return text
    try:
        return json.dumps(_sanitize_json_value(value), ensure_ascii=True, separators=(",", ":"))
    except (TypeError, ValueError):
        return "...redacted"


def _redact_assignment(match: re.Match[str]) -> str:
    if not is_sensitive_env_key(match.group("name").strip()):
        return match.group("assignment")
    value = match.group("value")
    quote = value[0] if value[:1] in {'"', "'"} else ""
    return f"{match.group('key')}{quote}...redacted{quote}"


def _public_sensitive_assignment_is_benign(name: str, value: str) -> bool:
    """Recognize a narrow vocabulary of ordinary, unquoted research prose."""
    value = value.strip()
    if value[:1] in {'"', "'"}:
        return False
    words = re.findall(r"[A-Za-z]+", value)
    if len(words) < 2 or not re.fullmatch(r"[A-Za-z][A-Za-z0-9 ._-]{1,255}", value):
        return False
    key = re.sub(r"[^a-z0-9]", "", name.casefold())
    allowed_first_words = {
        "token": {
            "accuracy",
            "budget",
            "bucket",
            "classification",
            "count",
            "economy",
            "embedding",
            "entropy",
            "length",
            "limit",
            "merging",
            "pruning",
            "representation",
            "ring",
            "routing",
            "sequence",
            "transformer",
            "usage",
        },
        "auth": {"authentication", "authorization", "method", "oauth", "protocol", "scheme"},
        "secret": {"biochemical", "biology", "protein"},
    }
    return words[0].casefold() in allowed_first_words.get(key, set())


def _redact_public_assignment(match: re.Match[str]) -> str:
    """Preserve a narrow vocabulary of ordinary multiword research prose."""
    if not is_sensitive_env_key(match.group("name").strip()):
        return match.group("assignment")
    if _public_sensitive_assignment_is_benign(match.group("name"), match.group("value")):
        return match.group("assignment")
    return _redact_assignment(match)


def _redact_sensitive_assignments(text: str, *, public: bool = False) -> str:
    """Replace classified assignments while allowing overlapping nested representations."""
    output: list[str] = []
    cursor = 0
    renderer = _redact_public_assignment if public else _redact_assignment
    for match in SENSITIVE_ASSIGNMENT.finditer(text):
        if not is_sensitive_env_key(match.group("name").strip()):
            continue
        if _is_k8s_reference_key(match, text) or _is_protected_reference_value(
            match.group("value")
        ):
            continue
        start, end = match.span("assignment")
        if start < cursor:
            continue
        output.append(text[cursor:start])
        output.append(renderer(match))
        cursor = end
    if cursor == 0:
        return text
    output.append(text[cursor:])
    return "".join(output)


def _is_k8s_reference_key(match: re.Match[str], text: str) -> bool:
    if re.sub(r"[^a-z0-9]", "", match.group("name").casefold()) != "key":
        return False
    line_start = text.rfind("\n", 0, match.start("name")) + 1
    current_line = text[line_start : match.start("name")]
    current_indent = len(current_line.expandtabs(8)) - len(current_line.lstrip().expandtabs(8))
    if current_indent == 0:
        return False
    for line in reversed(text[:line_start].splitlines()):
        if not line.strip():
            continue
        indent = len(line.expandtabs(8)) - len(line.lstrip().expandtabs(8))
        if indent < current_indent:
            return (
                re.fullmatch(r"(?:secretKeyRef|configMapKeyRef)[ \t]*:", line.strip(), re.I)
                is not None
            )
    return False


def _is_protected_reference_value(value: str) -> bool:
    return (
        re.fullmatch(r"__WEIPING_DYNAMIC_REFERENCE_[0-9]+__", value.strip().rstrip(",;"))
        is not None
    )


def _redact_auth_credential(match: re.Match[str]) -> str:
    value = match.group("value")
    quote = value[0] if value[:1] in {'"', "'"} else ""
    return f"{match.group('scheme')}{match.group('space')}{quote}...redacted{quote}"


def _redact_public_auth_credential(match: re.Match[str]) -> str:
    value = match.group("value")
    quoted = value[:1] in {'"', "'"} and value[-1:] == value[:1]
    candidate = value[1:-1] if quoted else value
    scheme = match.group("scheme").casefold()
    if candidate in {"=", "==", ":="}:
        return match.group(0)
    if scheme == "token" and candidate.casefold() in {
        "accuracy",
        "budget",
        "bucket",
        "classification",
        "count",
        "economy",
        "embedding",
        "entropy",
        "length",
        "limit",
        "merging",
        "pruning",
        "representation",
        "ring",
        "routing",
        "sequence",
        "transformer",
        "usage",
    }:
        return match.group(0)
    if scheme == "apikey" and candidate.casefold() in {
        "governance",
        "management",
        "policy",
        "rotation",
        "security",
    }:
        return match.group(0)
    if scheme == "bearer" and candidate.casefold() in {
        "bonds",
        "instruments",
        "plants",
        "securities",
        "shares",
    }:
        return match.group(0)
    if scheme == "bearer":
        pass
    elif scheme == "basic":
        try:
            decoded = base64.b64decode(candidate, validate=True)
        except (binascii.Error, ValueError):
            return match.group(0)
        if b":" not in decoded or len(decoded) > 1_024:
            return match.group(0)
    elif scheme in {"token", "apikey"}:
        if not 1 <= len(candidate) <= 2_048:
            return match.group(0)
    else:
        return match.group(0)
    return _redact_auth_credential(match)


def _scrub_configured_env_secrets(text: str) -> str:
    """Remove configured credentials and reconstructable canonical fragments."""
    secrets: set[str] = set()
    protected_canonical: set[str] = set()
    try:
        environment = tuple(os.environ.items())
    except Exception:
        return "...redacted"
    for name, value in environment:
        try:
            if (
                is_sensitive_env_key(name)
                and isinstance(value, str)
                and 4 <= len(value) <= 8_192
                and value.strip().casefold() not in EMPTY_CONFIG_VALUES
            ):
                variants = {value, unicodedata.normalize("NFKC", value)}
                decoded = unicodedata.normalize("NFKC", value)
                for _ in range(8):
                    candidate = unicodedata.normalize("NFKC", unquote(decoded))
                    if candidate == decoded:
                        break
                    decoded = candidate
                    variants.add(decoded)
                variants.update(_flatten_controls(candidate) for candidate in tuple(variants))
                raw_bytes = value.encode("utf-8")
                encoded_variants = {
                    base64.b64encode(raw_bytes).decode("ascii"),
                    base64.urlsafe_b64encode(raw_bytes).decode("ascii"),
                    raw_bytes.hex(),
                    raw_bytes.hex().upper(),
                }
                variants.update(encoded_variants)
                variants.update(encoded.rstrip("=") for encoded in encoded_variants)
                secrets.update(candidate for candidate in variants if len(candidate) >= 4)
                canonical = _canonical_secret_text(value)
                if len(canonical) >= 4:
                    protected_canonical.add(canonical)
                    if len(canonical) >= 12:
                        protected_canonical.update(
                            canonical[index : index + 12] for index in range(len(canonical) - 11)
                        )
        except Exception:
            continue
    for secret in sorted(secrets, key=len, reverse=True):
        text = text.replace(secret, "...redacted")
    canonical_text = _canonical_secret_text(text)
    if any(fragment in canonical_text for fragment in protected_canonical):
        return "...redacted"
    return text


def _canonical_secret_text(value: str) -> str:
    canonical = unicodedata.normalize("NFKC", value)
    for _ in range(8):
        candidate = unicodedata.normalize("NFKC", unquote(canonical))
        if candidate == canonical:
            break
        canonical = candidate
    return "".join(
        character
        for character in canonical
        if not character.isspace() and not _is_default_ignorable(character)
    )


def _is_default_ignorable(character: str) -> bool:
    codepoint = ord(character)
    return (
        unicodedata.category(character) in {"Cc", "Cf", "Cs", "Zl", "Zp"}
        or codepoint in {0x034F, 0x3164, 0xFEFF, 0xFFA0}
        or 0x115F <= codepoint <= 0x1160
        or 0x17B4 <= codepoint <= 0x17B5
        or 0x180B <= codepoint <= 0x180F
        or 0x2060 <= codepoint <= 0x206F
        or 0xFE00 <= codepoint <= 0xFE0F
        or 0xFFF0 <= codepoint <= 0xFFF8
        or 0x1BCA0 <= codepoint <= 0x1BCA3
        or 0x1D173 <= codepoint <= 0x1D17A
        or 0xE0000 <= codepoint <= 0xE0FFF
    )


def safe_error(error: object, limit: int = 300) -> str:
    try:
        normalized = str(error)
    except Exception:
        normalized = "...redacted"
    if len(normalized) > 65_536:
        normalized = normalized[:65_536]
    message = _scrub_configured_env_secrets(redact(normalized)).strip()
    try:
        safe_limit = max(4, int(limit))
    except (OverflowError, TypeError, ValueError):
        safe_limit = 300
    return message if len(message) <= safe_limit else f"{message[: safe_limit - 3]}..."


def endpoint_host(url: object) -> str:
    """Return only a validated host and optional port from an untrusted endpoint."""
    try:
        text = str(url or "").strip()
    except Exception:
        return UNCONFIGURED_ENDPOINT
    if not text or "\\" in text or any(char.isspace() or ord(char) < 32 for char in text):
        return UNCONFIGURED_ENDPOINT
    if re.match(r"^https?://", text, flags=re.IGNORECASE):
        candidate = text
    elif text.startswith("//"):
        candidate = text
    else:
        if any(marker in text for marker in ("/", "?", "#", "@")):
            return UNCONFIGURED_ENDPOINT
        if text.startswith("["):
            closing = text.find("]")
            if closing < 0 or (text[closing + 1 :] and not text[closing + 1 :].startswith(":")):
                return UNCONFIGURED_ENDPOINT
            port_text = text[closing + 2 :] if text[closing + 1 :].startswith(":") else ""
            if text[closing + 1 :].startswith(":") and not port_text:
                return UNCONFIGURED_ENDPOINT
            if port_text and not port_text.isdigit():
                return UNCONFIGURED_ENDPOINT
        elif ":" in text:
            if text.count(":") != 1:
                return UNCONFIGURED_ENDPOINT
            _, port_text = text.rsplit(":", 1)
            if not port_text or not port_text.isdigit():
                return UNCONFIGURED_ENDPOINT
        candidate = f"//{text}"
    try:
        parsed = urlsplit(candidate)
        host = _normalize_endpoint_hostname(parsed.hostname or "")
    except (TypeError, UnicodeError, ValueError):
        return UNCONFIGURED_ENDPOINT
    if not host:
        return UNCONFIGURED_ENDPOINT
    if parsed.netloc.endswith(":"):
        return UNCONFIGURED_ENDPOINT

    display_host = f"[{host}]" if ":" in host else host
    try:
        port = parsed.port
    except (TypeError, ValueError):
        return UNCONFIGURED_ENDPOINT
    return f"{display_host}:{port}" if port is not None else display_host


def _normalize_endpoint_hostname(host: str) -> str:
    if not host or len(host) > 253 or "%" in host:
        return ""
    try:
        return str(ipaddress.ip_address(host)).lower()
    except ValueError:
        pass
    try:
        ascii_host = host.rstrip(".").encode("idna").decode("ascii").lower()
    except (UnicodeError, ValueError):
        return ""
    if not ascii_host or len(ascii_host) > 253:
        return ""
    labels = ascii_host.split(".")
    if any(
        not label
        or len(label) > 63
        or label.startswith("-")
        or label.endswith("-")
        or re.fullmatch(r"[a-z0-9_-]+", label) is None
        for label in labels
    ):
        return ""
    return ascii_host


def env_flag(name: str) -> bool:
    return is_configured_value(os.environ.get(name, ""))


def is_configured_value(value: str) -> bool:
    text = str(value or "").strip()
    if text.lower() in EMPTY_CONFIG_VALUES:
        return False
    if text.startswith("<") and text.endswith(">"):
        return False
    return True
