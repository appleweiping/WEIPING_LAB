"""Release guard for public-safe Weiping Lab builds."""

from __future__ import annotations

import ast
import base64
import binascii
import hashlib
import io
import json
import re
import subprocess
import sys
import tomllib
import tokenize
import unicodedata
import yaml
from collections import Counter
from pathlib import Path
from urllib.parse import unquote, urlsplit


ROOT = Path(__file__).resolve().parents[1]
TEXT_SUFFIXES = {
    "",
    ".cmd",
    ".css",
    ".example",
    ".js",
    ".json",
    ".jsx",
    ".md",
    ".py",
    ".ps1",
    ".toml",
    ".txt",
    ".yml",
    ".yaml",
}
SKIP_PARTS = {
    ".git",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".tools",
    ".venv",
    "__pycache__",
    "build",
    "dist",
    "node_modules",
    "vipin_lab.egg-info",
    "weiping_lab.egg-info",
}
SECRET_PATTERNS = [
    ("secret-api-key", re.compile(r"\bsk-(?:or-v1-)?[A-Za-z0-9_-]{10,}", re.IGNORECASE)),
    ("github-token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b")),
    ("github-fine-grained-token", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b", re.I)),
    (
        "authorization-basic",
        re.compile(
            r"\bAuthorization\b(?:\\+)?['\"]?\s*[:=]\s*(?:\\+)?['\"]?Basic\s+"
            r"[A-Za-z0-9+/]{8,}={0,2}(?![A-Za-z0-9+/=])",
            re.I,
        ),
    ),
    (
        "authorization-bearer",
        re.compile(
            r"\bAuthorization\b(?:\\+)?['\"]?\s*[:=]\s*(?:\\+)?['\"]?Bearer\s+"
            r"[A-Za-z0-9._~+/-]{20,}(?![A-Za-z0-9._~+/-])",
            re.I,
        ),
    ),
    (
        "known-provider-token",
        re.compile(
            r"(?<![A-Za-z0-9])(?:"
            r"glpat-[A-Za-z0-9_-]{20,}|xox[baprs]-[A-Za-z0-9-]{20,}|"
            r"hf_[A-Za-z0-9]{20,}|sk_(?:live|test)_[A-Za-z0-9]{16,}|"
            r"npm_[A-Za-z0-9]{20,}|pypi-[A-Za-z0-9_-]{20,}|"
            r"AIza[0-9A-Za-z_-]{30,}|hvs\.[A-Za-z0-9_-]{20,}"
            r")(?![A-Za-z0-9])",
            re.I,
        ),
    ),
    (
        "jwt-token",
        re.compile(r"(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"),
    ),
    ("aws-access-key", re.compile(r"\bAKIA[A-Z0-9]{16}\b")),
    ("private-key", re.compile(r"BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY")),
    (
        "private-ipv4-endpoint",
        re.compile(
            r"(?<!\d)(?:10(?:\.\d{1,3}){3}|192\.168(?:\.\d{1,3}){2}|169\.254(?:\.\d{1,3}){2}|"
            r"172\.(?:1[6-9]|2\d|3[01])(?:\.\d{1,3}){2})(?::\d{1,5})?(?!\d)"
        ),
    ),
    (
        "private-ipv6-endpoint",
        re.compile(r"(?:\[)?f[cd][0-9a-f]{2}:[0-9a-f:]+(?:\])?(?::\d{1,5})?", re.I),
    ),
    (
        "link-local-ipv6-endpoint",
        re.compile(r"(?:\[)?fe[89ab][0-9a-f]:[0-9a-f:]+(?:\])?(?::\d{1,5})?", re.I),
    ),
    (
        "private-dns-endpoint",
        re.compile(
            r"(?<![a-z0-9.-])(?:[a-z0-9-]+\.)+(?:internal|local)"
            r"(?::\d{1,5})?(?![a-z0-9.-])",
            re.I,
        ),
    ),
    (
        "url-userinfo",
        re.compile(
            r"\b[A-Za-z][A-Za-z0-9+.-]*://[^\s/@?#]+(?::[^\s/@?#]*)?@",
            re.I,
        ),
    ),
]
STATIC_RECONSTRUCTED_SECRET_CODES = {
    "aws-access-key",
    "github-fine-grained-token",
    "github-token",
    "jwt-token",
    "known-provider-token",
    "private-key",
    "secret-api-key",
}
BINARY_PATTERN_MARKERS = {
    "secret-api-key": ("sk-",),
    "github-token": ("ghp_", "gho_", "ghu_", "ghs_", "ghr_"),
    "github-fine-grained-token": ("github_pat_",),
    "authorization-basic": ("authorization",),
    "authorization-bearer": ("authorization",),
    "known-provider-token": (
        "glpat-",
        "xox",
        "hf_",
        "sk_live_",
        "sk_test_",
        "npm_",
        "pypi-",
        "aiza",
        "hvs.",
    ),
    "jwt-token": ("eyj",),
    "aws-access-key": ("akia",),
    "private-key": ("private key",),
    "private-ipv4-endpoint": (".",),
    "private-ipv6-endpoint": (":",),
    "link-local-ipv6-endpoint": (":",),
    "private-dns-endpoint": (".internal", ".local"),
    "url-userinfo": ("://",),
}
BINARY_ASCII_RUN = re.compile(rb"[\t\n\r\x20-\x7e]{8,}")
BINARY_UTF16_RUNS = (
    ("utf-16-le", re.compile(rb"(?:[\t\n\r\x20-\x7e]\x00){8,}")),
    ("utf-16-be", re.compile(rb"(?:\x00[\t\n\r\x20-\x7e]){8,}")),
)
BINARY_CONFIG_MARKERS = (
    "api-key",
    "api_key",
    "apikey",
    "auth",
    "cookie",
    "credential",
    "dsn",
    "key",
    "passphrase",
    "passwd",
    "password",
    "putenv",
    "secret",
    "setenvironmentvariable",
    "setenv",
    "token",
    "webhook",
)
BINARY_SEMANTIC_WINDOW_BEFORE = 8_192
BINARY_SEMANTIC_WINDOW_AFTER = 32_768
RETIRED_MARKERS = (
    "agent" + "-hub",
    "messages" + "-vlab",
    "memory" + "\\sessions",
    "memory" + "/sessions",
    "sbb" + "bb",
    "xiang" + "sumao",
    "REDACTED" + "_",
    "registry." + "npmmirror.com",
    "Vipin" + "'s Knowledgebase" + "\\memory",
    "Vipin" + "'s Knowledgebase" + "/memory",
)
ALLOWED_ACTIONS = Counter(
    {
        "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1": 1,
        "actions/setup-python@5fda3b95a4ea91299a34e894583c3862153e4b97": 1,
        "actions/setup-node@820762786026740c76f36085b0efc47a31fe5020": 1,
    }
)
PRIVATE_TRACKED_NAMES = {
    ".envrc",
    ".git-credentials",
    ".htpasswd",
    ".netrc",
    ".pgpass",
    ".vault-token",
    "_netrc",
    "auth.json",
    ".npmrc",
    ".pypirc",
    "credentials",
    "credentials.json",
    "id_dsa",
    "id_ed25519",
    "id_ecdsa",
    "id_rsa",
    "pip.conf",
    "secrets.json",
}
PRIVATE_TRACKED_SUFFIXES = {".key", ".p12", ".pem", ".pfx"}
PRIVATE_TRACKED_PATHS = {
    ".config/gh/hosts.yml",
    ".docker/config.json",
    ".kube/config",
    ".ssh/config",
}
CRITICAL_GATE_SHA256 = {
    "Makefile": "1d36525cd0d4c8dcc42d8f1ddae59d2c7b02a9ac4a94a39dfe094453b63ade05",
    "scripts/run_ruff.py": "497f333d4745661df0d1c9951cbf37bc876e4dbd6a1083895b19079eb0389282",
    "scripts/verify.ps1": "7f4314029b16de206938554d68a640bf2ed93fc263fd6cc073ae2e790920fec9",
}
OVERRIDE_CONFIG_NAMES = {
    ".pytest.ini",
    ".pytest.toml",
    ".ruff.toml",
    "pytest.ini",
    "pytest.toml",
    "ruff.toml",
    "setup.cfg",
    "tox.ini",
}
EXPECTED_UI_SCRIPTS = {
    "build": "vite build",
    "dev": "vite",
    "lint": "eslint .",
    "preview": "vite preview",
}
UNICODE_ESCAPE = re.compile(r"\\u([0-9a-fA-F]{4})")
HEX_ESCAPE = re.compile(r"\\x([0-9a-fA-F]{2})")
OCTAL_ESCAPE = re.compile(r"\\([0-7]{1,3})")
CONFIGURED_CREDENTIAL_ASSIGNMENT = re.compile(
    r"(?<![A-Za-z0-9_])(?P<name>_*[A-Za-z][A-Za-z0-9_.-]{1,127})"
    r"(?P<key_quote>(?:\\+)?['\"])?\s*[:=]"
    r"(?P<gap>[ \t]*|[ \t]*\r?\n[ \t]*"
    r"(?!(?:\\+)?['\"][A-Za-z_][A-Za-z0-9_.-]*(?:\\+)?['\"][ \t]*[:=])"
    r"(?=(?:\\+)?['\"])|"
    r"[ \t]*\r?\n[ \t]+(?![A-Za-z_][A-Za-z0-9_.-]*[ \t]*[:=])"
    r"(?=[A-Za-z0-9_./:@+-])|"
    r"[ \t]*[|>](?:[1-9][+-]?|[+-][1-9]?)?[ \t]*\r?\n[ \t]+)"
    r"(?:(?P<triple_quote>'''|\"\"\")(?P<triple_value>"
    r"(?:(?!(?P=triple_quote))[^\ufdd0]){4,}?)(?P=triple_quote)|"
    r"(?:\\+)?(?P<value_quote>['\"])(?P<quoted_value>"
    r"(?:\\[^\ufdd0]|(?!(?P=value_quote))[^\ufdd0]){4,}?)(?P=value_quote)|"
    r"(?P<unquoted_value>[^\s#'\"<>{}$\ufdd0]{4,}))",
    re.I,
)
AUTHORIZATION_CREDENTIAL = re.compile(
    r"(?<![A-Za-z0-9_])authorization(?:\\+)?['\"]?\s*[:=]\s*"
    r"(?:\\+)?['\"]?(?:basic|bearer|digest|token|apikey)\s+"
    r"(?:(?P<credential_quote>['\"])(?P<quoted_credential>"
    r"(?:\\.|[^'\"\r\n]){4,}?)(?P=credential_quote)|"
    r"(?P<credential>[^\s\r\n'\"]{4,}))",
    re.I,
)
STRUCTURED_CREDENTIAL_ASSIGNMENTS = (
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
    r"(?<![A-Za-z0-9])[A-Z]:[\\/]"
    r"|\x5c\x5c[A-Z0-9][A-Z0-9._-]{0,62}[\\/][A-Z0-9][^\s]+"
    r"|(?<![A-Za-z0-9])/(?:home|Users)/[A-Z0-9._-]+(?:/|$)"
    r"|(?<![A-Za-z0-9])/(?:root|tmp/[A-Z0-9._-]+)(?:/|$)"
    r"|(?<![A-Za-z0-9])/mnt/[A-Z]/Users/[A-Z0-9._-]+(?:/|$)"
    r")"
)


class _UniqueSafeLoader(yaml.SafeLoader):
    """Safe YAML loader that rejects duplicate keys at every mapping depth."""


_UniqueSafeLoader.yaml_implicit_resolvers = {
    key: list(resolvers) for key, resolvers in yaml.SafeLoader.yaml_implicit_resolvers.items()
}
for _resolver_key, _resolvers in _UniqueSafeLoader.yaml_implicit_resolvers.items():
    _UniqueSafeLoader.yaml_implicit_resolvers[_resolver_key] = [
        (tag, pattern) for tag, pattern in _resolvers if tag != "tag:yaml.org,2002:bool"
    ]
_UniqueSafeLoader.add_implicit_resolver(
    "tag:yaml.org,2002:bool",
    re.compile(r"^(?:true|false)$", re.I),
    list("tTfF"),
)


def _construct_unique_mapping(loader, node, deep=False):
    loader.flatten_mapping(node)
    mapping = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        try:
            duplicate = key in mapping
        except TypeError as exc:
            raise yaml.constructor.ConstructorError(
                "while constructing a mapping",
                node.start_mark,
                "found an unhashable mapping key",
                key_node.start_mark,
            ) from exc
        if duplicate:
            raise yaml.constructor.ConstructorError(
                "while constructing a mapping",
                node.start_mark,
                f"found duplicate key {key!r}",
                key_node.start_mark,
            )
        mapping[key] = loader.construct_object(value_node, deep=deep)
    return mapping


_UniqueSafeLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_unique_mapping,
)


def main() -> int:
    failures: list[str] = []
    try:
        release_before = _read_release_snapshots()
    except (OSError, RuntimeError, UnicodeError) as exc:
        failures.append(f"release snapshot failed closed: {type(exc).__name__}")
        release_before = None
    _check_forbidden_text(failures)
    _check_version_consistency(failures)
    _check_workspace_source_tracked(failures)
    _check_env_example(failures)
    _check_package_lock(failures)
    _check_ruff_policy(failures)
    _check_evidence_contract(failures)
    _check_windows_gate(failures)
    _check_critical_gate_files(failures)
    _check_ci_contract(failures)

    if release_before is not None:
        try:
            release_after = _read_release_snapshots()
            tree_matches_index = _working_tree_matches_index()
            index_flags_safe = _index_flags_are_safe()
        except (OSError, RuntimeError, UnicodeError) as exc:
            failures.append(f"release resnapshot failed closed: {type(exc).__name__}")
        else:
            if release_before != release_after:
                failures.append("tracked sources changed during the complete release gate")
            if not tree_matches_index or release_after.get("index") != release_after.get(
                "worktree"
            ):
                failures.append("tracked index and worktree differ after the complete release gate")
            if not index_flags_safe:
                failures.append(
                    "tracked files gained unsafe index visibility flags during release gate"
                )

    if failures:
        print("release scan failed:")
        for item in failures:
            print(f" - {item}")
        return 1
    print("release scan passed")
    return 0


def _tracked_paths() -> tuple[Path, ...]:
    result = subprocess.run(
        ["git", "-C", str(ROOT), "ls-files", "-z"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError("git ls-files failed")
    paths = []
    for raw_name in result.stdout.split(b"\0"):
        if not raw_name:
            continue
        name = raw_name.decode("utf-8", errors="strict")
        relative = Path(name)
        if relative.is_absolute() or ".." in relative.parts or any(ord(char) < 32 for char in name):
            raise RuntimeError("git returned an unsafe tracked path")
        paths.append(relative)
    return tuple(sorted(paths, key=lambda path: path.as_posix()))


def _read_tracked_snapshot() -> dict[Path, bytes]:
    snapshot = {}
    for relative in _tracked_paths():
        path = ROOT / relative
        if not path.is_file():
            raise RuntimeError(f"tracked path is not a regular file: {relative.as_posix()}")
        snapshot[relative] = path.read_bytes()
    return snapshot


def _read_index_snapshot() -> dict[Path, bytes]:
    listing = subprocess.run(
        ["git", "-C", str(ROOT), "ls-files", "--stage", "-z"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if listing.returncode != 0:
        raise RuntimeError("git ls-files --stage failed")
    entries: list[tuple[Path, bytes]] = []
    for record in listing.stdout.split(b"\0"):
        if not record:
            continue
        try:
            metadata, raw_path = record.split(b"\t", 1)
            _mode, object_id, stage = metadata.split()
            relative = Path(raw_path.decode("utf-8"))
        except (UnicodeError, ValueError) as exc:
            raise RuntimeError("invalid staged index entry") from exc
        if stage != b"0":
            raise RuntimeError("unmerged staged index entry")
        entries.append((relative, object_id))

    batch = subprocess.run(
        ["git", "-C", str(ROOT), "cat-file", "--batch"],
        input=b"".join(object_id + b"\n" for _, object_id in entries),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if batch.returncode != 0:
        raise RuntimeError("git cat-file --batch failed")
    snapshot: dict[Path, bytes] = {}
    cursor = 0
    for relative, expected_id in entries:
        line_end = batch.stdout.find(b"\n", cursor)
        if line_end < 0:
            raise RuntimeError("truncated git cat-file header")
        header = batch.stdout[cursor:line_end].split()
        if len(header) != 3 or header[0] != expected_id or header[1] != b"blob":
            raise RuntimeError("unexpected staged object type")
        try:
            size = int(header[2])
        except ValueError as exc:
            raise RuntimeError("invalid staged object size") from exc
        start = line_end + 1
        end = start + size
        if end >= len(batch.stdout) or batch.stdout[end : end + 1] != b"\n":
            raise RuntimeError("truncated staged object")
        snapshot[relative] = batch.stdout[start:end]
        cursor = end + 1
    if cursor != len(batch.stdout):
        raise RuntimeError("unexpected trailing staged object data")
    return snapshot


def _read_release_snapshots() -> dict[str, dict[Path, bytes]]:
    return {
        "index": _read_index_snapshot(),
        "worktree": _read_tracked_snapshot(),
    }


def _working_tree_matches_index() -> bool:
    result = subprocess.run(
        ["git", "-C", str(ROOT), "diff", "--quiet", "--no-ext-diff", "--"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if result.returncode not in (0, 1):
        raise RuntimeError("git diff failed")
    return result.returncode == 0


def _index_flags_are_safe() -> bool:
    result = subprocess.run(
        ["git", "-C", str(ROOT), "ls-files", "-v", "-z"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError("git ls-files flags failed")
    for entry in result.stdout.split(b"\0"):
        if not entry:
            continue
        tag = chr(entry[0])
        if tag == "S" or tag.islower():
            return False
    return True


def _binary_text_runs(raw: bytes) -> tuple[str, ...]:
    """Extract bounded-cost ASCII and UTF-16 ASCII runs from an opaque binary blob."""
    runs = [match.group().decode("ascii") for match in BINARY_ASCII_RUN.finditer(raw)]
    for encoding, pattern in BINARY_UTF16_RUNS:
        runs.extend(match.group().decode(encoding) for match in pattern.finditer(raw))
    return tuple(dict.fromkeys(runs))


def _binary_configured_views(runs: tuple[str, ...]) -> tuple[str, ...]:
    """Return small marker-adjacent windows suitable for configured-credential semantics."""
    candidates: list[str] = []
    for view in runs:
        folded = view.casefold()
        positions: set[int] = set()
        for marker in BINARY_CONFIG_MARKERS:
            start = 0
            while (position := folded.find(marker, start)) >= 0:
                positions.add(position)
                start = position + len(marker)
        if not positions:
            continue
        if len(view) <= BINARY_SEMANTIC_WINDOW_BEFORE + BINARY_SEMANTIC_WINDOW_AFTER:
            candidates.append(view)
            continue
        for position in sorted(positions):
            candidates.append(
                view[
                    max(0, position - BINARY_SEMANTIC_WINDOW_BEFORE) : min(
                        len(view), position + BINARY_SEMANTIC_WINDOW_AFTER
                    )
                ]
            )
    return tuple(dict.fromkeys(candidates))


def _binary_scan_views(raw: bytes) -> tuple[tuple[str, ...], tuple[str, ...]]:
    runs = _binary_text_runs(raw)
    signature_views = ("\0".join(runs),) if runs else ()
    return signature_views, _binary_configured_views(runs)


def _scan_views(raw: bytes, *, text_like: bool | None = None) -> tuple[str, ...]:
    if text_like is None:
        text_like = _is_probably_text(raw)
    if not text_like:
        return _binary_scan_views(raw)[0]

    views = []
    encodings = ["utf-8-sig", "latin-1"]
    if raw.startswith((b"\xff\xfe", b"\xfe\xff")):
        encodings.append("utf-16")
    elif raw.count(b"\0") >= max(2, len(raw) // 10):
        encodings.extend(("utf-16-le", "utf-16-be"))
    for encoding in encodings:
        try:
            text = raw.decode(encoding)
        except (UnicodeDecodeError, UnicodeError):
            continue
        decoded = unicodedata.normalize("NFKC", text)
        views.extend(_unicode_escape_views(decoded))
        for _ in range(8):
            candidate = unicodedata.normalize("NFKC", unquote(decoded))
            if candidate == decoded:
                break
            decoded = candidate
        views.extend(_unicode_escape_views(decoded))
        views.append(_fixed_point_security_view(text))
    unique = list(dict.fromkeys(views))
    return tuple(dict.fromkeys(unique))


def _configured_credential_views(
    raw: bytes, source_path: Path, all_views: tuple[str, ...]
) -> tuple[tuple[str, Path | None], ...]:
    """Keep Python syntax parseable while decoding strings/comments as untrusted data."""
    if source_path.suffix.casefold() != ".py":
        return tuple((view, source_path) for view in all_views)
    try:
        text = raw.decode("utf-8-sig")
    except UnicodeDecodeError:
        text = raw.decode("latin-1")
    text = unicodedata.normalize("NFKC", text)
    views: list[tuple[str, Path | None]] = []
    views.extend((view, None) for view in _python_ast_configured_views(text))
    untrusted_tokens: list[str] = []
    masked = list(text)
    line_offsets = [0]
    line_offsets.extend(match.end() for match in re.finditer(r"\n", text))
    tokenized = False
    try:
        tokens = tokenize.generate_tokens(io.StringIO(text).readline)
        for token in tokens:
            if token.type not in {tokenize.STRING, tokenize.COMMENT}:
                continue
            tokenized = True
            untrusted_tokens.append(token.string)
            start = line_offsets[token.start[0] - 1] + token.start[1]
            end = line_offsets[token.end[0] - 1] + token.end[1]
            for index in range(start, min(end, len(masked))):
                if masked[index] not in {"\r", "\n"}:
                    masked[index] = " "
            if token.type == tokenize.STRING and start + 1 < min(end, len(masked)):
                masked[start] = '"'
                masked[start + 1] = '"'
    except (IndentationError, SyntaxError, tokenize.TokenError):
        pass
    views.insert(0, ("".join(masked) if tokenized else text, source_path))
    if untrusted_tokens:
        # Tokenize changed f-string token boundaries in Python 3.12 (PEP 701).
        # Scan each string/comment independently so neither that version change
        # nor a latin-1 view of a Unicode separator can synthesize a credential
        # across two unrelated source tokens. Static expressions are recovered
        # separately by the AST views above, so real constructed credentials
        # remain fail-closed.
        for token_text in dict.fromkeys(untrusted_tokens):
            views.extend(
                (view, None) for view in _scan_views(token_text.encode("utf-8"), text_like=True)
            )
    return tuple(dict.fromkeys(views))


def _unicode_escape_views(text: str) -> tuple[str, ...]:
    views = [text]
    decoded = text
    for _ in range(4):
        candidate = UNICODE_ESCAPE.sub(lambda match: chr(int(match.group(1), 16)), decoded)
        candidate = HEX_ESCAPE.sub(lambda match: chr(int(match.group(1), 16)), candidate)
        candidate = OCTAL_ESCAPE.sub(lambda match: chr(int(match.group(1), 8)), candidate)
        if candidate == decoded:
            break
        decoded = unicodedata.normalize("NFKC", candidate)
        views.append(decoded)
    return tuple(views)


def _fixed_point_security_view(text: str) -> str:
    """Compose bounded decoders until transform order can no longer hide a match."""
    decoded = text
    for _ in range(12):
        candidate = UNICODE_ESCAPE.sub(lambda match: chr(int(match.group(1), 16)), decoded)
        candidate = HEX_ESCAPE.sub(lambda match: chr(int(match.group(1), 16)), candidate)
        candidate = OCTAL_ESCAPE.sub(lambda match: chr(int(match.group(1), 8)), candidate)
        candidate = unicodedata.normalize("NFKC", candidate)
        candidate = re.sub(r"\\\r?\n[ \t]*", "", candidate)
        candidate = re.sub(r"\\(['\"])", r"\1", candidate)
        candidate = "".join(
            character
            for character in candidate
            if character in {"\r", "\n"} or not _is_default_ignorable(character)
        )
        candidate = unicodedata.normalize("NFKC", unquote(candidate))
        if candidate == decoded:
            break
        decoded = candidate
    return decoded


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


def _is_sensitive_config_name(value: str) -> bool:
    words = [word for word in re.split(r"[^a-z0-9]+", value.casefold()) if word]
    normalized = re.sub(r"[^a-z0-9]", "", value.casefold())
    if not words:
        return False
    if normalized.endswith("publickey"):
        return False
    if normalized in {
        "auth",
        "authorization",
        "cookie",
        "key",
        "password",
        "secret",
        "token",
    } or normalized.endswith(
        (
            "accesskey",
            "apikey",
            "clientsecret",
            "connectionstring",
            "credential",
            "credentials",
            "cookievalue",
            "databaseurl",
            "dburl",
            "dsn",
            "githubpat",
            "gitlabpat",
            "mongodburl",
            "mysqlurl",
            "passphrase",
            "password",
            "passwd",
            "postgresurl",
            "privatekey",
            "redisurl",
            "secret",
            "token",
            "authorizationvalue",
            "webhookurl",
        )
    ):
        return True
    if words[-1] in {
        "auth",
        "authorization",
        "cookie",
        "credential",
        "credentials",
        "dsn",
        "key",
        "password",
        "passwd",
        "passphrase",
        "pat",
        "secret",
        "token",
    }:
        return True
    if words[-2:] in (
        ["client", "secret"],
        ["connection", "string"],
        ["private", "key"],
        ["webhook", "url"],
    ):
        return True
    if words[-1] == "url" and words[-2:-1] in (
        ["database"],
        ["db"],
        ["mongodb"],
        ["mysql"],
        ["postgres"],
        ["redis"],
    ):
        return True
    if normalized.endswith(
        (
            "apikeybase",
            "apikeyconfig",
            "apikeyfile",
            "apikeyvalue",
            "authconfig",
            "secretkeybase",
            "tokenvalue",
        )
    ):
        return True
    if words[-1] in {"base", "config", "file", "value"}:
        stem = words[:-1]
        return bool(stem) and (
            stem[-1] in {"auth", "credential", "credentials", "secret", "token"}
            or stem[-2:] in (["api", "key"], ["secret", "key"])
        )
    return False


def _configured_value_is_placeholder(value: str) -> bool:
    value = re.sub(r"(?:\\[rnt])+$", "", value.strip(), flags=re.I)
    normalized = re.sub(r"[^a-z0-9]+", "_", value.casefold()).strip("_")
    return not normalized or normalized in {
        "api_key_placeholder",
        "change_me",
        "changeme",
        "configured",
        "enter_api_key_here",
        "example",
        "false",
        "insert_api_key_here",
        "none",
        "null",
        "placeholder",
        "redacted",
        "".join(("redacted", "_", "redacted", "_", "redacted")),
        "replace_me_with_your_api_key",
        "replace_with_your_api_key",
        "sample",
        "test",
        "test_key",
        "todo",
        "true",
        "unset",
        "yes",
        "no",
        "your_api_key",
    }


def _is_package_lock_path_key_semver(source_path: Path | None, name: str, value: str) -> bool:
    return (
        source_path is not None
        and source_path.name.casefold() == "package-lock.json"
        and name.casefold() == "path-key"
        and re.fullmatch(r"[~^]?\d+(?:\.\d+){1,3}(?:-[0-9A-Za-z.-]+)?", value) is not None
    )


def _is_generic_schema_placeholder(name: str, value: str) -> bool:
    return (
        re.sub(r"[^a-z0-9]", "", name.casefold()) == "key"
        and re.sub(r"[^a-z0-9]", "", value.casefold()) == "value"
    )


def _structured_value_is_reference(value: str) -> bool:
    if re.fullmatch(
        r"(?:\$(?:env:)?[A-Za-z_][A-Za-z0-9_]*|\$\{env:[A-Za-z_][A-Za-z0-9_]*\}|"
        r"%[A-Za-z_][A-Za-z0-9_]*%|"
        r"\$\([^)]+\))",
        value,
    ):
        return True
    expansion = re.fullmatch(r"\$\{[A-Za-z_][A-Za-z0-9_]*(?::[-+?=](?P<fallback>[^}]*))?\}", value)
    if expansion is None:
        return False
    fallback = expansion.group("fallback")
    return fallback in {None, ""} or fallback.casefold() in {
        "change_me",
        "changeme",
        "default",
        "fallback",
        "placeholder",
        "redacted",
        "unset",
    }


def _ast_offset(text: str, line_offsets: list[int], lineno: int, byte_offset: int) -> int:
    """Translate CPython's UTF-8 AST column offsets into character offsets."""
    line_start = line_offsets[lineno - 1]
    line_end = text.find("\n", line_start)
    if line_end < 0:
        line_end = len(text)
    line = text[line_start:line_end]
    prefix = line.encode("utf-8")[:byte_offset].decode("utf-8", errors="ignore")
    return line_start + len(prefix)


def _assignment_target_names(target: ast.AST) -> tuple[str, ...]:
    if isinstance(target, ast.Name):
        return (target.id,)
    if isinstance(target, ast.Attribute):
        return (target.attr,)
    if isinstance(target, ast.Starred):
        return _assignment_target_names(target.value)
    if isinstance(target, (ast.List, ast.Tuple)):
        return tuple(name for item in target.elts for name in _assignment_target_names(item))
    if isinstance(target, ast.Subscript):
        key = _static_python_text(target.slice)
        return (key,) if key is not None else ()
    return ()


def _static_python_text(node: ast.AST) -> str | None:
    if isinstance(node, ast.Constant):
        if isinstance(node.value, str):
            return node.value
        if isinstance(node.value, bytes):
            return node.value.decode("utf-8", errors="replace")
        return None
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left = _static_python_text(node.left)
        right = _static_python_text(node.right)
        if left is not None and right is not None and len(left) + len(right) <= 1_000_000:
            return left + right
    if isinstance(node, ast.JoinedStr):
        parts = []
        for value in node.values:
            part = _static_python_text(value)
            if part is None:
                return None
            parts.append(part)
        candidate = "".join(parts)
        return candidate if len(candidate) <= 1_000_000 else None
    return None


def _static_python_security_text(node: ast.AST) -> str | None:
    """Recover additional constant-only string forms for signature scanning."""
    direct = _static_python_text(node)
    if direct is not None:
        return direct
    if isinstance(node, ast.FormattedValue):
        if node.conversion != -1 or node.format_spec is not None:
            return None
        return _static_python_security_text(node.value)
    if isinstance(node, ast.JoinedStr):
        parts = [_static_python_security_text(value) for value in node.values]
        if any(part is None for part in parts):
            return None
        candidate = "".join(part for part in parts if part is not None)
        return candidate if len(candidate) <= 1_000_000 else None
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mult):
        if isinstance(node.right, ast.Constant) and isinstance(node.right.value, int):
            value = _static_python_security_text(node.left)
            count = node.right.value
        elif isinstance(node.left, ast.Constant) and isinstance(node.left.value, int):
            value = _static_python_security_text(node.right)
            count = node.left.value
        else:
            return None
        if value is not None and 0 <= count <= 1_000_000 and len(value) * count <= 1_000_000:
            return value * count
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "join"
        and len(node.args) == 1
        and not node.keywords
        and isinstance(node.args[0], (ast.List, ast.Tuple))
    ):
        separator = _static_python_security_text(node.func.value)
        parts = [_static_python_security_text(item) for item in node.args[0].elts]
        if separator is not None and all(part is not None for part in parts):
            candidate = separator.join(part for part in parts if part is not None)
            return candidate if len(candidate) <= 1_000_000 else None
    return None


def _python_call_path(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        prefix = _python_call_path(node.value)
        return f"{prefix}.{node.attr}" if prefix else node.attr
    return ""


def _resolve_python_call_path(path: str, aliases: dict[str, str]) -> str:
    resolved = path
    for _ in range(8):
        head, separator, tail = resolved.partition(".")
        replacement = aliases.get(head)
        if replacement is None:
            break
        candidate = replacement + (separator + tail if separator else "")
        if candidate == resolved:
            break
        resolved = candidate
    return resolved


def _python_call_aliases(tree: ast.AST) -> dict[str, str]:
    aliases: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for item in node.names:
                aliases[item.asname or item.name.split(".", 1)[0]] = item.name
        elif isinstance(node, ast.ImportFrom) and node.module:
            for item in node.names:
                if item.name != "*":
                    aliases[item.asname or item.name] = f"{node.module}.{item.name}"
    assignments = [node for node in ast.walk(tree) if isinstance(node, ast.Assign)]
    for _ in range(8):
        changed = False
        for node in assignments:
            if len(node.targets) != 1 or not isinstance(node.targets[0], ast.Name):
                continue
            path = _python_call_path(node.value)
            if not path:
                continue
            resolved = _resolve_python_call_path(path, aliases)
            if aliases.get(node.targets[0].id) != resolved:
                aliases[node.targets[0].id] = resolved
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
            path = _python_call_path(node.value)
            resolved = _resolve_python_call_path(path, aliases) if path else ""
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


def _is_generic_sensitive_config_name(value: str) -> bool:
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
        "value",
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


def _python_call_static_credentials(
    node: ast.Call, aliases: dict[str, str] | None = None
) -> tuple[tuple[str, str], ...]:
    """Recover literal credentials passed to common environment/config setters."""
    path = _resolve_python_call_path(_python_call_path(node.func), aliases or {}).casefold()
    pairs: list[tuple[ast.AST, ast.AST]] = []
    keywords = {item.arg.casefold(): item.value for item in node.keywords if item.arg is not None}
    if path in {"os.putenv", "putenv"} and len(node.args) >= 2:
        pairs.append((node.args[0], node.args[1]))
    elif path in {"os.putenv", "putenv"} and {"key", "value"} <= keywords.keys():
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
        name = _static_python_text(name_node)
        literal = _static_python_text(value_node)
        if name is not None and literal is not None:
            recovered.append((name, literal))
    return tuple(dict.fromkeys(recovered))


def _python_function_static_defaults(
    node: ast.FunctionDef | ast.AsyncFunctionDef | ast.Lambda,
) -> tuple[tuple[str, str], ...]:
    positional = (*node.args.posonlyargs, *node.args.args)
    pairs: list[tuple[ast.arg, ast.AST]] = list(
        zip(positional[-len(node.args.defaults) :], node.args.defaults, strict=True)
        if node.args.defaults
        else ()
    )
    pairs.extend(
        (argument, default)
        for argument, default in zip(node.args.kwonlyargs, node.args.kw_defaults, strict=True)
        if default is not None
    )
    recovered = []
    for argument, default in pairs:
        literal = _static_python_text(default)
        if literal is not None:
            recovered.append((argument.arg, literal))
    return tuple(recovered)


def _python_ast_configured_views(text: str) -> tuple[str, ...]:
    try:
        tree = ast.parse(text)
    except (SyntaxError, TypeError, ValueError):
        return ()
    alias_snapshots = _python_call_alias_snapshots(tree)
    reconstructed: list[str] = []
    for node in ast.walk(tree):
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
            literal = _static_python_text(value)
            if literal is not None and len(literal) >= 4:
                if _contains_configured_credential(literal):
                    reconstructed.append(literal)
                for target in targets:
                    names = (
                        (node.arg,)
                        if isinstance(node, ast.keyword) and node.arg is not None
                        else _assignment_target_names(target)
                    )
                    for name in names:
                        if (
                            _is_sensitive_config_name(name)
                            and (
                                not _is_generic_sensitive_config_name(name)
                                or _python_target_has_config_context(target)
                                or not _generic_python_key_value_is_semantic(name, literal)
                            )
                            and not _configured_value_is_placeholder(literal)
                        ):
                            reconstructed.append(f"{name}=static-python-credential")

        if isinstance(node, ast.Dict):
            for key, item_value in zip(node.keys, node.values, strict=True):
                if key is None:
                    continue
                name = _static_python_text(key)
                literal = _static_python_text(item_value)
                if (
                    name is not None
                    and literal is not None
                    and len(literal) >= 4
                    and _is_sensitive_config_name(name)
                    and (
                        not _is_generic_sensitive_config_name(name)
                        or not _generic_python_key_value_is_semantic(name, literal)
                    )
                    and not _configured_value_is_placeholder(literal)
                ):
                    reconstructed.append(f"{name}=static-python-credential")
        if isinstance(node, ast.Call):
            for name, literal in _python_call_static_credentials(
                node, alias_snapshots.get(id(node), {})
            ):
                if (
                    len(literal.strip()) >= 4
                    and _is_sensitive_config_name(name)
                    and not _configured_value_is_placeholder(literal)
                ):
                    reconstructed.append(f"{name}=static-python-credential")
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
            for name, literal in _python_function_static_defaults(node):
                if (
                    len(literal.strip()) >= 4
                    and _is_sensitive_config_name(name)
                    and (
                        not _is_generic_sensitive_config_name(name)
                        or not _generic_python_key_value_is_semantic(name, literal)
                    )
                    and not _configured_value_is_placeholder(literal)
                ):
                    reconstructed.append(f"{name}=static-python-credential")
    return tuple(dict.fromkeys(reconstructed))


def _python_ast_security_views(text: str) -> tuple[str, ...]:
    """Reconstruct static Python strings before applying high-confidence signatures."""
    try:
        tree = ast.parse(text)
    except (SyntaxError, TypeError, ValueError):
        return ()
    reconstructed: list[str] = []
    for node in ast.walk(tree):
        candidates: tuple[ast.AST, ...] = ()
        if isinstance(node, ast.Assign):
            candidates = (node.value,)
        elif isinstance(node, (ast.AnnAssign, ast.NamedExpr)):
            candidates = (node.value,)
        elif isinstance(node, ast.keyword):
            candidates = (node.value,)
        elif isinstance(node, ast.Dict):
            candidates = tuple(node.values)
        elif isinstance(node, ast.Call):
            candidates = tuple(node.args) + tuple(item.value for item in node.keywords)
        elif isinstance(node, (ast.List, ast.Set, ast.Tuple)):
            candidates = tuple(node.elts)
        elif isinstance(node, (ast.BinOp, ast.JoinedStr)):
            candidates = (node,)
        for candidate in candidates:
            literal = _static_python_text(candidate)
            if literal is None:
                extended = _static_python_security_text(candidate)
                if extended is not None and any(
                    code in STATIC_RECONSTRUCTED_SECRET_CODES and pattern.search(extended)
                    for code, pattern in SECRET_PATTERNS
                ):
                    literal = extended
            if literal is not None and len(literal) >= 4:
                reconstructed.append(literal)
    return tuple(dict.fromkeys(reconstructed))


def _python_reference_assignment_spans(text: str) -> tuple[tuple[int, int, str | None], ...]:
    try:
        tree = ast.parse(text)
    except (SyntaxError, TypeError, ValueError):
        return ()
    line_offsets = [0]
    line_offsets.extend(match.end() for match in re.finditer(r"\n", text))
    spans: list[tuple[int, int, str | None]] = []
    for node in ast.walk(tree):
        value: ast.AST | None = None
        targets: tuple[ast.AST, ...] = ()
        names: tuple[str, ...] = ()
        wildcard_name = False
        if isinstance(node, ast.Assign):
            value = node.value
            targets = tuple(node.targets)
        elif isinstance(node, (ast.AnnAssign, ast.NamedExpr)):
            value = node.value
            targets = (node.target,)
        elif isinstance(node, ast.keyword) and node.arg is not None:
            value = node.value
            names = (node.arg,)
            targets = (node,)
        elif isinstance(node, ast.DictComp):
            value = node.value
            targets = (node.key,)
            wildcard_name = True
        elif isinstance(node, ast.Dict):
            for key, item_value in zip(node.keys, node.values, strict=True):
                if key is None or isinstance(item_value, (ast.Constant, ast.JoinedStr)):
                    continue
                key_start = _ast_offset(text, line_offsets, key.lineno, key.col_offset)
                value_start = _ast_offset(
                    text, line_offsets, item_value.lineno, item_value.col_offset
                )
                spans.append((key_start, value_start, None))
            continue
        if value is None or isinstance(value, (ast.Constant, ast.JoinedStr)):
            continue
        value_start = _ast_offset(text, line_offsets, value.lineno, value.col_offset)
        for target in targets:
            target_start = _ast_offset(text, line_offsets, target.lineno, target.col_offset)
            target_names = names or _assignment_target_names(target)
            if wildcard_name:
                spans.append((target_start, value_start, None))
            else:
                spans.extend((target_start, value_start, name.casefold()) for name in target_names)
    return tuple(spans)


def _match_is_python_reference(
    match: re.Match[str],
    text: str,
    source_path: Path | None,
    spans: tuple[tuple[int, int, str | None], ...] | None,
) -> tuple[bool, tuple[tuple[int, int, str | None], ...]]:
    resolved = spans or ()
    if source_path is None or source_path.suffix.casefold() != ".py":
        return False, resolved
    if spans is None:
        resolved = _python_reference_assignment_spans(text)
    start = match.start("name")
    end = match.end()
    name = match.group("name").casefold()
    return (
        any(
            span_start <= start < value_start <= end
            and (
                expected_name is None or expected_name == name or name.endswith("." + expected_name)
            )
            for span_start, value_start, expected_name in resolved
        ),
        resolved,
    )


def _match_is_k8s_reference_key(match: re.Match[str], text: str) -> bool:
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


def _contains_configured_credential(text: str, *, source_path: Path | None = None) -> bool:
    if any(
        not _configured_value_is_placeholder(
            match.group("quoted_credential") or match.group("credential") or ""
        )
        for match in AUTHORIZATION_CREDENTIAL.finditer(text)
    ):
        return True
    python_source = source_path is not None and source_path.suffix.casefold() == ".py"
    python_syntax_valid = False
    if python_source:
        try:
            ast.parse(text)
        except (SyntaxError, TypeError, ValueError):
            pass
        else:
            python_syntax_valid = True
    structured_reference_spans: list[tuple[int, int]] = []
    if not python_syntax_valid:
        for pattern in STRUCTURED_CREDENTIAL_ASSIGNMENTS:
            for match in pattern.finditer(text):
                value = match.group("value").strip().rstrip(",/>")
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
                if is_reference:
                    structured_reference_spans.append((match.start("value"), match.end("value")))
                if (
                    _is_sensitive_config_name(match.group("name"))
                    and len(value) >= 4
                    and not is_reference
                    and not _configured_value_is_placeholder(value)
                    and not _is_package_lock_path_key_semver(
                        source_path, match.group("name"), value
                    )
                    and not _is_generic_schema_placeholder(match.group("name"), value)
                    and not bare_authorization_scheme
                ):
                    return True
    reference_spans: tuple[tuple[int, int, str | None], ...] | None = None
    for match in CONFIGURED_CREDENTIAL_ASSIGNMENT.finditer(text):
        if any(
            start <= match.start("name") and match.end() <= end
            for start, end in structured_reference_spans
        ):
            continue
        triple = match.group("triple_value")
        quoted = match.group("quoted_value")
        unquoted = match.group("unquoted_value")
        value = triple or quoted or unquoted or ""
        package_lock_semver = _is_package_lock_path_key_semver(
            source_path, match.group("name"), value
        )
        k8s_reference_key = _match_is_k8s_reference_key(match, text)
        normalized_name = re.sub(r"[^a-z0-9]", "", match.group("name").casefold())
        generic_name = normalized_name in {
            "auth",
            "authorization",
            "cookie",
            "key",
            "password",
            "secret",
            "token",
        }
        generic_python_semantic = (
            python_source
            and generic_name
            and _generic_python_key_value_is_semantic(match.group("name"), value)
        )
        is_reference = False
        if unquoted is not None:
            is_reference, reference_spans = _match_is_python_reference(
                match, text, source_path, reference_spans
            )
        if (
            unquoted is not None
            and "\n" in match.group("gap")
            and source_path is not None
            and source_path.suffix.casefold() == ".py"
        ):
            continue
        if (
            _is_sensitive_config_name(match.group("name"))
            and (
                not generic_name
                or (python_source and not generic_python_semantic)
                or (
                    not python_source
                    and not any(
                        character.isalnum() or character == "_"
                        for character in text[
                            text.rfind("\n", 0, match.start("name")) + 1 : match.start("name")
                        ]
                    )
                )
            )
            and not _configured_value_is_placeholder(value)
            and not _is_generic_schema_placeholder(match.group("name"), value)
            and not package_lock_semver
            and not k8s_reference_key
            and not (
                re.sub(r"[^a-z0-9]", "", match.group("name").casefold()) == "authorization"
                and re.sub(r"[^a-z0-9]", "", value.casefold())
                in {"apikey", "basic", "bearer", "digest", "token"}
            )
            and not is_reference
        ):
            return True
        nested_path = source_path if unquoted is not None else None
        if ("=" in value or ":" in value) and _contains_configured_credential(
            value, source_path=nested_path
        ):
            return True
    return False


def _is_probably_text(raw: bytes) -> bool:
    """Allow path heuristics only on text-like bytes; secret signatures still scan all bytes."""
    if not raw or raw.startswith((b"\xff\xfe", b"\xfe\xff")):
        return True
    sample = raw[:16_384]
    if b"\0" in sample:
        paired = sample[: len(sample) - (len(sample) % 2)]
        if paired:
            even_nulls = paired[0::2].count(0) / max(1, len(paired[0::2]))
            odd_nulls = paired[1::2].count(0) / max(1, len(paired[1::2]))
            if max(even_nulls, odd_nulls) >= 0.30 and min(even_nulls, odd_nulls) <= 0.05:
                return True
        return False
    try:
        decoded = sample.decode("utf-8")
    except UnicodeDecodeError:
        printable = sum(byte in b"\t\n\r" or 32 <= byte <= 126 for byte in sample)
        return printable / max(1, len(sample)) >= 0.90
    controls = sum(ord(char) < 32 and char not in "\t\n\r" for char in decoded)
    return controls / max(1, len(decoded)) < 0.01


def _iter_text_files() -> list[Path]:
    return [
        ROOT / relative
        for relative in _tracked_paths()
        if relative.suffix in TEXT_SUFFIXES or relative.name == "Makefile"
    ]


def _check_forbidden_text(failures: list[str]) -> None:
    try:
        before = _read_release_snapshots()
        tree_matches_index = _working_tree_matches_index()
        index_flags_safe = _index_flags_are_safe()
    except (OSError, RuntimeError, UnicodeError) as exc:
        failures.append(f"tracked source snapshot failed closed: {type(exc).__name__}")
        return
    snapshots_match = before.get("index") == before.get("worktree")
    if not tree_matches_index or not snapshots_match:
        failures.append("tracked index and worktree differ; stage or revert changes before release")
    if not index_flags_safe:
        failures.append("tracked files must not use assume-unchanged or skip-worktree flags")

    skipped_parts = {part.casefold() for part in SKIP_PARTS}
    for source, snapshot in before.items():
        for relative, raw in snapshot.items():
            folded_parts = tuple(part.casefold() for part in relative.parts)
            path_views = _path_scan_views(relative)
            blocked_path_codes = {
                code
                for code, pattern in SECRET_PATTERNS
                if any(pattern.search(view) for view in path_views)
            }
            blocked_path_retired = any(
                needle.casefold() in view.casefold()
                for needle in RETIRED_MARKERS
                for view in path_views
            )
            label = (
                "<redacted-path>"
                if blocked_path_codes or blocked_path_retired
                else relative.as_posix()
            )
            for code in sorted(blocked_path_codes):
                failures.append(f"{source}: tracked path contains blocked pattern {code}")
            if blocked_path_retired:
                failures.append(f"{source}: tracked path contains blocked retired marker")
            if (
                any(part in skipped_parts for part in folded_parts)
                or (folded_parts and folded_parts[0] in {"workspace", "data", "sessions"})
                or folded_parts[:2] == ("data", "sessions")
                or _is_private_tracked_path(relative)
            ):
                failures.append(f"{source}: tracked generated/private path is forbidden: {label}")
                continue
            text_like = _is_probably_text(raw)
            binary_configured_views: tuple[str, ...] = ()
            if text_like:
                views = _scan_views(raw, text_like=True)
            else:
                views, binary_configured_views = _binary_scan_views(raw)
            signature_views = views
            if text_like and relative.suffix.casefold() == ".py":
                try:
                    python_text = raw.decode("utf-8-sig")
                except UnicodeDecodeError:
                    python_text = raw.decode("latin-1")
                signature_views = tuple(
                    dict.fromkeys(
                        (
                            *views,
                            *_python_ast_security_views(unicodedata.normalize("NFKC", python_text)),
                        )
                    )
                )
            if text_like:
                configured_views = _configured_credential_views(raw, relative, views)
                if any(
                    _contains_configured_credential(view, source_path=semantic_path)
                    for view, semantic_path in configured_views
                ):
                    failures.append(f"{source}:{label}: blocked pattern configured-api-key")
                for view in views:
                    for needle in RETIRED_MARKERS:
                        if needle.lower() in view.lower():
                            failures.append(f"{source}:{label}: blocked retired marker")
                    if PRIVATE_PATH.search(view):
                        failures.append(f"{source}:{label}: blocked operator-specific path")
            elif any(
                _contains_configured_credential(view, source_path=relative)
                for view in binary_configured_views
            ):
                failures.append(f"{source}:{label}: blocked pattern configured-api-key")
            binary_signature_marker_view = (
                signature_views[0].casefold() if not text_like and signature_views else ""
            )
            for code, pattern in SECRET_PATTERNS:
                if not text_like and not any(
                    marker in binary_signature_marker_view
                    for marker in BINARY_PATTERN_MARKERS[code]
                ):
                    continue
                if any(pattern.search(candidate) for candidate in signature_views):
                    failures.append(f"{source}:{label}: blocked pattern {code}")

    try:
        after = _read_release_snapshots()
    except (OSError, RuntimeError, UnicodeError) as exc:
        failures.append(f"tracked source resnapshot failed closed: {type(exc).__name__}")
    else:
        if before != after:
            failures.append("tracked sources changed during release scan")


def _path_scan_views(relative: Path) -> tuple[str, ...]:
    value = relative.as_posix()
    views = [value, value.replace("/", "\\")]
    decoded = value
    for _ in range(3):
        candidate = unquote(decoded)
        if candidate == decoded:
            break
        decoded = unicodedata.normalize("NFKC", candidate)
        views.append(decoded)
    return tuple(dict.fromkeys(views))


def _is_private_tracked_path(relative: Path) -> bool:
    name = relative.name.casefold()
    folded_path = relative.as_posix().casefold()
    private_env = name == ".env" or (name.startswith(".env.") and name != ".env.example")
    return (
        private_env
        or name in PRIVATE_TRACKED_NAMES
        or folded_path in PRIVATE_TRACKED_PATHS
        or any(folded_path.endswith(f"/{path}") for path in PRIVATE_TRACKED_PATHS)
        or any(name.endswith(suffix) for suffix in PRIVATE_TRACKED_SUFFIXES)
    )


def _check_version_consistency(failures: list[str]) -> None:
    pyproject = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    package_name = pyproject["project"]["name"]
    package_version = pyproject["project"]["version"]
    runtime_text = (ROOT / "lab" / "runtime.py").read_text(encoding="utf-8")
    match = re.search(r'VERSION\s*=\s*"([^"]+)"', runtime_text)
    runtime_version = match.group(1) if match else ""
    readme = (ROOT / "README.md").read_text(encoding="utf-8", errors="replace")

    if package_name != "weiping-lab":
        failures.append(f"package name mismatch: pyproject={package_name}")
    if package_version != runtime_version:
        failures.append(f"version mismatch: pyproject={package_version}, runtime={runtime_version}")
    if f"v{runtime_version}" not in readme:
        failures.append(f"README.md does not mention v{runtime_version}")

    stale = ['version = "1.' + '4.0"', 'version = "1.' + '3.0"', "v1." + "0"]
    for rel in ["pyproject.toml", "README.md", "api/server.py", "cli/main.py", "CLAUDE.md"]:
        text = (ROOT / rel).read_text(encoding="utf-8", errors="replace")
        for marker in stale:
            if marker in text:
                failures.append(f"{rel}: stale marker {marker}")


def _check_workspace_source_tracked(failures: list[str]) -> None:
    manager = ROOT / "lab" / "workspace" / "manager.py"
    init_file = ROOT / "lab" / "workspace" / "__init__.py"
    if not manager.exists() or not init_file.exists():
        failures.append("lab/workspace source package is missing")

    check = subprocess.run(
        ["git", "check-ignore", "-q", "lab/workspace/manager.py"],
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if check.returncode == 0:
        failures.append("lab/workspace/manager.py is still gitignored")
    elif check.returncode not in (1,):
        failures.append(f"git check-ignore failed: {check.stderr.strip()}")


def _check_env_example(failures: list[str]) -> None:
    text = (ROOT / ".env.example").read_text(encoding="utf-8")
    if "sk-" in text:
        failures.append(".env.example contains secret-shaped placeholders")
    required = [
        "ANTHROPIC_API_KEY",
        "DEEPSEEK_API_KEY",
        "AGENTMEMORY_URL",
        "WEIPING_LAB_WORKSPACE_ROOT",
        "WEIPING_LAB_ARCHITECT_MODEL",
        "WEIPING_LAB_EXECUTOR_MODEL",
        "WEIPING_LAB_AUDITOR_MODEL",
        "WEIPING_LAB_SCREENER_MODEL",
        "WEIPING_LAB_CONTEXT_FILE",
        "WEIPING_LAB_RULES_FILE",
        "WEIPING_WIKI_ROOT",
    ]
    for name in required:
        if name not in text:
            failures.append(f".env.example missing {name}")


def _check_package_lock(failures: list[str]) -> None:
    lock = ROOT / "ui" / "package-lock.json"
    if not lock.exists():
        failures.append("ui/package-lock.json missing")
        return
    try:
        lock_data = json.loads(lock.read_text(encoding="utf-8"))
        package_data = json.loads((ROOT / "ui" / "package.json").read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        failures.append(f"ui/package-lock.json invalid JSON: {exc}")
        return
    expected_engine = ">=22.18.0"
    if package_data.get("scripts") != EXPECTED_UI_SCRIPTS:
        failures.append("ui/package.json scripts must exactly match the audited executable gates")
    if package_data.get("engines", {}).get("node") != expected_engine:
        failures.append("ui/package.json must require Node >=22.18.0")
    packages = lock_data.get("packages")
    root_package = packages.get("", {}) if isinstance(packages, dict) else {}
    if root_package.get("engines", {}).get("node") != expected_engine:
        failures.append("ui/package-lock.json must preserve the Node >=22.18.0 floor")
    for field in ("name", "version", "dependencies", "devDependencies", "engines"):
        if root_package.get(field) != package_data.get(field):
            failures.append(f"ui/package-lock.json root {field} does not match package.json")

    if lock_data.get("lockfileVersion") != 3 or lock_data.get("requires") is not True:
        failures.append("ui/package-lock.json must use lockfileVersion 3 with requires=true")
    if not isinstance(packages, dict):
        failures.append("ui/package-lock.json packages must be an object")
        return
    for name, metadata in packages.items():
        if not name:
            continue
        if not isinstance(metadata, dict):
            failures.append("ui/package-lock.json contains invalid package metadata")
            continue
        resolved = metadata.get("resolved")
        integrity = metadata.get("integrity")
        try:
            parsed = urlsplit(resolved) if isinstance(resolved, str) else None
        except (TypeError, UnicodeError, ValueError):
            parsed = None
        if (
            parsed is None
            or parsed.scheme != "https"
            or parsed.netloc != "registry.npmjs.org"
            or not parsed.path.startswith("/")
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
        ):
            failures.append("ui/package-lock.json contains a non-official resolved package URL")
        elif not _resolved_package_matches_lock_entry(name, metadata, parsed.path):
            failures.append(
                "ui/package-lock.json resolved package name/version does not match its entry"
            )
        if not _valid_sha512_integrity(integrity):
            failures.append("ui/package-lock.json package is missing a SHA-512 integrity pin")


def _resolved_package_matches_lock_entry(
    entry_name: str, metadata: dict, resolved_path: str
) -> bool:
    marker = "node_modules/"
    if marker not in entry_name:
        return False
    package_name = entry_name.rsplit(marker, 1)[-1]
    version = metadata.get("version")
    if (
        not package_name
        or not isinstance(version, str)
        or not re.fullmatch(r"[0-9A-Za-z][0-9A-Za-z.+_-]{0,127}", version)
    ):
        return False
    basename = package_name.rsplit("/", 1)[-1]
    expected_path = f"/{package_name}/-/{basename}-{version}.tgz"
    try:
        return unquote(resolved_path) == expected_path
    except (TypeError, UnicodeError, ValueError):
        return False


def _valid_sha512_integrity(value: object) -> bool:
    if not isinstance(value, str) or not value.startswith("sha512-"):
        return False
    try:
        digest = base64.b64decode(value.removeprefix("sha512-"), validate=True)
    except (binascii.Error, ValueError):
        return False
    return len(digest) == 64


def _check_ruff_policy(failures: list[str]) -> None:
    pyproject = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    tool = pyproject.get("tool", {})
    expected_ruff = {"line-length": 100, "lint": {"select": ["E4", "E7", "E9", "F"]}}
    if tool.get("ruff") != expected_ruff:
        failures.append("pyproject.toml must exactly pin the audited Ruff policy")
    if tool.get("pytest", {}).get("ini_options") != {"testpaths": ["tests"]}:
        failures.append("pyproject.toml must exactly pin the audited pytest policy")
    try:
        tracked = _tracked_paths()
    except (OSError, RuntimeError, UnicodeError):
        failures.append("tracked test/lint configuration inventory could not be verified")
        return
    for relative in tracked:
        name = relative.name.casefold()
        if name in OVERRIDE_CONFIG_NAMES or (
            name == "pyproject.toml" and relative != Path("pyproject.toml")
        ):
            failures.append("tracked test/lint override configuration is forbidden")


def _check_evidence_contract(failures: list[str]) -> None:
    contract = ROOT / "docs" / "RESULT_CONTRACT.md"
    if not contract.exists():
        failures.append("docs/RESULT_CONTRACT.md missing")
        return
    text = contract.read_text(encoding="utf-8", errors="replace")
    required = [
        '"schema_version": "1.0"',
        "code_revision",
        "dataset_version",
        "config_digest",
        "source filename and SHA-256",
        "claim",
    ]
    for marker in required:
        if marker not in text:
            failures.append(f"docs/RESULT_CONTRACT.md missing marker: {marker}")


def _check_windows_gate(failures: list[str]) -> None:
    verify = (ROOT / "scripts" / "verify.ps1").read_text(encoding="utf-8", errors="replace")
    if "$LASTEXITCODE -ne 0" not in verify:
        failures.append("scripts/verify.ps1 does not propagate external command failures")
    for marker in ("pip check", "pip_audit", "npm --prefix ui audit"):
        if marker not in verify:
            failures.append(f"scripts/verify.ps1 missing dependency gate: {marker}")


def _check_critical_gate_files(failures: list[str]) -> None:
    for relative, expected_digest in CRITICAL_GATE_SHA256.items():
        try:
            digest = hashlib.sha256((ROOT / relative).read_bytes()).hexdigest()
        except OSError:
            failures.append(f"critical gate file is unreadable: {relative}")
            continue
        if digest != expected_digest:
            failures.append(f"critical gate file changed outside its audited contract: {relative}")
    try:
        make_aliases = {
            path.as_posix() for path in _tracked_paths() if path.name in {"GNUmakefile", "makefile"}
        }
    except (OSError, RuntimeError, UnicodeError):
        failures.append("tracked makefile precedence inventory could not be verified")
        return
    if make_aliases:
        failures.append("tracked GNUmakefile or lowercase makefile may not override Makefile")


def _check_ci_contract(failures: list[str]) -> None:
    try:
        workflows = {
            path.as_posix()
            for path in _tracked_paths()
            if len(path.parts) >= 3
            and path.parts[0].casefold() == ".github"
            and path.parts[1].casefold() == "workflows"
        }
    except (OSError, RuntimeError, UnicodeError):
        failures.append("tracked CI workflow inventory could not be verified")
        return
    if workflows != {".github/workflows/ci.yml"}:
        failures.append("tracked CI workflow inventory must contain exactly ci.yml")
    workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    failures.extend(_validate_ci_workflow(workflow))


def _validate_ci_workflow(workflow: str) -> list[str]:
    errors: list[str] = []
    try:
        document = yaml.load(workflow, Loader=_UniqueSafeLoader)
    except (yaml.YAMLError, TypeError, ValueError):
        return ["CI workflow must be valid safe YAML"]
    if not isinstance(document, dict):
        return ["CI workflow root must be a mapping"]
    expected_root_fields = {"name", "on", "permissions", "concurrency", "jobs"}
    if set(document) != expected_root_fields:
        errors.append("CI workflow must contain exactly the audited root fields")
    if document.get("name") != "CI":
        errors.append("CI workflow name must be CI")
    if document.get("on") != {"push": None, "pull_request": None}:
        errors.append("CI triggers must contain exactly push and pull_request")
    if document.get("permissions") != {"contents": "read"}:
        errors.append("CI permissions must contain only contents: read")
    if document.get("concurrency") != {
        "group": "${{ github.workflow }}-${{ github.ref }}",
        "cancel-in-progress": True,
    }:
        errors.append("CI concurrency must match the audited cancellation policy")
    jobs = document.get("jobs")
    if not isinstance(jobs, dict) or set(jobs) != {"verify"}:
        errors.append("CI jobs must contain exactly the verify job")
        return errors
    job = jobs["verify"]
    if not isinstance(job, dict):
        return errors + ["CI verify job must be a mapping"]
    if set(job) != {"runs-on", "timeout-minutes", "steps"}:
        errors.append("CI verify job contains unsupported privilege-bearing keys")
    if job.get("runs-on") != "ubuntu-latest":
        errors.append("CI verify job must use ubuntu-latest")
    if job.get("timeout-minutes") != 30:
        errors.append("CI verify job timeout must be exactly 30 minutes")
    steps = job.get("steps")
    if not isinstance(steps, list) or not all(isinstance(step, dict) for step in steps):
        return errors + ["CI verify steps must be a list of mappings"]

    action_steps = [step for step in steps if "uses" in step]
    if not all(isinstance(step.get("uses"), str) for step in action_steps):
        return errors + ["CI action references must be strings"]
    action_uses = Counter(step.get("uses") for step in action_steps)
    if action_uses != ALLOWED_ACTIONS:
        errors.append("CI uses directives must exactly match the pinned official action allowlist")

    checkout_action = "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1"
    python_action = "actions/setup-python@5fda3b95a4ea91299a34e894583c3862153e4b97"
    node_action = "actions/setup-node@820762786026740c76f36085b0efc47a31fe5020"
    for step in action_steps:
        if set(step) - {"name", "uses", "with"}:
            errors.append("CI action step contains unsupported keys")
        action = step.get("uses")
        inputs = step.get("with")
        if not isinstance(inputs, dict):
            errors.append("every CI action step must use a with mapping")
            continue
        if action == checkout_action and inputs.get("persist-credentials") is not False:
            errors.append("every CI checkout must disable persisted credentials")
        if action == python_action and inputs.get("python-version") != "3.11":
            errors.append("CI setup-python must pin Python 3.11")
        if action == node_action and inputs.get("node-version") != "22.18.0":
            errors.append("CI setup-node must pin Node 22.18.0")
    expected_steps = [
        {
            "name": "Checkout",
            "uses": checkout_action,
            "with": {"persist-credentials": False},
        },
        {"name": "Check committed whitespace", "run": "git show --check --format= HEAD"},
        {
            "name": "Set up Python",
            "uses": python_action,
            "with": {"python-version": "3.11"},
        },
        {
            "name": "Set up Node",
            "uses": node_action,
            "with": {
                "node-version": "22.18.0",
                "cache": "npm",
                "cache-dependency-path": "ui/package-lock.json",
            },
        },
        {
            "name": "Install Python project",
            "run": 'python -m pip install --upgrade "pip>=26.2.1" "setuptools>=84.0.0"\n'
            'python -m pip install -e ".[dev]"\n',
        },
        {"name": "Install UI", "working-directory": "ui", "run": "npm ci"},
        {"name": "Verify release candidate", "run": "make -f Makefile verify"},
    ]
    if steps != expected_steps:
        errors.append("CI verify steps must exactly match the audited step structure")
    active_run_lines = {
        line.strip()
        for step in steps
        if isinstance(step.get("run"), str)
        for line in step["run"].splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    }
    required_commands = {
        'python -m pip install --upgrade "pip>=26.2.1" "setuptools>=84.0.0"',
        'python -m pip install -e ".[dev]"',
        "npm ci",
        "make -f Makefile verify",
    }
    if not required_commands <= active_run_lines:
        errors.append("CI workflow is missing an exact required install or verification command")
    if re.search(r"\$\{\{\s*secrets\.", workflow, flags=re.IGNORECASE):
        errors.append("CI workflow must not reference repository secrets")
    return errors


if __name__ == "__main__":
    sys.exit(main())
