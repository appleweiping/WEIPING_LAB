"""
Tool Registry — pluggable tools for agents.

Inspired by AI-Researcher's tool retrieval system.
Agents can call tools by name; the registry handles routing.

Available tools:
- web_search: search the web for recent papers/news
- semantic_scholar: search academic papers
- arxiv_fetch: fetch full paper abstract from arXiv ID
- code_exec: execute Python code in a sandbox (read-only analysis)
- file_read: read a file from the workspace
- file_write: write a file to the workspace
"""

from __future__ import annotations
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Awaitable
import httpx

from lab.runtime import (
    PRIVATE_KEY_MATERIAL,
    public_executable_artifact_is_safe,
    redact_public_artifact,
    redact_public_text,
    safe_error,
)


@dataclass
class ToolResult:
    tool: str
    success: bool
    output: str
    error: str = ""


ToolFn = Callable[[dict], Awaitable[ToolResult]]
TOOL_NAME = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
SENSITIVE_FILE_NAMES = {
    ".git-credentials",
    ".htpasswd",
    ".envrc",
    ".netrc",
    ".npmrc",
    ".pypirc",
    ".pgpass",
    ".vault-token",
    "_netrc",
    "auth.json",
    "credentials",
    "credentials.json",
    "id_dsa",
    "id_ecdsa",
    "id_ed25519",
    "id_rsa",
    "secrets.json",
}
SENSITIVE_FILE_SUFFIXES = {".key", ".p12", ".pem", ".pfx"}
SYNTAX_BEARING_SUFFIXES = {
    ".bat",
    ".c",
    ".cfg",
    ".cmd",
    ".cpp",
    ".css",
    ".dart",
    ".erl",
    ".ex",
    ".exs",
    ".gradle",
    ".go",
    ".h",
    ".ini",
    ".ipynb",
    ".java",
    ".js",
    ".json",
    ".jsx",
    ".kt",
    ".kts",
    ".lua",
    ".php",
    ".pl",
    ".properties",
    ".ps1",
    ".py",
    ".r",
    ".rb",
    ".rs",
    ".scala",
    ".sh",
    ".sql",
    ".svelte",
    ".swift",
    ".tf",
    ".tfvars",
    ".toml",
    ".ts",
    ".tsx",
    ".vue",
    ".xml",
    ".yaml",
    ".yml",
}
SYNTAX_BEARING_NAMES = {
    "cmakelists.txt",
    "containerfile",
    "dockerfile",
    "gemfile",
    "jenkinsfile",
    "justfile",
    "makefile",
    "procfile",
    "rakefile",
    "vagrantfile",
}


class ToolRegistry:
    def __init__(self, workspace_dir: str = "", semantic_scholar_key: str = ""):
        self._tools: dict[str, ToolFn] = {}
        self._workspace = (Path(workspace_dir) if workspace_dir else Path(".")).resolve()
        self._ss_key = semantic_scholar_key
        self._register_defaults()

    def register(self, name: str, fn: ToolFn):
        if not isinstance(name, str) or TOOL_NAME.fullmatch(name) is None:
            raise ValueError("tool name must be a lowercase public identifier")
        if not callable(fn):
            raise TypeError("tool implementation must be callable")
        self._tools[name] = fn

    async def call(self, name: str, args: dict) -> ToolResult:
        tool = self._tools.get(name) if isinstance(name, str) else None
        if tool is None:
            return ToolResult(
                tool="unknown",
                success=False,
                output="",
                error=f"Unknown tool. Available: {list(self._tools)}",
            )
        if not isinstance(args, dict):
            return ToolResult(tool=name, success=False, output="", error="Invalid tool arguments")
        try:
            result = await tool(args)
        except Exception as e:
            return ToolResult(tool=name, success=False, output="", error=safe_error(e))
        if type(result) is not ToolResult:
            return ToolResult(tool=name, success=False, output="", error="Invalid tool result")
        if not isinstance(result.success, bool):
            return ToolResult(tool=name, success=False, output="", error="Invalid tool result")
        if result.success and not isinstance(result.output, str):
            return ToolResult(tool=name, success=False, output="", error="Invalid tool result")
        return ToolResult(
            tool=name,
            success=result.success,
            output=redact_public_text(result.output)[:8_000] if result.success else "",
            error=safe_error(result.error),
        )

    def list_tools(self) -> list[dict]:
        return [
            {"name": name, "description": safe_error(fn.__doc__ or "", limit=500)}
            for name, fn in self._tools.items()
        ]

    def _register_defaults(self):
        self.register("semantic_scholar", self._semantic_scholar)
        self.register("arxiv_fetch", self._arxiv_fetch)
        self.register("file_read", self._file_read)
        self.register("file_write", self._file_write)
        self.register("web_search", self._web_search)

    async def _semantic_scholar(self, args: dict) -> ToolResult:
        """Search Semantic Scholar for papers. Args: {query, limit=10, year_from=2020}"""
        query = args.get("query", "")
        limit = min(int(args.get("limit", 10)), 20)
        year_from = args.get("year_from", 2020)
        params = {
            "query": query,
            "limit": limit,
            "fields": "title,abstract,year,venue,citationCount,tldr",
            "year": f"{year_from}-",
        }
        headers = {"x-api-key": self._ss_key} if self._ss_key else {}
        async with httpx.AsyncClient(timeout=30.0) as client:
            r = await client.get(
                "https://api.semanticscholar.org/graph/v1/paper/search",
                params=params,
                headers=headers,
            )
            r.raise_for_status()
            data = r.json()
        papers = data.get("data", [])
        lines = []
        for p in papers:
            tldr = p.get("tldr", {})
            tldr_text = tldr.get("text", "") if tldr else ""
            lines.append(
                f"[{p.get('year', '?')}] {p.get('title', '')} "
                f"({p.get('venue', 'arXiv')}, {p.get('citationCount', 0)} cites)\n"
                f"  {(p.get('abstract') or '')[:150]}..."
                + (f"\n  TL;DR: {tldr_text}" if tldr_text else "")
            )
        return ToolResult(
            tool="semantic_scholar",
            success=True,
            output="\n\n".join(lines) if lines else "No results found",
        )

    async def _arxiv_fetch(self, args: dict) -> ToolResult:
        """Fetch paper details from arXiv. Args: {arxiv_id}"""
        arxiv_id = args.get("arxiv_id", "").strip()
        if not arxiv_id:
            return ToolResult(
                tool="arxiv_fetch", success=False, output="", error="arxiv_id required"
            )
        url = f"https://export.arxiv.org/abs/{arxiv_id}"
        async with httpx.AsyncClient(timeout=20.0) as client:
            r = await client.get(url)
            r.raise_for_status()
        # Extract title and abstract from HTML
        title_match = re.search(r'<h1[^>]*class="title[^"]*"[^>]*>(.*?)</h1>', r.text, re.DOTALL)
        abstract_match = re.search(
            r'<blockquote[^>]*class="abstract[^"]*"[^>]*>(.*?)</blockquote>', r.text, re.DOTALL
        )
        title = re.sub(r"<[^>]+>", "", title_match.group(1)).strip() if title_match else arxiv_id
        abstract = re.sub(r"<[^>]+>", "", abstract_match.group(1)).strip() if abstract_match else ""
        return ToolResult(
            tool="arxiv_fetch", success=True, output=f"Title: {title}\n\nAbstract: {abstract}"
        )

    async def _file_read(self, args: dict) -> ToolResult:
        """Read a file from the workspace. Args: {path}"""
        rel_path = args.get("path", "")
        full_path = self._resolve_workspace_path(rel_path)
        if full_path is None:
            return ToolResult(
                tool="file_read",
                success=False,
                output="",
                error="Path escapes workspace",
            )
        if self._is_sensitive_workspace_path(full_path):
            return ToolResult(
                tool="file_read",
                success=False,
                output="",
                error="Sensitive file access denied",
            )
        try:
            exists = full_path.exists()
        except OSError:
            return ToolResult(
                tool="file_read", success=False, output="", error="File access failed"
            )
        if not exists:
            return ToolResult(tool="file_read", success=False, output="", error="File not found")
        try:
            content = full_path.read_text(encoding="utf-8", errors="replace")
        except (OSError, UnicodeError):
            return ToolResult(tool="file_read", success=False, output="", error="File read failed")
        if PRIVATE_KEY_MATERIAL.search(content):
            return ToolResult(
                tool="file_read",
                success=False,
                output="",
                error="Sensitive file content denied",
            )
        return ToolResult(tool="file_read", success=True, output=content[:8000])  # cap at 8K chars

    async def _file_write(self, args: dict) -> ToolResult:
        """Write a file to the workspace. Args: {path, content}"""
        rel_path = args.get("path", "")
        content = args.get("content", "")
        if not rel_path:
            return ToolResult(tool="file_write", success=False, output="", error="path required")
        if not isinstance(content, str):
            return ToolResult(
                tool="file_write", success=False, output="", error="content must be text"
            )
        full_path = self._resolve_workspace_path(rel_path)
        if full_path is None:
            return ToolResult(
                tool="file_write",
                success=False,
                output="",
                error="Path escapes workspace",
            )
        if self._is_sensitive_workspace_path(full_path):
            return ToolResult(
                tool="file_write",
                success=False,
                output="",
                error="Sensitive file access denied",
            )
        try:
            full_path.parent.mkdir(parents=True, exist_ok=True)
            syntax_name = full_path.name.casefold()
            syntax_bearing = (
                full_path.suffix.casefold() in SYNTAX_BEARING_SUFFIXES
                or syntax_name in SYNTAX_BEARING_NAMES
                or any(
                    syntax_name.startswith(f"{base}.")
                    for base in ("containerfile", "dockerfile", "makefile")
                )
                or content.lstrip("\ufeff").startswith("#!")
            )
            if syntax_bearing:
                if not public_executable_artifact_is_safe(content, artifact_path=full_path):
                    return ToolResult(
                        tool="file_write",
                        success=False,
                        output="",
                        error="Executable content rejected by public safety policy",
                    )
                safe_content = content
            else:
                safe_content = redact_public_artifact(content)
            full_path.write_text(safe_content, encoding="utf-8")
        except (OSError, TypeError, UnicodeError):
            return ToolResult(
                tool="file_write", success=False, output="", error="File write failed"
            )
        return ToolResult(
            tool="file_write", success=True, output=f"Written {len(safe_content)} chars"
        )

    async def _web_search(self, args: dict) -> ToolResult:
        """Search the web via DuckDuckGo. Args: {query, max_results=5}"""
        query = args.get("query", "")
        max_results = min(int(args.get("max_results", 5)), 10)
        # Use DuckDuckGo HTML search (no API key needed)
        url = "https://html.duckduckgo.com/html/"
        async with httpx.AsyncClient(timeout=20.0, follow_redirects=True) as client:
            r = await client.post(url, data={"q": query}, headers={"User-Agent": "Mozilla/5.0"})
        # Extract result snippets
        results = re.findall(
            r'<a[^>]+class="result__a"[^>]*>(.*?)</a>.*?<a[^>]+class="result__snippet"[^>]*>(.*?)</a>',
            r.text,
            re.DOTALL,
        )
        lines = []
        for title, snippet in results[:max_results]:
            title_clean = re.sub(r"<[^>]+>", "", title).strip()
            snippet_clean = re.sub(r"<[^>]+>", "", snippet).strip()
            lines.append(f"• {title_clean}\n  {snippet_clean}")
        return ToolResult(
            tool="web_search",
            success=True,
            output="\n\n".join(lines) if lines else "No results found",
        )

    def _resolve_workspace_path(self, rel_path: str) -> Path | None:
        try:
            candidate = Path(str(rel_path or ""))
            if candidate.is_absolute():
                return None
            resolved = (self._workspace / candidate).resolve()
            resolved.relative_to(self._workspace)
        except (OSError, RuntimeError, TypeError, ValueError):
            return None
        return resolved

    def _is_sensitive_workspace_path(self, path: Path) -> bool:
        try:
            relative = path.relative_to(self._workspace)
        except ValueError:
            return True
        parts = tuple(part.casefold() for part in relative.parts)
        name = relative.name.casefold()
        private_env = name == ".env" or (name.startswith(".env.") and name != ".env.example")
        return (
            private_env
            or any(
                name == sensitive
                or any(
                    name.startswith(f"{sensitive}{separator}") for separator in (".", "_", "-", "~")
                )
                for sensitive in SENSITIVE_FILE_NAMES
            )
            or any(
                name.endswith(suffix)
                or any(f"{suffix}{separator}" in name for separator in (".", "_", "-", "~"))
                for suffix in SENSITIVE_FILE_SUFFIXES
            )
            or any(part in {".git", ".ssh", ".kube"} for part in parts)
        )
