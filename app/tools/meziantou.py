"""Meziantou.Analyzer SAST adapter for C#/.NET (Roslyn analyzer via `dotnet build`).

Runs restore+build against a scratch COPY of target_path (never the original — this
project never mutates scanned source) with a Directory.Build.props injected to pull
in Meziantou.Analyzer as a NuGet PackageReference. Requires network access for NuGet
restore, same category of runtime dependency as pip-audit/osv-scanner's DB lookups.

Meziantou is a general-purpose Roslyn analyzer (code quality + some security-adjacent
rules), not a dedicated security scanner — confirmed no dedicated, functioning .NET
SAST tool exists for this platform (SecurityCodeScan and its forks install and run
cleanly but produce zero findings in this environment, evaluated against both a
synthetic vulnerable project and a real repo). Kept in category="sast" alongside
semgrep/bandit since it is the only tool that produces real signal for .cs files.

ToolRunner execs a single argv per adapter; the multi-step restore+build+read-SARIF
sequence is wrapped in a generated bash script so it still fits that single-exec model.
"""

from __future__ import annotations

import json
import os
import shutil
import tempfile
from typing import Any

from app.tools._sarif_shared import parse_sarif_msbuild_results, sarif_result_to_finding
from app.tools.base import ToolAdapter

_SEVERITY_MAPPING = {"error": "high", "warning": "medium", "note": "low"}
_PROJECT_EXTENSIONS = (".csproj", ".sln")
_IGNORED_DIRS = {".git", "node_modules", "bin", "obj", "__pycache__", ".venv", "venv", ".mypy_cache"}

_DIRECTORY_BUILD_PROPS_TEMPLATE = """<Project>
  <ItemGroup>
    <PackageReference Include="Meziantou.Analyzer" Version="{version}">
      <PrivateAssets>all</PrivateAssets>
    </PackageReference>
  </ItemGroup>
</Project>
"""


class MeziantouAnalyzerAdapter(ToolAdapter):
    name = "meziantou"
    category = "sast"

    def __init__(self) -> None:
        self._workdir: str | None = None
        self._sarif_path: str | None = None
        self._script_path: str | None = None
        self._original_target_path: str | None = None

    def is_available(self) -> bool:
        return shutil.which("dotnet") is not None

    def has_scannable_target(self, target_path: str) -> bool:
        for root, dirs, files in os.walk(target_path):
            dirs[:] = [d for d in dirs if d not in _IGNORED_DIRS]
            if any(f.endswith(_PROJECT_EXTENSIONS) for f in files):
                return True
        return False

    def build_command(self, target_path: str, config: dict[str, Any]) -> list[str]:
        version = config.get("meziantou_version", "2.0.*")
        self._original_target_path = os.path.abspath(target_path)

        self._workdir = tempfile.mkdtemp(prefix="meziantou-src-")
        shutil.copytree(
            target_path,
            self._workdir,
            dirs_exist_ok=True,
            ignore=shutil.ignore_patterns(*_IGNORED_DIRS),
        )

        with open(os.path.join(self._workdir, "Directory.Build.props"), "w", encoding="utf-8") as fh:
            fh.write(_DIRECTORY_BUILD_PROPS_TEMPLATE.format(version=version))

        fd, self._sarif_path = tempfile.mkstemp(suffix=".sarif", prefix="meziantou-")
        os.close(fd)

        fd, self._script_path = tempfile.mkstemp(suffix=".sh", prefix="meziantou-run-")
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(
                # DOTNET_CLI_USE_MSBUILD_SERVER=0 (Roslyn/MSBuild server reuse disabled)
                # is required here: MSBuild's persistent VBCSCompiler server process
                # detaches and inherits this subprocess's stdout/stderr pipe fds, so
                # asyncio's communicate() never sees EOF and hangs forever even after
                # the actual build has finished. -nodeReuse:false is the build-level
                # belt-and-suspenders equivalent.
                f"export DOTNET_CLI_USE_MSBUILD_SERVER=0 MSBUILDDISABLENODEREUSE=1 && "
                f"cd {self._workdir} && "
                f"dotnet restore --nologo && "
                f"dotnet build --nologo -nodeReuse:false /p:ErrorLog={self._sarif_path}\n"
            )

        return ["bash", self._script_path]

    def parse_output(
        self, stdout: str, stderr: str, exit_code: int
    ) -> tuple[list[dict[str, Any]], dict[str, Any]]:
        report_text = None
        workdir = self._workdir
        original_target = self._original_target_path
        if self._sarif_path and os.path.isfile(self._sarif_path):
            try:
                with open(self._sarif_path, encoding="utf-8") as fh:
                    report_text = fh.read()
            finally:
                self._cleanup()
        else:
            self._cleanup()

        if not report_text or not report_text.strip():
            return [], {"raw_stdout": stdout, "raw_stderr": stderr, "parse_error": "no_sarif_output"}

        try:
            data = json.loads(report_text)
        except json.JSONDecodeError:
            return [], {"raw_stdout": stdout, "raw_stderr": stderr, "parse_error": "invalid_json"}

        normalized_results = parse_sarif_msbuild_results(data)
        # MSBuild's SARIF logger mixes real compiler errors (CSxxxx) in with analyzer
        # warnings (MAxxxx) in the same results array - only MA-prefixed rules are
        # Meziantou's own findings, compiler errors are a build health signal, not a
        # security finding, and would otherwise show up as spurious "sast" findings.
        analyzer_results = [r for r in normalized_results if r["rule_id"].startswith("MA")]

        # File paths from the SARIF point at the scratch copy (workdir), not the
        # original scanned repo (which is never mutated/built-in-place) - rewrite
        # them back so findings are meaningful to whoever reads the report.
        if workdir and original_target:
            for result in analyzer_results:
                file_path = result.get("file_path")
                if file_path and file_path.startswith(workdir):
                    result["file_path"] = original_target + file_path[len(workdir) :]

        findings = [
            sarif_result_to_finding(r, self.name, self.category, _SEVERITY_MAPPING)
            for r in analyzer_results
        ]
        return findings, {"result_count": len(analyzer_results)}

    def _cleanup(self) -> None:
        if self._workdir and os.path.isdir(self._workdir):
            shutil.rmtree(self._workdir, ignore_errors=True)
        if self._sarif_path and os.path.isfile(self._sarif_path):
            try:
                os.remove(self._sarif_path)
            except OSError:
                pass
        if self._script_path and os.path.isfile(self._script_path):
            try:
                os.remove(self._script_path)
            except OSError:
                pass
