"""
NyxOS Reporting Agent — Auto-generates reports when an attack chain completes.

Uses the ReportEngine if available, otherwise falls back to a simple
Markdown report written directly.
"""

from __future__ import annotations

import os
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from loguru import logger

from nyxos.core.memory.memory_manager import MemoryManager

# ReportEngine may not be built yet (Agent 5) — guard the import
try:
    from nyxos.reporting.report_engine import ReportEngine
    HAS_REPORT_ENGINE = True
except ImportError:
    HAS_REPORT_ENGINE = False
    logger.debug("ReportEngine not available — will use fallback Markdown reporter")


class ReportingAgent:
    """
    Auto-generates a report when an attack chain completes.

    If the full ReportEngine (Agent 5) is installed it delegates to that.
    Otherwise it writes a clean Markdown report directly.

    Reports are saved to::

        ~/.nyxos/projects/{project_name}/reports/
    """

    def __init__(self, memory: MemoryManager) -> None:
        """
        Args:
            memory: MemoryManager for the current session / project.
        """
        self.memory = memory
        self._report_engine: Optional[Any] = None

        if HAS_REPORT_ENGINE:
            try:
                self._report_engine = ReportEngine(
                    project=memory.project,
                    ai_router=None,   # AI enrichment is optional
                    config=None,
                )
            except Exception as exc:
                logger.warning("ReportEngine init failed, using fallback: {}", exc)

        logger.debug("ReportingAgent initialised (engine={})",
                      "ReportEngine" if self._report_engine else "fallback")

    def generate(
        self,
        chain_result: Any,
        report_type: str = "pentest",
    ) -> str:
        """
        Generate a report from attack-chain results.

        Args:
            chain_result: A :class:`ChainResult` (or any object with
                          ``.tasks``, ``.findings``, ``.duration_seconds``,
                          ``.success``, and ``.errors`` attributes / keys).
            report_type:  One of ``"pentest"``, ``"bug_bounty"``,
                          ``"executive"``, ``"ctf_writeup"``.

        Returns:
            Absolute path to the generated report file.
        """
        logger.info("Generating '{}' report", report_type)

        # Ensure output directory exists
        reports_dir = self._reports_dir()
        reports_dir.mkdir(parents=True, exist_ok=True)

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        base_name = f"nyxos_{report_type}_{timestamp}"

        # --- Try ReportEngine first ----------------------------------------
        if self._report_engine is not None:
            try:
                out_path = str(reports_dir / f"{base_name}.html")
                result_path = self._report_engine.generate(
                    report_type=report_type,
                    output_path=out_path,
                )
                logger.info("Report generated via ReportEngine: {}", result_path)
                return result_path
            except Exception as exc:
                logger.warning("ReportEngine.generate() failed, using fallback: {}", exc)

        # --- Fallback: Markdown report -------------------------------------
        out_path = str(reports_dir / f"{base_name}.md")
        self._write_markdown_report(out_path, chain_result, report_type)
        logger.info("Markdown report written: {}", out_path)
        return out_path

    # ------------------------------------------------------------------
    # Markdown fallback
    # ------------------------------------------------------------------

    def _write_markdown_report(
        self,
        path: str,
        chain_result: Any,
        report_type: str,
    ) -> None:
        """
        Write a self-contained Markdown report.

        Args:
            path:         Output file path.
            chain_result: ChainResult-like object.
            report_type:  Report template name.
        """
        # Normalise chain_result to plain dicts
        if hasattr(chain_result, "to_dict"):
            cr = chain_result.to_dict()
        elif isinstance(chain_result, dict):
            cr = chain_result
        else:
            cr = {
                "tasks": [],
                "findings": [],
                "duration_seconds": 0,
                "success": False,
                "errors": [],
            }

        tasks = cr.get("tasks", [])
        findings = self._get_findings(chain_result, cr)
        duration = cr.get("duration_seconds", 0)
        success = cr.get("success", False)
        errors = cr.get("errors", [])
        project_name = self.memory.project.name if hasattr(self.memory.project, "name") else "default"
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # Sort findings by severity
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        findings_sorted = sorted(
            findings,
            key=lambda f: severity_order.get(
                f.get("severity", f.get("risk", "info")).lower(), 5
            ),
        )

        # Count by severity
        counts: Dict[str, int] = {}
        for f in findings_sorted:
            sev = f.get("severity", f.get("risk", "info")).lower()
            counts[sev] = counts.get(sev, 0) + 1

        lines: List[str] = []
        w = lines.append  # shorthand

        # --- Header --------------------------------------------------------
        w(f"# NyxOS {report_type.replace('_', ' ').title()} Report")
        w("")
        w(f"**Project:** {project_name}  ")
        w(f"**Date:** {now}  ")
        w(f"**Duration:** {duration:.1f} seconds  ")
        w(f"**Status:** {'✅ Completed' if success else '⚠️ Completed with errors'}  ")
        w("")

        # --- Executive Summary --------------------------------------------
        w("## Executive Summary")
        w("")
        total = len(findings_sorted)
        if total == 0:
            w("No findings were identified during this engagement.")
        else:
            w(f"A total of **{total}** findings were identified:")
            w("")
            for sev in ("critical", "high", "medium", "low", "info"):
                if counts.get(sev, 0) > 0:
                    emoji = {"critical": "🔴", "high": "🟠", "medium": "🟡",
                             "low": "🔵", "info": "⚪"}.get(sev, "⚪")
                    w(f"- {emoji} **{sev.upper()}**: {counts[sev]}")
            w("")

        # --- Scope --------------------------------------------------------
        w("## Scope")
        w("")
        targets = []
        if hasattr(self.memory.project, "targets"):
            targets = self.memory.project.targets or []
        if targets:
            for t in targets:
                w(f"- `{t}`")
        else:
            w("_Scope not explicitly defined._")
        w("")

        # --- Tasks Executed -----------------------------------------------
        w("## Tasks Executed")
        w("")
        w("| # | Task | Skill | Status | Duration |")
        w("|---|------|-------|--------|----------|")
        for i, t in enumerate(tasks, 1):
            name = t.get("name", t) if isinstance(t, dict) else getattr(t, "name", str(t))
            skill = t.get("skill", "") if isinstance(t, dict) else getattr(t, "skill", "")
            status = t.get("status", "") if isinstance(t, dict) else getattr(t, "status", "")
            dur = t.get("duration_seconds", 0) if isinstance(t, dict) else getattr(t, "duration_seconds", 0)
            status_icon = {"complete": "✅", "failed": "❌", "skipped": "⏭️"}.get(status, "⏳")
            w(f"| {i} | {name} | {skill} | {status_icon} {status} | {dur:.1f}s |")
        w("")

        # --- Findings -----------------------------------------------------
        w("## Findings")
        w("")
        if not findings_sorted:
            w("_No findings._")
        else:
            for i, f in enumerate(findings_sorted, 1):
                sev = f.get("severity", f.get("risk", "info")).upper()
                title = f.get("title", "Untitled Finding")
                w(f"### {i}. [{sev}] {title}")
                w("")

                if f.get("description"):
                    w(f"**Description:** {f['description']}")
                    w("")
                if f.get("host"):
                    w(f"**Host:** `{f['host']}`  ")
                if f.get("port"):
                    w(f"**Port:** `{f['port']}`  ")
                if f.get("service"):
                    w(f"**Service:** `{f['service']}`  ")
                if f.get("version"):
                    w(f"**Version:** `{f['version']}`  ")
                if f.get("evidence"):
                    w("")
                    w("**Evidence:**")
                    w(f"```\n{f['evidence']}\n```")
                if f.get("recommendation"):
                    w("")
                    w(f"**Recommendation:** {f['recommendation']}")
                w("")
                w("---")
                w("")

        # --- Errors -------------------------------------------------------
        if errors:
            w("## Errors")
            w("")
            for err in errors:
                w(f"- {err}")
            w("")

        # --- Footer -------------------------------------------------------
        w("---")
        w(f"_Generated by NyxOS on {now}_")

        # Write file
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("\n".join(lines))

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _get_findings(self, chain_result: Any, cr_dict: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract findings list from chain_result, handling both object and dict forms."""
        # Try the object's findings attribute first
        if hasattr(chain_result, "findings") and isinstance(chain_result.findings, list):
            return chain_result.findings

        # Then the dict
        findings = cr_dict.get("findings", [])
        if findings:
            return findings

        # Fall back to project memory
        if hasattr(self.memory.project, "findings"):
            return self.memory.project.findings or []

        return []

    def _reports_dir(self) -> Path:
        """Return the reports directory for the current project."""
        project_name = "default"
        if hasattr(self.memory.project, "name"):
            project_name = self.memory.project.name or "default"

        base = Path(os.path.expanduser("~/.nyxos/projects"))
        return base / project_name / "reports"
