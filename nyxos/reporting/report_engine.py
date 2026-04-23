"""
NyxOS Report Engine — Main report generation orchestrator.

Takes findings from project memory, uses AI to write narrative sections,
renders into professional HTML templates, and exports to PDF or Markdown.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from jinja2 import Environment, FileSystemLoader, select_autoescape
from loguru import logger

from nyxos.core.ai_engine.router import AIRouter
from nyxos.core.config.settings import NyxConfig, get_config
from nyxos.core.memory.project_memory import ProjectMemory
from nyxos.reporting.exporters.markdown_exporter import MarkdownExporter
from nyxos.reporting.exporters.pdf_exporter import PDFExporter


# NyxOS version constant
NYXOS_VERSION = "0.1.0"

# Severity ordering and weights for risk score calculation
SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]
SEVERITY_WEIGHTS = {
    "critical": 10.0,
    "high": 7.5,
    "medium": 5.0,
    "low": 2.5,
    "info": 0.5,
}
SEVERITY_COLORS = {
    "critical": "#e74c3c",
    "high": "#e67e22",
    "medium": "#f1c40f",
    "low": "#2ecc71",
    "info": "#3498db",
}

# Valid report types
VALID_REPORT_TYPES = ("pentest", "bug_bounty", "executive", "ctf_writeup")

# Template file mapping
TEMPLATE_MAP = {
    "pentest": "pentest_report.html",
    "bug_bounty": "bug_bounty_report.html",
    "executive": "executive_summary.html",
    "ctf_writeup": "pentest_report.html",  # reuse pentest template with CTF tweaks
}


class ReportEngine:
    """
    Main report generation orchestrator for NyxOS.

    Takes all findings from project memory, uses the AI router to write
    professional narrative sections, renders them into Jinja2 HTML templates,
    and exports the result to PDF or Markdown.
    """

    def __init__(
        self,
        project: ProjectMemory,
        ai_router: AIRouter,
        config: NyxConfig,
    ) -> None:
        """
        Initialize the ReportEngine.

        Args:
            project: The project memory containing findings, scope, and timeline.
            ai_router: The AI router for generating narrative content.
            config: The NyxOS configuration.
        """
        self.project = project
        self.ai_router = ai_router
        self.config = config

        # Template directory
        self.template_dir = Path(__file__).parent / "templates"
        if not self.template_dir.exists():
            self.template_dir.mkdir(parents=True, exist_ok=True)

        # Jinja2 environment with autoescaping for security
        self.jinja_env = Environment(
            loader=FileSystemLoader(str(self.template_dir)),
            autoescape=select_autoescape(["html", "xml"]),
            trim_blocks=True,
            lstrip_blocks=True,
        )

        # Register custom filters
        self.jinja_env.filters["severity_color"] = self._severity_color_filter
        self.jinja_env.filters["severity_badge"] = self._severity_badge_filter

        # Exporters
        self.pdf_exporter = PDFExporter()
        self.markdown_exporter = MarkdownExporter()

        # Narrative cache: hash(finding) → narrative string
        self._narrative_cache: Dict[str, str] = {}

        logger.debug("ReportEngine initialized for project '{}'", project.name)

    # ──────────────────────────────────────────────────────────
    #  Public API
    # ──────────────────────────────────────────────────────────

    def generate(self, report_type: str, output_path: str) -> str:
        """
        Generate a complete report.

        Args:
            report_type: One of 'pentest', 'bug_bounty', 'executive', 'ctf_writeup'.
            output_path: Destination file path. Extension determines format:
                         .pdf → PDF (falls back to .md if WeasyPrint unavailable),
                         .md → Markdown,
                         .html → raw HTML.

        Returns:
            The absolute path to the generated report file.

        Raises:
            ValueError: If report_type is invalid.
            FileNotFoundError: If the corresponding template is missing.
        """
        if report_type not in VALID_REPORT_TYPES:
            raise ValueError(
                f"Invalid report_type '{report_type}'. "
                f"Must be one of: {', '.join(VALID_REPORT_TYPES)}"
            )

        output = Path(output_path).expanduser().resolve()
        output.parent.mkdir(parents=True, exist_ok=True)

        logger.info(
            "Generating {} report → {}",
            report_type,
            output,
        )

        # 1. Collect findings from project memory
        findings = self._collect_findings()
        logger.info("Collected {} findings from project memory", len(findings))

        # 2. Sort findings by severity
        findings = self._sort_findings(findings)

        # 3. Derive target string from project
        target = self._get_target_string()

        # 4. Calculate risk score
        risk_score = self._calculate_risk_score(findings)

        # 5. AI-written sections (with caching)
        finding_narratives = self._generate_finding_narratives(findings)
        executive_summary = self._write_executive_summary(findings, target)
        remediation = self._write_remediation_section(findings)

        # 6. Build commands timeline from project
        commands_timeline = self._build_commands_timeline()

        # 7. Construct template context
        now = datetime.now(timezone.utc)
        author = self.config.user.get("name", "NyxOS Operator") if isinstance(self.config.user, dict) else getattr(self.config.user, "name", "NyxOS Operator")
        context: Dict[str, Any] = {
            "target": target,
            "date": now.strftime("%Y-%m-%d %H:%M UTC"),
            "date_iso": now.isoformat(),
            "findings": finding_narratives,
            "findings_raw": findings,
            "executive_summary": executive_summary,
            "remediation": remediation,
            "risk_score": risk_score,
            "commands_timeline": commands_timeline,
            "report_type": report_type,
            "report_type_display": report_type.replace("_", " ").title(),
            "author": author,
            "nyxos_version": NYXOS_VERSION,
            "project_name": self.project.name,
            "severity_colors": SEVERITY_COLORS,
            "total_findings": len(findings),
            "severity_counts": self._count_by_severity(findings),
        }

        # 8. Determine output format and render
        suffix = output.suffix.lower()

        if suffix == ".md":
            result_path = self.markdown_exporter.export(context, str(output))
        elif suffix == ".html":
            html_content = self._render_html(report_type, context)
            output.write_text(html_content, encoding="utf-8")
            result_path = str(output)
        else:
            # Default: attempt PDF, fall back to Markdown
            html_content = self._render_html(report_type, context)
            if suffix == ".pdf" and self.pdf_exporter.is_available():
                result_path = self.pdf_exporter.export(html_content, str(output))
            elif suffix == ".pdf":
                logger.warning(
                    "WeasyPrint not available — falling back to Markdown export"
                )
                md_path = output.with_suffix(".md")
                result_path = self.markdown_exporter.export(context, str(md_path))
            else:
                # Unknown extension: write HTML
                output.write_text(html_content, encoding="utf-8")
                result_path = str(output)

        logger.info("Report generated: {}", result_path)
        return result_path

    # ──────────────────────────────────────────────────────────
    #  AI-Powered Content Generation
    # ──────────────────────────────────────────────────────────

    def _write_finding_narrative(self, finding: dict) -> str:
        """
        Ask the AI to expand a single finding into a professional narrative paragraph.

        Args:
            finding: A finding dict with at least 'title', 'severity', 'description',
                     'evidence', and optionally 'recommendation'.

        Returns:
            A professional narrative string.
        """
        cache_key = self._finding_cache_key(finding)
        if cache_key in self._narrative_cache:
            logger.debug("Narrative cache hit for finding '{}'", finding.get("title", ""))
            return self._narrative_cache[cache_key]

        title = finding.get("title", "Untitled Finding")
        severity = finding.get("severity", "info").upper()
        description = finding.get("description", "No description provided.")
        evidence = finding.get("evidence", "")
        recommendation = finding.get("recommendation", "")

        prompt = (
            "You are a professional penetration testing report writer. "
            "Write a clear, concise, and professional narrative paragraph for the following "
            "security finding. The narrative should explain what was found, why it matters, "
            "and what the potential impact is. Keep it to 3-5 sentences. "
            "Do NOT use markdown formatting — return plain text only.\n\n"
            f"Title: {title}\n"
            f"Severity: {severity}\n"
            f"Description: {description}\n"
            f"Evidence: {evidence}\n"
            f"Existing recommendation: {recommendation}\n"
        )

        try:
            response = self.ai_router.route(
                prompt=prompt,
                system_prompt="You are a cybersecurity report writer producing professional pentest reports.",
                history=[],
                task_type="explain",
            )
            narrative = response.text.strip()
        except Exception as exc:
            logger.warning("AI narrative generation failed for '{}': {}", title, exc)
            narrative = description  # Graceful fallback to raw description

        self._narrative_cache[cache_key] = narrative
        return narrative

    def _write_executive_summary(self, findings: List[dict], target: str) -> str:
        """
        Ask the AI to write a one-page executive summary of all findings.

        Args:
            findings: Sorted list of all finding dicts.
            target: The target string (domain, IP range, etc.).

        Returns:
            An executive summary string.
        """
        if not findings:
            return (
                "No security findings were identified during the assessment of "
                f"{target}. This may indicate a strong security posture, or that "
                "the scope of testing was limited. Further assessment is recommended."
            )

        severity_counts = self._count_by_severity(findings)
        findings_summary = "\n".join(
            f"- [{f.get('severity', 'info').upper()}] {f.get('title', 'Untitled')}: "
            f"{f.get('description', '')[:120]}"
            for f in findings[:20]  # Limit to 20 to avoid token overflow
        )

        prompt = (
            "You are a cybersecurity executive report writer. Write a professional "
            "executive summary (3-4 paragraphs) for a penetration test / security assessment. "
            "The summary should:\n"
            "1. State the target and scope of the assessment\n"
            "2. Summarize the overall risk posture\n"
            "3. Highlight the most critical findings\n"
            "4. Provide a high-level recommendation\n\n"
            "Do NOT use markdown formatting — return plain text with paragraph breaks.\n\n"
            f"Target: {target}\n"
            f"Total findings: {len(findings)}\n"
            f"Critical: {severity_counts.get('critical', 0)}, "
            f"High: {severity_counts.get('high', 0)}, "
            f"Medium: {severity_counts.get('medium', 0)}, "
            f"Low: {severity_counts.get('low', 0)}, "
            f"Info: {severity_counts.get('info', 0)}\n\n"
            f"Findings:\n{findings_summary}\n"
        )

        try:
            response = self.ai_router.route(
                prompt=prompt,
                system_prompt="You are a cybersecurity executive report writer.",
                history=[],
                task_type="explain",
            )
            return response.text.strip()
        except Exception as exc:
            logger.warning("AI executive summary generation failed: {}", exc)
            return (
                f"A security assessment was conducted against {target}. "
                f"A total of {len(findings)} findings were identified: "
                f"{severity_counts.get('critical', 0)} critical, "
                f"{severity_counts.get('high', 0)} high, "
                f"{severity_counts.get('medium', 0)} medium, "
                f"{severity_counts.get('low', 0)} low, and "
                f"{severity_counts.get('info', 0)} informational. "
                "Review the detailed findings below for remediation guidance."
            )

    def _write_remediation_section(self, findings: List[dict]) -> str:
        """
        Ask the AI to write prioritized remediation steps based on findings.

        Args:
            findings: Sorted list of all finding dicts.

        Returns:
            A remediation section string.
        """
        if not findings:
            return "No remediation steps are required as no findings were identified."

        # Only send critical/high/medium for remediation to save tokens
        actionable = [
            f for f in findings
            if f.get("severity", "info").lower() in ("critical", "high", "medium")
        ]

        if not actionable:
            return (
                "All findings are of low or informational severity. "
                "While no urgent remediation is required, consider addressing "
                "low-severity findings as part of regular security hygiene."
            )

        findings_text = "\n".join(
            f"- [{f.get('severity', 'info').upper()}] {f.get('title', 'Untitled')}: "
            f"{f.get('description', '')[:150]}"
            for f in actionable[:15]
        )

        prompt = (
            "You are a cybersecurity remediation advisor. Based on the following findings, "
            "write a prioritized remediation plan. Group remediation steps by priority "
            "(Immediate / Short-term / Long-term). For each step, explain what to do and why. "
            "Keep it actionable and specific. Do NOT use markdown — use plain text with "
            "clear section headers and numbered steps.\n\n"
            f"Findings:\n{findings_text}\n"
        )

        try:
            response = self.ai_router.route(
                prompt=prompt,
                system_prompt="You are a cybersecurity remediation advisor.",
                history=[],
                task_type="explain",
            )
            return response.text.strip()
        except Exception as exc:
            logger.warning("AI remediation generation failed: {}", exc)
            return self._fallback_remediation(actionable)

    def _calculate_risk_score(self, findings: List[dict]) -> Dict[str, Any]:
        """
        Calculate a CVSS-like risk score from findings.

        Uses a weighted formula based on severity counts:
            raw_score = sum(count * weight) / max_possible * 10

        Args:
            findings: List of finding dicts.

        Returns:
            Dict with keys: score (float 0-10), level (str), color (str),
            breakdown (dict of severity → count).
        """
        if not findings:
            return {
                "score": 0.0,
                "level": "NONE",
                "color": "#2ecc71",
                "breakdown": {s: 0 for s in SEVERITY_ORDER},
                "description": "No findings identified.",
            }

        counts = self._count_by_severity(findings)

        # Weighted sum
        weighted_sum = sum(
            counts.get(sev, 0) * weight
            for sev, weight in SEVERITY_WEIGHTS.items()
        )

        # Normalize: max possible is if all findings were critical
        max_possible = len(findings) * SEVERITY_WEIGHTS["critical"]
        if max_possible == 0:
            raw_score = 0.0
        else:
            raw_score = (weighted_sum / max_possible) * 10.0

        # Clamp to 0-10
        score = round(min(max(raw_score, 0.0), 10.0), 1)

        # Boost score if any critical findings exist
        if counts.get("critical", 0) > 0:
            score = max(score, 7.0)

        # Determine level
        if score >= 9.0:
            level, color = "CRITICAL", SEVERITY_COLORS["critical"]
        elif score >= 7.0:
            level, color = "HIGH", SEVERITY_COLORS["high"]
        elif score >= 4.0:
            level, color = "MEDIUM", SEVERITY_COLORS["medium"]
        elif score > 0:
            level, color = "LOW", SEVERITY_COLORS["low"]
        else:
            level, color = "NONE", "#2ecc71"

        # Description
        descriptions = {
            "CRITICAL": "The target has critical security weaknesses requiring immediate attention.",
            "HIGH": "Significant security issues were identified that should be addressed promptly.",
            "MEDIUM": "Moderate security concerns exist that should be remediated in the near term.",
            "LOW": "Minor security issues were found with limited impact.",
            "NONE": "No significant security issues were identified.",
        }

        return {
            "score": score,
            "level": level,
            "color": color,
            "breakdown": counts,
            "description": descriptions.get(level, ""),
        }

    # ──────────────────────────────────────────────────────────
    #  HTML Rendering
    # ──────────────────────────────────────────────────────────

    def _render_html(self, report_type: str, context: Dict[str, Any]) -> str:
        """
        Render the appropriate Jinja2 HTML template with the given context.

        Args:
            report_type: The report type key.
            context: Template context dict.

        Returns:
            Rendered HTML string.
        """
        template_name = TEMPLATE_MAP.get(report_type, "pentest_report.html")

        try:
            template = self.jinja_env.get_template(template_name)
        except Exception as exc:
            logger.error("Failed to load template '{}': {}", template_name, exc)
            raise FileNotFoundError(
                f"Report template '{template_name}' not found in {self.template_dir}"
            ) from exc

        html = template.render(**context)
        logger.debug("Rendered HTML template '{}' ({} chars)", template_name, len(html))
        return html

    # ──────────────────────────────────────────────────────────
    #  Data Collection & Processing
    # ──────────────────────────────────────────────────────────

    def _collect_findings(self) -> List[dict]:
        """Collect all findings from project memory, ensuring consistent structure."""
        raw_findings = []

        # Try to get findings from project memory
        try:
            if hasattr(self.project, "findings"):
                raw_findings = list(self.project.findings) if self.project.findings else []
            elif hasattr(self.project, "get_summary"):
                summary = self.project.get_summary()
                if isinstance(summary, dict):
                    raw_findings = summary.get("findings", [])
        except Exception as exc:
            logger.warning("Failed to collect findings from project memory: {}", exc)

        # Normalize each finding to ensure required fields
        normalized = []
        for i, finding in enumerate(raw_findings):
            if not isinstance(finding, dict):
                continue
            normalized.append({
                "id": finding.get("id", f"FINDING-{i + 1:04d}"),
                "type": finding.get("type", "unknown"),
                "title": finding.get("title", "Untitled Finding"),
                "severity": finding.get("severity", "info").lower(),
                "description": finding.get("description", "No description available."),
                "evidence": finding.get("evidence", ""),
                "recommendation": finding.get("recommendation", ""),
                "url": finding.get("url", ""),
                "tool_used": finding.get("tool_used", ""),
                "timestamp": finding.get("timestamp", datetime.now(timezone.utc).isoformat()),
                "evidence_path": finding.get("evidence_path", ""),
            })

        return normalized

    def _sort_findings(self, findings: List[dict]) -> List[dict]:
        """Sort findings by severity (critical first)."""
        order_map = {s: i for i, s in enumerate(SEVERITY_ORDER)}
        return sorted(
            findings,
            key=lambda f: order_map.get(f.get("severity", "info").lower(), 99),
        )

    def _generate_finding_narratives(self, findings: List[dict]) -> List[dict]:
        """
        Generate AI narratives for each finding and return enriched finding dicts.

        Each finding gets an additional 'narrative' key with the AI-written text.
        """
        enriched = []
        for finding in findings:
            narrative = self._write_finding_narrative(finding)
            enriched_finding = {**finding, "narrative": narrative}
            enriched.append(enriched_finding)
        return enriched

    def _get_target_string(self) -> str:
        """Extract target string from project memory."""
        try:
            if hasattr(self.project, "targets") and self.project.targets:
                targets = self.project.targets
                if isinstance(targets, list):
                    return ", ".join(str(t) for t in targets[:5])
                return str(targets)
            if hasattr(self.project, "scope") and self.project.scope:
                scope = self.project.scope
                if isinstance(scope, dict) and "targets" in scope:
                    return ", ".join(str(t) for t in scope["targets"][:5])
            if hasattr(self.project, "name"):
                return str(self.project.name)
        except Exception as exc:
            logger.debug("Could not extract target string: {}", exc)

        return "Unknown Target"

    def _build_commands_timeline(self) -> List[dict]:
        """Build a timeline of commands run during the project."""
        timeline = []
        try:
            if hasattr(self.project, "timeline") and self.project.timeline:
                for entry in self.project.timeline:
                    if isinstance(entry, dict):
                        timeline.append({
                            "timestamp": entry.get("timestamp", ""),
                            "command": entry.get("command", entry.get("action", "")),
                            "result": entry.get("result", entry.get("output", ""))[:200],
                        })
        except Exception as exc:
            logger.debug("Could not build commands timeline: {}", exc)

        return timeline

    def _count_by_severity(self, findings: List[dict]) -> Dict[str, int]:
        """Count findings by severity level."""
        counts: Dict[str, int] = {s: 0 for s in SEVERITY_ORDER}
        for f in findings:
            sev = f.get("severity", "info").lower()
            if sev in counts:
                counts[sev] += 1
            else:
                counts["info"] += 1
        return counts

    # ──────────────────────────────────────────────────────────
    #  Fallbacks & Utilities
    # ──────────────────────────────────────────────────────────

    def _fallback_remediation(self, findings: List[dict]) -> str:
        """Generate a basic remediation section without AI."""
        lines = ["Prioritized Remediation Steps:", ""]
        for i, f in enumerate(findings, 1):
            title = f.get("title", "Untitled")
            severity = f.get("severity", "info").upper()
            recommendation = f.get("recommendation", "Review and remediate this finding.")
            lines.append(f"{i}. [{severity}] {title}")
            lines.append(f"   Action: {recommendation}")
            lines.append("")
        return "\n".join(lines)

    @staticmethod
    def _finding_cache_key(finding: dict) -> str:
        """Generate a deterministic cache key for a finding."""
        key_data = json.dumps(
            {
                "title": finding.get("title", ""),
                "severity": finding.get("severity", ""),
                "description": finding.get("description", ""),
                "evidence": finding.get("evidence", ""),
            },
            sort_keys=True,
        )
        return hashlib.sha256(key_data.encode("utf-8")).hexdigest()[:16]

    @staticmethod
    def _severity_color_filter(severity: str) -> str:
        """Jinja2 filter: severity string → hex color."""
        return SEVERITY_COLORS.get(severity.lower(), SEVERITY_COLORS["info"])

    @staticmethod
    def _severity_badge_filter(severity: str) -> str:
        """Jinja2 filter: severity string → HTML badge span."""
        color = SEVERITY_COLORS.get(severity.lower(), SEVERITY_COLORS["info"])
        label = severity.upper()
        return (
            f'<span class="severity-badge" style="background-color: {color}; '
            f'color: #fff; padding: 2px 10px; border-radius: 3px; '
            f'font-weight: bold; font-size: 0.85em;">{label}</span>'
        )
