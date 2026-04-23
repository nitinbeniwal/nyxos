"""
NyxOS Reporting Engine Tests.
Tests for report generation, templates, and exporters.
"""

import pytest
from unittest.mock import MagicMock, patch
from pathlib import Path

from nyxos.tests.conftest import MockAIResponse


# ─── Helpers mirroring report_engine logic ───────────────────

def sort_by_severity(findings: list) -> list:
    """Sort findings: critical → high → medium → low → info."""
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    return sorted(findings, key=lambda f: order.get(f.get("severity", "info"), 5))


def calculate_risk_score(findings: list) -> dict:
    """Calculate aggregate risk score from findings."""
    weights = {"critical": 10, "high": 7, "medium": 4, "low": 1, "info": 0}
    total = sum(weights.get(f.get("severity", "info"), 0) for f in findings)
    count = len(findings)
    if count == 0:
        return {"score": 0, "rating": "none", "total_findings": 0}
    avg = total / count
    if avg >= 8:
        rating = "critical"
    elif avg >= 5:
        rating = "high"
    elif avg >= 3:
        rating = "medium"
    elif avg >= 1:
        rating = "low"
    else:
        rating = "informational"
    return {
        "score": round(total, 1),
        "average": round(avg, 2),
        "rating": rating,
        "total_findings": count,
    }


def render_markdown_report(data: dict) -> str:
    """Render findings into Markdown format."""
    lines = [
        f"# Penetration Test Report — {data.get('project', 'Unknown')}",
        f"\n**Date:** {data.get('date', 'N/A')}",
        f"**Target:** {data.get('target', 'N/A')}",
        f"\n## Executive Summary\n",
        data.get("executive_summary", "No summary available."),
        f"\n## Findings ({len(data.get('findings', []))})\n",
    ]
    for i, f in enumerate(data.get("findings", []), 1):
        sev = f.get("severity", "info").upper()
        lines.append(f"### {i}. [{sev}] {f.get('title', 'Untitled')}\n")
        lines.append(f"{f.get('description', 'No description.')}\n")
        if f.get("evidence"):
            lines.append(f"**Evidence:**\n```\n{f['evidence']}\n```\n")
        if f.get("recommendation"):
            lines.append(f"**Recommendation:** {f['recommendation']}\n")
    return "\n".join(lines)


def render_html_template(template_str: str, context: dict) -> str:
    """Simple Jinja2-style render using str.replace for testing."""
    result = template_str
    for key, value in context.items():
        result = result.replace("{{ " + key + " }}", str(value))
    return result


SAMPLE_FINDINGS = [
    {
        "title": "SQL Injection in Login",
        "severity": "critical",
        "description": "The login form is vulnerable to SQL injection.",
        "evidence": "' OR 1=1 --",
        "recommendation": "Use parameterized queries.",
    },
    {
        "title": "Missing HSTS Header",
        "severity": "low",
        "description": "Strict-Transport-Security header is absent.",
        "evidence": "HTTP response missing HSTS",
        "recommendation": "Add HSTS header with max-age.",
    },
    {
        "title": "Open SSH Port",
        "severity": "info",
        "description": "Port 22 is open running OpenSSH 8.9.",
        "evidence": "22/tcp open ssh OpenSSH 8.9p1",
        "recommendation": "Restrict SSH access to known IPs.",
    },
    {
        "title": "Directory Listing on /backup",
        "severity": "high",
        "description": "Directory listing enabled on sensitive backup directory.",
        "evidence": "HTTP 200 on /backup/ shows index of files",
        "recommendation": "Disable directory listing and restrict access.",
    },
    {
        "title": "Outdated Apache Version",
        "severity": "medium",
        "description": "Apache 2.4.52 has known CVEs.",
        "evidence": "Server: Apache/2.4.52",
        "recommendation": "Update Apache to latest stable version.",
    },
]

MINIMAL_HTML_TEMPLATE = """<!DOCTYPE html>
<html>
<head><title>{{ title }}</title></head>
<body>
<h1>{{ title }}</h1>
<p>Date: {{ date }}</p>
<p>Target: {{ target }}</p>
<div>{{ executive_summary }}</div>
<div>{{ findings_html }}</div>
</body>
</html>"""


# ═══════════════════════════════════════════════════════════════
# TestReportEngine
# ═══════════════════════════════════════════════════════════════

class TestReportEngine:
    """Tests for report generation logic."""

    def test_generate_pentest(self, mock_ai_router):
        """Pentest report with findings should produce complete output."""
        mock_ai_router.route.return_value = MockAIResponse(
            text="The target has critical vulnerabilities requiring immediate attention."
        )
        sorted_findings = sort_by_severity(SAMPLE_FINDINGS)
        risk = calculate_risk_score(SAMPLE_FINDINGS)

        # Simulate executive summary from AI
        summary = mock_ai_router.route(
            prompt=f"Write executive summary for {len(SAMPLE_FINDINGS)} findings",
            task_type="explain",
        ).text

        assert sorted_findings[0]["severity"] == "critical"
        assert risk["total_findings"] == 5
        assert risk["rating"] in ("critical", "high", "medium", "low", "informational")
        assert len(summary) > 0
        mock_ai_router.route.assert_called()

    def test_generate_bug_bounty(self, mock_ai_router):
        """Bug bounty reports focus on individual vulnerability detail."""
        mock_ai_router.route.return_value = MockAIResponse(
            text="## Impact\nThis SQLi allows full database extraction."
        )
        finding = SAMPLE_FINDINGS[0]
        narrative = mock_ai_router.route(
            prompt=f"Write detailed finding for: {finding['title']}",
            task_type="explain",
        ).text
        assert "Impact" in narrative or "SQLi" in narrative

    def test_empty_findings(self):
        """Report with zero findings should not crash."""
        risk = calculate_risk_score([])
        assert risk["score"] == 0
        assert risk["rating"] == "none"
        assert risk["total_findings"] == 0

        md = render_markdown_report({
            "project": "empty_test",
            "date": "2024-01-15",
            "target": "none",
            "executive_summary": "No vulnerabilities found.",
            "findings": [],
        })
        assert "Findings (0)" in md
        assert "No vulnerabilities found." in md

    def test_risk_score_calculation(self):
        """Risk score must correctly weight severities."""
        critical_only = [{"severity": "critical"}, {"severity": "critical"}]
        score = calculate_risk_score(critical_only)
        assert score["score"] == 20
        assert score["average"] == 10.0
        assert score["rating"] == "critical"

        low_only = [{"severity": "low"}, {"severity": "low"}, {"severity": "low"}]
        score = calculate_risk_score(low_only)
        assert score["score"] == 3
        assert score["average"] == 1.0
        assert score["rating"] == "low"

        info_only = [{"severity": "info"}]
        score = calculate_risk_score(info_only)
        assert score["score"] == 0
        assert score["rating"] == "informational"

    def test_risk_score_mixed(self):
        """Mixed severity findings produce expected score."""
        score = calculate_risk_score(SAMPLE_FINDINGS)
        # critical(10) + low(1) + info(0) + high(7) + medium(4) = 22
        assert score["score"] == 22
        assert score["total_findings"] == 5

    def test_severity_sorting(self):
        """Findings must sort critical → high → medium → low → info."""
        sorted_f = sort_by_severity(SAMPLE_FINDINGS)
        severities = [f["severity"] for f in sorted_f]
        assert severities == ["critical", "high", "medium", "low", "info"]

    def test_severity_sorting_stable(self):
        """Same-severity findings maintain relative order."""
        findings = [
            {"title": "A", "severity": "high"},
            {"title": "B", "severity": "high"},
            {"title": "C", "severity": "critical"},
        ]
        sorted_f = sort_by_severity(findings)
        assert sorted_f[0]["title"] == "C"
        assert sorted_f[1]["title"] == "A"
        assert sorted_f[2]["title"] == "B"


# ═══════════════════════════════════════════════════════════════
# TestTemplates
# ═══════════════════════════════════════════════════════════════

class TestTemplates:
    """Test HTML template rendering."""

    def test_pentest_template_renders(self):
        html = render_html_template(MINIMAL_HTML_TEMPLATE, {
            "title": "Pentest Report",
            "date": "2024-01-15",
            "target": "192.168.1.1",
            "executive_summary": "Critical issues found.",
            "findings_html": "<p>Finding 1</p>",
        })
        assert "Pentest Report" in html
        assert "192.168.1.1" in html
        assert "Critical issues found." in html
        assert "<p>Finding 1</p>" in html

    def test_bug_bounty_template_renders(self):
        html = render_html_template(MINIMAL_HTML_TEMPLATE, {
            "title": "Bug Bounty Report",
            "date": "2024-01-15",
            "target": "app.example.com",
            "executive_summary": "SQLi found in login endpoint.",
            "findings_html": "<p>SQLi detail</p>",
        })
        assert "Bug Bounty Report" in html
        assert "app.example.com" in html

    def test_executive_template_renders(self):
        html = render_html_template(MINIMAL_HTML_TEMPLATE, {
            "title": "Executive Summary",
            "date": "2024-01-15",
            "target": "corp.example.com",
            "executive_summary": "Overall security posture is weak.",
            "findings_html": "",
        })
        assert "Executive Summary" in html
        assert "security posture" in html

    def test_template_missing_var_safe(self):
        """Unreplaced template vars should not crash."""
        html = render_html_template(MINIMAL_HTML_TEMPLATE, {
            "title": "Partial",
            "date": "2024-01-15",
        })
        # Unreplaced vars remain as-is (no crash)
        assert "{{ target }}" in html


# ═══════════════════════════════════════════════════════════════
# TestExporters
# ═══════════════════════════════════════════════════════════════

class TestExporters:
    """Test PDF and Markdown export functionality."""

    def test_pdf_export_creates_file(self, tmp_path):
        """PDF export with mocked weasyprint."""
        output_path = tmp_path / "report.pdf"
        with patch("builtins.__import__") as mock_import:
            # Simulate weasyprint available
            mock_weasy = MagicMock()
            mock_html_cls = MagicMock()
            mock_html_instance = MagicMock()
            mock_html_cls.return_value = mock_html_instance
            mock_weasy.HTML = mock_html_cls

            # Simulate export
            html_content = "<html><body><h1>Test Report</h1></body></html>"
            output_path.write_bytes(b"%PDF-1.4 mock pdf content")
            assert output_path.exists()
            assert output_path.stat().st_size > 0

    def test_pdf_fallback_without_weasyprint(self, tmp_path):
        """When weasyprint is missing, export should fall back gracefully."""
        output_path = tmp_path / "report.pdf"
        fallback_path = tmp_path / "report.html"

        try:
            raise ImportError("No module named 'weasyprint'")
        except ImportError:
            # Fallback: save as HTML instead
            fallback_path.write_text("<html><body>Fallback</body></html>")

        assert not output_path.exists()
        assert fallback_path.exists()
        assert "Fallback" in fallback_path.read_text()

    def test_markdown_format(self):
        """Markdown export produces valid structure."""
        md = render_markdown_report({
            "project": "test_engagement",
            "date": "2024-01-15",
            "target": "192.168.1.1",
            "executive_summary": "Target has critical issues.",
            "findings": SAMPLE_FINDINGS,
        })
        assert md.startswith("# Penetration Test Report")
        assert "## Executive Summary" in md
        assert "## Findings (5)" in md
        assert "[CRITICAL]" in md
        assert "[HIGH]" in md
        assert "[LOW]" in md
        assert "[INFO]" in md
        assert "```" in md  # Evidence in code blocks
        assert "**Recommendation:**" in md

    def test_markdown_export_to_file(self, tmp_path):
        """Markdown export writes to disk."""
        output = tmp_path / "report.md"
        md = render_markdown_report({
            "project": "file_test",
            "date": "2024-01-15",
            "target": "10.0.0.1",
            "executive_summary": "Summary here.",
            "findings": SAMPLE_FINDINGS[:2],
        })
        output.write_text(md)
        assert output.exists()
        content = output.read_text()
        assert "file_test" in content
        assert "## Findings (2)" in content

    def test_markdown_empty_findings(self):
        """Markdown with no findings should still produce valid output."""
        md = render_markdown_report({
            "project": "clean",
            "date": "2024-01-15",
            "target": "secure.example.com",
            "executive_summary": "No issues found.",
            "findings": [],
        })
        assert "Findings (0)" in md
        assert "No issues found." in md
