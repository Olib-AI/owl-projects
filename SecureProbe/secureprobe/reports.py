"""
Report generation for SecureProbe scan results.

Generates JSON and HTML reports with comprehensive vulnerability
information and remediation guidance.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import structlog
from jinja2 import Environment

from secureprobe.models import ScanResult, Severity
from secureprobe.utils import format_duration

logger = structlog.get_logger(__name__)


class ReportGenerator:
    """
    Generate security scan reports in various formats.

    Supports JSON and HTML output with customizable templates.
    """

    def __init__(self, result: ScanResult) -> None:
        """
        Initialize report generator.

        Args:
            result: Scan result to report on
        """
        self.result = result

    def generate_json(self, output_path: str | Path | None = None) -> str:
        """
        Generate JSON report.

        Args:
            output_path: Optional path to save report

        Returns:
            JSON string of the report
        """
        logger.info(
            "generating_json_report",
            total_findings=len(self.result.findings),
            severity_counts=dict(self.result.severity_counts),
        )
        report_data = self._build_report_data()
        json_str = json.dumps(report_data, indent=2, default=str)

        logger.info(
            "json_report_generated",
            findings_in_report=len(report_data.get("findings", [])),
        )

        if output_path:
            Path(output_path).write_text(json_str)
            logger.info("json_report_saved", path=str(output_path))

        return json_str

    def generate_html(self, output_path: str | Path | None = None) -> str:
        """
        Generate HTML report.

        Args:
            output_path: Optional path to save report

        Returns:
            HTML string of the report
        """
        logger.info(
            "generating_html_report",
            total_findings=len(self.result.findings),
            severity_counts=dict(self.result.severity_counts),
        )
        report_data = self._build_report_data()
        html = self._render_html(report_data)

        logger.info(
            "html_report_generated",
            findings_in_report=len(report_data.get("findings", [])),
        )

        if output_path:
            Path(output_path).write_text(html)
            logger.info("html_report_saved", path=str(output_path))

        return html

    def _build_report_data(self) -> dict[str, Any]:
        """Build report data structure."""
        severity_counts = self.result.severity_counts
        findings_by_severity = self.result.findings_by_severity

        return {
            "meta": {
                "report_generated": datetime.now(timezone.utc).isoformat(),
                "scanner_version": "1.0.0",
                "target_url": self.result.target_url,
                "scan_id": self.result.scan_id,
            },
            "summary": {
                "started_at": self.result.started_at.isoformat(),
                "completed_at": self.result.completed_at.isoformat() if self.result.completed_at else None,
                "duration": format_duration(self.result.duration_seconds),
                "duration_seconds": self.result.duration_seconds,
                "urls_scanned": self.result.urls_scanned,
                "total_findings": len(self.result.findings),
                "authorization_verified": self.result.authorization_verified,
                "severity_counts": {s.value: c for s, c in severity_counts.items()},
            },
            "findings": [
                {
                    "id": f.id,
                    "analyzer": f.analyzer.value,
                    "severity": f.severity.value,
                    "title": f.title,
                    "description": f.description,
                    "cwe_id": f.cwe_id,
                    "cwe_name": f.cwe_name,
                    "url": f.url,
                    "affected_urls": f.affected_urls,
                    "affected_count": len(f.affected_urls),
                    "evidence": f.evidence,
                    "remediation": f.remediation,
                    "cvss_score": f.cvss_score,
                    "references": f.references,
                    "metadata": f.metadata,
                    "timestamp": f.timestamp.isoformat(),
                }
                for f in self.result.findings
            ],
            "findings_by_severity": {
                s.value: [
                    {"id": f.id, "title": f.title, "cwe_id": f.cwe_id}
                    for f in findings
                ]
                for s, findings in findings_by_severity.items()
            },
            "errors": self.result.errors,
        }

    def _render_html(self, data: dict[str, Any]) -> str:
        """Render HTML report from data.

        Uses Jinja2 with autoescape enabled to prevent XSS attacks from
        malicious payloads in scan findings, evidence, and other user data.
        """
        env = Environment(autoescape=True)
        template = env.from_string(HTML_TEMPLATE)
        return template.render(
            data=data,
            severity_class=self._severity_class,
            Severity=Severity,
        )

    @staticmethod
    def _severity_class(severity: str) -> str:
        """Get CSS class for severity level."""
        classes = {
            "CRITICAL": "severity-critical",
            "HIGH": "severity-high",
            "MEDIUM": "severity-medium",
            "LOW": "severity-low",
            "INFO": "severity-info",
        }
        return classes.get(severity, "severity-info")


HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SecureProbe Scan Report - {{ data.meta.target_url }}</title>
    <style>
        :root {
            --primary: #2563eb;
            --primary-dark: #1d4ed8;
            --critical: #dc2626;
            --high: #ea580c;
            --medium: #ca8a04;
            --low: #16a34a;
            --info: #6b7280;
            --bg: #f8fafc;
            --card-bg: #ffffff;
            --text: #1e293b;
            --text-muted: #64748b;
            --border: #e2e8f0;
        }
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: var(--bg);
            color: var(--text);
            line-height: 1.6;
        }
        .container { max-width: 1200px; margin: 0 auto; padding: 2rem; }

        /* Header - Professional Blue/Slate */
        header {
            background: var(--primary);
            color: white;
            padding: 2rem;
            margin-bottom: 2rem;
            border-radius: 12px;
        }
        header h1 { font-size: 1.75rem; margin-bottom: 0.5rem; font-weight: 600; }
        header .target-url {
            font-size: 1.25rem;
            font-weight: 500;
            margin-bottom: 0.75rem;
            word-break: break-all;
        }
        header .meta { opacity: 0.9; font-size: 0.875rem; }

        /* Hero Score Section */
        .hero-section {
            background: var(--card-bg);
            border-radius: 12px;
            padding: 2rem;
            margin-bottom: 2rem;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
            display: grid;
            grid-template-columns: auto 1fr auto;
            gap: 2rem;
            align-items: center;
        }
        .score-circle {
            width: 140px;
            height: 140px;
            border-radius: 50%;
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            font-weight: 700;
            color: white;
        }
        .score-circle.score-excellent { background: var(--low); }
        .score-circle.score-good { background: #22c55e; }
        .score-circle.score-fair { background: var(--medium); }
        .score-circle.score-poor { background: var(--high); }
        .score-circle.score-critical { background: var(--critical); }
        .score-value { font-size: 2.5rem; line-height: 1; }
        .score-label { font-size: 0.65rem; opacity: 0.85; margin-top: 0.5rem; text-transform: uppercase; letter-spacing: 0.05em; }
        .score-rating { font-size: 0.75rem; font-weight: 600; margin-top: 0.125rem; text-transform: uppercase; }

        .hero-summary {
            display: flex;
            flex-direction: column;
            gap: 0.5rem;
        }
        .hero-summary h2 { font-size: 1.5rem; color: var(--text); margin-bottom: 0.5rem; }
        .executive-summary {
            color: var(--text-muted);
            font-size: 1rem;
            line-height: 1.7;
        }

        .severity-counts {
            display: flex;
            gap: 1rem;
        }
        .severity-count {
            display: flex;
            flex-direction: column;
            align-items: center;
            padding: 1rem;
            border-radius: 8px;
            min-width: 70px;
        }
        .severity-count.critical { background: #fef2f2; }
        .severity-count.high { background: #fff7ed; }
        .severity-count.medium { background: #fefce8; }
        .severity-count.low { background: #f0fdf4; }
        .severity-count.info { background: #f3f4f6; }
        .severity-count .count {
            font-size: 1.75rem;
            font-weight: 700;
            line-height: 1;
        }
        .severity-count.critical .count { color: var(--critical); }
        .severity-count.high .count { color: var(--high); }
        .severity-count.medium .count { color: var(--medium); }
        .severity-count.low .count { color: var(--low); }
        .severity-count.info .count { color: var(--info); }
        .severity-count .label {
            font-size: 0.75rem;
            color: var(--text-muted);
            margin-top: 0.25rem;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }
        .severity-count .icon {
            font-size: 1.25rem;
            margin-bottom: 0.25rem;
        }

        /* Quick Stats Bar */
        .quick-stats {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 1rem;
            margin-bottom: 2rem;
        }
        .stat-card {
            background: var(--card-bg);
            border-radius: 8px;
            padding: 1.25rem;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
            border-left: 4px solid var(--primary);
        }
        .stat-card h3 {
            font-size: 0.75rem;
            color: var(--text-muted);
            text-transform: uppercase;
            letter-spacing: 0.05em;
            margin-bottom: 0.5rem;
        }
        .stat-card .value {
            font-size: 1.5rem;
            font-weight: 700;
            color: var(--text);
        }

        /* Filter Buttons */
        .filter-bar {
            background: var(--card-bg);
            border-radius: 8px;
            padding: 1rem 1.5rem;
            margin-bottom: 1.5rem;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
            display: flex;
            align-items: center;
            gap: 0.75rem;
            flex-wrap: wrap;
        }
        .filter-bar .filter-label {
            font-weight: 600;
            color: var(--text-muted);
            font-size: 0.875rem;
            margin-right: 0.5rem;
        }
        .filter-btn {
            display: inline-flex;
            align-items: center;
            gap: 0.375rem;
            padding: 0.5rem 1rem;
            border: 2px solid var(--border);
            border-radius: 6px;
            background: var(--card-bg);
            color: var(--text);
            font-size: 0.875rem;
            font-weight: 500;
            cursor: pointer;
            transition: all 0.15s ease;
        }
        .filter-btn:hover {
            border-color: var(--primary);
            background: #eff6ff;
        }
        .filter-btn.active {
            border-color: var(--primary);
            background: var(--primary);
            color: white;
        }
        .filter-btn .filter-count {
            background: rgba(0,0,0,0.1);
            padding: 0.125rem 0.5rem;
            border-radius: 10px;
            font-size: 0.75rem;
            font-weight: 600;
        }
        .filter-btn.active .filter-count {
            background: rgba(255,255,255,0.2);
        }
        .filter-btn.filter-critical { border-color: #fecaca; }
        .filter-btn.filter-critical:hover, .filter-btn.filter-critical.active { background: var(--critical); border-color: var(--critical); color: white; }
        .filter-btn.filter-high { border-color: #fed7aa; }
        .filter-btn.filter-high:hover, .filter-btn.filter-high.active { background: var(--high); border-color: var(--high); color: white; }
        .filter-btn.filter-medium { border-color: #fef08a; }
        .filter-btn.filter-medium:hover, .filter-btn.filter-medium.active { background: var(--medium); border-color: var(--medium); color: white; }
        .filter-btn.filter-low { border-color: #bbf7d0; }
        .filter-btn.filter-low:hover, .filter-btn.filter-low.active { background: var(--low); border-color: var(--low); color: white; }
        .filter-btn.filter-info { border-color: #d1d5db; }
        .filter-btn.filter-info:hover, .filter-btn.filter-info.active { background: var(--info); border-color: var(--info); color: white; }
        .filter-status {
            margin-left: auto;
            font-size: 0.875rem;
            color: var(--text-muted);
        }

        /* Findings Section */
        .findings-section { margin-top: 2rem; }
        .findings-section h2 {
            margin-bottom: 1rem;
            font-size: 1.25rem;
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }
        .findings-section h2::before {
            content: '';
            display: inline-block;
            width: 4px;
            height: 1.25rem;
            background: var(--primary);
            border-radius: 2px;
        }
        .finding-card {
            background: var(--card-bg);
            border-radius: 8px;
            padding: 1.5rem;
            margin-bottom: 1rem;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
            border-left: 4px solid var(--info);
        }
        .finding-card.severity-critical { border-left-color: var(--critical); }
        .finding-card.severity-high { border-left-color: var(--high); }
        .finding-card.severity-medium { border-left-color: var(--medium); }
        .finding-card.severity-low { border-left-color: var(--low); }
        .finding-card.hidden { display: none; }
        .finding-header {
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            margin-bottom: 1rem;
            gap: 1rem;
        }
        .finding-title { font-size: 1.1rem; font-weight: 600; }
        .finding-badges { display: flex; gap: 0.5rem; flex-shrink: 0; }
        .badge {
            font-size: 0.75rem;
            padding: 0.25rem 0.625rem;
            border-radius: 4px;
            font-weight: 600;
        }
        .badge.severity-critical { background: #fef2f2; color: var(--critical); }
        .badge.severity-high { background: #fff7ed; color: var(--high); }
        .badge.severity-medium { background: #fefce8; color: var(--medium); }
        .badge.severity-low { background: #f0fdf4; color: var(--low); }
        .badge.severity-info { background: #f3f4f6; color: var(--info); }
        .badge.cwe { background: #eff6ff; color: var(--primary); }
        .finding-content p { margin-bottom: 1rem; color: var(--text-muted); }
        .finding-detail { margin-bottom: 0.75rem; }
        .finding-detail strong { color: var(--text); }
        .evidence {
            background: #f1f5f9;
            padding: 0.75rem 1rem;
            border-radius: 6px;
            font-family: 'SF Mono', Monaco, 'Cascadia Code', monospace;
            font-size: 0.85rem;
            word-break: break-all;
            margin-top: 0.5rem;
            border: 1px solid var(--border);
        }
        .remediation {
            background: #f0fdf4;
            border: 1px solid #86efac;
            padding: 0.75rem 1rem;
            border-radius: 6px;
            margin-top: 0.5rem;
            color: #166534;
        }
        .cvss-score {
            display: inline-flex;
            align-items: center;
            gap: 0.5rem;
            background: #f1f5f9;
            padding: 0.25rem 0.75rem;
            border-radius: 4px;
            font-weight: 600;
            font-size: 0.875rem;
        }

        /* Empty State */
        .empty-state {
            text-align: center;
            padding: 3rem;
            color: var(--text-muted);
        }
        .empty-state .icon { font-size: 3rem; margin-bottom: 1rem; }
        .no-results-message {
            text-align: center;
            padding: 2rem;
            color: var(--text-muted);
            background: var(--card-bg);
            border-radius: 8px;
            margin-bottom: 1rem;
            display: none;
        }

        /* Errors Section */
        .error-card {
            background: #fef2f2;
            border: 1px solid #fecaca;
            border-radius: 8px;
            padding: 1rem;
            margin-bottom: 0.75rem;
            color: var(--critical);
        }

        /* Footer */
        footer {
            text-align: center;
            color: var(--text-muted);
            font-size: 0.875rem;
            margin-top: 3rem;
            padding-top: 1.5rem;
            border-top: 1px solid var(--border);
        }
        footer a { color: var(--primary); text-decoration: none; }
        footer a:hover { text-decoration: underline; }

        /* Responsive */
        @media (max-width: 900px) {
            .hero-section {
                grid-template-columns: 1fr;
                text-align: center;
            }
            .score-circle { margin: 0 auto; }
            .severity-counts { justify-content: center; flex-wrap: wrap; }
        }
        @media (max-width: 640px) {
            .container { padding: 1rem; }
            .quick-stats { grid-template-columns: 1fr 1fr; }
            .finding-header { flex-direction: column; }
            .filter-bar { justify-content: center; }
            .filter-status { margin-left: 0; width: 100%; text-align: center; margin-top: 0.5rem; }
        }

        /* Print-friendly styles for PDF export */
        @media print {
            * {
                -webkit-print-color-adjust: exact !important;
                print-color-adjust: exact !important;
                color-adjust: exact !important;
            }
            body {
                background: white !important;
                color: black !important;
                font-size: 11pt;
                line-height: 1.4;
            }
            .container {
                max-width: 100%;
                padding: 0;
                margin: 0;
            }

            /* Hide filter bar in print */
            .filter-bar {
                display: none !important;
            }
            .no-results-message {
                display: none !important;
            }

            /* Show all findings regardless of filter */
            .finding-card.hidden {
                display: block !important;
            }

            /* Header styling for print */
            header {
                background: #2563eb !important;
                border-radius: 0;
                margin-bottom: 1rem;
                padding: 1rem 1.5rem;
                page-break-after: avoid;
            }
            header h1 {
                font-size: 1.5rem;
                margin-bottom: 0.25rem;
            }
            header .target-url {
                font-size: 1rem;
            }

            /* Hero section for print */
            .hero-section {
                box-shadow: none;
                border: 1px solid #ddd;
                border-radius: 0;
                padding: 1rem;
                margin-bottom: 1rem;
                page-break-after: avoid;
                page-break-inside: avoid;
            }
            .score-circle {
                width: 100px;
                height: 100px;
            }
            .score-value {
                font-size: 2rem;
            }
            .severity-counts {
                gap: 0.5rem;
            }
            .severity-count {
                padding: 0.5rem;
                min-width: 50px;
            }
            .severity-count .count {
                font-size: 1.25rem;
            }

            /* Quick stats for print */
            .quick-stats {
                margin-bottom: 1rem;
            }
            .stat-card {
                box-shadow: none;
                border: 1px solid #ddd;
                border-radius: 0;
                padding: 0.75rem;
                background: white !important;
            }
            .stat-card .value {
                font-size: 1.25rem;
            }

            /* Findings for print */
            .findings-section {
                margin-top: 1rem;
            }
            .findings-section h2 {
                font-size: 1.1rem;
                margin-bottom: 0.75rem;
                page-break-after: avoid;
            }
            .finding-card {
                box-shadow: none;
                border: 1px solid #ddd;
                border-radius: 0;
                padding: 1rem;
                margin-bottom: 0.75rem;
                page-break-inside: avoid;
                break-inside: avoid;
                background: white !important;
            }
            .finding-card.severity-critical { border-left: 4px solid #dc2626 !important; }
            .finding-card.severity-high { border-left: 4px solid #ea580c !important; }
            .finding-card.severity-medium { border-left: 4px solid #ca8a04 !important; }
            .finding-card.severity-low { border-left: 4px solid #16a34a !important; }
            .finding-card.severity-info { border-left: 4px solid #6b7280 !important; }

            .finding-header {
                margin-bottom: 0.5rem;
            }
            .finding-title {
                font-size: 1rem;
            }
            .badge {
                border: 1px solid currentColor;
            }
            .evidence {
                background: #f5f5f5 !important;
                border: 1px solid #ddd;
                font-size: 0.8rem;
                padding: 0.5rem;
            }
            .remediation {
                background: #f0fff0 !important;
                border: 1px solid #90ee90;
                padding: 0.5rem;
            }

            /* Footer for print */
            footer {
                margin-top: 1.5rem;
                padding-top: 1rem;
                font-size: 0.8rem;
                page-break-before: avoid;
            }
            footer a {
                color: black !important;
                text-decoration: underline;
            }

            /* Error cards for print */
            .error-card {
                background: #fff0f0 !important;
                border: 1px solid #ffcccc;
                page-break-inside: avoid;
            }

            /* Page margins */
            @page {
                margin: 1.5cm;
                size: A4;
            }
            @page :first {
                margin-top: 1cm;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>SecureProbe Security Scan Report</h1>
            <div class="target-url">{{ data.meta.target_url }}</div>
            <div class="meta">
                Scan ID: {{ data.meta.scan_id }} | Completed: {{ data.meta.report_generated[:19].replace('T', ' ') }} UTC
            </div>
        </header>

        <!-- Hero Section with Score -->
        {% set critical_count = data.summary.severity_counts.get('CRITICAL', 0) %}
        {% set high_count = data.summary.severity_counts.get('HIGH', 0) %}
        {% set medium_count = data.summary.severity_counts.get('MEDIUM', 0) %}
        {% set low_count = data.summary.severity_counts.get('LOW', 0) %}
        {% set info_count = data.summary.severity_counts.get('INFO', 0) %}
        {% set total = data.summary.total_findings %}
        {# Weighted penalty with diminishing returns per category #}
        {# Formula: Each category has a max penalty cap to prevent instant zero #}
        {# Critical: 8 pts each, max 40 pts; High: 4 pts each, max 30 pts #}
        {# Medium: 2 pts each, max 20 pts; Low: 0.5 pts each, max 10 pts #}
        {% set critical_penalty = [critical_count * 8, 40] | min %}
        {% set high_penalty = [high_count * 4, 30] | min %}
        {% set medium_penalty = [medium_count * 2, 20] | min %}
        {% set low_penalty = [(low_count * 0.5) | int, 10] | min %}
        {% set score = 100 - critical_penalty - high_penalty - medium_penalty - low_penalty %}
        {% set score = [score, 0] | max %}
        {% set score = [score, 100] | min %}
        {% if score >= 90 %}
            {% set score_class = 'score-excellent' %}
            {% set score_text = 'Secure' %}
        {% elif score >= 70 %}
            {% set score_class = 'score-good' %}
            {% set score_text = 'Good' %}
        {% elif score >= 50 %}
            {% set score_class = 'score-fair' %}
            {% set score_text = 'Fair' %}
        {% elif score >= 25 %}
            {% set score_class = 'score-poor' %}
            {% set score_text = 'At Risk' %}
        {% else %}
            {% set score_class = 'score-critical' %}
            {% set score_text = 'Vulnerable' %}
        {% endif %}

        <div class="hero-section">
            <div class="score-circle {{ score_class }}">
                <span class="score-value">{{ score }}</span>
                <span class="score-label">Security Score</span>
                <span class="score-rating">{{ score_text }}</span>
            </div>

            <div class="hero-summary">
                <h2>Security Assessment</h2>
                <p class="executive-summary">
                    {% if total == 0 %}
                        No security vulnerabilities were detected during this scan. The target appears to have strong security controls in place.
                    {% elif critical_count > 0 %}
                        Critical security issues detected requiring immediate attention. Found {{ critical_count }} critical and {{ high_count }} high severity vulnerabilities that could lead to significant compromise.
                    {% elif high_count > 0 %}
                        High severity issues detected that should be addressed promptly. Found {{ high_count }} high and {{ medium_count }} medium severity vulnerabilities requiring remediation.
                    {% elif medium_count > 0 %}
                        Moderate security issues detected. Found {{ medium_count }} medium severity findings that should be reviewed and addressed according to risk appetite.
                    {% else %}
                        Minor security observations detected. Found {{ low_count + info_count }} low severity or informational findings for review.
                    {% endif %}
                </p>
            </div>

            <div class="severity-counts">
                <div class="severity-count critical">
                    <span class="icon">!!</span>
                    <span class="count">{{ critical_count }}</span>
                    <span class="label">Critical</span>
                </div>
                <div class="severity-count high">
                    <span class="icon">!</span>
                    <span class="count">{{ high_count }}</span>
                    <span class="label">High</span>
                </div>
                <div class="severity-count medium">
                    <span class="icon">~</span>
                    <span class="count">{{ medium_count }}</span>
                    <span class="label">Medium</span>
                </div>
                <div class="severity-count low">
                    <span class="icon">-</span>
                    <span class="count">{{ low_count }}</span>
                    <span class="label">Low</span>
                </div>
                <div class="severity-count info">
                    <span class="icon">i</span>
                    <span class="count">{{ info_count }}</span>
                    <span class="label">Info</span>
                </div>
            </div>
        </div>

        <!-- Quick Stats -->
        <div class="quick-stats">
            <div class="stat-card">
                <h3>Total Findings</h3>
                <div class="value">{{ total }}</div>
            </div>
            <div class="stat-card">
                <h3>URLs Scanned</h3>
                <div class="value">{{ data.summary.urls_scanned }}</div>
            </div>
            <div class="stat-card">
                <h3>Scan Duration</h3>
                <div class="value">{{ data.summary.duration }}</div>
            </div>
            <div class="stat-card">
                <h3>Authorization</h3>
                <div class="value">{% if data.summary.authorization_verified %}Verified{% else %}Pending{% endif %}</div>
            </div>
        </div>

        <!-- Findings -->
        <div class="findings-section">
            <h2>Detailed Findings</h2>

            <!-- Filter Bar -->
            {% if data.findings %}
            <div class="filter-bar" id="filterBar">
                <span class="filter-label">Filter by Severity:</span>
                <button class="filter-btn active" data-filter="all" onclick="filterFindings('all')">
                    All <span class="filter-count">{{ total }}</span>
                </button>
                <button class="filter-btn filter-critical" data-filter="CRITICAL" onclick="filterFindings('CRITICAL')">
                    Critical <span class="filter-count">{{ critical_count }}</span>
                </button>
                <button class="filter-btn filter-high" data-filter="HIGH" onclick="filterFindings('HIGH')">
                    High <span class="filter-count">{{ high_count }}</span>
                </button>
                <button class="filter-btn filter-medium" data-filter="MEDIUM" onclick="filterFindings('MEDIUM')">
                    Medium <span class="filter-count">{{ medium_count }}</span>
                </button>
                <button class="filter-btn filter-low" data-filter="LOW" onclick="filterFindings('LOW')">
                    Low <span class="filter-count">{{ low_count }}</span>
                </button>
                <button class="filter-btn filter-info" data-filter="INFO" onclick="filterFindings('INFO')">
                    Info <span class="filter-count">{{ info_count }}</span>
                </button>
                <span class="filter-status" id="filterStatus">Showing all {{ total }} findings</span>
            </div>
            {% endif %}

            <div class="no-results-message" id="noResultsMessage">
                No findings match the selected filter.
            </div>

            <div id="findingsContainer">
            {% for finding in data.findings %}
            <div class="finding-card {{ severity_class(finding.severity) }}" data-severity="{{ finding.severity }}">
                <div class="finding-header">
                    <div class="finding-title">{{ finding.title }}</div>
                    <div class="finding-badges">
                        <span class="badge {{ severity_class(finding.severity) }}">{{ finding.severity }}</span>
                        <span class="badge cwe">{{ finding.cwe_id }}</span>
                        {% if finding.cvss_score > 0 %}
                        <span class="cvss-score">CVSS {{ finding.cvss_score }}</span>
                        {% endif %}
                    </div>
                </div>
                <div class="finding-content">
                    <p>{{ finding.description }}</p>
                    <div class="finding-detail">
                        <strong>Affected URLs ({{ finding.affected_count }}):</strong>
                        {% if finding.affected_count <= 3 %}
                        {{ finding.affected_urls | join(', ') }}
                        {% else %}
                        <details>
                            <summary>{{ finding.affected_urls[0] }} and {{ finding.affected_count - 1 }} more...</summary>
                            <ul style="margin-top: 0.5rem; padding-left: 1.5rem;">
                            {% for url in finding.affected_urls %}
                                <li style="word-break: break-all;">{{ url }}</li>
                            {% endfor %}
                            </ul>
                        </details>
                        {% endif %}
                    </div>
                    {% if finding.evidence %}
                    <div class="finding-detail">
                        <strong>Evidence:</strong>
                        <div class="evidence">{{ finding.evidence }}</div>
                    </div>
                    {% endif %}
                    {% if finding.remediation %}
                    <div class="finding-detail">
                        <strong>Remediation:</strong>
                        <div class="remediation">{{ finding.remediation }}</div>
                    </div>
                    {% endif %}
                </div>
            </div>
            {% endfor %}
            </div>
            {% if not data.findings %}
            <div class="finding-card">
                <div class="empty-state">
                    <div class="icon">[OK]</div>
                    <p>No security vulnerabilities were detected during this scan.</p>
                </div>
            </div>
            {% endif %}
        </div>

        {% if data.errors %}
        <div class="findings-section">
            <h2>Scan Errors</h2>
            {% for error in data.errors %}
            <div class="error-card">{{ error }}</div>
            {% endfor %}
        </div>
        {% endif %}

        <footer>
            <p>Generated by <strong>SecureProbe v1.0.0</strong> | <a href="https://olib.ai">Olib AI</a></p>
            <p style="margin-top: 0.5rem; font-size: 0.8rem;">Report generated at {{ data.meta.report_generated[:19].replace('T', ' ') }} UTC</p>
        </footer>
    </div>

    <script>
        /**
         * Filter findings by severity level.
         * @param {string} severity - Severity level to filter by, or 'all' for all findings
         */
        function filterFindings(severity) {
            const findings = document.querySelectorAll('.finding-card[data-severity]');
            const buttons = document.querySelectorAll('.filter-btn');
            const statusEl = document.getElementById('filterStatus');
            const noResultsEl = document.getElementById('noResultsMessage');

            // Update active button
            buttons.forEach(btn => {
                btn.classList.remove('active');
                if (btn.dataset.filter === severity) {
                    btn.classList.add('active');
                }
            });

            // Filter findings
            let visibleCount = 0;
            findings.forEach(card => {
                if (severity === 'all' || card.dataset.severity === severity) {
                    card.classList.remove('hidden');
                    visibleCount++;
                } else {
                    card.classList.add('hidden');
                }
            });

            // Update status text
            if (severity === 'all') {
                statusEl.textContent = `Showing all ${visibleCount} findings`;
            } else {
                const severityName = severity.charAt(0) + severity.slice(1).toLowerCase();
                statusEl.textContent = `Showing ${visibleCount} ${severityName} finding${visibleCount !== 1 ? 's' : ''}`;
            }

            // Show/hide no results message
            if (visibleCount === 0) {
                noResultsEl.style.display = 'block';
            } else {
                noResultsEl.style.display = 'none';
            }
        }

        // Initialize - ensure all findings are visible on load
        document.addEventListener('DOMContentLoaded', function() {
            const findings = document.querySelectorAll('.finding-card[data-severity]');
            findings.forEach(card => card.classList.remove('hidden'));
        });
    </script>
</body>
</html>"""
