import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def generate_report(
    expected_path: str,
    actual_path: str,
    findings: list[dict[str, Any]],
) -> dict[str, Any]:
    """Create a structured DriftGuard report."""

    summary = {
        "total": len(findings),
        "critical": sum(
            f["severity"] == "CRITICAL" for f in findings
        ),
        "medium": sum(
            f["severity"] == "MEDIUM" for f in findings
        ),
        "low": sum(
            f["severity"] == "LOW" for f in findings
        ),
    }

    return {
        "tool": "DriftGuard",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "expected_config": expected_path,
        "actual_config": actual_path,
        "status": (
            "BLOCKED"
            if summary["critical"] > 0
            else "PASSED"
        ),
        "summary": summary,
        "findings": findings,
    }


def format_terminal_report(report: dict[str, Any]) -> str:
    """Format a report for terminal output."""

    summary = report["summary"]
    lines = [
        "=" * 55,
        "              DRIFTGUARD REPORT",
        "=" * 55,
        f"Status:   {report['status']}",
        f"Expected: {report['expected_config']}",
        f"Actual:   {report['actual_config']}",
        "",
        "SUMMARY",
        "-" * 55,
        f"Total differences : {summary['total']}",
        f"Critical          : {summary['critical']}",
        f"Medium            : {summary['medium']}",
        f"Low               : {summary['low']}",
        "",
        "FINDINGS",
        "-" * 55,
    ]

    if not report["findings"]:
        lines.append("No configuration drift detected.")

    for finding in report["findings"]:
        lines.extend([
            f"Setting:  {finding['setting']}",
            f"Change:   {finding['change']}",
            f"Expected: {finding['expected']}",
            f"Actual:   {finding['actual']}",
            f"Severity: {finding['severity']}",
            "-" * 55,
        ])

    return "\n".join(lines)


def save_json_report(
    report: dict[str, Any],
    output_path: str = "reports/drift-report.json",
) -> Path:
    """Save the report as JSON."""

    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    path.write_text(
        json.dumps(report, indent=2),
        encoding="utf-8",
    )

    return path


def save_markdown_report(
    report: dict[str, Any],
    output_path: str = "reports/drift-report.md",
) -> Path:
    """Save a readable Markdown report."""

    summary = report["summary"]

    lines = [
        "# DriftGuard Configuration Drift Report",
        "",
        f"**Status:** {report['status']}",
        f"**Generated:** {report['generated_at']}",
        f"**Expected configuration:** `{report['expected_config']}`",
        f"**Actual configuration:** `{report['actual_config']}`",
        "",
        "## Summary",
        "",
        f"- Total differences: {summary['total']}",
        f"- Critical: {summary['critical']}",
        f"- Medium: {summary['medium']}",
        f"- Low: {summary['low']}",
        "",
        "## Findings",
        "",
    ]

    if not report["findings"]:
        lines.append("No configuration drift detected.")

    for finding in report["findings"]:
        lines.extend([
            f"### {finding['setting']}",
            "",
            f"- **Change:** {finding['change']}",
            f"- **Expected:** `{finding['expected']}`",
            f"- **Actual:** `{finding['actual']}`",
            f"- **Severity:** {finding['severity']}",
            "",
        ])

    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines), encoding="utf-8")

    return path
