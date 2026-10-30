import json

from driftguard.reporter import (
    format_terminal_report,
    generate_report,
    save_json_report,
    save_markdown_report,
)


def sample_findings():
    return [
        {
            "setting": "app.debug",
            "expected": False,
            "actual": True,
            "change": "changed",
            "severity": "CRITICAL",
        },
        {
            "setting": "app.port",
            "expected": 8000,
            "actual": 9000,
            "change": "changed",
            "severity": "MEDIUM",
        },
    ]


def test_critical_finding_marks_report_blocked():
    report = generate_report(
        "expected.yaml",
        "actual.yaml",
        sample_findings(),
    )

    assert report["status"] == "BLOCKED"
    assert report["summary"]["critical"] == 1
    assert report["summary"]["medium"] == 1
    assert report["summary"]["total"] == 2


def test_clean_report_passes():
    report = generate_report(
        "expected.yaml",
        "actual.yaml",
        [],
    )

    assert report["status"] == "PASSED"
    assert report["summary"]["total"] == 0


def test_json_report_is_saved(tmp_path):
    report = generate_report(
        "expected.yaml",
        "actual.yaml",
        sample_findings(),
    )

    output = tmp_path / "report.json"
    save_json_report(report, str(output))

    saved_report = json.loads(output.read_text(encoding="utf-8"))

    assert saved_report["status"] == "BLOCKED"
    assert len(saved_report["findings"]) == 2


def test_markdown_report_contains_findings(tmp_path):
    report = generate_report(
        "expected.yaml",
        "actual.yaml",
        sample_findings(),
    )

    output = tmp_path / "report.md"
    save_markdown_report(report, str(output))

    content = output.read_text(encoding="utf-8")

    assert "DriftGuard Configuration Drift Report" in content
    assert "app.debug" in content
    assert "CRITICAL" in content


def test_terminal_report_shows_clean_state():
    report = generate_report(
        "expected.yaml",
        "actual.yaml",
        [],
    )

    output = format_terminal_report(report)

    assert "PASSED" in output
    assert "No configuration drift detected." in output

