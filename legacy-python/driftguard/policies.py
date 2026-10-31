def assign_severity(difference: dict) -> str:
    setting = difference["setting"]
    actual = difference["actual"]
    change = difference.get("change")

    if setting == "app.debug" and actual is True:
        return "CRITICAL"

    if setting == "security.https_required":
        if change == "removed" or actual is not True:
            return "CRITICAL"

    if setting == "app.port":
        return "MEDIUM"

    return "LOW"


def evaluate_findings(differences: list[dict]) -> list[dict]:
    findings = []

    for difference in differences:
        finding = difference.copy()
        finding["severity"] = assign_severity(finding)
        findings.append(finding)

    return findings


def should_block(findings: list[dict]) -> bool:
    return any(
        finding["severity"] == "CRITICAL"
        for finding in findings
    )

