import { DriftFinding, DriftReport, DriftSummary } from "./types";

/**
 * Determine if a setting name or leaf property matches sensitive secret patterns.
 */
export function isSensitiveKey(setting: string, ruleId?: string): boolean {
  if (ruleId === "CIS-SEC-1") return true;
  const leaf = setting.split(".").pop() || setting;
  const cleanLeaf = leaf.replace(/\[\d+\]$/, "");
  return /(?:secret|api[-_]?key|private[-_]?key|pass(?:word|wd)?|db[-_]?pass|token|credential)/i.test(
    cleanLeaf
  );
}

/**
 * Mask sensitive values such as tokens, passwords, and API keys to prevent secret leakage in reports.
 * Recursively redacts nested objects, arrays, and credential fields.
 */
export function maskSensitiveValue(setting: string, value: any, ruleId?: string): any {
  if (value === null || value === undefined) return value;

  // Recursively sanitize arrays
  if (Array.isArray(value)) {
    return value.map((item, idx) =>
      maskSensitiveValue(`${setting}[${idx}]`, item, ruleId)
    );
  }

  // Recursively sanitize objects
  if (typeof value === "object") {
    const sanitized: Record<string, any> = {};
    for (const [key, val] of Object.entries(value)) {
      sanitized[key] = maskSensitiveValue(`${setting}.${key}`, val, ruleId);
    }
    return sanitized;
  }

  const isSecret = isSensitiveKey(setting, ruleId);

  if (isSecret) {
    if (typeof value === "string") {
      if (value.startsWith("${")) return value; // Preserve environment variable placeholders
      return "[REDACTED_SECRET]";
    }
    if (typeof value === "number" || typeof value === "boolean") {
      return "[REDACTED_SECRET]";
    }
  }

  return value;
}

/**
 * Format a value cleanly for text display without showing [object Object].
 */
function formatDisplayValue(val: any): string {
  if (val === null || val === undefined) return String(val);
  if (typeof val === "object") return JSON.stringify(val);
  return String(val);
}

/**
 * Generate a structured DriftGuard report object with automatic secret redaction.
 */
export function generateReport(
  expectedPath: string,
  actualPath: string,
  findings: DriftFinding[]
): DriftReport {
  const sanitizedFindings: DriftFinding[] = findings.map((f) => ({
    ...f,
    expected: maskSensitiveValue(f.setting, f.expected, f.ruleId),
    actual: maskSensitiveValue(f.setting, f.actual, f.ruleId),
  }));

  const summary: DriftSummary = {
    total: sanitizedFindings.length,
    critical: sanitizedFindings.filter((f) => f.severity === "CRITICAL").length,
    medium: sanitizedFindings.filter((f) => f.severity === "MEDIUM").length,
    low: sanitizedFindings.filter((f) => f.severity === "LOW").length,
  };

  return {
    tool: "DriftGuard",
    generated_at: new Date().toISOString(),
    expected_config: expectedPath,
    actual_config: actualPath,
    status: summary.critical > 0 ? "BLOCKED" : "PASSED",
    summary,
    findings: sanitizedFindings,
  };
}

/**
 * Format a report for terminal output.
 */
export function formatTerminalReport(report: DriftReport): string {
  const { summary } = report;
  const lines: string[] = [
    "=".repeat(55),
    "              DRIFTGUARD REPORT",
    "=".repeat(55),
    `Status:   ${report.status}`,
    `Expected: ${report.expected_config}`,
    `Actual:   ${report.actual_config}`,
    "",
    "SUMMARY",
    "-".repeat(55),
    `Total differences : ${summary.total}`,
    `Critical          : ${summary.critical}`,
    `Medium            : ${summary.medium}`,
    `Low               : ${summary.low}`,
    "",
    "FINDINGS",
    "-".repeat(55),
  ];

  if (report.findings.length === 0) {
    lines.push("No configuration drift detected.");
  } else {
    for (const finding of report.findings) {
      lines.push(
        `Setting:  ${finding.setting}`,
        `Change:   ${finding.change}`,
        `Expected: ${formatDisplayValue(finding.expected)}`,
        `Actual:   ${formatDisplayValue(finding.actual)}`,
        `Severity: ${finding.severity}`
      );
      if (finding.ruleId && finding.reason) {
        lines.push(`Policy:   [${finding.ruleId}] ${finding.reason}`);
      }
      lines.push("-".repeat(55));
    }
  }

  return lines.join("\n");
}

/**
 * Generate a readable Markdown report.
 */
export function generateMarkdownReport(report: DriftReport): string {
  const { summary } = report;
  const lines: string[] = [
    "# DriftGuard Configuration Drift Report",
    "",
    `**Status:** ${report.status}`,
    `**Generated:** ${report.generated_at}`,
    `**Expected configuration:** \`${report.expected_config}\``,
    `**Actual configuration:** \`${report.actual_config}\``,
    "",
    "## Summary",
    "",
    `- Total differences: ${summary.total}`,
    `- Critical: ${summary.critical}`,
    `- Medium: ${summary.medium}`,
    `- Low: ${summary.low}`,
    "",
    "## Findings",
    "",
  ];

  if (report.findings.length === 0) {
    lines.push("No configuration drift detected.");
  } else {
    for (const finding of report.findings) {
      lines.push(
        `### ${finding.setting}`,
        "",
        `- **Change:** ${finding.change}`,
        `- **Expected:** \`${formatDisplayValue(finding.expected)}\``,
        `- **Actual:** \`${formatDisplayValue(finding.actual)}\``,
        `- **Severity:** ${finding.severity}`
      );
      if (finding.ruleId && finding.reason) {
        lines.push(`- **Policy (${finding.ruleId}):** ${finding.reason}`);
      }
      lines.push("");
    }
  }

  return lines.join("\n");
}
