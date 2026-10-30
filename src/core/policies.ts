import { DriftDifference, DriftFinding, Severity } from "./types";

/**
 * Assign severity to a single configuration difference.
 */
export function assignSeverity(difference: DriftDifference): Severity {
  const { setting, actual, change } = difference;

  if (setting === "app.debug" && actual === true) {
    return "CRITICAL";
  }

  if (setting === "security.https_required") {
    if (change === "removed" || actual !== true) {
      return "CRITICAL";
    }
  }

  if (setting === "app.port") {
    return "MEDIUM";
  }

  return "LOW";
}

/**
 * Evaluate all differences and attach their risk severity.
 */
export function evaluateFindings(differences: DriftDifference[]): DriftFinding[] {
  return differences.map((diff) => ({
    ...diff,
    severity: assignSeverity(diff),
  }));
}

/**
 * Determine whether deployment should be blocked based on findings.
 */
export function shouldBlock(findings: DriftFinding[]): boolean {
  return findings.some((f) => f.severity === "CRITICAL");
}

