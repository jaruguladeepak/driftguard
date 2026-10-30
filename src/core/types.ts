export type Severity = "CRITICAL" | "MEDIUM" | "LOW";

export type ChangeType = "added" | "removed" | "changed";

export interface DriftDifference {
  setting: string;
  expected: any;
  actual: any;
  change: ChangeType;
}

export interface DriftFinding extends DriftDifference {
  severity: Severity;
}

export interface DriftSummary {
  total: number;
  critical: number;
  medium: number;
  low: number;
}

export type DeploymentStatus = "BLOCKED" | "PASSED";

export interface DriftReport {
  tool: string;
  generated_at: string;
  expected_config: string;
  actual_config: string;
  status: DeploymentStatus;
  summary: DriftSummary;
  findings: DriftFinding[];
}

