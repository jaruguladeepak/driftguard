import { describe, it, expect } from "vitest";
import {
  generateReport,
  formatTerminalReport,
  generateMarkdownReport,
} from "../src/core/reporter";
import { DriftFinding } from "../src/core/types";

function sampleFindings(): DriftFinding[] {
  return [
    {
      setting: "app.debug",
      expected: false,
      actual: true,
      change: "changed",
      severity: "CRITICAL",
    },
    {
      setting: "app.port",
      expected: 8000,
      actual: 9000,
      change: "changed",
      severity: "MEDIUM",
    },
  ];
}

describe("reporter", () => {
  it("critical finding marks report blocked", () => {
    const report = generateReport("expected.yaml", "actual.yaml", sampleFindings());

    expect(report.status).toBe("BLOCKED");
    expect(report.summary.critical).toBe(1);
    expect(report.summary.medium).toBe(1);
    expect(report.summary.total).toBe(2);
  });

  it("clean report passes", () => {
    const report = generateReport("expected.yaml", "actual.yaml", []);

    expect(report.status).toBe("PASSED");
    expect(report.summary.total).toBe(0);
    expect(report.summary.critical).toBe(0);
  });

  it("markdown report contains findings", () => {
    const report = generateReport("expected.yaml", "actual.yaml", sampleFindings());
    const content = generateMarkdownReport(report);

    expect(content).toContain("DriftGuard Configuration Drift Report");
    expect(content).toContain("app.debug");
    expect(content).toContain("CRITICAL");
  });

  it("terminal report shows clean state", () => {
    const report = generateReport("expected.yaml", "actual.yaml", []);
    const output = formatTerminalReport(report);

    expect(output).toContain("PASSED");
    expect(output).toContain("No configuration drift detected.");
  });
});

