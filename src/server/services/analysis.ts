import { parseConfig, detectFormat, ConfigFormat } from "../../core/parser";
import { detectDrift } from "../../core/detector";
import { evaluateFindings } from "../../core/policies";
import { generateReport, generateMarkdownReport } from "../../core/reporter";
import { DriftReport } from "../../core/types";
import { Repositories, AnalysisRunRecord, FindingRecord } from "../db/repositories";

export interface AnalysisInput {
  expected: string;
  actual: string;
  format?: ConfigFormat;
  expectedSource?: string;
  actualSource?: string;
  projectId?: string | null;
  userId?: string | null;
}

export interface AnalysisComparison {
  baseRunId: string;
  targetRunId: string;
  newFindings: FindingRecord[];
  persistentFindings: FindingRecord[];
  resolvedFindings: FindingRecord[];
  summary: {
    baseTotal: number;
    targetTotal: number;
    newCount: number;
    persistentCount: number;
    resolvedCount: number;
  };
}

export class AnalysisService {
  constructor(private repos: Repositories) { }

  /**
   * Run drift detection and security policy evaluation in-memory only.
   * Does NOT write to the database. Used for unauthenticated / one-off analysis requests.
   */
  public executeAnalysisOnly(input: AnalysisInput): { report: DriftReport } {
    const expectedSource = input.expectedSource || "Expected Baseline";
    const actualSource = input.actualSource || "Actual Configuration";

    const expFmt = input.format || detectFormat(input.expected, expectedSource);
    const actFmt = input.format || detectFormat(input.actual, actualSource);

    const expObj = parseConfig(input.expected, expectedSource, expFmt);
    const actObj = parseConfig(input.actual, actualSource, actFmt);

    const diffs = detectDrift(expObj, actObj);
    const findings = evaluateFindings(diffs);
    const report = generateReport(expectedSource, actualSource, findings);

    return { report };
  }

  /**
   * Run drift detection and security policy evaluation, and persist run, findings,
   * and reports to SQLite for an authenticated user.
   */
  public executeAndPersistAnalysis(input: AnalysisInput): { report: DriftReport; run: AnalysisRunRecord } {
    const startTime = Date.now();

    const expectedSource = input.expectedSource || "Expected Baseline";
    const actualSource = input.actualSource || "Actual Configuration";

    const expFmt = input.format || detectFormat(input.expected, expectedSource);
    const actFmt = input.format || detectFormat(input.actual, actualSource);

    // Parse configurations using existing multi-format parser
    const expObj = parseConfig(input.expected, expectedSource, expFmt);
    const actObj = parseConfig(input.actual, actualSource, actFmt);

    // Run core recursive diff and CIS policy evaluation
    const diffs = detectDrift(expObj, actObj);
    const findings = evaluateFindings(diffs);

    // Generate sanitized structured report and Markdown brief
    const report = generateReport(expectedSource, actualSource, findings);
    const markdownReport = generateMarkdownReport(report);
    const durationMs = Date.now() - startTime;

    // Persist analysis run record tied to user
    const run = this.repos.createAnalysisRun({
      projectId: input.projectId,
      userId: input.userId,
      expectedSource,
      actualSource,
      format: expFmt,
      status: report.status,
      totalDiffs: report.summary.total,
      criticalCount: report.summary.critical,
      mediumCount: report.summary.medium,
      lowCount: report.summary.low,
      durationMs,
    });

    // Persist findings
    if (report.findings.length > 0) {
      this.repos.createFindings(
        run.id,
        report.findings.map((f) => ({
          setting: f.setting,
          change: f.change,
          expected: f.expected,
          actual: f.actual,
          severity: f.severity,
          ruleId: f.ruleId,
          reason: f.reason,
        }))
      );
    }

    // Persist JSON and Markdown reports
    this.repos.saveReports(run.id, {
      json: JSON.stringify(report, null, 2),
      markdown: markdownReport,
    });

    return { report, run };
  }

  /**
   * Compare two historical analysis runs belonging to the user.
   * Validates that both runs exist and belong to the authenticated user.
   */
  public compareHistoricalRuns(baseRunId: string, targetRunId: string, userId: string): AnalysisComparison {
    const baseRun = this.repos.getAnalysisRunById(baseRunId, userId);
    const targetRun = this.repos.getAnalysisRunById(targetRunId, userId);

    if (!baseRun) throw new Error(`Base analysis run not found or access denied.`);
    if (!targetRun) throw new Error(`Target analysis run not found or access denied.`);

    const baseFindings = this.repos.getFindingsByRun(baseRunId, undefined, userId);
    const targetFindings = this.repos.getFindingsByRun(targetRunId, undefined, userId);

    const baseMap = new Map<string, FindingRecord>();
    for (const f of baseFindings) {
      const key = `${f.setting}:${f.rule_id || "general"}`;
      baseMap.set(key, f);
    }

    const targetMap = new Map<string, FindingRecord>();
    for (const f of targetFindings) {
      const key = `${f.setting}:${f.rule_id || "general"}`;
      targetMap.set(key, f);
    }

    const newFindings: FindingRecord[] = [];
    const persistentFindings: FindingRecord[] = [];
    const resolvedFindings: FindingRecord[] = [];

    for (const [key, f] of targetMap.entries()) {
      if (baseMap.has(key)) {
        persistentFindings.push(f);
      } else {
        newFindings.push(f);
      }
    }

    for (const [key, f] of baseMap.entries()) {
      if (!targetMap.has(key)) {
        resolvedFindings.push(f);
      }
    }

    return {
      baseRunId,
      targetRunId,
      newFindings,
      persistentFindings,
      resolvedFindings,
      summary: {
        baseTotal: baseFindings.length,
        targetTotal: targetFindings.length,
        newCount: newFindings.length,
        persistentCount: persistentFindings.length,
        resolvedCount: resolvedFindings.length,
      },
    };
  }
}
