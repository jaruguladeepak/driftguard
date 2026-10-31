import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { DatabaseManager } from "../src/server/db/index";
import { Repositories } from "../src/server/db/repositories";
import { AnalysisService } from "../src/server/services/analysis";

describe("Database & Persistence Layer (node:sqlite)", () => {
  let db: DatabaseManager;
  let repos: Repositories;
  let analysisService: AnalysisService;

  beforeEach(() => {
    // In-memory isolated database for each test
    db = new DatabaseManager(":memory:");
    repos = new Repositories(db);
    analysisService = new AnalysisService(repos);
  });

  afterEach(() => {
    db.close();
  });

  it("initializes schema and records migration", () => {
    const migrations = db.query("SELECT * FROM _migrations");
    expect(migrations.length).toBeGreaterThan(0);
    expect(migrations[0].name).toBe("001_initial_schema");
  });

  it("creates, queries, and deletes users", () => {
    const user = repos.createUser({
      username: "alice",
      email: "alice@example.com",
      password_hash: "salt:fakehash",
      role: "admin",
    });

    expect(user.id).toBeDefined();
    expect(user.username).toBe("alice");

    const fetched = repos.getUserByUsername("alice");
    expect(fetched?.email).toBe("alice@example.com");

    const byEmail = repos.getUserByEmail("alice@example.com");
    expect(byEmail?.id).toBe(user.id);
  });

  it("enforces foreign key constraints and cascade deletion", () => {
    const user = repos.createUser({
      username: "bob",
      email: "bob@example.com",
      password_hash: "salt:hash",
    });

    const project = repos.createProject(user.id, "Production Cloud", "Infrastructure configs");
    expect(project.id).toBeDefined();

    const config = repos.createConfiguration({
      projectId: project.id,
      name: "prod-baseline.yaml",
      format: "yaml",
      content: "app:\n  port: 8080",
      isBaseline: true,
    });
    expect(config.id).toBeDefined();

    // Delete project -> should cascade delete configurations
    repos.deleteProject(project.id, user.id);

    const fetchedConfig = repos.getConfigurationById(config.id);
    expect(fetchedConfig).toBeUndefined();
  });

  it("rolls back transactions on error", () => {
    const user = repos.createUser({
      username: "charlie",
      email: "charlie@example.com",
      password_hash: "salt:hash",
    });

    expect(() => {
      db.transaction(() => {
        repos.createProject(user.id, "Tx Project");
        throw new Error("Intentional abort");
      });
    }).toThrow("Intentional abort");

    const projects = repos.listProjectsByUser(user.id);
    expect(projects.length).toBe(0);
  });

  it("persists analysis runs, findings, and reports", () => {
    const user = repos.createUser({
      username: "dave",
      email: "dave@example.com",
      password_hash: "salt:hash",
    });
    const project = repos.createProject(user.id, "Security Audit Project");

    const { report, run } = analysisService.executeAndPersistAnalysis({
      expected: "app:\n  debug: false\n  port: 8000",
      actual: "app:\n  debug: true\n  port: 9000",
      format: "yaml",
      projectId: project.id,
      userId: user.id,
    });

    expect(report.status).toBe("BLOCKED");

    expect(run.status).toBe("BLOCKED");
    expect(run.total_diffs).toBe(2);
    expect(run.critical_count).toBe(1);

    const fetchedRun = repos.getAnalysisRunById(run.id);
    expect(fetchedRun).toBeDefined();
    expect(fetchedRun?.status).toBe("BLOCKED");

    const findings = repos.getFindingsByRun(run.id);
    expect(findings.length).toBe(2);

    const debugFinding = findings.find((f) => f.setting === "app.debug");
    expect(debugFinding?.severity).toBe("CRITICAL");
    expect(debugFinding?.rule_id).toBe("CIS-APP-1");
    expect(debugFinding?.review_status).toBe("PENDING");

    // Update review status
    repos.updateFindingReviewStatus(debugFinding!.id, "RESOLVED");
    const updatedFindings = repos.getFindingsByRun(run.id);
    const updatedDebug = updatedFindings.find((f) => f.id === debugFinding!.id);
    expect(updatedDebug?.review_status).toBe("RESOLVED");

    // Fetch reports
    const jsonReport = repos.getReportByRunAndFormat(run.id, "json");
    expect(jsonReport).toBeDefined();
    expect(JSON.parse(jsonReport!.content).status).toBe("BLOCKED");

    const mdReport = repos.getReportByRunAndFormat(run.id, "markdown");
    expect(mdReport).toBeDefined();
    expect(mdReport!.content).toContain("# DriftGuard Configuration Drift Report");
  });

  it("correctly compares two historical analysis runs", () => {
    const user = repos.createUser({
      username: "historian",
      email: "historian@example.com",
      password_hash: "salt:hash",
    });

    // Run 1: has debug: true (CIS-APP-1)
    const { run: run1 } = analysisService.executeAndPersistAnalysis({
      expected: "app:\n  debug: false",
      actual: "app:\n  debug: true",
      format: "yaml",
      userId: user.id,
    });

    // Run 2: fixed debug, but changed port to 9000 (DRIFT-NET-PORT)
    const { run: run2 } = analysisService.executeAndPersistAnalysis({
      expected: "app:\n  port: 8000\n  debug: false",
      actual: "app:\n  port: 9000\n  debug: false",
      format: "yaml",
      userId: user.id,
    });

    const comparison = analysisService.compareHistoricalRuns(run1.id, run2.id, user.id);
    expect(comparison.resolvedFindings.length).toBe(1);
    expect(comparison.resolvedFindings[0].setting).toBe("app.debug");

    expect(comparison.newFindings.length).toBe(1);
    expect(comparison.newFindings[0].setting).toBe("app.port");

    expect(comparison.persistentFindings.length).toBe(0);
  });
});
