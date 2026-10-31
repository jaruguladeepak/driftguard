import crypto from "node:crypto";
import { DatabaseManager } from "./index";

export interface UserRecord {
  id: string;
  username: string;
  email: string;
  password_hash: string;
  role: string;
  created_at: string;
}

export interface SessionRecord {
  id: string;
  token_hash: string;
  user_id: string;
  expires_at: string;
  created_at: string;
}

export interface ProjectRecord {
  id: string;
  name: string;
  description: string | null;
  user_id: string;
  created_at: string;
  updated_at: string;
}

export interface ConfigurationRecord {
  id: string;
  project_id: string;
  name: string;
  format: "yaml" | "json" | "toml";
  content: string;
  is_baseline: number;
  created_at: string;
  updated_at: string;
}

export interface AnalysisRunRecord {
  id: string;
  project_id: string | null;
  expected_source: string;
  actual_source: string;
  format: string;
  status: "PASSED" | "BLOCKED";
  total_diffs: number;
  critical_count: number;
  medium_count: number;
  low_count: number;
  execution_duration_ms: number;
  user_id: string | null;
  created_at: string;
}

export interface FindingRecord {
  id: string;
  analysis_run_id: string;
  setting: string;
  change_type: string;
  expected_value: string | null;
  actual_value: string | null;
  severity: "CRITICAL" | "MEDIUM" | "LOW";
  rule_id: string | null;
  reason: string | null;
  review_status: "PENDING" | "ACKNOWLEDGED" | "RESOLVED";
  created_at: string;
}

export interface ReportRecord {
  id: string;
  analysis_run_id: string;
  format: "json" | "markdown";
  content: string;
  created_at: string;
}

export interface AuditEventRecord {
  id: string;
  user_id: string | null;
  action: string;
  resource_type: string;
  resource_id: string | null;
  details: string | null;
  ip_address: string | null;
  created_at: string;
}

export class Repositories {
  constructor(private db: DatabaseManager) {}

  // ================= USERS =================
  public createUser(user: { username: string; email: string; password_hash: string; role?: string }): UserRecord {
    const id = crypto.randomUUID();
    const role = user.role || "user";
    this.db.run(
      "INSERT INTO users (id, username, email, password_hash, role) VALUES (?, ?, ?, ?, ?)",
      [id, user.username, user.email, user.password_hash, role]
    );
    return this.getUserById(id)!;
  }

  public getUserById(id: string): UserRecord | undefined {
    return this.db.queryOne<UserRecord>("SELECT * FROM users WHERE id = ?", [id]);
  }

  public getUserByUsername(username: string): UserRecord | undefined {
    return this.db.queryOne<UserRecord>("SELECT * FROM users WHERE username = ?", [username]);
  }

  public getUserByEmail(email: string): UserRecord | undefined {
    return this.db.queryOne<UserRecord>("SELECT * FROM users WHERE email = ?", [email]);
  }

  // ================= SESSIONS =================
  public createSession(userId: string, tokenHash: string, expiresAt: string): SessionRecord {
    const id = crypto.randomUUID();
    this.db.run(
      "INSERT INTO sessions (id, token_hash, user_id, expires_at) VALUES (?, ?, ?, ?)",
      [id, tokenHash, userId, expiresAt]
    );
    return this.db.queryOne<SessionRecord>("SELECT * FROM sessions WHERE id = ?", [id])!;
  }

  public getSessionByTokenHash(tokenHash: string): (SessionRecord & { username: string; email: string; role: string }) | undefined {
    return this.db.queryOne<SessionRecord & { username: string; email: string; role: string }>(
      `SELECT s.*, u.username, u.email, u.role
       FROM sessions s
       JOIN users u ON s.user_id = u.id
       WHERE s.token_hash = ? AND datetime(s.expires_at) > datetime('now')`,
      [tokenHash]
    );
  }

  public deleteSession(tokenHash: string): void {
    this.db.run("DELETE FROM sessions WHERE token_hash = ?", [tokenHash]);
  }

  public deleteExpiredSessions(): void {
    this.db.run("DELETE FROM sessions WHERE datetime(expires_at) <= datetime('now')");
  }

  // ================= PROJECTS =================
  public createProject(userId: string, name: string, description?: string): ProjectRecord {
    const id = crypto.randomUUID();
    this.db.run(
      "INSERT INTO projects (id, name, description, user_id) VALUES (?, ?, ?, ?)",
      [id, name, description || null, userId]
    );
    return this.getProjectById(id, userId)!;
  }

  public listProjectsByUser(userId: string): (ProjectRecord & { configuration_count: number; analysis_count: number })[] {
    return this.db.query(
      `SELECT p.*,
        (SELECT COUNT(*) FROM configurations c WHERE c.project_id = p.id) as configuration_count,
        (SELECT COUNT(*) FROM analysis_runs a WHERE a.project_id = p.id) as analysis_count
       FROM projects p
       WHERE p.user_id = ?
       ORDER BY p.updated_at DESC`,
      [userId]
    );
  }

  public getProjectById(id: string, userId?: string): ProjectRecord | undefined {
    if (userId) {
      return this.db.queryOne<ProjectRecord>("SELECT * FROM projects WHERE id = ? AND user_id = ?", [id, userId]);
    }
    return this.db.queryOne<ProjectRecord>("SELECT * FROM projects WHERE id = ?", [id]);
  }

  public updateProject(id: string, userId: string, data: { name?: string; description?: string }): ProjectRecord | undefined {
    const existing = this.getProjectById(id, userId);
    if (!existing) return undefined;

    const name = data.name !== undefined ? data.name : existing.name;
    const desc = data.description !== undefined ? data.description : existing.description;

    this.db.run(
      "UPDATE projects SET name = ?, description = ?, updated_at = datetime('now') WHERE id = ? AND user_id = ?",
      [name, desc, id, userId]
    );
    return this.getProjectById(id, userId);
  }

  public deleteProject(id: string, userId: string): boolean {
    const result = this.db.run("DELETE FROM projects WHERE id = ? AND user_id = ?", [id, userId]);
    return result.changes > 0;
  }

  // ================= CONFIGURATIONS =================
  public createConfiguration(data: {
    projectId: string;
    name: string;
    format: "yaml" | "json" | "toml";
    content: string;
    isBaseline?: boolean;
  }): ConfigurationRecord {
    const id = crypto.randomUUID();
    this.db.run(
      "INSERT INTO configurations (id, project_id, name, format, content, is_baseline) VALUES (?, ?, ?, ?, ?, ?)",
      [id, data.projectId, data.name, data.format, data.content, data.isBaseline ? 1 : 0]
    );
    return this.getConfigurationById(id)!;
  }

  public listConfigurationsByProject(projectId: string): ConfigurationRecord[] {
    return this.db.query<ConfigurationRecord>(
      "SELECT id, project_id, name, format, is_baseline, created_at, updated_at FROM configurations WHERE project_id = ? ORDER BY is_baseline DESC, name ASC",
      [projectId]
    );
  }

  public getConfigurationById(id: string, userId?: string): ConfigurationRecord | undefined {
    if (userId) {
      return this.db.queryOne<ConfigurationRecord>(
        `SELECT c.* FROM configurations c
         JOIN projects p ON c.project_id = p.id
         WHERE c.id = ? AND p.user_id = ?`,
        [id, userId]
      );
    }
    return this.db.queryOne<ConfigurationRecord>("SELECT * FROM configurations WHERE id = ?", [id]);
  }

  public updateConfiguration(
    id: string,
    data: { name?: string; content?: string; isBaseline?: boolean },
    userId?: string
  ): ConfigurationRecord | undefined {
    const existing = this.getConfigurationById(id, userId);
    if (!existing) return undefined;

    const name = data.name !== undefined ? data.name : existing.name;
    const content = data.content !== undefined ? data.content : existing.content;
    const isBaseline = data.isBaseline !== undefined ? (data.isBaseline ? 1 : 0) : existing.is_baseline;

    this.db.run(
      "UPDATE configurations SET name = ?, content = ?, is_baseline = ?, updated_at = datetime('now') WHERE id = ?",
      [name, content, isBaseline, id]
    );
    return this.getConfigurationById(id, userId);
  }

  public deleteConfiguration(id: string, userId?: string): boolean {
    if (userId) {
      const res = this.db.run(
        `DELETE FROM configurations
         WHERE id = ? AND project_id IN (SELECT id FROM projects WHERE user_id = ?)`,
        [id, userId]
      );
      return res.changes > 0;
    }
    const res = this.db.run("DELETE FROM configurations WHERE id = ?", [id]);
    return res.changes > 0;
  }

  // ================= ANALYSES & FINDINGS =================
  public createAnalysisRun(run: {
    projectId?: string | null;
    userId?: string | null;
    expectedSource: string;
    actualSource: string;
    format: string;
    status: "PASSED" | "BLOCKED";
    totalDiffs: number;
    criticalCount: number;
    mediumCount: number;
    lowCount: number;
    durationMs: number;
  }): AnalysisRunRecord {
    const id = crypto.randomUUID();
    this.db.run(
      `INSERT INTO analysis_runs (
        id, project_id, user_id, expected_source, actual_source, format,
        status, total_diffs, critical_count, medium_count, low_count, execution_duration_ms
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        id,
        run.projectId || null,
        run.userId || null,
        run.expectedSource,
        run.actualSource,
        run.format,
        run.status,
        run.totalDiffs,
        run.criticalCount,
        run.mediumCount,
        run.lowCount,
        run.durationMs,
      ]
    );
    return this.getAnalysisRunById(id)!;
  }

  public listAnalysisRuns(options: { projectId?: string; userId: string; limit?: number; offset?: number }): AnalysisRunRecord[] {
    const conditions: string[] = ["user_id = ?"];
    const params: any[] = [options.userId];

    if (options.projectId) {
      conditions.push("project_id = ?");
      params.push(options.projectId);
    }

    const whereClause = `WHERE ${conditions.join(" AND ")}`;
    const limit = options.limit || 50;
    const offset = options.offset || 0;
    params.push(limit, offset);

    return this.db.query<AnalysisRunRecord>(
      `SELECT * FROM analysis_runs ${whereClause} ORDER BY created_at DESC LIMIT ? OFFSET ?`,
      params
    );
  }

  public getAnalysisRunById(id: string, userId?: string): AnalysisRunRecord | undefined {
    if (userId) {
      return this.db.queryOne<AnalysisRunRecord>(
        "SELECT * FROM analysis_runs WHERE id = ? AND user_id = ?",
        [id, userId]
      );
    }
    return this.db.queryOne<AnalysisRunRecord>("SELECT * FROM analysis_runs WHERE id = ?", [id]);
  }

  public createFindings(analysisRunId: string, findings: Array<{
    setting: string;
    change: string;
    expected: any;
    actual: any;
    severity: "CRITICAL" | "MEDIUM" | "LOW";
    ruleId?: string;
    reason?: string;
  }>): void {
    const stmt = this.db.getRawDb().prepare(
      `INSERT INTO findings (
        id, analysis_run_id, setting, change_type, expected_value, actual_value, severity, rule_id, reason
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
    );

    for (const f of findings) {
      const id = crypto.randomUUID();
      const expVal = f.expected !== null && f.expected !== undefined
        ? (typeof f.expected === "object" ? JSON.stringify(f.expected) : String(f.expected))
        : null;
      const actVal = f.actual !== null && f.actual !== undefined
        ? (typeof f.actual === "object" ? JSON.stringify(f.actual) : String(f.actual))
        : null;

      stmt.run(
        id,
        analysisRunId,
        f.setting,
        f.change,
        expVal,
        actVal,
        f.severity,
        f.ruleId || null,
        f.reason || null
      );
    }
  }

  public getFindingsByRun(
    analysisRunId: string,
    filter?: { severity?: string; ruleId?: string },
    userId?: string
  ): FindingRecord[] {
    const conditions = ["f.analysis_run_id = ?"];
    const params: any[] = [analysisRunId];

    if (userId) {
      conditions.push("a.user_id = ?");
      params.push(userId);
    }

    if (filter?.severity && filter.severity !== "ALL") {
      conditions.push("f.severity = ?");
      params.push(filter.severity);
    }
    if (filter?.ruleId) {
      conditions.push("f.rule_id = ?");
      params.push(filter.ruleId);
    }

    return this.db.query<FindingRecord>(
      `SELECT f.* FROM findings f
       JOIN analysis_runs a ON f.analysis_run_id = a.id
       WHERE ${conditions.join(" AND ")}
       ORDER BY CASE f.severity WHEN 'CRITICAL' THEN 1 WHEN 'MEDIUM' THEN 2 ELSE 3 END, f.setting ASC`,
      params
    );
  }

  public updateFindingReviewStatus(
    id: string,
    status: "PENDING" | "ACKNOWLEDGED" | "RESOLVED",
    userId?: string
  ): boolean {
    if (userId) {
      const res = this.db.run(
        `UPDATE findings
         SET review_status = ?
         WHERE id = ? AND analysis_run_id IN (SELECT id FROM analysis_runs WHERE user_id = ?)`,
        [status, id, userId]
      );
      return res.changes > 0;
    }
    const res = this.db.run("UPDATE findings SET review_status = ? WHERE id = ?", [status, id]);
    return res.changes > 0;
  }

  // ================= REPORTS =================
  public saveReports(analysisRunId: string, reports: { json: string; markdown: string }): void {
    const jsonId = crypto.randomUUID();
    const mdId = crypto.randomUUID();

    this.db.run(
      "INSERT INTO reports (id, analysis_run_id, format, content) VALUES (?, ?, 'json', ?)",
      [jsonId, analysisRunId, reports.json]
    );
    this.db.run(
      "INSERT INTO reports (id, analysis_run_id, format, content) VALUES (?, ?, 'markdown', ?)",
      [mdId, analysisRunId, reports.markdown]
    );
  }

  public getReportByRunAndFormat(analysisRunId: string, format: "json" | "markdown", userId?: string): ReportRecord | undefined {
    if (userId) {
      return this.db.queryOne<ReportRecord>(
        `SELECT r.* FROM reports r
         JOIN analysis_runs a ON r.analysis_run_id = a.id
         WHERE r.analysis_run_id = ? AND r.format = ? AND a.user_id = ?`,
        [analysisRunId, format, userId]
      );
    }
    return this.db.queryOne<ReportRecord>(
      "SELECT * FROM reports WHERE analysis_run_id = ? AND format = ?",
      [analysisRunId, format]
    );
  }

  // ================= AUDIT LOGS =================
  public logAudit(event: {
    userId?: string | null;
    action: string;
    resourceType: string;
    resourceId?: string | null;
    details?: any;
    ipAddress?: string | null;
  }): void {
    const id = crypto.randomUUID();
    const detailsStr = event.details ? (typeof event.details === "string" ? event.details : JSON.stringify(event.details)) : null;

    this.db.run(
      "INSERT INTO audit_events (id, user_id, action, resource_type, resource_id, details, ip_address) VALUES (?, ?, ?, ?, ?, ?, ?)",
      [id, event.userId || null, event.action, event.resourceType, event.resourceId || null, detailsStr, event.ipAddress || null]
    );
  }

  public listAuditEvents(userId?: string, limit = 100): AuditEventRecord[] {
    if (userId) {
      return this.db.query<AuditEventRecord>(
        "SELECT * FROM audit_events WHERE user_id = ? ORDER BY created_at DESC LIMIT ?",
        [userId, limit]
      );
    }
    return this.db.query<AuditEventRecord>(
      "SELECT * FROM audit_events ORDER BY created_at DESC LIMIT ?",
      [limit]
    );
  }
}
